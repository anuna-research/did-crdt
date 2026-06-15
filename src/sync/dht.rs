//! DHT peer discovery and genesis bootstrap (CON-006).
//!
//! Implements pkarr-based DHT registration and lookup so nodes can discover
//! each other without pre-configured `PEERS`. Any node holding a DID derives
//! a deterministic Ed25519 keypair from the DID's BLAKE3 hash and publishes a
//! signed pkarr TXT record advertising its iroh NodeId. Resolvers derive the
//! same key and query the relay to find bootstrap peers.
//!
//! See ADR-006 for the rationale and CON-006 for the full protocol contract.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::net::{NodeAddr, NodeId};
use pkarr::dns::{self, rdata::RData, ResourceRecord};
use pkarr::{Keypair, PkarrRelayClient, PublicKey, RelaySettings, SignedPacket};

use crate::core::did::Did;

// ── Constants ─────────────────────────────────────────────────────────────────

const RECORD_NAME: &str = "_did-crdt";
const RECORD_TTL: u32 = 3600;
const KDF_DOMAIN: &[u8] = b"did-crdt/discovery/v1";

/// Maximum direct addresses encoded in the TXT record (DNS character strings
/// are capped at 255 bytes; a handful of addresses is plenty for dialing).
const MAX_TXT_ADDRS: usize = 4;

/// Publications for the same `(did, node_addr)` within this window are
/// deduplicated (CON-006 §publication trigger 1 is idempotent per
/// `(did, node)` pair); the periodic refresh task bypasses the window so
/// records never expire.
const PUBLISH_DEDUP_WINDOW: Duration = Duration::from_secs(30 * 60);

/// Cadence of the background republication task (CON-006 §publication
/// trigger 3) — comfortably inside both the HTTP-relay TTL (3600 s) and the
/// mainline DHT retention (~2 h).
const REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Default pkarr relay URL (pkarr.org public relay).
pub const DEFAULT_RELAY: &str = "https://relay.pkarr.org";

// ── Keypair derivation ────────────────────────────────────────────────────────

/// Derive the deterministic pkarr [`Keypair`] for a given DID.
///
/// Any node with the DID string can reproduce this keypair; it is not secret.
/// Authentication of the document comes from the delta signature chain.
fn derive_keypair(did: &Did) -> Keypair {
    let hex = did.method_specific_id();
    let did_hash = decode_hex32(hex).expect("Did invariant guarantees 64 valid hex chars");
    let seed = blake3::hash(&[KDF_DOMAIN, &did_hash].concat());
    Keypair::from_secret_key(seed.as_bytes())
}

/// Decode a 64-char lowercase-or-uppercase hex string into 32 bytes.
fn decode_hex32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = hex.as_bytes();
    for i in 0..32 {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ── PkarrBackend ─────────────────────────────────────────────────────────────

/// Pluggable pkarr backend: either a real HTTP relay or an in-process stub for
/// tests. The enum avoids `async_trait` while keeping the injection point clean.
pub enum PkarrBackend {
    Http(pkarr::PkarrRelayClientAsync),
    /// Shared in-memory store mapping `pub_key_bytes → SignedPacket`.
    InProcess(Arc<Mutex<HashMap<[u8; 32], SignedPacket>>>),
}

impl PkarrBackend {
    async fn publish(&self, packet: &SignedPacket) -> anyhow::Result<()> {
        match self {
            PkarrBackend::Http(client) => {
                client.publish(packet).await?;
                Ok(())
            }
            PkarrBackend::InProcess(store) => {
                let key_bytes = packet.public_key().to_bytes();
                let mut guard = store.lock().unwrap();
                guard.insert(key_bytes, packet.clone());
                Ok(())
            }
        }
    }

    /// Resolve `key`, distinguishing the CON-006 error-model cases: `Ok(None)`
    /// means no record exists (NoPeersFound); `Err` means the relay was
    /// unreachable or the lookup timed out (DhtTimeout) — callers and logs can
    /// then tell a dead relay apart from an unpublished DID.
    async fn resolve(
        &self,
        key: &PublicKey,
        timeout: Duration,
    ) -> anyhow::Result<Option<SignedPacket>> {
        match self {
            PkarrBackend::Http(client) => {
                match tokio::time::timeout(timeout, client.resolve(key)).await {
                    Err(_) => anyhow::bail!("DHT lookup timed out after {timeout:?}"),
                    Ok(Err(e)) => Err(anyhow::anyhow!("pkarr relay error: {e}")),
                    Ok(Ok(packet)) => Ok(packet),
                }
            }
            PkarrBackend::InProcess(store) => {
                let key_bytes = key.to_bytes();
                let guard = store.lock().unwrap();
                Ok(guard.get(&key_bytes).cloned())
            }
        }
    }
}

// ── DhtNode ───────────────────────────────────────────────────────────────────

/// DHT peer discovery node (CON-006).
///
/// Wraps a pkarr relay backend and provides:
/// - [`Self::publish`]: advertise this node's iroh NodeId for a DID.
/// - [`Self::lookup`]: find the NodeId of any peer holding a DID.
/// - [`Self::spawn_refresh_task`]: periodic 60-minute republication.
pub struct DhtNode {
    backend: PkarrBackend,
    /// Sub-timeout for DHT lookups (env: `DHT_LOOKUP_TIMEOUT_MS`, default 5 s).
    pub lookup_timeout: Duration,
    /// Optional secondary address store for in-process test mode.
    /// Keyed by `derive_keypair(did).public_key().to_bytes()`.
    /// When set, `publish` writes the full `NodeAddr` here and `lookup` returns
    /// it so in-process tests get direct socket addresses without a relay.
    addr_store: Option<Arc<Mutex<HashMap<[u8; 32], NodeAddr>>>>,
    /// Last successful publication per DID, for trigger-1 deduplication
    /// (CON-006 §publication). The refresh task bypasses this.
    published: Mutex<HashMap<Did, (std::time::Instant, NodeAddr)>>,
}

impl DhtNode {
    /// Create a `DhtNode` backed by a real HTTP pkarr relay.
    pub fn new_http(relay_url: &str, lookup_timeout: Duration) -> anyhow::Result<Self> {
        let settings = RelaySettings {
            relays: vec![relay_url.to_owned()],
            ..RelaySettings::default()
        };
        let client = PkarrRelayClient::new(settings)?.as_async();
        Ok(Self {
            backend: PkarrBackend::Http(client),
            lookup_timeout,
            addr_store: None,
            published: Mutex::new(HashMap::new()),
        })
    }

    /// Create a `DhtNode` backed by an in-process store (for tests).
    ///
    /// `addr_store` is a shared map from pkarr public-key bytes to full
    /// `NodeAddr`s; both nodes in a test must use the same `Arc` so that
    /// node B can retrieve node A's direct socket address after it publishes.
    pub fn new_in_process(
        store: Arc<Mutex<HashMap<[u8; 32], SignedPacket>>>,
        addr_store: Arc<Mutex<HashMap<[u8; 32], NodeAddr>>>,
        lookup_timeout: Duration,
    ) -> Self {
        Self {
            backend: PkarrBackend::InProcess(store),
            lookup_timeout,
            addr_store: Some(addr_store),
            published: Mutex::new(HashMap::new()),
        }
    }

    /// Publish a pkarr TXT record advertising `node_addr` for `did`.
    ///
    /// Constructs and signs the record with the deterministic keypair derived
    /// from the DID hash. Repeat publications of an unchanged `(did, node_addr)`
    /// within [`PUBLISH_DEDUP_WINDOW`] are skipped (returns `Ok(false)`) so
    /// busy DIDs do not hammer the relay (CON-006 §publication trigger 1).
    /// For in-process test nodes, also stores the full `NodeAddr` in
    /// `addr_store` so `lookup` can return direct socket addresses.
    /// Failures are non-fatal: the startup and periodic refresh triggers will
    /// retry (CON-006 §publication).
    pub async fn publish(&self, did: &Did, node_addr: &NodeAddr) -> anyhow::Result<bool> {
        {
            let published = self.published.lock().unwrap();
            if let Some((at, addr)) = published.get(did) {
                if addr == node_addr && at.elapsed() < PUBLISH_DEDUP_WINDOW {
                    return Ok(false);
                }
            }
        }
        self.publish_force(did, node_addr).await?;
        Ok(true)
    }

    /// Publish unconditionally (used by the periodic refresh task).
    async fn publish_force(&self, did: &Did, node_addr: &NodeAddr) -> anyhow::Result<()> {
        let node_id = node_addr.node_id;
        let keypair = derive_keypair(did);

        // TXT format (CON-006 §record format): each char string is a separate
        // key=value attribute parsed by attributes().
        //   "v=1" + "nid=<node_id>" + optional "relay=<url>"
        //         + optional "addrs=<sockaddr>,<sockaddr>,…"
        // relay/addrs are unauthenticated dialing hints; the iroh handshake
        // authenticates the NodeId, so a forged hint only wastes a connection
        // attempt. Strings must outlive `txt` (borrowed, not owned by TXT).
        let nid_string = format!("nid={node_id}");
        let relay_string: Option<String> =
            node_addr.info.relay_url.as_ref().map(|u| format!("relay={u}"));
        let addrs_string: Option<String> = if node_addr.info.direct_addresses.is_empty() {
            None
        } else {
            let joined = node_addr
                .info
                .direct_addresses
                .iter()
                .take(MAX_TXT_ADDRS)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            Some(format!("addrs={joined}"))
        };
        let mut txt = dns::rdata::TXT::new();
        txt.add_string("v=1")?;
        txt.add_string(&nid_string)?;
        if let Some(ref s) = relay_string {
            txt.add_string(s)?;
        }
        if let Some(ref s) = addrs_string {
            txt.add_string(s)?;
        }

        let mut packet = dns::Packet::new_reply(0);
        packet.answers.push(ResourceRecord::new(
            dns::Name::new(RECORD_NAME).unwrap(),
            dns::CLASS::IN,
            RECORD_TTL,
            RData::TXT(txt),
        ));

        let signed = SignedPacket::from_packet(&keypair, &packet)?;
        self.backend.publish(&signed).await?;

        // For the in-process backend: also persist the full NodeAddr so `lookup`
        // can return direct socket addresses (needed for tests without a relay).
        if let Some(ref store) = self.addr_store {
            let key_bytes = keypair.public_key().to_bytes();
            store.lock().unwrap().insert(key_bytes, node_addr.clone());
        }

        self.published
            .lock()
            .unwrap()
            .insert(did.clone(), (std::time::Instant::now(), node_addr.clone()));
        Ok(())
    }

    /// Resolve the pkarr record for `did` and return the holder's NodeAddr.
    ///
    /// Returns an empty `Vec` if no record is found within `lookup_timeout`.
    /// For in-process nodes that have an `addr_store`, returns the full
    /// `NodeAddr` (with direct socket addresses) stored at publish time.
    pub async fn lookup(&self, did: &Did) -> anyhow::Result<Vec<NodeAddr>> {
        let keypair = derive_keypair(did);
        let pub_key = keypair.public_key();
        let key_bytes = pub_key.to_bytes();

        let Some(packet) = self.backend.resolve(&pub_key, self.lookup_timeout).await? else {
            return Ok(vec![]);
        };

        let mut addrs = Vec::new();
        for rr in packet.resource_records(RECORD_NAME) {
            if let RData::TXT(ref txt) = rr.rdata {
                // TXT format (CON-006 §record format): "v=1" + "nid=<node_id>"
                // + optional "relay=<url>" + optional "addrs=<a>,<b>,…".
                // attributes() parses each char string as a key=value pair.
                let attrs = txt.attributes();
                if attrs.get("v").and_then(|v| v.as_deref()) != Some("1") {
                    continue;
                }
                if let Some(Some(nid_str)) = attrs.get("nid") {
                    if let Ok(node_id) = nid_str.parse::<NodeId>() {
                        // In-process nodes: prefer the full NodeAddr stored at
                        // publish time (direct socket addresses without TXT parse).
                        let full_addr = self
                            .addr_store
                            .as_ref()
                            .and_then(|s| s.lock().unwrap().get(&key_bytes).cloned());
                        let addr = if let Some(a) = full_addr {
                            a
                        } else {
                            // HTTP relay path: parse the unauthenticated dialing
                            // hints. A malformed or forged hint costs at most a
                            // failed connection attempt — the iroh handshake
                            // authenticates the NodeId.
                            let relay_url = attrs
                                .get("relay")
                                .and_then(|v| v.as_deref())
                                .and_then(|s| s.parse::<iroh::net::relay::RelayUrl>().ok());
                            let direct_addresses: std::collections::BTreeSet<_> = attrs
                                .get("addrs")
                                .and_then(|v| v.as_deref())
                                .map(|list| {
                                    list.split(',')
                                        .filter_map(|s| s.parse::<std::net::SocketAddr>().ok())
                                        .collect()
                                })
                                .unwrap_or_default();
                            NodeAddr {
                                node_id,
                                info: iroh::net::AddrInfo { relay_url, direct_addresses },
                            }
                        };
                        addrs.push(addr);
                    }
                }
            }
        }
        Ok(addrs)
    }

    /// Spawn a background task that republishes every DID in `docs` every
    /// [`REFRESH_INTERVAL`] so pkarr records do not expire (CON-006
    /// §publication trigger 3). The node address is re-resolved from
    /// `endpoint` each cycle so address changes (DHCP, network moves) are
    /// reflected rather than republishing a stale address forever; the
    /// trigger-1 dedup window is bypassed.
    pub fn spawn_refresh_task(
        self: Arc<Self>,
        docs: crate::DocStore,
        endpoint: iroh::net::Endpoint,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(REFRESH_INTERVAL).await;
                let node_addr = match endpoint.node_addr().await {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!("did-crdt: DHT refresh: could not resolve node addr: {e}");
                        continue;
                    }
                };
                let dids: Vec<Did> = docs.lock().keys().cloned().collect();
                for did in dids {
                    if let Err(e) = self.publish_force(&did, &node_addr).await {
                        eprintln!("did-crdt: DHT refresh failed for {did}: {e}");
                    }
                }
            }
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{delta::DeltaOp, document::Document};
    use crate::sync::gossip::genesis_bootstrap;

    fn make_dht() -> (DhtNode, Arc<Mutex<HashMap<[u8; 32], SignedPacket>>>) {
        let store = Arc::new(Mutex::new(HashMap::new()));
        let addr_store = Arc::new(Mutex::new(HashMap::new()));
        let node = DhtNode::new_in_process(store.clone(), addr_store, Duration::from_secs(5));
        (node, store)
    }

    fn make_doc() -> (Document, Did) {
        use base64ct::{Base64UrlUnpadded, Encoding as _};
        use ed25519_dalek::SigningKey;
        let dk = SigningKey::from_bytes(&[42u8; 32]);
        let pk_mb =
            format!("u{}", Base64UrlUnpadded::encode_string(dk.verifying_key().as_bytes()));
        let (doc, _) = Document::new(&pk_mb).expect("new() must succeed");
        let did = doc.did.clone();
        (doc, did)
    }

    /// ServerConfig::default() mirrors DEFAULT_RELAY as a literal because a
    /// service-only build cannot reach this module; keep them in lockstep.
    #[cfg(feature = "service")]
    #[test]
    fn server_default_relay_matches_dht_default() {
        assert_eq!(
            crate::service::server::ServerConfig::default().dht_relay_url,
            DEFAULT_RELAY
        );
    }

    // ── TEST-022: DHT publication and lookup ──────────────────────────────────

    #[tokio::test]
    async fn dht_publish_and_lookup_returns_node_id() {
        let (dht, _store) = make_dht();
        let (_, did) = make_doc();

        // Generate a synthetic NodeId from a fresh iroh secret key.
        let sk = iroh::net::key::SecretKey::generate();
        let node_id = sk.public();
        let node_addr = iroh::net::NodeAddr {
            node_id,
            info: iroh::net::AddrInfo { relay_url: None, direct_addresses: Default::default() },
        };

        dht.publish(&did, &node_addr).await.expect("publish must succeed");

        let addrs = dht.lookup(&did).await.expect("lookup must succeed");
        assert!(!addrs.is_empty(), "lookup should return at least one addr");
        assert_eq!(addrs[0].node_id, node_id, "returned NodeId must match the publishing node");
    }

    #[tokio::test]
    async fn dht_lookup_unknown_did_returns_empty() {
        let (dht, _) = make_dht();
        let (_, did) = make_doc();
        let addrs = dht.lookup(&did).await.unwrap();
        assert!(addrs.is_empty());
    }

    #[tokio::test]
    async fn txt_record_format_is_correct() {
        let (dht, store) = make_dht();
        let (_, did) = make_doc();
        let sk = iroh::net::key::SecretKey::generate();
        let node_id = sk.public();
        let node_addr = iroh::net::NodeAddr {
            node_id,
            info: iroh::net::AddrInfo { relay_url: None, direct_addresses: Default::default() },
        };

        dht.publish(&did, &node_addr).await.unwrap();

        // Read the raw packet from the stub store and verify the TXT value.
        let keypair = derive_keypair(&did);
        let key_bytes = keypair.public_key().to_bytes();
        let guard = store.lock().unwrap();
        let packet = guard.get(&key_bytes).expect("packet must be stored");
        let records: Vec<_> = packet.resource_records(RECORD_NAME).collect();
        assert!(!records.is_empty());
        if let RData::TXT(ref txt) = records[0].rdata {
            let attrs = txt.attributes();
            assert_eq!(attrs.get("v").and_then(|v| v.as_deref()), Some("1"), "v must be 1");
            let nid_str = attrs.get("nid").and_then(|v| v.as_deref()).expect("nid must be present");
            let parsed: NodeId = nid_str.parse().expect("nid must be a valid NodeId");
            assert_eq!(parsed, node_id);
        } else {
            panic!("expected TXT record");
        }
    }

    /// The HTTP-relay lookup path (no `addr_store` short-circuit): the full
    /// NodeAddr — NodeId, relay URL, direct addresses — must round-trip through
    /// the TXT record itself, since that is the only channel real deployments
    /// have (CON-006 §record format).
    #[tokio::test]
    async fn txt_record_roundtrips_addressing_hints_without_addr_store() {
        let store = Arc::new(Mutex::new(HashMap::new()));
        // No addr_store: lookup must reconstruct the NodeAddr from TXT alone.
        let dht = DhtNode {
            backend: PkarrBackend::InProcess(store),
            lookup_timeout: Duration::from_secs(5),
            addr_store: None,
            published: Mutex::new(HashMap::new()),
        };
        let (_, did) = make_doc();

        let sk = iroh::net::key::SecretKey::generate();
        let node_id = sk.public();
        let relay_url: iroh::net::relay::RelayUrl =
            "https://relay.example".parse().expect("valid relay url");
        let direct: std::collections::BTreeSet<std::net::SocketAddr> =
            ["10.0.0.1:4433".parse().unwrap(), "[2001:db8::1]:4433".parse().unwrap()]
                .into_iter()
                .collect();
        let node_addr = iroh::net::NodeAddr {
            node_id,
            info: iroh::net::AddrInfo {
                relay_url: Some(relay_url.clone()),
                direct_addresses: direct.clone(),
            },
        };

        dht.publish(&did, &node_addr).await.expect("publish must succeed");
        let addrs = dht.lookup(&did).await.expect("lookup must succeed");

        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].node_id, node_id);
        assert_eq!(
            addrs[0].info.relay_url.as_ref(),
            Some(&relay_url),
            "relay hint must round-trip through the TXT record"
        );
        assert_eq!(
            addrs[0].info.direct_addresses, direct,
            "direct-address hints must round-trip through the TXT record"
        );
    }

    /// Trigger-1 dedup (CON-006 §publication): republishing an unchanged
    /// `(did, node_addr)` within the dedup window is skipped; a changed
    /// address publishes immediately.
    #[tokio::test]
    async fn publish_deduplicates_unchanged_did_node_pair() {
        let (dht, _store) = make_dht();
        let (_, did) = make_doc();
        let sk = iroh::net::key::SecretKey::generate();
        let mk_addr = |port| iroh::net::NodeAddr {
            node_id: sk.public(),
            info: iroh::net::AddrInfo {
                relay_url: None,
                direct_addresses: [std::net::SocketAddr::from(([127, 0, 0, 1], port))]
                    .into_iter()
                    .collect(),
            },
        };

        assert!(dht.publish(&did, &mk_addr(1111)).await.unwrap(), "first publish goes out");
        assert!(
            !dht.publish(&did, &mk_addr(1111)).await.unwrap(),
            "unchanged repeat within the window is deduplicated"
        );
        assert!(
            dht.publish(&did, &mk_addr(2222)).await.unwrap(),
            "changed address publishes immediately"
        );
    }

    // ── TEST-024: genesis bootstrap failure cases ─────────────────────────────

    fn make_non_genesis_delta(doc: &Document) -> crate::core::delta::SignedDelta {
        use crate::core::delta::SigningKey;
        use ed25519_dalek::SigningKey as DalekKey;
        let dk = DalekKey::from_bytes(&[42u8; 32]);
        let sk = SigningKey::Ed25519(dk);
        let signer = doc.verification_methods.entries()[0].id.clone();
        let genesis_hash = doc.export_bundle().unwrap().deltas[0].content_hash().unwrap();
        crate::core::delta::SignedDelta::new_with_parents(
            doc.did.clone(),
            DeltaOp::RevokeCredential { credential_id: "cred-1".to_owned() },
            crate::core::hlc::HlcTimestamp { wall_ms: 100, logical: 0, node_id: 1 },
            vec![genesis_hash],
            signer,
            &sk,
        )
        .expect("sign")
    }

    /// Scenario A: no genesis delta (no delta has empty parents) → PartialHistory.
    #[test]
    fn genesis_bootstrap_no_genesis_returns_partial_history() {
        use crate::sync::gossip::BootstrapError;
        let (doc, did) = make_doc();
        let delta = make_non_genesis_delta(&doc);
        let mut docs = std::collections::HashMap::new();

        let result = genesis_bootstrap(&mut docs, &did, vec![delta]);
        assert!(matches!(result, Err(BootstrapError::PartialHistory)), "{result:?}");
        assert!(docs.is_empty(), "DocStore must remain unchanged on failure");
    }

    /// Scenario B: two genesis-like deltas (both have empty parents) → BootstrapFailed.
    #[test]
    fn genesis_bootstrap_two_genesis_deltas_returns_bootstrap_failed() {
        use crate::core::delta::{SignedDelta, SigningKey};
        use crate::sync::gossip::BootstrapError;
        use base64ct::{Base64UrlUnpadded, Encoding as _};
        use ed25519_dalek::SigningKey as DalekKey;

        // Two different genesis-like deltas: same did, each with parents=[]
        let (doc, did) = make_doc();
        let bundle = doc.export_bundle().unwrap();
        let genesis1 = bundle.deltas[0].clone();

        // Create a second "genesis": AddVerificationMethod with a different key
        let dk2 = DalekKey::from_bytes(&[99u8; 32]);
        let pk2 = format!("u{}", Base64UrlUnpadded::encode_string(dk2.verifying_key().as_bytes()));
        let sk2 = SigningKey::Ed25519(dk2);
        let genesis2 = SignedDelta::new_with_parents(
            did.clone(),
            DeltaOp::AddVerificationMethod {
                id: format!("{did}#key-99"),
                public_key_multibase: pk2,
                suite_type: Default::default(),
                relationships: crate::core::delta::default_relationships(),
            },
            crate::core::hlc::HlcTimestamp { wall_ms: 1, logical: 0, node_id: 2 },
            vec![], // empty parents — second "genesis"
            format!("{did}#key-99"),
            &sk2,
        )
        .unwrap();

        let mut docs = std::collections::HashMap::new();
        let result = genesis_bootstrap(&mut docs, &did, vec![genesis1, genesis2]);
        assert!(matches!(result, Err(BootstrapError::BootstrapFailed(_))), "{result:?}");
        assert!(docs.is_empty());
    }

    /// Scenario C: genesis delta with wrong key → BootstrapFailed (hash mismatch).
    #[test]
    fn genesis_bootstrap_wrong_key_returns_bootstrap_failed() {
        use crate::core::delta::{SignedDelta, SigningKey};
        use crate::sync::gossip::BootstrapError;
        use base64ct::{Base64UrlUnpadded, Encoding as _};
        use ed25519_dalek::SigningKey as DalekKey;

        let (_doc, did) = make_doc();

        // Build a genesis-like delta for `did` but with an unrelated key.
        let dk2 = DalekKey::from_bytes(&[77u8; 32]);
        let pk2 = format!("u{}", Base64UrlUnpadded::encode_string(dk2.verifying_key().as_bytes()));
        let sk2 = SigningKey::Ed25519(dk2);
        let fake_genesis = SignedDelta::new_with_parents(
            did.clone(),
            DeltaOp::AddVerificationMethod {
                id: format!("{did}#key-0"),
                public_key_multibase: pk2,
                suite_type: Default::default(),
                relationships: crate::core::delta::default_relationships(),
            },
            crate::core::hlc::HlcTimestamp { wall_ms: 0, logical: 0, node_id: 0 },
            vec![], // empty parents
            format!("{did}#key-0"),
            &sk2,
        )
        .unwrap();

        let mut docs = std::collections::HashMap::new();
        let result = genesis_bootstrap(&mut docs, &did, vec![fake_genesis]);
        assert!(matches!(result, Err(BootstrapError::BootstrapFailed(_))), "{result:?}");
        assert!(docs.is_empty());
    }

    /// Scenario F: genesis delta with the *correct* key but tampered metadata
    /// (non-genesis timestamp) → BootstrapFailed via check (b) specifically.
    /// Check (a) passes here — the DID is re-derived from the key alone, which
    /// is genuine — so this is the case where check (b) earns its keep: the
    /// content hash covers the full genesis tuple, catching any tampering with
    /// op fields or timestamp that the key check cannot see.
    #[test]
    fn genesis_bootstrap_tampered_genesis_metadata_returns_bootstrap_failed() {
        use crate::core::delta::{SignedDelta, SigningKey};
        use crate::sync::gossip::BootstrapError;
        use base64ct::{Base64UrlUnpadded, Encoding as _};
        use ed25519_dalek::SigningKey as DalekKey;

        let (_doc, did) = make_doc();

        // Same key as make_doc, so check (a) (DID ← key) passes…
        let dk = DalekKey::from_bytes(&[42u8; 32]);
        let pk_mb =
            format!("u{}", Base64UrlUnpadded::encode_string(dk.verifying_key().as_bytes()));
        let sk = SigningKey::Ed25519(dk);
        // …but the timestamp is not the canonical all-zero genesis timestamp,
        // so the received genesis hash differs from the reconstructed one.
        let tampered = SignedDelta::new_with_parents(
            did.clone(),
            DeltaOp::AddVerificationMethod {
                id: format!("{did}#key-0"),
                public_key_multibase: pk_mb,
                suite_type: Default::default(),
                relationships: crate::core::delta::default_relationships(),
            },
            crate::core::hlc::HlcTimestamp { wall_ms: 5, logical: 0, node_id: 0 },
            vec![], // empty parents — claims to be genesis
            format!("{did}#key-0"),
            &sk,
        )
        .unwrap();

        let mut docs = std::collections::HashMap::new();
        let result = genesis_bootstrap(&mut docs, &did, vec![tampered]);
        assert!(matches!(result, Err(BootstrapError::BootstrapFailed(_))), "{result:?}");
        assert!(docs.is_empty(), "DocStore must remain unchanged on failure");
    }

    /// Scenario D: genesis op is not AddVerificationMethod → BootstrapFailed.
    #[test]
    fn genesis_bootstrap_wrong_op_type_returns_bootstrap_failed() {
        use crate::core::delta::{SignedDelta, SigningKey};
        use crate::sync::gossip::BootstrapError;
        use ed25519_dalek::SigningKey as DalekKey;

        let (_doc, did) = make_doc();
        let dk = DalekKey::from_bytes(&[42u8; 32]);
        let sk = SigningKey::Ed25519(dk);

        let bad_genesis = SignedDelta::new_with_parents(
            did.clone(),
            DeltaOp::Deactivate, // wrong op type for genesis
            crate::core::hlc::HlcTimestamp { wall_ms: 0, logical: 0, node_id: 0 },
            vec![], // empty parents
            format!("{did}#key-0"),
            &sk,
        )
        .unwrap();

        let mut docs = std::collections::HashMap::new();
        let result = genesis_bootstrap(&mut docs, &did, vec![bad_genesis]);
        assert!(matches!(result, Err(BootstrapError::BootstrapFailed(_))), "{result:?}");
        assert!(docs.is_empty());
    }
}
