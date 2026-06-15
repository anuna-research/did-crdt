//! Live iroh-gossip transport for did-crdt sync.
//!
//! Binds the pure [`GossipEngine`](crate::sync::gossip::GossipEngine) routing —
//! and the SPEC-036 frontier-exchange reconciliation it drives — to a real iroh
//! endpoint and gossip topic, so networked replicas converge over the wire.
//!
//! The protocol/routing itself is tested deterministically by the in-process
//! simulation in [`crate::sync::gossip`]; this module is the thin transport
//! binding (endpoint, topic subscription, accept + receive loops, peer
//! bootstrap), exercised by a localhost two-endpoint convergence test.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use iroh::net::key::SecretKey;
use iroh::net::relay::RelayMode;
use iroh::net::{AddrInfo, Endpoint, NodeAddr, NodeId};
use iroh_gossip::net::{Event, Gossip, GOSSIP_ALPN};
use iroh_gossip::proto::TopicId;

use crate::core::did::Did;
use crate::core::hlc::HlcTimestamp;
use crate::sync::dht::DhtNode;
use crate::sync::gossip::{merge_inbound, BootstrapPolicy, GossipEngine, MergeOutcome};
use crate::sync::protocol::SyncMessage;

/// Per-peer budget for one cold-start attempt: connect + REQUEST/DELTAS
/// round-trip (CON-006 §cold-start, suggested sub-timeout). Bounded so that at
/// least one further peer can be tried within `RESOLVE_TIMEOUT_MS`.
const COLD_START_PER_PEER: Duration = Duration::from_secs(4);

/// How often the cold-start loop re-broadcasts its REQUEST while waiting, in
/// case the first broadcast raced the gossip-swarm join and was lost.
const COLD_START_REBROADCAST: Duration = Duration::from_secs(1);

/// A shared, mutex-guarded per-DID document store reconciled by the sync loop.
/// Defined at the crate root so the service layer can share the same store.
pub use crate::DocStore;

/// Derive a gossip [`TopicId`] from a seed (e.g. a DID) so replicas of the same
/// DID join the same topic without coordination.
#[must_use]
pub fn topic_for(seed: &[u8]) -> TopicId {
    TopicId::from_bytes(*blake3::hash(seed).as_bytes())
}

/// A live gossip node: a bound iroh endpoint, a gossip instance for one topic,
/// and a shared document store.
pub struct LiveNode {
    endpoint: Endpoint,
    gossip: Gossip,
    topic: TopicId,
    docs: DocStore,
    /// Optional DHT node for peer discovery and genesis bootstrap publish.
    /// `None` when `DISABLE_DHT_PUBLISH=true`.
    pub dht: Option<Arc<DhtNode>>,
    /// Admission policy for unknown DIDs (CON-006 §admission control), shared
    /// with the sync loop and gossip engine.
    policy: BootstrapPolicy,
}

impl LiveNode {
    /// Bind a fresh iroh endpoint and attach a gossip instance for `topic`.
    ///
    /// `dht` is `None` when DHT publication is disabled via `DISABLE_DHT_PUBLISH`.
    /// `replicate_all` opts this node into bootstrapping every DID announced on
    /// the mesh (`REPLICATE_ALL=true`); the default admits only DIDs with a
    /// pending cold-start request.
    ///
    /// # Errors
    ///
    /// Propagates iroh endpoint bind failures.
    pub async fn bind(
        topic: TopicId,
        docs: DocStore,
        dht: Option<Arc<DhtNode>>,
        replicate_all: bool,
    ) -> anyhow::Result<Self> {
        let endpoint = Endpoint::builder()
            .secret_key(SecretKey::generate())
            .alpns(vec![GOSSIP_ALPN.to_vec()])
            .relay_mode(RelayMode::Default)
            .bind(0)
            .await?;
        let gossip =
            Gossip::from_endpoint(endpoint.clone(), Default::default(), &AddrInfo::default());
        let policy = if replicate_all {
            BootstrapPolicy::replicate_all()
        } else {
            BootstrapPolicy::solicited_only()
        };
        Ok(Self { endpoint, gossip, topic, docs, dht, policy })
    }

    /// The underlying iroh endpoint (for address refresh in the DHT task).
    pub(crate) fn endpoint(&self) -> Endpoint {
        self.endpoint.clone()
    }

    /// This node's dialable address (node id + direct socket addresses).
    ///
    /// # Errors
    ///
    /// Propagates iroh address-resolution failures.
    pub async fn node_addr(&self) -> anyhow::Result<NodeAddr> {
        self.endpoint.node_addr().await
    }

    /// This node's public key.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        self.endpoint.node_id()
    }

    /// Join the topic as a seed (no bootstrap peers) so other nodes can connect.
    ///
    /// # Errors
    ///
    /// Propagates gossip join failures.
    pub async fn seed(&self) -> anyhow::Result<()> {
        self.gossip.join(self.topic, vec![]).await?;
        Ok(())
    }

    /// Connect to `peer` and join the topic, waiting for the swarm link to
    /// establish.
    ///
    /// # Errors
    ///
    /// Propagates address or gossip-join failures.
    pub async fn connect(&self, peer: NodeAddr) -> anyhow::Result<()> {
        let peer_id = peer.node_id;
        self.endpoint.add_node_addr(peer)?;
        self.gossip.join(self.topic, vec![peer_id]).await?.await?;
        Ok(())
    }

    /// Broadcast an ANNOUNCE for `did`'s current state, so peers reconcile.
    /// Call after a local change.
    ///
    /// # Errors
    ///
    /// Errors if the DID is untracked, or on hash/serialise/broadcast failure.
    pub async fn announce(&self, did: &Did) -> anyhow::Result<()> {
        let hash = {
            let store = self.docs.lock();
            let doc = store
                .get(did)
                .ok_or_else(|| anyhow::anyhow!("announce: untracked DID {did}"))?;
            *doc.content_hash()?.as_bytes()
        };
        let msg =
            SyncMessage::Announce { did: did.clone(), hash, clock: HlcTimestamp::default() };
        self.gossip.broadcast(self.topic, Bytes::from(serde_json::to_vec(&msg)?)).await?;
        Ok(())
    }

    /// Attempt cold-start bootstrap for `did` (CON-006 §cold-start resolution).
    ///
    /// 1. Register `did` in the admission policy's wanted set, so the sync loop
    ///    will accept (and the engine will request) its history.
    /// 2. DHT lookup → peers.
    /// 3. For each peer, within a per-peer sub-timeout: connect, broadcast an
    ///    empty-frontier REQUEST (re-broadcast periodically in case the first
    ///    raced the swarm join), and poll the DocStore until `did` appears.
    /// 4. Withdraw the wanted entry and return `Ok(())` if the DID appeared
    ///    within `total_timeout`.
    ///
    /// # Errors
    ///
    /// Returns an error if DHT is disabled, the lookup fails or finds no peers,
    /// all peers fail, or `total_timeout` elapses before the DID bootstraps.
    pub async fn cold_start_bootstrap(
        &self,
        did: &Did,
        total_timeout: Duration,
    ) -> anyhow::Result<()> {
        // Solicit the DID before any traffic, and always withdraw afterwards
        // (on success the DID is in the DocStore and needs no admission).
        self.policy.add_wanted(did);
        let result = self.cold_start_inner(did, total_timeout).await;
        self.policy.remove_wanted(did);
        result
    }

    async fn cold_start_inner(&self, did: &Did, total_timeout: Duration) -> anyhow::Result<()> {
        let dht = self
            .dht
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("DHT disabled (DISABLE_DHT_PUBLISH=true)"))?;

        let deadline = tokio::time::Instant::now() + total_timeout;
        let mut last_failure = String::from("no lookup attempted");

        // Lookup → per-peer attempt rounds, retried until RESOLVE_TIMEOUT_MS
        // elapses (CON-006: resolution returns 404 only after the budget is
        // spent). Retrying the lookup also covers a freshly created DID whose
        // background DHT publication races our first resolve.
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            // Step 1: DHT lookup. Errors (relay unreachable, lookup timeout)
            // are distinct from an empty result (no record published).
            let peers = match dht.lookup(did).await {
                Ok(peers) if peers.is_empty() => {
                    last_failure = format!("no peers found in DHT for {did}");
                    vec![]
                }
                Ok(peers) => peers,
                Err(e) => {
                    last_failure = format!("DHT lookup failed for {did}: {e}");
                    vec![]
                }
            };

            // Step 2: per-peer attempts, each bounded by COLD_START_PER_PEER so
            // a dead first peer cannot consume the whole budget.
            for peer in peers {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }
                let per_peer = COLD_START_PER_PEER.min(remaining);
                let attempt = async {
                    self.connect(peer.clone()).await?;
                    let req = SyncMessage::Request { did: did.clone(), frontier: vec![] };
                    let bytes = Bytes::from(serde_json::to_vec(&req)?);
                    // Broadcast the REQUEST, then poll for the bootstrap;
                    // re-broadcast each interval in case the first send raced
                    // the swarm join.
                    loop {
                        let _ = self.gossip.broadcast(self.topic, bytes.clone()).await;
                        let poll_deadline = tokio::time::Instant::now() + COLD_START_REBROADCAST;
                        while tokio::time::Instant::now() < poll_deadline {
                            if self.docs.lock().contains_key(did) {
                                return Ok::<(), anyhow::Error>(());
                            }
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                    }
                };
                match tokio::time::timeout(per_peer, attempt).await {
                    Ok(Ok(())) => return Ok(()),
                    Ok(Err(e)) => last_failure = format!("peer {} failed: {e}", peer.node_id),
                    Err(_) => {
                        last_failure = format!("peer {} timed out", peer.node_id);
                    }
                }
            }

            // Pause before the next lookup round (bounded by the deadline).
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500).min(remaining)).await;
        }

        Err(anyhow::anyhow!("cold-start bootstrap failed for {did}: {last_failure}"))
    }

    /// Spawn the background sync loop: accept incoming gossip connections, and
    /// for each received message route it through the engine (broadcasting
    /// responses) and merge delivered deltas into the shared store. The
    /// returned handle runs until aborted or the gossip stream closes.
    pub fn spawn(&self) -> tokio::task::JoinHandle<()> {
        let endpoint = self.endpoint.clone();
        let gossip = self.gossip.clone();
        let topic = self.topic;
        let docs = self.docs.clone();
        let dht = self.dht.clone();
        let policy = self.policy.clone();
        tokio::spawn(async move {
            let _ = run_loop(endpoint, gossip, topic, docs, dht, policy).await;
        })
    }
}

/// The live sync loop for one node: accept connections, and route/merge received
/// messages.
async fn run_loop(
    endpoint: Endpoint,
    gossip: Gossip,
    topic: TopicId,
    docs: DocStore,
    dht: Option<Arc<DhtNode>>,
    policy: BootstrapPolicy,
) -> anyhow::Result<()> {
    let mut engine = GossipEngine::new(gossip.clone(), topic, policy.clone());
    let mut stream = gossip.subscribe(topic).await?;

    // Accept incoming gossip connections in the background.
    let accept = {
        let endpoint = endpoint.clone();
        let gossip = gossip.clone();
        tokio::spawn(async move {
            while let Some(conn) = endpoint.accept().await {
                if let Ok(conn) = conn.await {
                    let _ = gossip.handle_connection(conn).await;
                }
            }
        })
    };

    // Route received messages; the engine broadcasts responses, and DELTAS
    // deliveries are merged into the shared store.
    while let Ok(ev) = stream.recv().await {
        if let Event::Received(msg) = ev {
            // Read-only snapshot for routing (no lock held across the await).
            let snapshot = { docs.lock().clone() };
            if let Ok(Some(deliver)) = engine.handle_bytes(&msg.content, &snapshot).await {
                // Acquire lock for the sync merge, then release before any await.
                let outcome = {
                    let mut guard = docs.lock();
                    merge_inbound(&mut guard, deliver, &policy)
                };
                // After genesis bootstrap, publish this node to DHT (trigger 1).
                if let MergeOutcome::Bootstrapped(did) = outcome {
                    if let Some(ref dht) = dht {
                        match endpoint.node_addr().await {
                            Ok(node_addr) => {
                                if let Err(e) = dht.publish(&did, &node_addr).await {
                                    eprintln!(
                                        "did-crdt: DHT publish after bootstrap failed for {did}: {e}"
                                    );
                                }
                            }
                            Err(e) => {
                                eprintln!("did-crdt: could not get node addr for DHT publish after bootstrap of {did}: {e}");
                            }
                        }
                    }
                }
            }
        }
    }
    accept.abort();
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::delta::{DeltaOp, SignedDelta};
    use crate::core::document::Document;
    use std::time::Duration;

    /// Build a document with `updates` credential revocations applied on top of
    /// genesis (same key ⇒ same DID across calls).
    fn doc_with(updates: &[&str]) -> Document {
        use crate::core::delta::SigningKey;
        use crate::core::validate::node_id_from_pubkey;
        use base64ct::{Base64UrlUnpadded, Encoding as _};
        use ed25519_dalek::SigningKey as DalekKey;

        const SEED: [u8; 32] = [11u8; 32];
        let dk = DalekKey::from_bytes(&SEED);
        let nid = node_id_from_pubkey(dk.verifying_key().as_bytes());
        let pk_mb = format!("u{}", Base64UrlUnpadded::encode_string(dk.verifying_key().as_bytes()));
        let sk = SigningKey::Ed25519(dk);

        let (mut doc, _) = Document::new(&pk_mb).expect("new() must succeed");
        let signer = doc.verification_methods.entries()[0].id.clone();
        for (i, cred) in updates.iter().enumerate() {
            let d = SignedDelta::new_with_parents(
                doc.did.clone(),
                DeltaOp::RevokeCredential { credential_id: (*cred).to_owned() },
                HlcTimestamp { wall_ms: (i as u64 + 1) * 10, logical: 0, node_id: nid },
                doc.frontier(),
                signer.clone(),
                &sk,
            )
            .expect("sign");
            doc.merge(d).expect("merge must succeed");
        }
        doc
    }

    fn store(doc: Document) -> DocStore {
        let ds = DocStore::new();
        ds.lock().insert(doc.did.clone(), doc);
        ds
    }

    /// Two real iroh endpoints on localhost: a behind replica converges to an
    /// ahead one purely over the wire via gossip + frontier reconciliation.
    #[tokio::test]
    async fn live_loopback_two_nodes_converge() {
        let a_doc = doc_with(&["x", "y"]); // ahead: genesis + 2 updates
        let did = a_doc.did.clone();
        let b_doc = doc_with(&[]); // behind: genesis only
        assert_eq!(a_doc.did, b_doc.did);
        let target = a_doc.content_hash().unwrap();

        let topic = topic_for(b"did-crdt/live-loopback-test");
        let a_docs = store(a_doc);
        let b_docs = store(b_doc);

        let a = LiveNode::bind(topic, a_docs.clone(), None, false).await.unwrap();
        let b = LiveNode::bind(topic, b_docs.clone(), None, false).await.unwrap();

        let _a_task = a.spawn();
        let _b_task = b.spawn();

        // A seeds the topic; B dials A and joins.
        a.seed().await.unwrap();
        let a_addr = a.node_addr().await.unwrap();
        b.connect(a_addr).await.unwrap();

        // A announces its state; B reconciles to it over live gossip.
        a.announce(&did).await.unwrap();

        let converged = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let h = b_docs.lock().get(&did).map(|d| d.content_hash().unwrap());
                if h == Some(target) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;

        assert!(converged.is_ok(), "node B did not converge to A over live iroh gossip");
    }
}
