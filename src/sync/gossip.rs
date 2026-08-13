//! iroh-gossip delta propagation (CON-004).
//!
//! Manages peer connections, subscribes to the did-crdt gossip topic, and
//! delivers incoming `SignedDelta` messages to the local `Document` store.
//!
//! # Protocol (CON-004)
//!
//! 1. On local delta creation: broadcast `ANNOUNCE` for the updated document.
//! 2. On receiving `ANNOUNCE` with an unknown `(did, hash)`: broadcast a
//!    `REQUEST` advertising the local frontier.
//! 3. On receiving `REQUEST`: respond with the `DELTAS` above the peer's
//!    frontier (signed deltas only — no full-state shipping over the wire).
//! 4. Deduplication: `(did, hash)` pairs already seen are silently dropped.
//!
//! # Architecture
//!
//! The pure protocol routing logic lives in [`GossipState`] (no I/O).
//! [`GossipEngine`] wraps it together with an iroh-gossip [`Gossip`] handle,
//! serialises outgoing messages to JSON, and broadcasts them.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use iroh_gossip::{net::Gossip, proto::TopicId};

use crate::core::{delta::DeltaOp, did::Did, document::Document, hlc::HlcTimestamp};
use crate::sync::protocol::{Blake3Hash, SyncMessage};

// ── BootstrapPolicy (CON-006 §admission control) ──────────────────────────────

/// Admission policy for genesis-bootstrapping unknown DIDs.
///
/// A node only fetches and stores a DID it does not yet hold when that DID is
/// *solicited* — registered in the `wanted` set by a pending cold-start
/// resolution — or when the operator has opted the node into replicate-all
/// mode (`REPLICATE_ALL=true`). Unsolicited DELTAS for unknown DIDs are
/// ignored, preserving the invariant that a gossip peer can only extend a
/// document we already hold or have asked for. Without this gate, any peer
/// could force unbounded document storage onto every node on the topic by
/// flooding validly-formed genesis deltas (the ADR-003 sybil scenario).
#[derive(Clone, Default)]
pub struct BootstrapPolicy {
    /// DIDs with a pending cold-start resolution (CON-006 §cold-start).
    /// Shared with `LiveNode::cold_start_bootstrap`, which registers a DID
    /// here before requesting it and removes it when the attempt ends.
    wanted: Arc<Mutex<HashSet<Did>>>,
    /// Opt-in full-replica mode: bootstrap every DID announced on the mesh.
    replicate_all: bool,
}

impl BootstrapPolicy {
    /// A policy that bootstraps only solicited DIDs (the safe default).
    #[must_use]
    pub fn solicited_only() -> Self {
        Self::default()
    }

    /// A policy that bootstraps every DID seen on the mesh (full replica).
    #[must_use]
    pub fn replicate_all() -> Self {
        Self {
            wanted: Arc::default(),
            replicate_all: true,
        }
    }

    /// Whether this node is willing to genesis-bootstrap `did`.
    #[must_use]
    pub fn wants(&self, did: &Did) -> bool {
        self.replicate_all || self.lock_wanted().contains(did)
    }

    /// Register a pending cold-start request for `did`.
    pub fn add_wanted(&self, did: &Did) {
        self.lock_wanted().insert(did.clone());
    }

    /// Withdraw the pending cold-start request for `did`.
    ///
    /// Note: concurrent cold-starts for the same DID share one entry, so the
    /// first to finish withdraws it for both. The loser still polls the
    /// DocStore directly, so at worst it times out and the caller retries.
    pub fn remove_wanted(&self, did: &Did) {
        self.lock_wanted().remove(did);
    }

    fn lock_wanted(&self) -> std::sync::MutexGuard<'_, HashSet<Did>> {
        // Recover from poisoning like DocStore: a panicked holder must not
        // wedge every subsequent sync-loop iteration.
        self.wanted.lock().unwrap_or_else(|p| p.into_inner())
    }
}

// ── Bootstrap errors ──────────────────────────────────────────────────────────

/// Errors produced by genesis bootstrap (CON-006 §error model).
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    /// No genesis delta (empty `parents`) found in the batch.
    #[error("no genesis delta in batch")]
    PartialHistory,
    /// Genesis verification failed: wrong op type, hash mismatch, or multiple genesis deltas.
    #[error("genesis bootstrap failed: {0}")]
    BootstrapFailed(String),
}

// ── MergeOutcome ──────────────────────────────────────────────────────────────

/// Result of [`merge_inbound`], so callers can react to genesis bootstraps.
pub(crate) enum MergeOutcome {
    /// Nothing happened (ANNOUNCE/REQUEST, not DELTAS).
    Noop,
    /// Known-DID deltas were merged (normal path).
    Merged,
    /// A previously-unknown DID was bootstrapped from received DELTAS.
    Bootstrapped(Did),
    /// Genesis bootstrap attempted but failed; DocStore unchanged.
    BootstrapError,
    /// DELTAS for an unknown DID this node never solicited; ignored,
    /// DocStore unchanged (CON-006 §admission control).
    IgnoredUnsolicited,
}

// ── Genesis bootstrap (CON-006) ───────────────────────────────────────────────

/// Attempt to bootstrap a new DID from a received DELTAS batch.
///
/// Called by [`merge_inbound`] when a DELTAS message arrives for a DID that is
/// not yet in `docs`. On success the reconstructed document is inserted and all
/// remaining deltas are applied. On failure `docs` is unchanged.
///
/// # Steps (CON-006 §genesis bootstrap)
///
/// 1. Find the unique genesis delta (empty `parents`).
/// 2. Extract the public key from its `AddVerificationMethod` op.
/// 3. Reconstruct and verify the document locally.
/// 4. Insert the document into `docs`.
/// 5. Apply remaining deltas via the existing retry loop.
pub(crate) fn genesis_bootstrap(
    docs: &mut HashMap<Did, Document>,
    did: &Did,
    deltas: Vec<crate::core::delta::SignedDelta>,
) -> std::result::Result<(), BootstrapError> {
    // Step 1: find the unique genesis delta.
    let genesis_deltas: Vec<_> = deltas.iter().filter(|d| d.parents.is_empty()).collect();
    let genesis = match genesis_deltas.len() {
        0 => return Err(BootstrapError::PartialHistory),
        1 => genesis_deltas[0].clone(),
        _ => {
            return Err(BootstrapError::BootstrapFailed(
                "multiple genesis-like deltas".to_owned(),
            ))
        }
    };

    // Step 2: genesis op must be AddVerificationMethod.
    let public_key_multibase = match &genesis.op {
        DeltaOp::AddVerificationMethod {
            public_key_multibase,
            ..
        } => public_key_multibase.clone(),
        _ => {
            return Err(BootstrapError::BootstrapFailed(
                "genesis op is not AddVerificationMethod".to_owned(),
            ))
        }
    };

    // Step 3: reconstruct locally and verify DID + genesis hash.
    let (reconstructed, computed_genesis) = Document::new(&public_key_multibase)
        .map_err(|e| BootstrapError::BootstrapFailed(format!("Document::new failed: {e}")))?;

    if &reconstructed.did != did {
        return Err(BootstrapError::BootstrapFailed(format!(
            "DID mismatch: reconstructed={} claimed={did}",
            reconstructed.did
        )));
    }
    let received_hash = genesis
        .content_hash()
        .map_err(|e| BootstrapError::BootstrapFailed(format!("content_hash failed: {e}")))?;
    let computed_hash = computed_genesis
        .content_hash()
        .map_err(|e| BootstrapError::BootstrapFailed(format!("content_hash failed: {e}")))?;
    if received_hash != computed_hash {
        return Err(BootstrapError::BootstrapFailed(
            "genesis delta hash mismatch".to_owned(),
        ));
    }

    // Step 4: insert into DocStore.
    docs.insert(did.clone(), reconstructed);

    // Step 5: apply remaining deltas via the existing retry loop.
    let remaining: Vec<_> = deltas
        .into_iter()
        .filter(|d| !d.parents.is_empty())
        .collect();
    let fake_msg = SyncMessage::Deltas {
        did: did.clone(),
        deltas: remaining,
    };
    // The DID is now in docs, so merge_inbound takes the known-DID path and the
    // policy is never consulted; deny-all keeps that explicit.
    merge_inbound(docs, fake_msg, &BootstrapPolicy::solicited_only());

    Ok(())
}

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors produced by the gossip layer.
#[derive(Debug, thiserror::Error)]
pub enum GossipError {
    /// JSON serialisation / deserialisation failure.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// iroh-gossip broadcast failure.
    #[error("broadcast failed: {0}")]
    Broadcast(#[from] anyhow::Error),
    /// BLAKE3 content-hash failure.
    #[error("content hash error: {0}")]
    Hash(String),
}

/// Result alias for the gossip layer.
pub type Result<T> = std::result::Result<T, GossipError>;

// ── GossipState (pure, no I/O) ────────────────────────────────────────────────

/// Pure protocol state: deduplication set and routing decisions.
///
/// Contains no networking code; all decisions are based only on the in-memory
/// seen set and the locally-available document/delta maps passed in.  This
/// makes the core logic unit-testable without a real iroh endpoint.
struct GossipState {
    /// Set of `(did, hash)` pairs that have already been seen, used to
    /// suppress duplicate ANNOUNCEs and redundant REQUESTs.
    seen: HashSet<(Did, Blake3Hash)>,
}

impl GossipState {
    fn new() -> Self {
        Self {
            seen: HashSet::new(),
        }
    }

    /// Record a `(did, hash)` pair.  Returns `true` if it was not yet known.
    fn mark_seen(&mut self, did: &Did, hash: Blake3Hash) -> bool {
        self.seen.insert((did.clone(), hash))
    }

    /// Given an incoming [`SyncMessage`], decide what to broadcast.
    ///
    /// Returns:
    /// - `outgoing` — messages to broadcast to the gossip swarm.
    /// - `deliver` — an optional inbound `DELTAS` message that the caller must
    ///   merge into its local document store.
    fn handle(
        &mut self,
        msg: SyncMessage,
        docs: &HashMap<Did, Document>,
        policy: &BootstrapPolicy,
    ) -> (Vec<SyncMessage>, Option<SyncMessage>) {
        match msg {
            // ── ANNOUNCE ─────────────────────────────────────────────────────
            SyncMessage::Announce { did, hash, .. } => {
                if !self.mark_seen(&did, hash) {
                    // Already-known state — dedup, no action needed.
                    return (vec![], None);
                }
                // Unknown state: reconcile by advertising our current frontier so
                // the peer sends exactly the deltas we lack (REQ-366).
                match docs.get(&did) {
                    Some(doc) => (
                        vec![SyncMessage::Request {
                            did: did.clone(),
                            frontier: doc.frontier(),
                        }],
                        None,
                    ),
                    // Untracked DID: request the full history (empty frontier)
                    // only if this node solicited it or replicates everything.
                    // Otherwise stay silent — requesting histories we would
                    // refuse to merge wastes peer bandwidth (CON-006
                    // §admission control).
                    None if policy.wants(&did) => (
                        vec![SyncMessage::Request {
                            did,
                            frontier: vec![],
                        }],
                        None,
                    ),
                    None => (vec![], None),
                }
            }

            // ── REQUEST ───────────────────────────────────────────────────────
            SyncMessage::Request { did, frontier } => {
                let Some(doc) = docs.get(&did) else {
                    // We don't know this DID — nothing to send.
                    return (vec![], None);
                };
                // Respond with the deltas above the requester's frontier (the
                // closure transfer of anti-entropy, REQ-366). Nothing to send if
                // the peer is already up to date or extraction fails.
                match doc.deltas_for_peer(&frontier) {
                    Ok(deltas) if !deltas.is_empty() => {
                        (vec![SyncMessage::Deltas { did, deltas }], None)
                    }
                    _ => (vec![], None),
                }
            }

            // ── DELTAS ────────────────────────────────────────────────────────
            // Inbound signed-delta payload for the caller to merge.
            other => (vec![], Some(other)),
        }
    }
}

// ── GossipEngine ──────────────────────────────────────────────────────────────

/// iroh-gossip engine for did-crdt delta propagation.
///
/// Wraps an iroh-gossip [`Gossip`] handle and a [`TopicId`].  Uses
/// [`GossipState`] for pure routing decisions and broadcasts serialised
/// [`SyncMessage`]s over the gossip topic.
///
/// # Usage
///
/// ```ignore
/// let engine = GossipEngine::new(gossip, topic, BootstrapPolicy::solicited_only());
///
/// // On local delta creation:
/// engine.announce(&updated_doc, hlc.send()).await?;
///
/// // On incoming gossip event:
/// if let Some(to_merge) = engine.handle_bytes(&raw, &docs, &log).await? {
///     match to_merge {
///         SyncMessage::Deltas { did, deltas } => { /* merge deltas */ }
///         _ => {}
///     }
/// }
/// ```
pub struct GossipEngine {
    gossip: Gossip,
    topic: TopicId,
    state: GossipState,
    /// Admission policy for unknown DIDs (CON-006 §admission control); shared
    /// with the owning `LiveNode` so cold-start requests gate routing too.
    policy: BootstrapPolicy,
}

impl GossipEngine {
    /// Create a new engine for the given gossip handle, topic, and admission
    /// policy.
    pub fn new(gossip: Gossip, topic: TopicId, policy: BootstrapPolicy) -> Self {
        Self {
            gossip,
            topic,
            state: GossipState::new(),
            policy,
        }
    }

    // ── outbound ─────────────────────────────────────────────────────────────

    /// Broadcast an `ANNOUNCE` for the current state of `doc`.
    ///
    /// Computes the BLAKE3 content hash of `doc`, adds it to the deduplication
    /// set, and broadcasts `SyncMessage::Announce` to all topic peers.
    ///
    /// If the same `(did, hash)` pair was already announced this call is a
    /// no-op (deduplication prevents redundant broadcasts).
    pub async fn announce(&mut self, doc: &Document, clock: HlcTimestamp) -> Result<()> {
        let hash = doc
            .content_hash()
            .map_err(|e| GossipError::Hash(e.to_string()))?;
        let hash_bytes: Blake3Hash = *hash.as_bytes();

        if !self.state.mark_seen(&doc.did, hash_bytes) {
            return Ok(());
        }

        let msg = SyncMessage::Announce {
            did: doc.did.clone(),
            hash: hash_bytes,
            clock,
        };
        self.do_broadcast(&msg).await
    }

    // ── inbound ──────────────────────────────────────────────────────────────

    /// Handle a raw gossip payload received from the network.
    ///
    /// Deserialises `raw` as a [`SyncMessage`].  Malformed bytes are silently
    /// dropped (returns `Ok(None)`).  Otherwise delegates to
    /// [`handle_message`].
    pub async fn handle_bytes(
        &mut self,
        raw: &Bytes,
        docs: &HashMap<Did, Document>,
    ) -> Result<Option<SyncMessage>> {
        let msg: SyncMessage = match serde_json::from_slice(raw) {
            Ok(m) => m,
            Err(_) => return Ok(None),
        };
        self.handle_message(msg, docs).await
    }

    /// Handle a decoded [`SyncMessage`].
    ///
    /// Broadcasts any required response messages and returns `Some(msg)` when
    /// the caller must merge an inbound `DELTAS` or `STATE` payload into the
    /// local document store.
    pub async fn handle_message(
        &mut self,
        msg: SyncMessage,
        docs: &HashMap<Did, Document>,
    ) -> Result<Option<SyncMessage>> {
        let (outgoing, deliver) = self.state.handle(msg, docs, &self.policy);
        for out_msg in outgoing {
            self.do_broadcast(&out_msg).await?;
        }
        Ok(deliver)
    }

    // ── private ───────────────────────────────────────────────────────────────

    async fn do_broadcast(&self, msg: &SyncMessage) -> Result<()> {
        let bytes = Bytes::from(serde_json::to_vec(msg)?);
        self.gossip.broadcast(self.topic, bytes).await?;
        Ok(())
    }
}

/// Merge a delivered inbound payload (the `deliver` a [`GossipEngine`] returns)
/// into a document store, the way a live caller must: DELTAS are merged
/// delta-by-delta with retry so out-of-order deltas held `DeltaPending` resolve.
/// Every inbound delta is signature-verified at the trust boundary via
/// [`Document::merge_verified_delta`] — a forged signature under a real key id is
/// rejected, and there is no unauthenticated full-state injection.
///
/// A DELTAS message for an untracked DID is ignored unless this node solicited
/// it — a peer can only extend a DID we already hold or have asked for
/// (CON-006 §admission control, [`BootstrapPolicy`]). For solicited DIDs,
/// [`genesis_bootstrap`] is attempted (CON-006). Returns [`MergeOutcome`] so
/// the caller can trigger DHT publish on a successful bootstrap.
pub(crate) fn merge_inbound(
    docs: &mut HashMap<Did, Document>,
    msg: SyncMessage,
    policy: &BootstrapPolicy,
) -> MergeOutcome {
    let SyncMessage::Deltas { did, deltas } = msg else {
        return MergeOutcome::Noop;
    };

    if !docs.contains_key(&did) {
        if !policy.wants(&did) {
            // Unsolicited unknown DID: ignore silently (the pre-CON-006
            // invariant). Logging here would let a flood fill the logs.
            return MergeOutcome::IgnoredUnsolicited;
        }
        // Solicited unknown DID: attempt genesis bootstrap (CON-006).
        return match genesis_bootstrap(docs, &did, deltas) {
            Ok(()) => MergeOutcome::Bootstrapped(did),
            Err(e) => {
                eprintln!("did-crdt: genesis bootstrap failed for {did}: {e}");
                MergeOutcome::BootstrapError
            }
        };
    }

    // Known DID: apply deltas delta-by-delta with out-of-order retry.
    let doc = docs.get_mut(&did).expect("just checked contains_key");
    let mut pending = deltas;
    loop {
        let mut progressed = false;
        let mut still = Vec::new();
        for d in pending {
            match doc.merge_verified_delta(d.clone()) {
                Err(crate::core::Error::DeltaPending { .. }) => still.push(d),
                _ => progressed = true, // applied, duplicate, or rejected (incl. bad signature)
            }
        }
        if still.is_empty() || !progressed {
            break;
        }
        pending = still;
    }
    MergeOutcome::Merged
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        delta::{DeltaOp, SignedDelta},
        document::Document,
        hlc::HlcTimestamp,
    };

    // ── helpers ───────────────────────────────────────────────────────────────

    use crate::core::delta::SigningKey;
    use crate::core::validate::node_id_from_pubkey;
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use ed25519_dalek::SigningKey as DalekKey;

    /// Deterministic genesis keypair shared by all replicas in a test (same key
    /// ⇒ same DID + genesis), so concurrently-signed deltas verify on each peer.
    const GOSSIP_SEED: [u8; 32] = [7u8; 32];

    fn signing_key() -> SigningKey {
        SigningKey::Ed25519(DalekKey::from_bytes(&GOSSIP_SEED))
    }

    fn signer_node_id() -> u64 {
        node_id_from_pubkey(
            DalekKey::from_bytes(&GOSSIP_SEED)
                .verifying_key()
                .as_bytes(),
        )
    }

    fn make_doc() -> Document {
        let pk_mb = format!(
            "u{}",
            Base64UrlUnpadded::encode_string(
                DalekKey::from_bytes(&GOSSIP_SEED)
                    .verifying_key()
                    .as_bytes()
            )
        );
        let (doc, _) = Document::new(&pk_mb).expect("new() must succeed");
        doc
    }

    fn ts(wall_ms: u64) -> HlcTimestamp {
        HlcTimestamp {
            wall_ms,
            logical: 0,
            node_id: 1,
        }
    }

    fn doc_hash(doc: &Document) -> Blake3Hash {
        *doc.content_hash().unwrap().as_bytes()
    }

    fn make_delta(doc: &Document, wall_ms: u64) -> SignedDelta {
        let signer = doc.verification_methods.entries()[0].id.clone();
        SignedDelta::unsigned(
            doc.did.clone(),
            DeltaOp::RevokeCredential {
                credential_id: format!("cred-{}", wall_ms),
            },
            ts(wall_ms),
            signer,
        )
    }

    fn no_docs() -> HashMap<Did, Document> {
        HashMap::new()
    }

    /// Solicited-only policy with an empty wanted set (the safe default).
    fn deny() -> BootstrapPolicy {
        BootstrapPolicy::solicited_only()
    }

    fn docs_for(doc: &Document) -> HashMap<Did, Document> {
        let mut m = HashMap::new();
        m.insert(doc.did.clone(), doc.clone());
        m
    }

    // ── deduplication ─────────────────────────────────────────────────────────

    #[test]
    fn announce_new_pair_is_marked_seen() {
        let doc = make_doc();
        let hash = doc_hash(&doc);
        let mut state = GossipState::new();

        // First time: new, should be recorded.
        assert!(state.mark_seen(&doc.did, hash));
        // Second time: already seen.
        assert!(!state.mark_seen(&doc.did, hash));
    }

    #[test]
    fn different_hash_same_did_is_new() {
        let doc = make_doc();
        let hash1 = doc_hash(&doc);
        let hash2 = [0u8; 32];
        let mut state = GossipState::new();

        assert!(state.mark_seen(&doc.did, hash1));
        assert!(state.mark_seen(&doc.did, hash2));
    }

    #[test]
    fn same_hash_different_did_is_new() {
        let doc_a = make_doc();
        let (doc_b, _) = Document::new("zAnotherKey").unwrap();
        let hash = [42u8; 32];
        let mut state = GossipState::new();

        assert!(state.mark_seen(&doc_a.did, hash));
        assert!(state.mark_seen(&doc_b.did, hash)); // different DID
    }

    // ── ANNOUNCE handling ─────────────────────────────────────────────────────

    #[test]
    fn announce_tracked_did_produces_request_with_frontier() {
        let doc = make_doc();
        let docs = docs_for(&doc);
        let mut state = GossipState::new();

        // Announce a hash we have not seen for a DID we hold.
        let msg = SyncMessage::Announce {
            did: doc.did.clone(),
            hash: [9u8; 32],
            clock: ts(1),
        };
        let (outgoing, deliver) = state.handle(msg, &docs, &deny());

        assert!(deliver.is_none());
        assert_eq!(outgoing.len(), 1);
        match &outgoing[0] {
            SyncMessage::Request { did, frontier } => {
                assert_eq!(did, &doc.did);
                assert_eq!(
                    frontier,
                    &doc.frontier(),
                    "tracked DID → request above our frontier"
                );
            }
            other => panic!("expected Request, got {:?}", other),
        }
    }

    #[test]
    fn announce_unsolicited_unknown_did_is_ignored() {
        // CON-006 §admission control: an untracked, unsolicited DID does not
        // trigger a full-history REQUEST — we would refuse to merge the reply.
        let doc = make_doc();
        let hash = doc_hash(&doc);
        let mut state = GossipState::new();

        let msg = SyncMessage::Announce {
            did: doc.did.clone(),
            hash,
            clock: ts(1),
        };
        let (outgoing, deliver) = state.handle(msg, &no_docs(), &deny());

        assert!(
            outgoing.is_empty(),
            "unsolicited unknown DID must not be requested"
        );
        assert!(deliver.is_none());
    }

    #[test]
    fn announce_wanted_unknown_did_produces_full_history_request() {
        // A pending cold-start request (wanted set) admits the DID.
        let doc = make_doc();
        let hash = doc_hash(&doc);
        let mut state = GossipState::new();
        let policy = BootstrapPolicy::solicited_only();
        policy.add_wanted(&doc.did);

        let msg = SyncMessage::Announce {
            did: doc.did.clone(),
            hash,
            clock: ts(1),
        };
        let (outgoing, deliver) = state.handle(msg, &no_docs(), &policy);

        assert!(deliver.is_none());
        assert_eq!(outgoing.len(), 1);
        match &outgoing[0] {
            SyncMessage::Request { did, frontier } => {
                assert_eq!(did, &doc.did);
                assert!(
                    frontier.is_empty(),
                    "wanted untracked DID → request full history"
                );
            }
            other => panic!("expected Request, got {:?}", other),
        }
    }

    #[test]
    fn announce_replicate_all_unknown_did_produces_full_history_request() {
        // Opt-in full-replica mode admits every DID.
        let doc = make_doc();
        let hash = doc_hash(&doc);
        let mut state = GossipState::new();

        let msg = SyncMessage::Announce {
            did: doc.did.clone(),
            hash,
            clock: ts(1),
        };
        let (outgoing, _) = state.handle(msg, &no_docs(), &BootstrapPolicy::replicate_all());

        assert_eq!(outgoing.len(), 1);
        assert!(matches!(
            &outgoing[0],
            SyncMessage::Request { frontier, .. } if frontier.is_empty()
        ));
    }

    #[test]
    fn announce_known_hash_is_deduped() {
        let doc = make_doc();
        let hash = doc_hash(&doc);
        let mut state = GossipState::new();
        state.mark_seen(&doc.did, hash);

        let msg = SyncMessage::Announce {
            did: doc.did.clone(),
            hash,
            clock: ts(1),
        };
        let (outgoing, deliver) = state.handle(msg, &no_docs(), &deny());

        assert!(outgoing.is_empty(), "dedup: no outgoing on second ANNOUNCE");
        assert!(deliver.is_none());
    }

    // ── REQUEST handling (frontier-based reconciliation, REQ-366) ───────────────

    #[test]
    fn request_for_unknown_did_produces_nothing() {
        let doc = make_doc();
        let mut state = GossipState::new();

        let msg = SyncMessage::Request {
            did: doc.did.clone(),
            frontier: vec![],
        };
        let (outgoing, deliver) = state.handle(msg, &no_docs(), &deny());

        assert!(outgoing.is_empty());
        assert!(deliver.is_none());
    }

    #[test]
    fn request_with_empty_frontier_responds_with_full_history() {
        let doc = make_doc();
        let docs = docs_for(&doc);
        let mut state = GossipState::new();

        // Empty frontier ⇒ peer has nothing ⇒ send the whole history (genesis).
        let msg = SyncMessage::Request {
            did: doc.did.clone(),
            frontier: vec![],
        };
        let (outgoing, deliver) = state.handle(msg, &docs, &deny());

        assert!(deliver.is_none());
        assert_eq!(outgoing.len(), 1);
        match &outgoing[0] {
            SyncMessage::Deltas { did, deltas } => {
                assert_eq!(did, &doc.did);
                assert_eq!(deltas.len(), 1, "fresh doc has only the genesis delta");
            }
            other => panic!("expected Deltas, got {:?}", other),
        }
    }

    #[test]
    fn request_with_current_frontier_responds_nothing() {
        let doc = make_doc();
        let docs = docs_for(&doc);
        let mut state = GossipState::new();

        // Peer already holds our frontier ⇒ nothing to send.
        let msg = SyncMessage::Request {
            did: doc.did.clone(),
            frontier: doc.frontier(),
        };
        let (outgoing, deliver) = state.handle(msg, &docs, &deny());

        assert!(outgoing.is_empty(), "peer up to date ⇒ no deltas");
        assert!(deliver.is_none());
    }

    #[test]
    fn request_with_stale_frontier_responds_with_missing_deltas() {
        // Responder holds genesis + one update; peer's frontier is just genesis.
        let mut doc = make_doc();
        let stale = doc.frontier(); // {genesis}
        let signer = doc.verification_methods.entries()[0].id.clone();
        let mut d1 = SignedDelta::unsigned(
            doc.did.clone(),
            DeltaOp::RevokeCredential {
                credential_id: "c1".to_owned(),
            },
            ts(100),
            signer,
        );
        d1.parents = doc.frontier();
        doc.merge(d1.clone()).unwrap();
        let docs = docs_for(&doc);
        let mut state = GossipState::new();

        let msg = SyncMessage::Request {
            did: doc.did.clone(),
            frontier: stale,
        };
        let (outgoing, _) = state.handle(msg, &docs, &deny());

        assert_eq!(outgoing.len(), 1);
        match &outgoing[0] {
            SyncMessage::Deltas { deltas, .. } => {
                assert_eq!(
                    deltas.len(),
                    1,
                    "peer lacks exactly the one post-genesis delta"
                );
                assert_eq!(
                    deltas[0].content_hash().unwrap(),
                    d1.content_hash().unwrap()
                );
            }
            other => panic!("expected Deltas, got {:?}", other),
        }
    }

    // ── DELTAS passthrough ──────────────────────────────────────────────────────

    #[test]
    fn incoming_deltas_delivered_to_caller() {
        let doc = make_doc();
        let delta = make_delta(&doc, 100);
        let mut state = GossipState::new();

        let msg = SyncMessage::Deltas {
            did: doc.did.clone(),
            deltas: vec![delta],
        };
        let (outgoing, deliver) = state.handle(msg, &no_docs(), &deny());

        assert!(outgoing.is_empty());
        assert!(matches!(deliver, Some(SyncMessage::Deltas { .. })));
    }

    // ── Simulated multi-node gossip network (in-process, deterministic) ─────────
    //
    // Drives the real `GossipState` routing over an in-memory *broadcast* network
    // and merges delivered payloads into each node's store, so the end-to-end
    // ANNOUNCE→REQUEST→DELTAS reconciliation + convergence is tested without iroh
    // or sockets. Only iroh's transport/DHT glue is left to a live network.

    struct SimNode {
        docs: HashMap<Did, Document>,
        state: GossipState,
    }

    impl SimNode {
        fn new() -> Self {
            Self {
                docs: HashMap::new(),
                state: GossipState::new(),
            }
        }
        fn track(&mut self, doc: Document) {
            self.docs.insert(doc.did.clone(), doc);
        }
    }

    /// Apply a delivered inbound payload (the `deliver` from `handle`) the way a
    /// real caller would: merge DELTAS (with retry so out-of-order deltas held as
    /// `DeltaPending` resolve).
    fn apply_deliver(node: &mut SimNode, msg: SyncMessage) {
        let _ = merge_inbound(&mut node.docs, msg, &deny());
    }

    /// One anti-entropy round over an in-memory broadcast network: every node
    /// ANNOUNCEs its current state; messages from node `i` are delivered to all
    /// `j != i`; outgoing responses are queued; deliveries are merged. Runs to
    /// quiescence (empty queue).
    fn gossip_round(nodes: &mut [SimNode]) {
        use std::collections::VecDeque;
        let mut queue: VecDeque<(usize, SyncMessage)> = VecDeque::new();
        for (i, n) in nodes.iter().enumerate() {
            for (did, doc) in &n.docs {
                let hash = *doc.content_hash().unwrap().as_bytes();
                queue.push_back((
                    i,
                    SyncMessage::Announce {
                        did: did.clone(),
                        hash,
                        clock: ts(0),
                    },
                ));
            }
        }
        let mut budget = 100_000;
        while let Some((from, msg)) = queue.pop_front() {
            budget -= 1;
            assert!(budget > 0, "gossip simulation did not quiesce");
            for j in 0..nodes.len() {
                if j == from {
                    continue;
                }
                let docs = nodes[j].docs.clone();
                let (out, deliver) = nodes[j].state.handle(msg.clone(), &docs, &deny());
                for o in out {
                    queue.push_back((j, o));
                }
                if let Some(d) = deliver {
                    apply_deliver(&mut nodes[j], d);
                }
            }
        }
    }

    fn revoke(doc: &mut Document, cred: &str, wall: u64) {
        let signer = doc.verification_methods.entries()[0].id.clone();
        let d = SignedDelta::new_with_parents(
            doc.did.clone(),
            DeltaOp::RevokeCredential {
                credential_id: cred.to_owned(),
            },
            HlcTimestamp {
                wall_ms: wall,
                logical: 0,
                node_id: signer_node_id(),
            },
            doc.frontier(),
            signer,
            &signing_key(),
        )
        .expect("sign");
        doc.merge(d).unwrap();
    }

    #[test]
    fn simulated_network_two_nodes_catch_up() {
        // A is ahead (genesis + 2 updates); B has only genesis. After gossip, B
        // converges to A byte-for-byte — purely in-process, no iroh.
        let mut a = make_doc();
        revoke(&mut a, "x", 10);
        revoke(&mut a, "y", 20);
        let b = make_doc(); // same key ⇒ same DID + genesis
        assert_eq!(a.did, b.did);
        assert_ne!(a.content_hash().unwrap(), b.content_hash().unwrap());

        let mut net = [SimNode::new(), SimNode::new()];
        net[0].track(a.clone());
        net[1].track(b);
        gossip_round(&mut net);

        assert_eq!(
            net[1].docs[&a.did].content_hash().unwrap(),
            a.content_hash().unwrap(),
            "B converges to A via simulated gossip reconciliation"
        );
    }

    #[test]
    fn simulated_network_bidirectional_converges() {
        // A and B apply different concurrent updates to the same DID; after a
        // gossip round both hold the union and converge.
        let mut a = make_doc();
        let did = a.did.clone();
        let mut b = make_doc();
        revoke(&mut a, "from-a", 10);
        revoke(&mut b, "from-b", 11);
        assert_ne!(a.content_hash().unwrap(), b.content_hash().unwrap());

        let mut net = [SimNode::new(), SimNode::new()];
        net[0].track(a);
        net[1].track(b);
        gossip_round(&mut net);

        assert_eq!(
            net[0].docs[&did].content_hash().unwrap(),
            net[1].docs[&did].content_hash().unwrap(),
            "both nodes converge to the union after bidirectional gossip"
        );
    }

    #[test]
    fn simulated_network_three_nodes_converge() {
        // Three nodes, three different updates, one broadcast round → all converge.
        let mut a = make_doc();
        let did = a.did.clone();
        let mut b = make_doc();
        let mut c = make_doc();
        revoke(&mut a, "a", 10);
        revoke(&mut b, "b", 11);
        revoke(&mut c, "c", 12);

        let mut net = [SimNode::new(), SimNode::new(), SimNode::new()];
        net[0].track(a);
        net[1].track(b);
        net[2].track(c);
        // Two rounds: round 1 spreads each node's own update; round 2 lets the
        // now-merged states reconcile the remaining gaps.
        gossip_round(&mut net);
        gossip_round(&mut net);

        let h0 = net[0].docs[&did].content_hash().unwrap();
        assert_eq!(net[1].docs[&did].content_hash().unwrap(), h0);
        assert_eq!(net[2].docs[&did].content_hash().unwrap(), h0);
    }

    #[test]
    fn merge_inbound_rejects_forged_signature() {
        // Sender A: genesis + one validly-signed revocation.
        let mut a = make_doc();
        revoke(&mut a, "legit", 10);

        // A forged delta claims A's authorised key id and the real node_id but is
        // signed by a key the document never authorised — so neither node binding
        // nor causal admission rejects it; only the signature check can.
        const ATTACKER_SEED: [u8; 32] = [0x99u8; 32];
        let attacker = SigningKey::Ed25519(DalekKey::from_bytes(&ATTACKER_SEED));
        let key_id = a.verification_methods.entries()[0].id.clone();
        let forged = SignedDelta::new_with_parents(
            a.did.clone(),
            DeltaOp::RevokeCredential {
                credential_id: "forged".to_owned(),
            },
            HlcTimestamp {
                wall_ms: 20,
                logical: 0,
                node_id: signer_node_id(),
            },
            a.frontier(),
            key_id,
            &attacker,
        )
        .expect("sign");

        // Ship A's full signed history plus the forged delta to a fresh replica B.
        let mut deltas = a.export_bundle().unwrap().deltas; // genesis + legit
        deltas.push(forged);
        let b = make_doc(); // genesis only, same DID
        let mut docs = docs_for(&b);
        let _ = merge_inbound(
            &mut docs,
            SyncMessage::Deltas {
                did: b.did.clone(),
                deltas,
            },
            &deny(),
        );

        // B applied genesis + the legit revocation and REJECTED the forgery, so it
        // is byte-identical to A (which never held the forged delta).
        assert_eq!(
            docs[&b.did].content_hash().unwrap(),
            a.content_hash().unwrap(),
            "forged-signature delta must be rejected on the live gossip ingest"
        );
    }

    // ── CON-006 §admission control (TEST-024 scenario E) ──────────────────────

    /// Scenario E: unsolicited DELTAS for an unknown DID is ignored — the
    /// pre-CON-006 invariant ("a peer can only extend a DID we already hold")
    /// holds for all unsolicited traffic. DocStore unchanged.
    #[test]
    fn merge_inbound_ignores_unsolicited_unknown_did() {
        let doc = make_doc();
        let deltas = doc.export_bundle().unwrap().deltas; // valid genesis batch
        let mut docs: HashMap<Did, Document> = HashMap::new();

        let outcome = merge_inbound(
            &mut docs,
            SyncMessage::Deltas {
                did: doc.did.clone(),
                deltas,
            },
            &deny(),
        );

        assert!(matches!(outcome, MergeOutcome::IgnoredUnsolicited));
        assert!(
            docs.is_empty(),
            "unsolicited unknown DID must not be stored"
        );
    }

    /// A pending cold-start request (wanted set) admits the same batch.
    #[test]
    fn merge_inbound_bootstraps_wanted_unknown_did() {
        let doc = make_doc();
        let deltas = doc.export_bundle().unwrap().deltas;
        let mut docs: HashMap<Did, Document> = HashMap::new();
        let policy = BootstrapPolicy::solicited_only();
        policy.add_wanted(&doc.did);

        let outcome = merge_inbound(
            &mut docs,
            SyncMessage::Deltas {
                did: doc.did.clone(),
                deltas,
            },
            &policy,
        );

        assert!(matches!(outcome, MergeOutcome::Bootstrapped(ref d) if d == &doc.did));
        assert!(
            docs.contains_key(&doc.did),
            "wanted DID must be bootstrapped"
        );
    }

    /// Replicate-all mode admits any DID announced on the mesh.
    #[test]
    fn merge_inbound_bootstraps_unknown_did_in_replicate_all() {
        let doc = make_doc();
        let deltas = doc.export_bundle().unwrap().deltas;
        let mut docs: HashMap<Did, Document> = HashMap::new();

        let outcome = merge_inbound(
            &mut docs,
            SyncMessage::Deltas {
                did: doc.did.clone(),
                deltas,
            },
            &BootstrapPolicy::replicate_all(),
        );

        assert!(matches!(outcome, MergeOutcome::Bootstrapped(_)));
        assert!(docs.contains_key(&doc.did));
    }
}
