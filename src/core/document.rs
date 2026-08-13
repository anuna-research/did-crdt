//! `Document` — the top-level DID document CRDT.
//!
//! A `Document` is a composition of typed CRDT fields.  It supports three
//! primary operations:
//!
//! - `new(public_key_multibase)` — create a new DID from a public key, producing
//!   a creation delta and deriving the `did:crdt` identifier.
//! - `merge(delta)` — validate and apply an incoming signed delta.
//! - `merge_state(other)` — state-based CRDT merge with another replica.
//! - `resolve()` — project the CRDT state to a W3C DID Core JSON-LD document.
//! - `content_hash()` — BLAKE3 hash of the current serialised CRDT state.
//! - `to_bytes()` / `from_bytes()` — serialise / deserialise the full state.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::admission::{AdmissionResult, RejectReason};
use crate::core::causal::verify_causal;
use crate::core::crdt::{
    ActiveKey, AlsoKnownAs, Deactivated, DocumentData, Revocations, RevokedVerificationMethods,
    ServiceEndpoints, ServiceEntry, VerificationMethodEntry, VerificationMethods,
};
use crate::core::dag::DeltaDag;
use crate::core::delta::ms_to_iso8601;
use crate::core::delta::{
    DeltaHash, DeltaOp, SignedDelta, SuiteType, VerificationRelationship, MAX_DELTA_SIZE,
};
use crate::core::did::Did;
use crate::core::hlc::HlcTimestamp;
use crate::core::recon::ClosureBundle;
use crate::core::resolve::{
    DidDocument, DidDocumentMetadata, DidResolutionMetadata, ResolutionResult, ServiceEndpoint,
    VerificationMethod,
};
use crate::core::{Error, Result};
use std::collections::{HashMap, HashSet};

/// A replicated DID document backed by a composition of CRDTs.
///
/// All CRDT fields are public-in-crate so that tests and the sync layer can
/// inspect state; external callers use the public API methods.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "DocumentRepr")]
pub struct Document {
    /// The stable `did:crdt` identifier (derived from the creation delta hash).
    pub did: Did,

    /// Grow-only set of verification methods.
    pub(crate) verification_methods: VerificationMethods,

    /// OR-Set of service endpoints.
    pub(crate) service_endpoints: ServiceEndpoints,

    /// LWW-Map of arbitrary document metadata.
    pub(crate) document_data: DocumentData,

    /// LWW-Register holding the whole `alsoKnownAs` URI set.
    pub(crate) also_known_as: AlsoKnownAs,

    /// Max-Register holding the currently-active key reference.
    pub(crate) active_key: ActiveKey,

    /// Grow-only set of revoked credential identifiers.
    pub(crate) revocations: Revocations,

    /// Grow-only set of revoked verification method key IDs (2P-Set remove half).
    ///
    /// Together with `verification_methods` (add half), forms a 2P-Set:
    /// `authorized = added \ revoked`.
    pub(crate) revoked_verification_methods: RevokedVerificationMethods,

    /// Boolean latch — once true the document is permanently deactivated.
    pub(crate) deactivated: Deactivated,

    /// Unix millisecond timestamp of the genesis (creation) delta.
    #[serde(default)]
    pub(crate) created_ms: Option<u64>,

    /// Unix millisecond timestamp of the most recent applied delta.
    #[serde(default)]
    pub(crate) updated_ms: Option<u64>,

    /// Applied deltas retained for sync and auditability, and the source from
    /// which the [`Self::dag`] frontier is rebuilt on load.
    ///
    /// Serialized so that a `to_bytes`/`from_bytes`, blob-store, or state-sync
    /// round trip preserves the delta history; `from_bytes` rebuilds the DAG
    /// from it (otherwise a loaded document would have an empty frontier and
    /// reject correctly-parented updates as `DeltaPending`). [`Self::merge_state`]
    /// likewise merges the incoming log so the frontier reflects imported updates.
    /// It is **not** part of observable CRDT state: state identity is
    /// [`Self::content_hash`], which hashes only the resolved state.
    #[serde(default)]
    pub(crate) delta_log: Vec<SignedDelta>,

    /// Per-replica delta DAG: hash index + frontier, for causal admission
    /// (SPEC-036) and reconciliation. Not serialized directly (it is
    /// `HashMap`-backed, hence not canonically orderable); instead it is rebuilt
    /// from [`Self::delta_log`] by [`Self::rebuild_dag`] on load.
    #[serde(skip)]
    pub(crate) dag: DeltaDag,
}

/// Deserialisation shadow for [`Document`] (via `#[serde(from)]`).
///
/// The DAG is derived state and is never serialised, so `Document` cannot be
/// deserialised field-by-field without leaving an empty DAG (and therefore an
/// empty frontier, which would reject correctly-parented updates as
/// `DeltaPending`). Deserialising through this shadow and rebuilding the DAG
/// makes *every* path — `from_bytes`, blob load, and direct serde — restore a
/// valid frontier (SPEC-036).
#[derive(Deserialize)]
struct DocumentRepr {
    did: Did,
    verification_methods: VerificationMethods,
    service_endpoints: ServiceEndpoints,
    document_data: DocumentData,
    // Defaulted: state serialised before `alsoKnownAs` existed must still load,
    // and an absent set is exactly an empty one.
    #[serde(default)]
    also_known_as: AlsoKnownAs,
    active_key: ActiveKey,
    revocations: Revocations,
    revoked_verification_methods: RevokedVerificationMethods,
    deactivated: Deactivated,
    #[serde(default)]
    created_ms: Option<u64>,
    #[serde(default)]
    updated_ms: Option<u64>,
    #[serde(default)]
    delta_log: Vec<SignedDelta>,
}

impl TryFrom<DocumentRepr> for Document {
    type Error = String;

    fn try_from(r: DocumentRepr) -> std::result::Result<Self, String> {
        // Reject a document that carries CRDT state but no delta log: the DAG
        // would rebuild empty, leaving an empty frontier so the next update is
        // treated as a non-genesis root and rejected, and peer updates referencing
        // the real genesis stay pending — a silently-frozen document. This is the
        // shape produced by a pre-DAG serialisation (the delta log absent). There
        // are no deployed DIDs, so we refuse such input loudly rather than admit a
        // broken state; a future migration would reconstruct the delta history.
        if r.delta_log.is_empty() && !r.verification_methods.entries().is_empty() {
            return Err(
                "document has CRDT state but no delta log: unsupported pre-DAG \
                 serialisation (cannot reconstruct the frontier; recreate the document)"
                    .to_owned(),
            );
        }
        let mut doc = Document {
            did: r.did,
            verification_methods: r.verification_methods,
            service_endpoints: r.service_endpoints,
            document_data: r.document_data,
            also_known_as: r.also_known_as,
            active_key: r.active_key,
            revocations: r.revocations,
            revoked_verification_methods: r.revoked_verification_methods,
            deactivated: r.deactivated,
            created_ms: r.created_ms,
            updated_ms: r.updated_ms,
            delta_log: r.delta_log,
            dag: DeltaDag::new(),
        };
        doc.rebuild_dag();
        Ok(doc)
    }
}

/// Whether a parent set is canonical: strictly ascending (hence sorted with no
/// duplicates), per SPEC-036 REQ-361.
fn is_canonical_parents(parents: &[DeltaHash]) -> bool {
    parents.windows(2).all(|w| w[0] < w[1])
}

/// Topologically order the deltas of a bundle (indexed by content hash) so that
/// every delta follows its in-bundle parents (SPEC-036 Phase 4 replay order).
/// Parents resolved outside the bundle (already held by the receiver) are
/// treated as roots. Returns [`Error::DeltaRejected`] if the bundle contains a
/// parent cycle — impossible for honest content-addressed deltas, hence evidence
/// of tampering.
fn topo_order_bundle(by_hash: &HashMap<DeltaHash, SignedDelta>) -> Result<Vec<DeltaHash>> {
    // In-degree counts only parents that are themselves in the bundle.
    let mut indeg: HashMap<DeltaHash, usize> =
        by_hash.keys().map(|h| (h.clone(), 0usize)).collect();
    let mut children: HashMap<DeltaHash, Vec<DeltaHash>> = HashMap::new();
    for (h, d) in by_hash {
        for p in &d.parents {
            if by_hash.contains_key(p) {
                *indeg.get_mut(h).unwrap() += 1;
                children.entry(p.clone()).or_default().push(h.clone());
            }
        }
    }
    // Kahn's algorithm. Roots are drained in sorted order for a deterministic,
    // reproducible result (correctness only needs parents-before-children).
    let mut ready: Vec<DeltaHash> = indeg
        .iter()
        .filter(|(_, &n)| n == 0)
        .map(|(h, _)| h.clone())
        .collect();
    ready.sort();
    let mut order: Vec<DeltaHash> = Vec::with_capacity(by_hash.len());
    while let Some(h) = ready.pop() {
        if let Some(cs) = children.get(&h) {
            let mut unlocked: Vec<DeltaHash> = Vec::new();
            for c in cs {
                let n = indeg.get_mut(c).unwrap();
                *n -= 1;
                if *n == 0 {
                    unlocked.push(c.clone());
                }
            }
            unlocked.sort();
            ready.extend(unlocked);
        }
        order.push(h);
    }
    if order.len() != by_hash.len() {
        return Err(Error::DeltaRejected(
            "bundle has a parent cycle: tampered".to_owned(),
        ));
    }
    Ok(order)
}

/// Derive the `did:crdt:<hash>` identifier from the genesis public key.
///
/// The identifier is a pure function of that ONE input: the timestamp is the
/// all-zero default and the proto-op is built from the key, so nothing else
/// varies. That is what lets a verifier holding the key recompute the DID for
/// itself rather than taking a resolver's word for it — see
/// [`Document::genesis_public_key_multibase`].
///
/// Creation and recomputation share this function deliberately. Two copies
/// that drifted would produce a document whose own identifier no longer
/// verifies against its genesis key, and nothing else in the system checks
/// that relation — so the drift would surface as an unexplained verification
/// failure at a consumer, arbitrarily far from the change that caused it.
fn derive_did(public_key_multibase: &str) -> Result<Did> {
    let timestamp = HlcTimestamp::default();

    // A placeholder fragment, because the real key id embeds the DID, which
    // does not exist until this hash has been taken.
    let proto_op = DeltaOp::AddVerificationMethod {
        id: "#key-0".to_owned(),
        public_key_multibase: public_key_multibase.to_owned(),
        suite_type: SuiteType::default(),
        relationships: crate::core::delta::default_relationships(),
    };
    let signer_key = public_key_multibase.to_owned();

    let seed_bytes = serde_json::to_vec(&(&timestamp, &proto_op, &signer_key))?;
    Ok(Did::from_creation_hash(&blake3::hash(&seed_bytes)))
}

impl Document {
    /// Every verification method currently in resolved state, with the
    /// relationships each one holds.
    ///
    /// Unlike [`Self::resolve`] this does **not** drop revoked methods and does
    /// not disappear when the document is deactivated: a consumer deciding
    /// whether to trust a signature needs to see a method that exists and is
    /// revoked as something different from a method that was never there.
    /// Filtering is the caller's, because which relationship matters is the
    /// caller's question.
    pub fn verification_methods(&self) -> Vec<VerificationMethodEntry> {
        self.verification_methods.entries()
    }

    /// The grow-only credential revocation set.
    ///
    /// [`Self::is_revoked`] answers membership for one identifier; a consumer
    /// building its own view of revocation state needs the set itself, and a
    /// G-Set is safe to hand out whole because it only ever grows.
    pub fn revoked_credential_ids(&self) -> Vec<String> {
        self.revocations.entries()
    }

    // ── construction ─────────────────────────────────────────────────────────

    /// Create a new DID document from a public key in Multibase encoding.
    ///
    /// Derives the `did:crdt:<hash>` identifier by (see [`derive_did`]):
    /// 1. Building a genesis `AddVerificationMethod` delta (using a stable
    ///    `#key-0` fragment with a temporary placeholder DID).
    /// 2. Hashing `(timestamp, op, signer_key)` with BLAKE3.
    /// 3. Forming the real DID from that hash.
    /// 4. Applying the genesis op with the resolved key id.
    ///
    /// The returned [`SignedDelta`] has an empty signature because no signing
    /// infrastructure is wired in this phase; callers that need signed creation
    /// deltas must fill `signature` before broadcasting.
    pub fn new(public_key_multibase: &str) -> Result<(Self, SignedDelta)> {
        // Genesis timestamp — all-zero so every subsequent delta is causally
        // later and the creation event is reproducible across replicas.
        let timestamp = HlcTimestamp::default();
        let signer_key = public_key_multibase.to_owned();
        let did = derive_did(public_key_multibase)?;

        // Now that we know the DID, build the real key id.
        let key_id = format!("{}#key-0", did);
        let op = DeltaOp::AddVerificationMethod {
            id: key_id,
            public_key_multibase: public_key_multibase.to_owned(),
            suite_type: SuiteType::default(),
            relationships: crate::core::delta::default_relationships(),
        };

        let mut doc = Document {
            did: did.clone(),
            verification_methods: VerificationMethods::new(),
            service_endpoints: ServiceEndpoints::new(),
            document_data: DocumentData::new(),
            also_known_as: AlsoKnownAs::new(),
            active_key: ActiveKey::new(),
            revocations: Revocations::new(),
            revoked_verification_methods: RevokedVerificationMethods::new(),
            deactivated: Deactivated::new(),
            created_ms: Some(timestamp.wall_ms),
            updated_ms: Some(timestamp.wall_ms),
            delta_log: Vec::new(),
            dag: DeltaDag::new(),
        };

        // Apply the creation op directly (no auth check — this *is* genesis).
        // Genesis has no parents, so its causal past is empty.
        doc.apply_op(&op, timestamp, &[])?;

        // The creation delta is unsigned at this layer — callers that need a
        // signed genesis delta MUST call SignedDelta::new with the private key.
        let creation_delta = SignedDelta::unsigned(did, op, timestamp, signer_key);

        // Record the genesis delta in the log and the DAG (it is the DAG root).
        doc.delta_log.push(creation_delta.clone());
        doc.dag.insert(creation_delta.clone())?;

        Ok((doc, creation_delta))
    }

    // ── delta-based merge ─────────────────────────────────────────────────────

    /// Validate and apply a signed delta to the CRDT state.
    ///
    /// Structural checks performed:
    /// - The delta's DID must match `self.did`.
    /// - If the document is already deactivated, all further deltas are
    ///   rejected (the only exception would be a duplicate deactivation,
    ///   which is a no-op — but we still reject it for simplicity).
    /// - The signer must be a key that exists in `verification_methods`
    ///   (or the document must be empty, i.e., this is the genesis delta).
    ///
    /// # Note on signature verification
    ///
    /// Cryptographic signature verification is deferred to a later phase (see
    /// `core::validate`).  Callers that operate in a trust boundary MUST call
    /// `validate::verify_signature` before calling this method.
    pub fn merge(&mut self, delta: SignedDelta) -> Result<()> {
        // 0. Size gate — reject oversized deltas before any processing (ADR-004).
        let serialised_size = serde_json::to_vec(&delta)?.len();
        if serialised_size > MAX_DELTA_SIZE {
            return Err(Error::DeltaTooLarge {
                size: serialised_size,
                max: MAX_DELTA_SIZE,
            });
        }

        // 1. DID match.
        if delta.did != self.did {
            return Err(Error::DeltaRejected(format!(
                "delta DID {} does not match document DID {}",
                delta.did, self.did
            )));
        }

        // 1a. Reserved-name gate — `documentData` may not carry a DID Core
        //     property. Such a key projects into the same JSON object as the
        //     typed fields and shadows it for any last-wins parser, which lets
        //     it replace `verificationMethod` or restate `id`. Refused here so
        //     the delta never enters the log; see
        //     `resolve::RESERVED_DOCUMENT_PROPERTIES` for why the projection
        //     ALSO filters.
        // 1a-bis. Recognise the alsoKnownAs set in full before any of it is
        //     applied. These strings are republished by verifiers into
        //     documents consumed by software this project does not control, so
        //     they are recognised at the boundary rather than sanitised later.
        if let DeltaOp::SetAlsoKnownAs { uris } = &delta.op {
            crate::core::validate::recognise_also_known_as(uris)?;
        }

        if let DeltaOp::SetDocumentData { key, .. } = &delta.op {
            if crate::core::resolve::is_reserved_document_property(key) {
                return Err(Error::DeltaRejected(format!(
                    "documentData key {key:?} is a reserved DID Core property"
                )));
            }
        }

        // 1b. Idempotent dedup: if this exact delta is already held, re-applying
        //     it would derive fresh CRDT metadata (e.g. a new ORSWOT dot) and
        //     mutate state, content hash, and log even though the DAG already
        //     contains it. Duplicate delivery must be a true no-op, so check the
        //     content hash *before* apply_op / log.
        let delta_hash = delta.content_hash()?;
        if self.dag.contains(&delta_hash) {
            return Ok(());
        }

        // 2. Reject non-canonical parent sets: `parents` MUST be sorted and
        //    deduplicated (REQ-361). The raw order is covered by the signature
        //    and the content hash, so a non-canonical set would yield a second
        //    identity / frontier leaf for the same causal parents.
        if !is_canonical_parents(&delta.parents) {
            return Err(Error::DeltaRejected(
                "delta parents are not sorted and deduplicated".to_owned(),
            ));
        }

        // 3. Causal admission against the content-fixed past `↓D` (SPEC-036
        //    REQ-363). With the full delta log always retained, `verify_causal`
        //    is exact and AUTHORITATIVE: `Valid` means the signer is added in `↓D`
        //    and neither revoked nor deactivated *in `↓D`*. Because this is a
        //    function of the delta's own causal past, it is order-independent —
        //    concurrent siblings (e.g. a delta signed by K alongside a concurrent
        //    revocation of K) are both admitted, since neither's revocation is in
        //    the other's past ("containment, not recovery").
        let signer = delta.proof.verification_method.clone();
        match verify_causal(&delta, &self.dag) {
            AdmissionResult::Unknown(missing) => return Err(Error::DeltaPending { missing }),
            AdmissionResult::Valid => {}
            AdmissionResult::Invalid(RejectReason::SignerNotAuthorised)
                // Defer ONLY a signer with no `AddVerificationMethod` delta in the
                // DAG: it can only have arrived via a trusted state-merge import,
                // which causal cannot see, so it falls through to the state-import
                // floor below. A parentless (ungrounded) delta, or a signer whose
                // AddVM IS a held delta but was excluded from `↓D` (back-parenting),
                // is rejected here.
                if !delta.parents.is_empty() && !self.dag.has_authorising_delta(&signer) => {}
            AdmissionResult::Invalid(reason) => {
                return Err(Error::Unauthorised(format!(
                    "delta is causally unauthorised ({reason:?}): its signer's \
                     authorisation is not present in its causal past"
                )));
            }
        }

        // 4. State-import floor. `merge_state` can import facts — revocations,
        //    deactivation, key additions — WITHOUT their originating deltas, so
        //    they are invisible to the causal check above. Enforce ONLY those: a
        //    fact backed by a delta in the DAG is already decided causally and MUST
        //    NOT be re-checked against current state here, or a delta concurrent
        //    with a revocation/deactivation *delta* would be wrongly rejected.
        if self.deactivated.is_set() && !self.dag.has_deactivate_delta() {
            return Err(Error::DeltaRejected(
                "document is deactivated (state-imported); no further mutations accepted"
                    .to_owned(),
            ));
        }
        // A signer known only via state-import (no AddVM delta) must actually be a
        // current, non-revoked verification method.
        if !self.dag.has_authorising_delta(&signer)
            && !self.verification_methods.entries().is_empty()
            && !self.verification_methods.contains_id(&signer)
        {
            return Err(Error::Unauthorised(format!(
                "signer key {signer} is not an authorised verification method"
            )));
        }
        // A revocation present only in current state (no `RevokeVerificationMethod`
        // delta) is a state-import fact the causal check could not see.
        if self.revoked_verification_methods.contains(&signer)
            && !self.dag.has_revoking_delta(&signer)
        {
            return Err(Error::Unauthorised(format!(
                "signer key {signer} has been revoked (state-imported)"
            )));
        }

        // 5. RotateKey: no current-state staleness gate. A rotation with a lower
        //    sequence than the current one may be a *concurrent* rotation, not a
        //    causal descendant — rejecting it here would leave any delta parented
        //    on it permanently `DeltaPending` on this replica while another
        //    replica (that saw the lower sequence first) accepts it, a divergence.
        //    All rotations are admitted; the ActiveKey Max-Register resolves them
        //    deterministically (higher sequence wins, hash tiebreak at equal
        //    sequence), and a lower-sequence rotation simply never wins.

        self.apply_op(&delta.op, delta.timestamp, &delta.parents)?;

        // Track the delta in the log and the per-replica DAG (SPEC-036). The full
        // log is always retained, so the DAG is always complete and causal
        // admission is exact. (Compaction is deferred to Phase 3, SPEC-036 §10, and
        // is not part of this codebase.)
        self.dag.insert(delta.clone())?;
        self.delta_log.push(delta);

        Ok(())
    }

    /// Trust-boundary single-delta merge for **untrusted** inbound deltas (the
    /// live gossip path): verifies the cryptographic signature in addition to the
    /// structural and causal admission of [`Self::merge`].
    ///
    /// Out-of-order deltas whose causal parents are not yet present return
    /// [`Error::DeltaPending`] *without* signature checking — the signer's key may
    /// not be materialised yet, so verifying now could fail spuriously; the caller
    /// retries once the parents arrive. Once a delta is admissible its signer's
    /// verification method (introduced in its causal past `↓D`) is guaranteed
    /// materialised, so a signature failure is a genuine forgery and is rejected.
    ///
    /// This is the per-delta counterpart to [`Self::merge_verified_bundle`]: both
    /// guarantee no delta affects state without a valid signature under an
    /// authorised key, unlike [`Self::merge`] (which defers signature verification
    /// to the caller) and [`Self::merge_state`] (which trusts raw imported state).
    pub fn merge_verified_delta(&mut self, delta: SignedDelta) -> Result<()> {
        // Idempotent dedup mirrors `merge`: a delta already held is a no-op and was
        // authenticated when first admitted, so it must not be re-verified.
        let delta_hash = delta.content_hash()?;
        if self.dag.contains(&delta_hash) {
            return Ok(());
        }
        // Hold out-of-order deltas pending without verifying: `Unknown` means a
        // causal parent is missing — exactly `merge`'s DeltaPending case — and the
        // signer's key may not be materialised yet.
        if let AdmissionResult::Unknown(missing) = verify_causal(&delta, &self.dag) {
            return Err(Error::DeltaPending { missing });
        }
        // Parents present ⇒ the signer's authorising delta (in `↓D`) is applied, so
        // the verification method is materialised. Verify the signature before any
        // state change; a forged signature under a real key id is rejected here.
        crate::core::validate::verify_signature(&delta, self)?;
        self.merge(delta)
    }

    // ── state-based merge ─────────────────────────────────────────────────────

    /// Merge the full CRDT state of `other` into `self` (state-based / CvRDT),
    /// including its delta history.
    ///
    /// This is the **canonical convergence primitive**: a true semilattice join
    /// over the typed CRDT fields, provably commutative, associative, and
    /// idempotent (TEST-002/003/005). It is the ground truth for strong eventual
    /// consistency, and the correct way to reconcile two replicas of *concurrent
    /// observed-remove* state (e.g. add/remove of the same service endpoint),
    /// which op-replay alone does not yet handle — a remove delta does not carry
    /// the dots it observed, so replaying it re-derives context from local state.
    /// See SPEC-036 §11 (op-replay remove-context gap, future work).
    ///
    /// Both documents MUST share the same DID; otherwise the merge is rejected.
    /// The incoming delta log is merged (deduped) into the DAG, so the frontier
    /// reflects the imported updates (later deltas parented on them are then
    /// admitted, not held `DeltaPending`).
    ///
    /// # Safety / trust
    ///
    /// This method performs **no** authentication: it checks only DID equality,
    /// then merges `other`'s fields and deltas unconditionally. It does not
    /// re-verify any signature or admission decision, so a malicious peer could
    /// inject fabricated keys or spurious metadata through it. It is therefore
    /// for use **only among trusted (intra-domain) replicas** — your own devices,
    /// a backup you control. It is deliberately **not reachable from the
    /// network**: there is no `SyncMessage::State` wire message, so an untrusted
    /// gossip peer can only extend a DID via signed deltas. For convergence with
    /// untrusted peers use [`Self::merge_verified_bundle`], which re-derives
    /// state from a verified signed-delta chain (SPEC-036 REQ-368).
    pub fn merge_state(&mut self, other: Document) -> Result<()> {
        if other.did != self.did {
            return Err(Error::DeltaRejected(format!(
                "cannot merge documents with different DIDs: {} vs {}",
                self.did, other.did
            )));
        }

        self.verification_methods.merge(other.verification_methods);
        self.service_endpoints.merge(other.service_endpoints);
        self.document_data.merge(other.document_data);
        self.also_known_as.merge(other.also_known_as);
        self.active_key.merge(other.active_key);
        self.revocations.merge(other.revocations);
        self.revoked_verification_methods
            .merge(other.revoked_verification_methods);
        self.deactivated.merge(other.deactivated);

        // Merge timestamps: take the earliest created and latest updated.
        match (self.created_ms, other.created_ms) {
            (Some(a), Some(b)) => self.created_ms = Some(a.min(b)),
            (None, Some(b)) => self.created_ms = Some(b),
            _ => {}
        }
        match (self.updated_ms, other.updated_ms) {
            (Some(a), Some(b)) => self.updated_ms = Some(a.max(b)),
            (None, Some(b)) => self.updated_ms = Some(b),
            _ => {}
        }

        // Merge the incoming delta history into the log and DAG. Merging only the
        // materialised state would leave the frontier stalled on local history, so
        // a later delta parented on an imported update would be held `DeltaPending`
        // (or rejected as back-parented by a full-history peer) even though the
        // state visibly converged. Dedup by content hash; DAG insertion is
        // order-independent (REQ-360), so the frontier converges to the union.
        let mut seen: HashSet<DeltaHash> = self
            .delta_log
            .iter()
            .filter_map(|d| d.content_hash().ok())
            .collect();
        for d in other.delta_log {
            let Ok(h) = d.content_hash() else { continue };
            if seen.insert(h) {
                let _ = self.dag.insert(d.clone());
                self.delta_log.push(d);
            }
        }

        Ok(())
    }

    // ── authenticated state sync (SPEC-036 Phase 4, REQ-368) ─────────────────

    /// Export the entire local history as a self-verifying [`ClosureBundle`] for
    /// transfer to another replica (SPEC-036 REQ-365). The bundle carries the
    /// signed deltas of every frontier head's causal closure; the receiver
    /// re-derives authenticated state with [`Self::merge_verified_bundle`].
    ///
    /// # Errors
    ///
    /// [`Error::DeltaRejected`] if the local history is empty, or
    /// [`Error::Serialisation`] if a delta cannot be hashed.
    pub fn export_bundle(&self) -> Result<ClosureBundle> {
        let heads = self.dag.frontier();
        let target = heads
            .iter()
            .max()
            .cloned()
            .ok_or_else(|| Error::DeltaRejected("cannot export an empty history".to_owned()))?;
        // Union the closures of all frontier heads (concurrent branches), deduped
        // by content hash. `target` is one head; the others ride along as deltas
        // with no dangling parents, and each is independently re-verified on merge.
        let mut seen: HashSet<DeltaHash> = HashSet::new();
        let mut deltas: Vec<SignedDelta> = Vec::new();
        for h in &heads {
            for d in self.dag.extract_closure(h, &[])?.deltas {
                if seen.insert(d.content_hash()?) {
                    deltas.push(d);
                }
            }
        }
        Ok(ClosureBundle { target, deltas })
    }

    /// Re-derive authenticated state from a verified signed-delta chain
    /// (SPEC-036 REQ-368, Phase 4) — the safe counterpart to [`Self::merge_state`].
    ///
    /// Unlike `merge_state`, which trusts raw CRDT state, this replays every
    /// delta in `bundle` through the full admission path ([`Self::merge`]):
    /// signature verification and current-state authorisation. Injected or
    /// fabricated state therefore cannot enter — a delta signed by a
    /// non-authorised key has no valid signature/authorisation and is rejected.
    /// This is the authenticated path for **untrusted** peers.
    ///
    /// Guarantees:
    /// - **Atomic.** The bundle is validated and replayed on a working copy; if
    ///   *any* delta is rejected, `self` is left entirely unchanged and the error
    ///   is returned. There is no partial application.
    /// - **Idempotent.** Deltas already held are skipped (dedup in `merge`).
    /// - **Order-independent input.** The bundle's deltas may be in any order;
    ///   they are applied in causal (topological) order so replay never stalls.
    ///
    /// Returns the number of deltas newly applied.
    ///
    /// # Errors
    ///
    /// [`Error::DeltaRejected`] if the bundle is structurally invalid (missing
    /// its target, a dangling parent resolvable neither in the bundle nor in the
    /// held DAG, or a parent cycle); otherwise whatever [`Self::merge`] returns
    /// for the first delta it rejects (e.g. [`Error::Unauthorised`] on a forged
    /// signer).
    pub fn merge_verified_bundle(&mut self, bundle: ClosureBundle) -> Result<usize> {
        // 1. Structural pre-validation, before touching any state. Index the
        //    bundle by content hash and require (a) the claimed target is present
        //    (else a tampered leaf could be smuggled under a requested hash) and
        //    (b) no delta dangles a parent that resolves neither in the bundle
        //    nor in what we already hold (tampered or incomplete closure).
        let mut by_hash: HashMap<DeltaHash, SignedDelta> = HashMap::new();
        for d in &bundle.deltas {
            by_hash.insert(d.content_hash()?, d.clone());
        }
        if !by_hash.contains_key(&bundle.target) {
            return Err(Error::DeltaRejected(format!(
                "bundle does not contain its target {}",
                bundle.target
            )));
        }
        for d in &bundle.deltas {
            for p in &d.parents {
                // A parent must resolve in the bundle or in what we already hold;
                // otherwise the bundle is tampered or incomplete.
                if !by_hash.contains_key(p) && !self.dag.contains(p) {
                    return Err(Error::DeltaRejected(format!(
                        "bundle has a dangling parent {p}: tampered or incomplete"
                    )));
                }
            }
        }

        // 2. Causal (topological) order: parents before children, so each replay
        //    finds its predecessors present and never returns `DeltaPending`.
        //    Parents resolved outside the bundle (already held) count as roots.
        let order = topo_order_bundle(&by_hash)?;

        // 3. Replay on a working copy for atomicity, then commit. The first
        //    rejection aborts and leaves `self` untouched.
        let mut working = self.clone();
        let start = working.delta_count();
        for h in &order {
            // Idempotent skip BEFORE signature verification: an already-held delta
            // (notably the genesis, whose empty proof is valid only against an empty
            // document) must not be re-verified against the now-populated state.
            if working.dag.contains(h) {
                continue;
            }
            let d = &by_hash[h];
            // Cryptographic signature verification against the keys present in
            // `working` — which, because we replay in topological order, already
            // include every causally-prior `AddVerificationMethod`. THIS is what
            // makes the path authenticated: `merge` enforces authorisation (key
            // membership) but does NOT verify signatures, so a bundle carrying a
            // delta with a forged signature under a real key id would otherwise
            // be admitted. Verifying here rejects it.
            crate::core::validate::verify_signature(d, &working)?;
            working.merge(d.clone())?;
        }
        let applied = working.delta_count() - start;
        *self = working;
        Ok(applied)
    }

    /// Render a multibase Ed25519 public key as an RFC 8037 OKP JWK.
    ///
    /// Returns `None` for anything this cannot render faithfully — an unexpected
    /// multibase prefix, or a key that is not 32 octets. A twin is omitted rather
    /// than guessed at: a `JsonWebKey` carrying the wrong bytes would verify
    /// signatures made by a key nobody authorised, which is worse than a document
    /// with no twin in it.
    ///
    /// `d` is never present. A projection reads public state and has no private
    /// component to leak, and `CON-206` step 6 in the adopting profile refuses a
    /// JWK that carries one.
    fn jwk_from_multibase(multibase: &str) -> Option<Value> {
        use base64ct::{Base64UrlUnpadded, Encoding as _};

        let raw = Base64UrlUnpadded::decode_vec(multibase.strip_prefix('u')?).ok()?;
        if raw.len() != 32 {
            return None;
        }
        Some(serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": Base64UrlUnpadded::encode_string(&raw),
        }))
    }

    // ── projection ───────────────────────────────────────────────────────────

    /// Project the current CRDT state to a W3C DID Core 1.1 resolution result.
    ///
    /// Returns the three-part `(didResolutionMetadata, didDocument, didDocumentMetadata)`
    /// tuple as a [`ResolutionResult`].  When the DID is deactivated the
    /// `didDocument` field is `None` per DID Core 1.1 §7.1.
    ///
    /// This operation is pure and read-only — it never mutates CRDT state.
    /// The public key this DID was derived from, when it can be established.
    ///
    /// Published so a verifier can recompute the identifier ITSELF. Two facts
    /// make that worth carrying:
    ///
    /// - [`Self::resolve`] filters revoked keys out of the DID document
    ///   (2P-Set: authorized = added \ revoked). Once the genesis key is
    ///   rotated, the served document no longer contains the input its own
    ///   identifier derives from — the relation stops being checkable exactly
    ///   when the document stops being self-describing. The 2P-Set still holds
    ///   the entry, so the node can answer even though its document cannot.
    /// - The answer cannot be faked. Deriving the DID is a BLAKE3 hash, so
    ///   preimage resistance means no node can invent a genesis key for a DID
    ///   it was asked about. A verifier that recomputes needs to trust nothing
    ///   — which is what separates this from a self-reported boolean, where a
    ///   dishonest node and an honest one emit the same byte.
    ///
    /// The `#key-0` naming convention is deliberately NOT consulted. The
    /// backing set is a G-Set of whole entries rather than a map keyed on `id`,
    /// so several entries may carry the same `id` with different keys — picking
    /// by name would pick by sort order, and a second `#key-0` entry would be
    /// enough to shadow the genuine one. The hash decides instead, and preimage
    /// resistance means at most one entry can satisfy it.
    ///
    /// Returns `None` when no key held derives this DID. Absent means "could
    /// not establish", and must never be read as "established, and it failed".
    pub fn genesis_public_key_multibase(&self) -> Option<String> {
        self.verification_methods
            .entries()
            .into_iter()
            .find(|e| derive_did(&e.public_key_multibase).is_ok_and(|d| d == self.did))
            .map(|e| e.public_key_multibase)
    }

    /// The signed deltas this replica holds, as a causal-closure bundle.
    ///
    /// This is what a verifier that will not take a resolver's word for the
    /// document needs: a projected document carries no signatures, so
    /// deserialising one makes the RESOLVER authoritative on the DID's own
    /// revocations. Replaying these makes the signatures authoritative instead.
    ///
    /// EVERY frontier head's closure is included, not just the target's. With
    /// concurrent heads, one head's ancestry omits the other branch, and a
    /// verifier replaying it would materialise a document missing whatever only
    /// the other branch carries — a revocation, for instance. Serving less than
    /// the full history is how a resolver silently answers an old question.
    ///
    /// `target` names one head deterministically (the greatest hash), so the
    /// answer is stable across replicas holding the same state. It is the head
    /// the bundle was extracted at, not a claim that it is the only one.
    ///
    /// # Errors
    ///
    /// Fails if the local closure is incomplete — an ancestor is referenced but
    /// not held. Refusing beats serving a bundle a verifier would reject for
    /// dangling parents after paying to transfer it.
    pub fn closure_bundle(&self) -> Result<ClosureBundle> {
        let mut heads = self.dag.frontier();
        heads.sort();
        let Some(target) = heads.last().cloned() else {
            return Err(Error::DeltaRejected(
                "no delta history from which to extract a closure".to_owned(),
            ));
        };

        let mut deltas: Vec<SignedDelta> = Vec::new();
        let mut seen: HashSet<DeltaHash> = HashSet::new();
        for head in &heads {
            for delta in self.dag.extract_closure(head, &[])?.deltas {
                if seen.insert(delta.content_hash()?) {
                    deltas.push(delta);
                }
            }
        }
        Ok(ClosureBundle { target, deltas })
    }

    pub fn resolve(&self) -> Result<ResolutionResult> {
        let is_deactivated = self.deactivated.is_set();

        // Build the DID document (None if deactivated).
        let did_document = if is_deactivated {
            None
        } else {
            let mut doc = DidDocument::empty(&self.did);

            // Map verification methods, excluding revoked keys (2P-Set semantics:
            // authorized = added \ revoked).
            for entry in self.verification_methods.entries() {
                if self.revoked_verification_methods.contains(&entry.id) {
                    continue;
                }
                doc.verification_method.push(VerificationMethod {
                    id: entry.id.clone(),
                    r#type: entry.suite_type.verification_method_type().to_owned(),
                    controller: self.did.to_string(),
                    public_key_multibase: Some(entry.public_key_multibase.clone()),
                    public_key_jwk: None,
                });
                // Place the key ID into each relationship array it belongs to.
                for rel in &entry.relationships {
                    let key_ref = Value::String(entry.id.clone());
                    match rel {
                        VerificationRelationship::Authentication => {
                            doc.authentication.push(key_ref);
                        }
                        VerificationRelationship::AssertionMethod => {
                            doc.assertion_method.push(key_ref);
                        }
                        VerificationRelationship::KeyAgreement => {
                            doc.key_agreement.push(key_ref);
                        }
                        VerificationRelationship::CapabilityInvocation => {
                            doc.capability_invocation.push(key_ref);
                        }
                        VerificationRelationship::CapabilityDelegation => {
                            doc.capability_delegation.push(key_ref);
                        }
                    }
                }
            }

            // Project `JsonWebKey` twins for the keys that already assert.
            //
            // Computed from state that exists, so nothing signed changes and the
            // bytes deriving the identifier are untouched. See
            // `resolve::JsonWebKey2020` for why only assertion keys are twinned
            // and why the index is positional.
            let mut asserting: Vec<&VerificationMethod> = doc
                .verification_method
                .iter()
                .filter(|m| {
                    doc.assertion_method
                        .iter()
                        .any(|r| r.as_str() == Some(m.id.as_str()))
                })
                .collect();
            // Ordered by id so the numbering is a function of state rather than
            // of the order deltas happened to arrive.
            asserting.sort_by(|a, b| a.id.cmp(&b.id));

            let twins: Vec<VerificationMethod> = asserting
                .into_iter()
                .enumerate()
                .filter_map(|(index, method)| {
                    let jwk = Self::jwk_from_multibase(method.public_key_multibase.as_deref()?)?;
                    Some(VerificationMethod {
                        id: format!(
                            "{}{}{index}",
                            self.did,
                            crate::core::resolve::JWK_FRAGMENT_PREFIX
                        ),
                        r#type: crate::core::resolve::JSON_WEB_KEY_TYPE.to_owned(),
                        controller: self.did.to_string(),
                        public_key_multibase: None,
                        public_key_jwk: Some(jwk),
                    })
                })
                .collect();

            for twin in twins {
                doc.assertion_method.push(Value::String(twin.id.clone()));
                doc.verification_method.push(twin);
            }

            // Map service endpoints.
            for entry in self.service_endpoints.entries() {
                doc.service.push(ServiceEndpoint {
                    id: entry.id,
                    r#type: entry.service_type,
                    endpoint: Value::String(entry.endpoint),
                });
            }

            doc.also_known_as = self.also_known_as.entries().to_vec();

            // Map LWW document data into the extra flat map, refusing anything
            // that would collide with a DID Core property.
            //
            // `extra` is flattened into the same JSON object as the typed
            // fields, and serde does not deduplicate across that boundary — a
            // key of `id` here emits a second `id` member and the consumer's
            // parser decides which one counts. Filtering at projection rather
            // than only at admission is deliberate: state-based merge unions
            // `document_data` wholesale, so a reserved key can enter state
            // without ever passing `merge`'s check.
            for (key, value) in self.document_data.iter() {
                if crate::core::resolve::is_reserved_document_property(key) {
                    continue;
                }
                doc.extra.insert(key.to_owned(), value.clone());
            }

            Some(doc)
        };

        // Compute a content-addressed version identifier from all observable
        // CRDT state.  We avoid calling `to_bytes()` directly because the
        // ORSWOT's internal causal context uses u64 map keys which are
        // incompatible with JSON serialisation.  Instead we hash the safe
        // public projections of each CRDT field.
        let version_id = {
            let vm_entries = self.verification_methods.entries();
            let svc_entries = self.service_endpoints.entries();
            let data_entries: Vec<(&str, &Value)> = self.document_data.iter().collect();
            let content = (
                &self.did.to_string(),
                &vm_entries,
                &svc_entries,
                &data_entries,
                self.also_known_as.entries(),
                self.revocations.entries(),
                self.revoked_verification_methods.entries(),
                self.active_key.current(),
                self.active_key.seq(),
                is_deactivated,
            );
            let bytes = serde_json::to_vec(&content)?;
            blake3::hash(&bytes).to_hex().to_string()
        };

        let did_document_metadata = DidDocumentMetadata {
            deactivated: is_deactivated,
            version_id,
            created: self.created_ms.map(ms_to_iso8601),
            updated: self.updated_ms.map(ms_to_iso8601),
            // Emitted even when the document is deactivated: the identifier is
            // still derived from this key, and a verifier checking a tombstone
            // has the same reason to want the relation as one checking a live
            // document.
            genesis_public_key_multibase: self.genesis_public_key_multibase(),
            // Off unless the caller asked for it with the `includeClosure`
            // resolution option; the handler stamps it. Extracting the whole
            // history on every resolution would make callers who only want the
            // document pay for evidence they never read.
            signed_closure: None,
        };

        Ok(ResolutionResult {
            did_resolution_metadata: DidResolutionMetadata {
                content_type: "application/did+ld+json".to_owned(),
            },
            did_document,
            did_document_metadata,
        })
    }

    // ── hashing ──────────────────────────────────────────────────────────────

    /// Returns `true` if `credential_id` has been revoked on this replica.
    pub fn is_revoked(&self, credential_id: &str) -> bool {
        self.revocations.contains(credential_id)
    }

    /// Returns `true` if the verification method `key_id` has been revoked.
    pub fn is_vm_revoked(&self, key_id: &str) -> bool {
        self.revoked_verification_methods.contains(key_id)
    }

    /// Returns `true` if this document has been deactivated.
    pub fn is_deactivated(&self) -> bool {
        self.deactivated.is_set()
    }

    /// The current frontier of this replica's delta DAG: the content hashes of
    /// the deltas not yet referenced as a parent (SPEC-036 REQ-364).
    ///
    /// A node creating a new delta SHOULD commit to this set as its `parents`
    /// (via [`SignedDelta::new_with_parents`]); it is also the handle for
    /// anti-entropy reconciliation (`core::recon`).
    pub fn frontier(&self) -> Vec<DeltaHash> {
        self.dag.frontier()
    }

    /// The signed deltas this replica holds that a peer advertising
    /// `peer_frontier` is missing (SPEC-036 REQ-366): the responder side of
    /// frontier-exchange reconciliation. Cost is proportional to the divergence,
    /// not the whole history; an empty result means the peer is up to date.
    ///
    /// # Errors
    ///
    /// Propagates [`DeltaDag::deltas_for_peer`] failures.
    pub fn deltas_for_peer(&self, peer_frontier: &[DeltaHash]) -> Result<Vec<SignedDelta>> {
        self.dag.deltas_for_peer(peer_frontier)
    }

    /// The causal predecessors of `delta` that this replica has not yet seen, or
    /// empty if its closure is complete (SPEC-036 REQ-363/366).
    ///
    /// A trust-boundary caller (e.g. the HTTP service) SHOULD consult this
    /// *before* signature verification: a delta signed by a key introduced by a
    /// not-yet-delivered `AddVerificationMethod` is not forgeable but
    /// undecidable — it should be held for retry (returning these hashes to
    /// fetch), not rejected as a bad signature.
    pub fn missing_parents(&self, delta: &SignedDelta) -> Vec<DeltaHash> {
        match verify_causal(delta, &self.dag) {
            AdmissionResult::Unknown(missing) => missing,
            _ => Vec::new(),
        }
    }

    /// Compute the BLAKE3 hash of the **full CRDT state** (not the per-replica
    /// delta log).
    ///
    /// Hashes each CRDT field via its own serialisation, so it captures the
    /// hidden convergence metadata — LWW-Map HLC timestamps, ORSWOT causal
    /// context, Max-Register markers — not just the currently-visible values.
    /// Two states that resolve to the same visible values but would merge
    /// differently (e.g. the same LWW value written at timestamp 10 vs 20)
    /// therefore hash differently, so gossip cannot wrongly dedup and skip a
    /// genuinely-needed sync. It is deterministic (the CRDT serialisers emit
    /// canonically-ordered maps), and independent of the delta log (which
    /// [`Self::to_bytes`] additionally carries).
    pub fn content_hash(&self) -> Result<blake3::Hash> {
        // Serialise each CRDT field in full — these impls include the causal
        // metadata that `entries()` projections drop. `created_ms`/`updated_ms`
        // are included because they are observable in `resolve()`: an op that
        // only advances `updated_ms` (e.g. removing an absent service endpoint)
        // changes the resolved metadata, and without them gossip would dedup the
        // two states and leave peers with divergent resolution metadata.
        let content = (
            &self.did,
            &self.verification_methods,
            &self.service_endpoints,
            &self.document_data,
            &self.active_key,
            &self.revocations,
            &self.revoked_verification_methods,
            &self.deactivated,
            self.created_ms,
            self.updated_ms,
        );
        let bytes = serde_json::to_vec(&content)?;
        Ok(blake3::hash(&bytes))
    }

    /// Return the number of deltas currently in the delta log.
    pub fn delta_count(&self) -> usize {
        self.delta_log.len()
    }

    // ── serialisation ────────────────────────────────────────────────────────

    /// Serialise the full CRDT state to bytes (for storage or transfer).
    ///
    /// Uses compact JSON via `serde_json`.  The format is stable — field names
    /// match the Rust struct fields and will not change without a migration.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(Error::Serialisation)
    }

    /// Deserialise CRDT state from bytes produced by [`Document::to_bytes`].
    ///
    /// Rebuilds the delta DAG (and therefore the frontier) from the serialized
    /// delta log, so a loaded document can admit correctly-parented updates
    /// rather than rejecting them as `DeltaPending` (SPEC-036).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Deserialisation rebuilds the DAG via `DocumentRepr` (see its docs), so
        // every path — here, blob load, and direct serde — restores the frontier.
        serde_json::from_slice(bytes).map_err(Error::Serialisation)
    }

    /// Reconstruct the per-replica delta DAG from [`Self::delta_log`].
    ///
    /// The DAG is derived state (it is not serialized directly), so it is
    /// rebuilt whenever a document is loaded or its log is otherwise restored.
    /// Insertion is order-independent (the frontier converges regardless), so
    /// the log may be replayed in any order.
    pub(crate) fn rebuild_dag(&mut self) {
        self.dag = DeltaDag::new();
        for delta in &self.delta_log {
            // Ignore hash failures: a delta already accepted into the log has a
            // well-formed serialisation, so this cannot fail in practice.
            let _ = self.dag.insert(delta.clone());
        }
    }

    // ── private helpers ──────────────────────────────────────────────────────

    /// Apply a single [`DeltaOp`] to the appropriate CRDT field.
    fn apply_op(
        &mut self,
        op: &DeltaOp,
        timestamp: HlcTimestamp,
        parents: &[DeltaHash],
    ) -> Result<()> {
        // Track the most recent wall-clock timestamp.
        let wall = timestamp.wall_ms;
        match self.updated_ms {
            Some(prev) if wall > prev => self.updated_ms = Some(wall),
            None => self.updated_ms = Some(wall),
            _ => {}
        }

        match op {
            DeltaOp::AddVerificationMethod {
                id,
                public_key_multibase,
                suite_type,
                relationships,
            } => {
                self.verification_methods.insert(
                    id.clone(),
                    public_key_multibase.clone(),
                    suite_type.clone(),
                    relationships.clone(),
                );
            }
            DeltaOp::AddServiceEndpoint {
                id,
                service_type,
                endpoint,
            } => {
                // The add's dot is this delta's own HLC timestamp — stable on
                // every replica because it travels in the signed delta.
                self.service_endpoints.apply_add(
                    ServiceEntry {
                        id: id.clone(),
                        service_type: service_type.clone(),
                        endpoint: endpoint.clone(),
                    },
                    timestamp,
                );
            }
            DeltaOp::RemoveServiceEndpoint { id } => {
                // Observe exactly the adds for `id` in this remove's causal past
                // (↓R) — fixed by the content-addressed parents, so identical on
                // every replica and independent of delivery order. A concurrent
                // add lies outside ↓R and is therefore never cancelled (add
                // wins). At apply time the remove is not yet in the DAG, so ↓R is
                // the closure of its parents.
                let observed: Vec<HlcTimestamp> =
                    self.dag.closure_collect(parents, |d| match &d.op {
                        DeltaOp::AddServiceEndpoint { id: added_id, .. } if added_id == id => {
                            Some(d.timestamp)
                        }
                        _ => None,
                    });
                self.service_endpoints.apply_remove(&observed, timestamp);
            }
            DeltaOp::SetAlsoKnownAs { uris } => {
                self.also_known_as.set(uris.clone(), timestamp);
            }
            DeltaOp::SetDocumentData { key, value } => {
                self.document_data
                    .set(key.clone(), value.clone(), timestamp);
            }
            DeltaOp::RotateKey { seq, key_ref } => {
                self.active_key.rotate(*seq, key_ref.clone());
            }
            DeltaOp::RevokeCredential { credential_id } => {
                self.revocations.insert(credential_id.clone());
            }
            DeltaOp::RevokeVerificationMethod { key_id } => {
                self.revoked_verification_methods.insert(key_id.clone());
            }
            DeltaOp::Deactivate => {
                self.deactivated.set();
            }
        }
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_doc() -> (Document, SignedDelta) {
        Document::new("zEd25519TestKey").expect("new() must succeed")
    }

    // ── new() ─────────────────────────────────────────────────────────────────

    #[test]
    fn new_produces_valid_did() {
        let (doc, delta) = make_doc();
        assert_eq!(doc.did, delta.did);
        assert!(doc.did.as_str().starts_with("did:crdt:"));
        assert_eq!(doc.did.method_specific_id().len(), 64);
    }

    #[test]
    fn new_adds_initial_verification_method() {
        let (doc, _) = make_doc();
        let entries = doc.verification_methods.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].public_key_multibase, "zEd25519TestKey");
        assert!(entries[0].id.ends_with("#key-0"));
    }

    #[test]
    fn new_is_deterministic() {
        let (a, _) = Document::new("zSameKey").unwrap();
        let (b, _) = Document::new("zSameKey").unwrap();
        assert_eq!(a.did, b.did);
    }

    #[test]
    fn new_different_keys_give_different_dids() {
        let (a, _) = Document::new("zKeyA").unwrap();
        let (b, _) = Document::new("zKeyB").unwrap();
        assert_ne!(a.did, b.did);
    }

    #[test]
    fn did_derivation_is_pinned_to_known_vectors() {
        // The derivation is the most consequential constant in the method: if
        // it changes, every DID already issued becomes unresolvable, and every
        // signature chained to one stops verifying. Nothing else in the suite
        // pins it — the other tests assert relations between DIDs (distinct
        // keys differ, round-trips agree), all of which hold just as well
        // AFTER a change to the hash input. So a refactor could silently
        // reissue every identifier in the world and the suite would stay green.
        //
        // These vectors were captured from the implementation as it stood at
        // c59fd24, before `derive_did` was extracted, and confirmed identical
        // after. Changing them is not a test fix — it is a breaking change to
        // the method, and needs a migration story before the numbers move.
        for (key, expected) in [
            (
                "zEd25519TestKey",
                "did:crdt:a9baa8e5775077f7c22e671167a641bab4498c7e06e7dd7d92c43b83656504db",
            ),
            (
                "zAnotherKey",
                "did:crdt:bb2800f268648cc3abe559bcab94edcedcfa68ef7d462304e9920316c4c81f6b",
            ),
            // The empty key is not a valid input, but it is a valid probe of
            // the encoding: it pins the framing around a zero-length field.
            (
                "",
                "did:crdt:cc650842519c330619c244a36d0530dab5eee84bd785a00c7b989121ba2f6d06",
            ),
        ] {
            assert_eq!(
                Document::new(key).unwrap().0.did.as_str(),
                expected,
                "DID derivation changed for {key:?} — see the note above before touching this"
            );
            // The standalone entry point must agree with creation, or a
            // verifier recomputing would disagree with the issuer.
            assert_eq!(derive_did(key).unwrap().as_str(), expected);
        }
    }

    // ── merge() ───────────────────────────────────────────────────────────────

    fn signed_delta(doc: &Document, op: DeltaOp, signer: &str) -> SignedDelta {
        let ts = HlcTimestamp {
            wall_ms: 1_000,
            logical: 0,
            node_id: 1,
        };
        // Commit to the current frontier so the delta is causally grounded
        // (SPEC-036). Unsigned deltas are not signature-checked by merge, so we
        // set `parents` directly. Re-stamp with a fresh frontier each call.
        let mut d = SignedDelta::unsigned(doc.did.clone(), op, ts, signer.to_owned());
        d.parents = doc.frontier();
        d
    }

    /// Build a frontier-grounded unsigned delta with an explicit timestamp and
    /// merge it. The DAG-era replacement for `doc.merge(SignedDelta::unsigned(..))`.
    fn merge_op(doc: &mut Document, op: DeltaOp, ts: HlcTimestamp, signer: &str) -> Result<()> {
        let mut d = SignedDelta::unsigned(doc.did.clone(), op, ts, signer.to_owned());
        d.parents = doc.frontier();
        doc.merge(d)
    }

    #[test]
    fn merge_add_service_endpoint() {
        let (mut doc, _) = make_doc();
        let signer = doc.verification_methods.entries()[0].id.clone();
        let delta = signed_delta(
            &doc,
            DeltaOp::AddServiceEndpoint {
                id: format!("{}#svc-1", doc.did),
                service_type: "LinkedDomains".to_owned(),
                endpoint: "https://example.com".to_owned(),
            },
            &signer,
        );
        doc.merge(delta).expect("merge must succeed");
        assert!(doc
            .service_endpoints
            .contains_id(&format!("{}#svc-1", doc.did)));
    }

    #[test]
    fn document_dag_frontier_advances_with_parents() {
        use crate::core::delta::SigningKey;
        use ed25519_dalek::SigningKey as DalekKey;

        let (mut doc, genesis) = make_doc();
        // Genesis is the sole frontier member after creation.
        let gh = genesis.content_hash().unwrap();
        assert_eq!(doc.frontier(), vec![gh.clone()]);

        // A delta committing to the current frontier (proper DAG usage, REQ-361)
        // advances the frontier: the child replaces its parent.
        let signer = doc.verification_methods.entries()[0].id.clone();
        let key = SigningKey::Ed25519(DalekKey::from_bytes(&[9u8; 32]));
        let ts = HlcTimestamp {
            wall_ms: 2_000,
            logical: 0,
            node_id: 1,
        };
        let delta = SignedDelta::new_with_parents(
            doc.did.clone(),
            DeltaOp::RevokeCredential {
                credential_id: "c1".to_owned(),
            },
            ts,
            doc.frontier(),
            signer,
            &key,
        )
        .unwrap();
        let dh = delta.content_hash().unwrap();
        doc.merge(delta).expect("merge must succeed");

        assert_eq!(
            doc.frontier(),
            vec![dh],
            "child must replace genesis at the frontier"
        );
    }

    #[test]
    fn from_bytes_rebuilds_dag_and_accepts_updates() {
        // Regression: a persisted/synced document must keep a usable frontier so
        // it can admit correctly-parented updates (SPEC-036).
        let (mut doc, _) = make_doc();
        let signer = doc.verification_methods.entries()[0].id.clone();
        let ts = HlcTimestamp {
            wall_ms: 5,
            logical: 0,
            node_id: 1,
        };
        merge_op(
            &mut doc,
            DeltaOp::RevokeCredential {
                credential_id: "c1".to_owned(),
            },
            ts,
            &signer,
        )
        .unwrap();
        let frontier_before = doc.frontier();
        assert_eq!(
            frontier_before.len(),
            1,
            "non-trivial frontier after a mutation"
        );

        // Round-trip through to_bytes/from_bytes.
        let bytes = doc.to_bytes().unwrap();
        let mut reloaded = Document::from_bytes(&bytes).unwrap();
        assert_eq!(
            reloaded.frontier(),
            frontier_before,
            "frontier must survive serialization round-trip"
        );

        // A correctly-parented update on the reloaded doc must be accepted, not
        // rejected as DeltaPending.
        let ts2 = HlcTimestamp {
            wall_ms: 6,
            logical: 0,
            node_id: 1,
        };
        merge_op(
            &mut reloaded,
            DeltaOp::RevokeCredential {
                credential_id: "c2".to_owned(),
            },
            ts2,
            &signer,
        )
        .expect("reloaded document must accept a parented update");
    }

    #[test]
    fn merge_rejects_non_canonical_parents() {
        // Inbound deltas must carry a sorted, deduplicated parent set (REQ-361),
        // else the same causal parents could mint multiple identities / leaves.
        let (mut doc, _) = make_doc();
        let signer = doc.verification_methods.entries()[0].id.clone();
        let g = doc.frontier()[0].clone();
        let mut d = SignedDelta::unsigned(
            doc.did.clone(),
            DeltaOp::RevokeCredential {
                credential_id: "c".to_owned(),
            },
            HlcTimestamp {
                wall_ms: 5,
                logical: 0,
                node_id: 1,
            },
            signer,
        );
        d.parents = vec![g.clone(), g]; // duplicate → non-canonical
        assert!(
            matches!(doc.merge(d), Err(Error::DeltaRejected(_))),
            "non-canonical (duplicate) parents must be rejected"
        );
    }
    #[test]
    fn state_sync_imports_revocation_and_addition_safely() {
        // After merge_state imports facts (without the originating deltas),
        // current-state authorisation must (a) reject an imported-revoked signer
        // and (b) accept an imported-added key.
        let (mut a, _) = make_doc();
        let key0 = a.verification_methods.entries()[0].id.clone();
        let key1 = format!("{}#key-1", a.did);
        merge_op(
            &mut a,
            DeltaOp::AddVerificationMethod {
                id: key1.clone(),
                public_key_multibase: "zKey1".to_owned(),
                suite_type: SuiteType::default(),
                relationships: crate::core::delta::default_relationships(),
            },
            HlcTimestamp {
                wall_ms: 10,
                logical: 0,
                node_id: 1,
            },
            &key0,
        )
        .unwrap();
        merge_op(
            &mut a,
            DeltaOp::RevokeVerificationMethod {
                key_id: key0.clone(),
            },
            HlcTimestamp {
                wall_ms: 20,
                logical: 0,
                node_id: 1,
            },
            &key1,
        )
        .unwrap();

        // Fresh replica B imports A's state (no DAG transfer).
        let (mut b, _) = make_doc();
        b.merge_state(a).unwrap();

        // (a) imported-revoked key0 is rejected.
        let revoked = merge_op(
            &mut b,
            DeltaOp::RevokeCredential {
                credential_id: "y".to_owned(),
            },
            HlcTimestamp {
                wall_ms: 30,
                logical: 0,
                node_id: 1,
            },
            &key0,
        );
        assert!(revoked.is_err(), "imported-revoked signer must be rejected");

        // (b) imported-added key1 is accepted (not over-rejected for an absent
        // DAG entry).
        let added = merge_op(
            &mut b,
            DeltaOp::RevokeCredential {
                credential_id: "z".to_owned(),
            },
            HlcTimestamp {
                wall_ms: 40,
                logical: 0,
                node_id: 1,
            },
            &key1,
        );
        assert!(added.is_ok(), "imported-added signer must be accepted");
    }
    #[test]
    fn duplicate_delivery_is_a_true_noop() {
        let (mut doc, _) = make_doc();
        let signer = doc.verification_methods.entries()[0].id.clone();
        let svc_id = format!("{}#svc", doc.did);
        let mut d = SignedDelta::unsigned(
            doc.did.clone(),
            DeltaOp::AddServiceEndpoint {
                id: svc_id,
                service_type: "LinkedDomains".to_owned(),
                endpoint: "https://e.example.com".to_owned(),
            },
            HlcTimestamp {
                wall_ms: 5,
                logical: 0,
                node_id: 1,
            },
            signer,
        );
        d.parents = doc.frontier();
        doc.merge(d.clone()).unwrap();
        let hash1 = doc.content_hash().unwrap();
        let count1 = doc.delta_count();

        // Re-deliver the identical delta — must be a true no-op (no fresh ORSWOT
        // dot, no state/hash/log change).
        doc.merge(d).unwrap();
        assert_eq!(
            doc.content_hash().unwrap(),
            hash1,
            "duplicate must not change state"
        );
        assert_eq!(doc.delta_count(), count1, "duplicate must not grow the log");
    }
    #[test]
    fn deserialize_via_serde_rebuilds_frontier() {
        // Direct serde deserialisation (e.g. a blob-store load), not
        // from_bytes, must still yield a usable frontier.
        let (mut doc, _) = make_doc();
        let signer = doc.verification_methods.entries()[0].id.clone();
        merge_op(
            &mut doc,
            DeltaOp::RevokeCredential {
                credential_id: "c".to_owned(),
            },
            HlcTimestamp {
                wall_ms: 5,
                logical: 0,
                node_id: 1,
            },
            &signer,
        )
        .unwrap();
        let expected = doc.frontier();

        let value = serde_json::to_value(&doc).unwrap();
        let restored: Document = serde_json::from_value(value).unwrap();
        assert_eq!(
            restored.frontier(),
            expected,
            "direct serde must rebuild the DAG/frontier"
        );
    }

    #[test]
    fn merge_rejects_wrong_did() {
        let (mut doc, _) = make_doc();
        let (other, _) = Document::new("zDifferentKey").unwrap();
        let signer = doc.verification_methods.entries()[0].id.clone();
        let mut delta = signed_delta(&doc, DeltaOp::Deactivate, &signer);
        delta.did = other.did.clone();
        assert!(doc.merge(delta).is_err());
    }

    #[test]
    fn merge_rejects_unknown_signer() {
        let (mut doc, _) = make_doc();
        let delta = signed_delta(&doc, DeltaOp::Deactivate, "zUnknownKey");
        assert!(doc.merge(delta).is_err());
    }

    // ── Genesis op restriction (FINDING-002, defense-in-depth) ────────────────

    fn empty_doc(did_from: &Document) -> Document {
        Document {
            did: did_from.did.clone(),
            verification_methods: crate::core::crdt::VerificationMethods::new(),
            service_endpoints: crate::core::crdt::ServiceEndpoints::new(),
            document_data: crate::core::crdt::DocumentData::new(),
            also_known_as: crate::core::crdt::AlsoKnownAs::new(),
            active_key: crate::core::crdt::ActiveKey::new(),
            revocations: crate::core::crdt::Revocations::new(),
            revoked_verification_methods: crate::core::crdt::RevokedVerificationMethods::new(),
            deactivated: crate::core::crdt::Deactivated::new(),
            created_ms: None,
            updated_ms: None,
            delta_log: Vec::new(),
            dag: crate::core::dag::DeltaDag::new(),
        }
    }

    #[test]
    fn merge_genesis_rejects_deactivate() {
        let (ref_doc, _) = make_doc();
        let mut empty = empty_doc(&ref_doc);
        let signer = format!("{}#ghost-key", ref_doc.did);
        let delta = signed_delta(&empty, DeltaOp::Deactivate, &signer);
        assert!(
            empty.merge(delta).is_err(),
            "genesis document must reject Deactivate"
        );
    }

    #[test]
    fn merge_genesis_rejects_rotate_key() {
        let (ref_doc, _) = make_doc();
        let mut empty = empty_doc(&ref_doc);
        let signer = format!("{}#ghost-key", ref_doc.did);
        let delta = signed_delta(
            &empty,
            DeltaOp::RotateKey {
                seq: 1,
                key_ref: signer.clone(),
            },
            &signer,
        );
        assert!(
            empty.merge(delta).is_err(),
            "genesis document must reject RotateKey"
        );
    }

    #[test]
    fn merge_deactivate_then_reject_further_ops() {
        let (mut doc, _) = make_doc();
        let signer = doc.verification_methods.entries()[0].id.clone();

        let deactivate = signed_delta(&doc, DeltaOp::Deactivate, &signer);
        doc.merge(deactivate).expect("deactivate must succeed");

        let follow_up = signed_delta(
            &doc,
            DeltaOp::AddVerificationMethod {
                id: format!("{}#key-1", doc.did),
                public_key_multibase: "zAnotherKey".to_owned(),
                suite_type: SuiteType::default(),
                relationships: crate::core::delta::default_relationships(),
            },
            &signer,
        );
        assert!(
            doc.merge(follow_up).is_err(),
            "ops after deactivation must be rejected"
        );
    }

    // ── merge_state() ─────────────────────────────────────────────────────────

    #[test]
    fn merge_state_union_of_fields() {
        let (mut a, _) = Document::new("zKeyA").unwrap();
        let mut b = a.clone();

        // A adds a service, B rotates the key.
        let ts_a = HlcTimestamp {
            wall_ms: 10,
            logical: 0,
            node_id: 1,
        };
        let signer = a.verification_methods.entries()[0].id.clone();
        let svc_id = format!("{}#svc-1", a.did);
        merge_op(
            &mut a,
            DeltaOp::AddServiceEndpoint {
                id: svc_id,
                service_type: "LinkedDomains".to_owned(),
                endpoint: "https://example.com".to_owned(),
            },
            ts_a,
            &signer,
        )
        .unwrap();

        let ts_b = HlcTimestamp {
            wall_ms: 10,
            logical: 0,
            node_id: 2,
        };
        let key_ref = format!("{}#key-0", b.did);
        merge_op(
            &mut b,
            DeltaOp::RotateKey { seq: 1, key_ref },
            ts_b,
            &signer,
        )
        .unwrap();

        a.merge_state(b).unwrap();
        assert!(a.service_endpoints.contains_id(&format!("{}#svc-1", a.did)));
        assert_eq!(a.active_key.seq(), 1);
    }

    #[test]
    fn merge_state_rejects_different_dids() {
        let (mut a, _) = Document::new("zKeyA").unwrap();
        let (b, _) = Document::new("zKeyB").unwrap();
        assert!(a.merge_state(b).is_err());
    }

    #[test]
    fn merge_state_idempotent() {
        let (mut a, _) = Document::new("zKeyA").unwrap();
        let snapshot = a.clone();
        a.merge_state(snapshot).unwrap();
        assert_eq!(a.verification_methods.entries().len(), 1);
    }

    // ── resolve() ─────────────────────────────────────────────────────────────

    #[test]
    fn resolve_returns_resolution_result_with_three_parts() {
        let (doc, _) = make_doc();
        let result = doc.resolve().unwrap();
        assert!(result.did_document.is_some());
        assert_eq!(
            result.did_resolution_metadata.content_type,
            "application/did+ld+json"
        );
    }

    #[test]
    fn resolve_contains_did_and_context() {
        let (doc, _) = make_doc();
        let result = doc.resolve().unwrap();
        let resolved = result.did_document.unwrap();
        assert_eq!(resolved.id, doc.did.to_string());
        assert!(!resolved.context.is_empty());
    }

    #[test]
    fn resolve_verification_methods_present() {
        let (doc, _) = make_doc();
        let result = doc.resolve().unwrap();
        let resolved = result.did_document.unwrap();
        assert_eq!(resolved.verification_method.len(), 1);
        assert_eq!(
            resolved.verification_method[0]
                .public_key_multibase
                .as_deref(),
            Some("zEd25519TestKey")
        );
        assert_eq!(
            resolved.verification_method[0].r#type,
            "Ed25519VerificationKey2020"
        );
        assert_eq!(resolved.authentication.len(), 1);
    }

    #[test]
    fn resolve_deactivated_returns_null_document() {
        let (mut doc, _) = make_doc();
        let signer = doc.verification_methods.entries()[0].id.clone();
        let ts = HlcTimestamp {
            wall_ms: 1,
            logical: 0,
            node_id: 0,
        };
        merge_op(&mut doc, DeltaOp::Deactivate, ts, &signer).unwrap();
        let result = doc.resolve().unwrap();
        assert!(result.did_document_metadata.deactivated);
        assert!(
            result.did_document.is_none(),
            "deactivated DID must have null document"
        );
    }

    #[test]
    fn resolve_version_id_is_hex_string() {
        let (doc, _) = make_doc();
        let result = doc.resolve().unwrap();
        let version_id = &result.did_document_metadata.version_id;
        // BLAKE3 hex output is always 64 hex characters.
        assert_eq!(version_id.len(), 64);
        assert!(version_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn resolve_version_id_changes_after_mutation() {
        let (mut doc, _) = make_doc();
        let before = doc.resolve().unwrap().did_document_metadata.version_id;

        let signer = doc.verification_methods.entries()[0].id.clone();
        let ts = HlcTimestamp {
            wall_ms: 500,
            logical: 0,
            node_id: 1,
        };
        let mut delta = SignedDelta::unsigned(
            doc.did.clone(),
            DeltaOp::RevokeCredential {
                credential_id: "cred-abc".to_owned(),
            },
            ts,
            signer,
        );
        delta.parents = doc.frontier();
        doc.merge(delta).unwrap();

        let after = doc.resolve().unwrap().did_document_metadata.version_id;
        assert_ne!(before, after);
    }

    #[test]
    fn resolve_created_and_updated_timestamps() {
        let (doc, _) = make_doc();
        let result = doc.resolve().unwrap();
        // Genesis has wall_ms=0, so created and updated should be epoch.
        assert_eq!(
            result.did_document_metadata.created,
            Some("1970-01-01T00:00:00.000Z".to_owned())
        );
        assert_eq!(
            result.did_document_metadata.updated,
            Some("1970-01-01T00:00:00.000Z".to_owned())
        );
    }

    #[test]
    fn resolve_updated_advances_after_mutation() {
        let (mut doc, _) = make_doc();
        let signer = doc.verification_methods.entries()[0].id.clone();
        let ts = HlcTimestamp {
            wall_ms: 5000,
            logical: 0,
            node_id: 1,
        };
        let mut delta = SignedDelta::unsigned(
            doc.did.clone(),
            DeltaOp::RevokeCredential {
                credential_id: "cred-x".to_owned(),
            },
            ts,
            signer,
        );
        delta.parents = doc.frontier();
        doc.merge(delta).unwrap();
        let result = doc.resolve().unwrap();
        assert_eq!(
            result.did_document_metadata.created,
            Some("1970-01-01T00:00:00.000Z".to_owned())
        );
        assert_ne!(
            result.did_document_metadata.updated,
            result.did_document_metadata.created
        );
    }

    // ── content_hash() ────────────────────────────────────────────────────────

    #[test]
    fn content_hash_is_deterministic() {
        let (doc, _) = make_doc();
        let h1 = doc.content_hash().unwrap();
        let h2 = doc.content_hash().unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn content_hash_changes_on_mutation() {
        let (mut doc, _) = make_doc();
        let before = doc.content_hash().unwrap();

        let signer = doc.verification_methods.entries()[0].id.clone();
        let ts = HlcTimestamp {
            wall_ms: 500,
            logical: 0,
            node_id: 1,
        };
        let mut delta = SignedDelta::unsigned(
            doc.did.clone(),
            DeltaOp::RevokeCredential {
                credential_id: "cred-999".to_owned(),
            },
            ts,
            signer,
        );
        delta.parents = doc.frontier();
        doc.merge(delta).unwrap();

        let after = doc.content_hash().unwrap();
        assert_ne!(before, after);
    }

    // ── to_bytes / from_bytes ─────────────────────────────────────────────────

    #[test]
    fn serde_roundtrip() {
        let (doc, _) = make_doc();
        let bytes = doc.to_bytes().unwrap();
        let recovered = Document::from_bytes(&bytes).unwrap();
        assert_eq!(doc.did, recovered.did);
        assert_eq!(
            doc.verification_methods.entries(),
            recovered.verification_methods.entries()
        );
    }

    #[test]
    fn serde_roundtrip_with_service_endpoints() {
        let (mut doc, _) = make_doc();
        let signer = doc.verification_methods.entries()[0].id.clone();
        let delta = signed_delta(
            &doc,
            DeltaOp::AddServiceEndpoint {
                id: format!("{}#svc-1", doc.did),
                service_type: "LinkedDomains".to_owned(),
                endpoint: "https://example.com".to_owned(),
            },
            &signer,
        );
        doc.merge(delta).expect("merge must succeed");
        assert!(doc
            .service_endpoints
            .contains_id(&format!("{}#svc-1", doc.did)));

        let bytes = doc
            .to_bytes()
            .expect("to_bytes must succeed with ORSWOT entries");
        let recovered = Document::from_bytes(&bytes).expect("from_bytes must succeed");
        assert_eq!(doc.did, recovered.did);
        assert_eq!(
            doc.service_endpoints.entries(),
            recovered.service_endpoints.entries()
        );
    }

    #[test]
    fn from_bytes_rejects_garbage() {
        assert!(Document::from_bytes(b"not json at all!").is_err());
    }

    // ── 2P-Set verification method revocation ────────────────────────────────

    // ── delta size limit (ADR-004) ────────────────────────────────────────────

    #[test]
    fn merge_rejects_oversized_delta() {
        let (mut doc, _) = make_doc();
        let signer = doc.verification_methods.entries()[0].id.clone();
        // Build a delta with a ~70 KB payload to exceed the 64 KiB limit.
        let big_value = "x".repeat(70_000);
        let op = DeltaOp::SetDocumentData {
            key: "big".to_owned(),
            value: serde_json::Value::String(big_value),
        };
        let ts = HlcTimestamp {
            wall_ms: 100,
            logical: 0,
            node_id: 1,
        };
        let delta = SignedDelta::unsigned(doc.did.clone(), op, ts, signer);
        let err = doc.merge(delta).unwrap_err();
        assert!(
            matches!(err, Error::DeltaTooLarge { .. }),
            "expected DeltaTooLarge, got: {err:?}"
        );
    }

    #[test]
    fn merge_accepts_delta_just_under_limit() {
        let (mut doc, _) = make_doc();
        let signer = doc.verification_methods.entries()[0].id.clone();
        // Build a delta that is close to but under 64 KiB.  The envelope
        // (DID, timestamp, proof, JSON structure) consumes some bytes, so we
        // pick a payload size that keeps the total under 65 536.
        let payload_size = 60_000; // comfortably under 64 KiB with envelope overhead
        let value = "y".repeat(payload_size);
        let op = DeltaOp::SetDocumentData {
            key: "ok".to_owned(),
            value: serde_json::Value::String(value),
        };
        let ts = HlcTimestamp {
            wall_ms: 200,
            logical: 0,
            node_id: 1,
        };
        merge_op(&mut doc, op, ts, &signer).expect("delta under 64 KiB should be accepted");
    }

    // ── closure bundle (the includeClosure resolution option) ─────────────────

    /// A real Ed25519-backed document. Unsigned test deltas cannot be replayed:
    /// `verify_signature` permits an empty proof only at genesis, which is
    /// exactly the property a replay-based verifier depends on.
    fn signed_doc() -> (Document, crate::core::delta::SigningKey, String) {
        use base64ct::{Base64UrlUnpadded, Encoding as _};
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let pk_mb = format!(
            "u{}",
            Base64UrlUnpadded::encode_string(sk.verifying_key().as_bytes())
        );
        let (doc, _) = Document::new(&pk_mb).unwrap();
        let key_id = doc.verification_methods.entries()[0].id.clone();
        (doc, crate::core::delta::SigningKey::Ed25519(sk), key_id)
    }

    fn node_id_of(key: &crate::core::delta::SigningKey) -> u64 {
        match key {
            crate::core::delta::SigningKey::Ed25519(sk) => {
                crate::core::validate::node_id_from_pubkey(sk.verifying_key().as_bytes())
            }
            _ => unreachable!("tests use Ed25519"),
        }
    }

    /// Replay a bundle the way selfsame's verifier does: bootstrap from the
    /// genesis root key — which recomputes the self-certifying DID — and merge.
    /// Nothing here deserialises a projected document.
    fn replay(bundle: ClosureBundle, expected: &Document) {
        let root = bundle
            .deltas
            .iter()
            .find(|d| d.parents.is_empty())
            .expect("a closure has exactly one genesis delta");
        let DeltaOp::AddVerificationMethod {
            public_key_multibase,
            ..
        } = &root.op
        else {
            panic!("genesis must add a verification method")
        };
        let (mut replayed, _) = Document::new(public_key_multibase).unwrap();
        assert_eq!(
            replayed.did, expected.did,
            "genesis must derive the same DID"
        );
        replayed.merge_verified_bundle(bundle).unwrap();
        assert_eq!(
            replayed.content_hash().unwrap(),
            expected.content_hash().unwrap()
        );
    }

    #[test]
    fn closure_bundle_replays_to_the_same_document() {
        // The property that matters: a verifier who takes ONLY the bundle, and
        // trusts none of the projection, reaches the state we would have served.
        let (mut doc, sk, key_id) = signed_doc();
        let delta = SignedDelta::new_with_parents(
            doc.did.clone(),
            DeltaOp::SetAlsoKnownAs {
                uris: vec!["acct:hugo@chat.anuna.io".to_owned()],
            },
            HlcTimestamp {
                wall_ms: 10,
                logical: 0,
                node_id: node_id_of(&sk),
            },
            doc.dag.frontier(),
            key_id,
            &sk,
        )
        .unwrap();
        doc.merge(delta).unwrap();

        let bundle = doc.closure_bundle().unwrap();
        assert!(
            bundle
                .deltas
                .iter()
                .any(|d| d.content_hash().unwrap() == bundle.target),
            "the target must be present in its own bundle, or a replay refuses it"
        );
        replay(bundle, &doc);
    }

    #[test]
    fn closure_bundle_carries_every_head_not_just_the_target() {
        // With concurrent heads, the target's ancestry alone omits the other
        // branch. A verifier replaying that would materialise a document missing
        // whatever only the other branch carries — a revocation, say — and would
        // have no way to tell. This is the case a single extract_closure(target)
        // gets wrong, and the reason closure_bundle unions every head.
        let (mut doc, sk, key_id) = signed_doc();
        let genesis_head = doc.dag.frontier();

        for i in [1u64, 2] {
            let delta = SignedDelta::new_with_parents(
                doc.did.clone(),
                DeltaOp::SetDocumentData {
                    key: format!("branch{i}"),
                    value: serde_json::json!(i),
                },
                HlcTimestamp {
                    wall_ms: 9 + i,
                    logical: 0,
                    node_id: node_id_of(&sk),
                },
                genesis_head.clone(),
                key_id.clone(),
                &sk,
            )
            .unwrap();
            doc.merge(delta).unwrap();
        }
        assert_eq!(doc.dag.frontier().len(), 2, "premise: two concurrent heads");

        let bundle = doc.closure_bundle().unwrap();
        assert_eq!(bundle.deltas.len(), 3, "genesis plus both branches");
        replay(bundle, &doc);
    }

    #[test]
    fn closure_bundle_is_deterministic_across_replicas() {
        // `target` names one head; two replicas holding the same state must
        // name the same one, or a caller comparing two resolvers sees a
        // difference that is not one.
        let (mut a, _) = make_doc();
        let (mut b, _) = make_doc();
        for doc in [&mut a, &mut b] {
            let signer = doc.verification_methods.entries()[0].id.clone();
            merge_op(
                doc,
                DeltaOp::SetAlsoKnownAs {
                    uris: vec!["acct:hugo@chat.anuna.io".to_owned()],
                },
                HlcTimestamp {
                    wall_ms: 10,
                    logical: 0,
                    node_id: 1,
                },
                &signer,
            )
            .unwrap();
        }
        assert_eq!(
            a.closure_bundle().unwrap().target,
            b.closure_bundle().unwrap().target
        );
    }

    #[test]
    fn resolve_omits_the_closure_unless_asked() {
        // Off by default: the option is what turns it on, and the property must
        // be absent rather than null so a caller cannot read an omission as an
        // established empty history.
        let (doc, _) = make_doc();
        let result = doc.resolve().unwrap();
        assert!(result.did_document_metadata.signed_closure.is_none());
        let json: Value =
            serde_json::from_str(&serde_json::to_string(&result.did_document_metadata).unwrap())
                .unwrap();
        assert!(json.get("signedClosure").is_none());
    }

    // ── alsoKnownAs ───────────────────────────────────────────────────────────

    fn set_aka(doc: &mut Document, uris: &[&str], ms: u64) -> Result<()> {
        let signer = doc.verification_methods.entries()[0].id.clone();
        merge_op(
            doc,
            DeltaOp::SetAlsoKnownAs {
                uris: uris.iter().map(|s| (*s).to_owned()).collect(),
            },
            HlcTimestamp {
                wall_ms: ms,
                logical: 0,
                node_id: 1,
            },
            &signer,
        )
    }

    #[test]
    fn also_known_as_projects_as_a_typed_property() {
        let (mut doc, _) = make_doc();
        set_aka(&mut doc, &["acct:hugo@chat.anuna.io"], 10).unwrap();

        let served = doc.resolve().unwrap().did_document.unwrap();
        assert_eq!(served.also_known_as, vec!["acct:hugo@chat.anuna.io"]);

        // Exactly one member, unlike the documentData passthrough this replaced.
        let text = serde_json::to_string(&served).unwrap();
        assert_eq!(text.matches("\"alsoKnownAs\":").count(), 1);
        let reparsed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            reparsed["alsoKnownAs"],
            serde_json::json!(["acct:hugo@chat.anuna.io"])
        );
    }

    #[test]
    fn absent_when_empty_rather_than_an_empty_array() {
        let (doc, _) = make_doc();
        let served = doc.resolve().unwrap().did_document.unwrap();
        let reparsed: Value =
            serde_json::from_str(&serde_json::to_string(&served).unwrap()).unwrap();
        assert!(reparsed.get("alsoKnownAs").is_none());
    }

    #[test]
    fn a_withdrawn_alias_can_be_reinstated() {
        // The reason this is an LWW register over the whole set rather than the
        // 2P-Set used for keys. cbcl-bus's WebFinger store can reinstate a
        // withdrawn alias; if the holder's half could not, a binding either side
        // withdrew would be permanently unrestorable from one end only.
        let (mut doc, _) = make_doc();
        let alias = "acct:hugo@chat.anuna.io";

        set_aka(&mut doc, &[alias], 10).unwrap();
        set_aka(&mut doc, &[], 20).unwrap();
        assert!(doc.also_known_as.entries().is_empty(), "withdrawn");

        set_aka(&mut doc, &[alias], 30).unwrap();
        assert_eq!(doc.also_known_as.entries(), [alias], "reinstated");
    }

    #[test]
    fn a_stale_write_does_not_resurrect_a_withdrawn_alias() {
        // LWW is only safe here if an out-of-order delivery loses. A withdrawal
        // that could be undone by a delta that merely arrived later would make
        // withdrawal unreliable, which is the half of the binding that matters.
        let (mut doc, _) = make_doc();
        set_aka(&mut doc, &["acct:hugo@chat.anuna.io"], 20).unwrap();
        set_aka(&mut doc, &[], 30).unwrap();

        set_aka(&mut doc, &["acct:hugo@chat.anuna.io"], 10).unwrap();
        assert!(
            doc.also_known_as.entries().is_empty(),
            "a delta older than the withdrawal must not reinstate the alias"
        );
    }

    #[test]
    fn the_set_is_canonicalised_so_replicas_agree() {
        // Two replicas writing the same aliases in different order must reach
        // identical state, or versionId would differ between replicas that agree.
        let (mut a, _) = make_doc();
        let (mut b, _) = make_doc();
        set_aka(&mut a, &["did:crdt:zzz", "acct:hugo@chat.anuna.io"], 10).unwrap();
        set_aka(
            &mut b,
            &["acct:hugo@chat.anuna.io", "did:crdt:zzz", "did:crdt:zzz"],
            10,
        )
        .unwrap();

        assert_eq!(a.also_known_as.entries(), b.also_known_as.entries());
        assert_eq!(a.content_hash().unwrap(), b.content_hash().unwrap());
    }

    #[test]
    fn changing_aliases_moves_the_version_id() {
        // The alias set is observable state, so it must be inside the content
        // hash. If it were not, a consumer caching on versionId would never see
        // an alias withdrawal.
        let (mut doc, _) = make_doc();
        let before = doc.resolve().unwrap().did_document_metadata.version_id;
        set_aka(&mut doc, &["acct:hugo@chat.anuna.io"], 10).unwrap();
        let after = doc.resolve().unwrap().did_document_metadata.version_id;
        assert_ne!(before, after);
    }

    #[test]
    fn malformed_aliases_are_refused_at_admission() {
        let (mut doc, _) = make_doc();
        for (uri, why) in [
            ("", "empty"),
            (
                "hugo@chat.anuna.io",
                "no scheme — a bare handle is not a URI",
            ),
            ("/relative/path", "relative reference has no base here"),
            ("1nvalid:x", "scheme must start with a letter"),
            ("acct:", "empty body"),
            ("acct:hugo chat", "space"),
            ("acct:hugo\u{7f}x", "DEL is not printable"),
            ("acct:hugo\nx", "control character"),
        ] {
            assert!(
                set_aka(&mut doc, &[uri], 10).is_err(),
                "{uri:?} must be refused ({why})"
            );
        }
        // And the whole delta is refused, not just the offending entry.
        assert!(set_aka(&mut doc, &["acct:ok@x.io", "no-scheme"], 10).is_err());
        assert!(doc.also_known_as.entries().is_empty());
    }

    #[test]
    fn well_formed_aliases_are_admitted() {
        // The refusal test above is only meaningful if the forms the binding
        // actually uses pass.
        let (mut doc, _) = make_doc();
        set_aka(
            &mut doc,
            &[
                "acct:hugo@chat.anuna.io",
                "https://chat.anuna.io/u/hugo",
                "did:crdt:a9baa8e5",
            ],
            10,
        )
        .unwrap();
        assert_eq!(doc.also_known_as.entries().len(), 3);
    }

    #[test]
    fn an_oversized_alias_set_is_refused() {
        let (mut doc, _) = make_doc();
        let many: Vec<String> = (0..=crate::core::validate::MAX_ALSO_KNOWN_AS)
            .map(|i| format!("acct:user{i}@x.io"))
            .collect();
        let refs: Vec<&str> = many.iter().map(|s| s.as_str()).collect();
        assert!(set_aka(&mut doc, &refs, 10).is_err());

        let long = format!("acct:{}@x.io", "a".repeat(600));
        assert!(set_aka(&mut doc, &[&long], 10).is_err());
    }

    // ── documentData must not shadow DID Core properties ──────────────────────
    #[test]
    fn reserved_document_data_key_is_refused_at_admission() {
        let (mut doc, _) = make_doc();
        let signer = doc.verification_methods.entries()[0].id.clone();
        for key in crate::core::resolve::RESERVED_DOCUMENT_PROPERTIES {
            let err = merge_op(
                &mut doc,
                DeltaOp::SetDocumentData {
                    key: (*key).to_owned(),
                    value: serde_json::json!("anything"),
                },
                HlcTimestamp {
                    wall_ms: 10,
                    logical: 0,
                    node_id: 1,
                },
                &signer,
            );
            assert!(
                matches!(err, Err(Error::DeltaRejected(_))),
                "{key} must be refused as a documentData key"
            );
        }
    }

    #[test]
    fn state_borne_reserved_key_cannot_shadow_id() {
        // Admission alone is not enough: state-based merge unions
        // `document_data` wholesale, so a peer running older code — or a
        // hostile one — can seat a reserved key without passing `merge`.
        // Inserted directly here for exactly that reason.
        let (mut doc, _) = make_doc();
        let real_did = doc.did.clone();
        doc.document_data.set(
            "id".to_owned(),
            serde_json::json!("did:crdt:ATTACKER"),
            HlcTimestamp {
                wall_ms: 99,
                logical: 0,
                node_id: 1,
            },
        );

        let json_text =
            serde_json::to_string(&doc.resolve().unwrap().did_document.unwrap()).unwrap();
        // Reparse rather than inspect the struct: the defect only exists once
        // the document is serialised, and it is the consumer's parse that
        // decides which member wins.
        let reparsed: Value = serde_json::from_str(&json_text).unwrap();
        assert_eq!(
            reparsed["id"],
            serde_json::json!(real_did.as_str()),
            "documentData must not be able to restate the document's own id"
        );
        assert_eq!(
            json_text.matches("\"id\":").count(),
            // One for the document, one for its single verification method.
            2,
            "no duplicate top-level id member may be emitted"
        );
    }

    #[test]
    fn injected_verification_method_cannot_outlive_its_revoked_key() {
        // The sharpest form. A key writes a shadow `verificationMethod` into
        // documentData and is then revoked. Revocation acts on the 2P-Set, and
        // the injected value does not live there — so before the reserved-name
        // gate it survived, and a last-wins parser saw ONLY the injected array.
        // Privilege persisting past revocation is what the 2P-Set exists to
        // prevent, so this is a regression test for that property, not for a
        // serialisation nicety.
        let (mut doc, _) = make_doc();
        let genesis = doc.verification_methods.entries()[0].id.clone();
        let k1 = format!("{}#key-1", doc.did);
        merge_op(
            &mut doc,
            DeltaOp::AddVerificationMethod {
                id: k1.clone(),
                public_key_multibase: "zSecondKey".to_owned(),
                suite_type: SuiteType::default(),
                relationships: crate::core::delta::default_relationships(),
            },
            HlcTimestamp {
                wall_ms: 10,
                logical: 0,
                node_id: 1,
            },
            &genesis,
        )
        .unwrap();

        let injected = merge_op(
            &mut doc,
            DeltaOp::SetDocumentData {
                key: "verificationMethod".to_owned(),
                value: serde_json::json!([{"id": "injected", "type": "X", "controller": "c"}]),
            },
            HlcTimestamp {
                wall_ms: 20,
                logical: 0,
                node_id: 1,
            },
            &k1,
        );
        assert!(matches!(injected, Err(Error::DeltaRejected(_))));

        merge_op(
            &mut doc,
            DeltaOp::RevokeVerificationMethod { key_id: k1.clone() },
            HlcTimestamp {
                wall_ms: 30,
                logical: 0,
                node_id: 1,
            },
            &genesis,
        )
        .unwrap();
        assert!(doc.is_vm_revoked(&k1));

        let reparsed: Value = serde_json::from_str(
            &serde_json::to_string(&doc.resolve().unwrap().did_document.unwrap()).unwrap(),
        )
        .unwrap();
        let methods = reparsed["verificationMethod"].as_array().unwrap();
        assert!(
            methods
                .iter()
                .all(|m| m["id"] != serde_json::json!("injected")),
            "a revoked key must not leave authentication material behind"
        );
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0]["id"], serde_json::json!(genesis));
    }

    // ── genesis key, published so a verifier can recompute the DID ────────────
    #[test]
    fn genesis_key_recomputes_the_did() {
        let (doc, _) = make_doc();
        let published = doc
            .genesis_public_key_multibase()
            .expect("a freshly created document knows its own genesis key");

        // The property is only worth anything if it actually derives the
        // identifier — assert the relation, not the string.
        assert_eq!(derive_did(&published).unwrap(), doc.did);
        assert_eq!(published, "zEd25519TestKey");
    }

    #[test]
    fn genesis_key_survives_revocation_of_that_key() {
        // The whole reason this property exists. `resolve` filters revoked keys
        // out of `verificationMethod`, so after rotation the document no longer
        // carries the input its own identifier derives from. The metadata must
        // still carry it, or the relation becomes uncheckable at exactly the
        // point a verifier most wants to check it.
        let (mut doc, _) = make_doc();
        let genesis_id = doc.verification_methods.entries()[0].id.clone();
        let key1_id = format!("{}#key-1", doc.did);
        merge_op(
            &mut doc,
            DeltaOp::AddVerificationMethod {
                id: key1_id.clone(),
                public_key_multibase: "zSecondKey".to_owned(),
                suite_type: SuiteType::default(),
                relationships: crate::core::delta::default_relationships(),
            },
            HlcTimestamp {
                wall_ms: 10,
                logical: 0,
                node_id: 1,
            },
            &genesis_id,
        )
        .unwrap();
        merge_op(
            &mut doc,
            DeltaOp::RevokeVerificationMethod {
                key_id: genesis_id.clone(),
            },
            HlcTimestamp {
                wall_ms: 20,
                logical: 0,
                node_id: 1,
            },
            &key1_id,
        )
        .unwrap();

        let result = doc.resolve().unwrap();
        let served = result.did_document.unwrap();

        // Precondition: the served document has genuinely lost the key.
        assert!(
            !served
                .verification_method
                .iter()
                .any(|m| m.id == genesis_id),
            "the revoked genesis key must not appear in the served document"
        );

        // And the metadata still lets a verifier close the loop.
        let published = result
            .did_document_metadata
            .genesis_public_key_multibase
            .expect("genesis key must outlive its own revocation in metadata");
        assert_eq!(derive_did(&published).unwrap(), doc.did);
    }

    #[test]
    fn a_shadowing_key_0_entry_does_not_displace_the_genesis_key() {
        // The set is a G-Set of whole entries, so an `id` is not unique: adding
        // a second `#key-0` carrying a different key leaves BOTH present. If
        // this property were resolved by name it would be resolved by sort
        // order, and this is the entry that would decide it.
        let (mut doc, _) = make_doc();
        let genesis_id = format!("{}#key-0", doc.did);
        doc.verification_methods.insert(
            genesis_id.clone(),
            "zAAAShadowSortsFirst".to_owned(),
            SuiteType::default(),
            crate::core::delta::default_relationships(),
        );
        assert_eq!(
            doc.verification_methods
                .entries()
                .iter()
                .filter(|e| e.id == genesis_id)
                .count(),
            2,
            "premise: both entries coexist under one id"
        );

        let published = doc
            .genesis_public_key_multibase()
            .expect("the genuine genesis key must still be found");
        assert_eq!(published, "zEd25519TestKey");
        assert_eq!(derive_did(&published).unwrap(), doc.did);
    }

    #[test]
    fn genesis_key_is_omitted_when_no_held_key_derives_the_did() {
        // Models the substitution this property exists to expose: state served
        // under a DID that none of its keys derive. Emitting a plausible-looking
        // key here would invite a verifier to conclude the relation holds.
        let (mut doc, _) = make_doc();
        doc.did = derive_did("zSomeOtherKeyEntirely").unwrap();

        assert_eq!(
            doc.genesis_public_key_multibase(),
            None,
            "no key derives this DID, so nothing may be published"
        );
        assert!(doc
            .resolve()
            .unwrap()
            .did_document_metadata
            .genesis_public_key_multibase
            .is_none());
    }

    #[test]
    fn revoke_vm_excludes_key_from_resolved_doc() {
        let (mut doc, _) = make_doc();
        // Add a second key so we can revoke the first without leaving the doc keyless.
        let signer = doc.verification_methods.entries()[0].id.clone();
        let key1_id = format!("{}#key-1", doc.did);
        let ts1 = HlcTimestamp {
            wall_ms: 10,
            logical: 0,
            node_id: 1,
        };
        merge_op(
            &mut doc,
            DeltaOp::AddVerificationMethod {
                id: key1_id.clone(),
                public_key_multibase: "zSecondKey".to_owned(),
                suite_type: SuiteType::default(),
                relationships: crate::core::delta::default_relationships(),
            },
            ts1,
            &signer,
        )
        .unwrap();
        assert_eq!(
            doc.resolve()
                .unwrap()
                .did_document
                .unwrap()
                .verification_method
                .len(),
            2
        );

        // Revoke the genesis key.
        let ts2 = HlcTimestamp {
            wall_ms: 20,
            logical: 0,
            node_id: 1,
        };
        merge_op(
            &mut doc,
            DeltaOp::RevokeVerificationMethod {
                key_id: signer.clone(),
            },
            ts2,
            &key1_id,
        )
        .unwrap();

        // Resolved doc should only show key-1 now.
        let resolved = doc.resolve().unwrap().did_document.unwrap();
        assert_eq!(resolved.verification_method.len(), 1);
        assert_eq!(resolved.verification_method[0].id, key1_id);
        assert!(doc.is_vm_revoked(&signer));
    }

    #[test]
    fn revoked_key_cannot_sign_further_deltas() {
        let (mut doc, _) = make_doc();
        let key0 = doc.verification_methods.entries()[0].id.clone();
        let key1_id = format!("{}#key-1", doc.did);

        // Add second key, then revoke key-0.
        let ts1 = HlcTimestamp {
            wall_ms: 10,
            logical: 0,
            node_id: 1,
        };
        merge_op(
            &mut doc,
            DeltaOp::AddVerificationMethod {
                id: key1_id.clone(),
                public_key_multibase: "zSecondKey".to_owned(),
                suite_type: SuiteType::default(),
                relationships: crate::core::delta::default_relationships(),
            },
            ts1,
            &key0,
        )
        .unwrap();

        let ts2 = HlcTimestamp {
            wall_ms: 20,
            logical: 0,
            node_id: 1,
        };
        merge_op(
            &mut doc,
            DeltaOp::RevokeVerificationMethod {
                key_id: key0.clone(),
            },
            ts2,
            &key1_id,
        )
        .unwrap();

        // Attempt to use revoked key-0 — must be rejected.
        let ts3 = HlcTimestamp {
            wall_ms: 30,
            logical: 0,
            node_id: 1,
        };
        let res = merge_op(
            &mut doc,
            DeltaOp::SetDocumentData {
                key: "evil".to_owned(),
                value: serde_json::json!("attack"),
            },
            ts3,
            &key0,
        );
        assert!(res.is_err(), "revoked key must be rejected");
    }

    #[test]
    fn revoke_vm_survives_state_merge() {
        let (mut a, _) = make_doc();
        let key0 = a.verification_methods.entries()[0].id.clone();
        let key1_id = format!("{}#key-1", a.did);

        // Add key-1 on both replicas.
        let ts1 = HlcTimestamp {
            wall_ms: 10,
            logical: 0,
            node_id: 1,
        };
        merge_op(
            &mut a,
            DeltaOp::AddVerificationMethod {
                id: key1_id.clone(),
                public_key_multibase: "zKey1".to_owned(),
                suite_type: SuiteType::default(),
                relationships: crate::core::delta::default_relationships(),
            },
            ts1,
            &key0,
        )
        .unwrap();

        let mut b = a.clone();

        // Replica A: revoke key-0.
        let ts2 = HlcTimestamp {
            wall_ms: 20,
            logical: 0,
            node_id: 1,
        };
        merge_op(
            &mut a,
            DeltaOp::RevokeVerificationMethod {
                key_id: key0.clone(),
            },
            ts2,
            &key1_id,
        )
        .unwrap();

        // Replica B: doesn't know about revocation yet.
        assert!(!b.is_vm_revoked(&key0));

        // Merge A into B — revocation must propagate.
        b.merge_state(a.clone()).unwrap();
        assert!(b.is_vm_revoked(&key0));
        assert_eq!(
            b.resolve()
                .unwrap()
                .did_document
                .unwrap()
                .verification_method
                .len(),
            1
        );
    }

    #[test]
    fn delta_count_tracks_log_size() {
        let (mut doc, _) = make_doc();
        // Genesis delta is already in the log.
        assert_eq!(doc.delta_count(), 1);

        let signer = doc.verification_methods.entries()[0].id.clone();
        let ts = HlcTimestamp {
            wall_ms: 100,
            logical: 0,
            node_id: 1,
        };
        merge_op(
            &mut doc,
            DeltaOp::SetDocumentData {
                key: "k".to_owned(),
                value: serde_json::json!(1),
            },
            ts,
            &signer,
        )
        .unwrap();

        assert_eq!(doc.delta_count(), 2);
    }

    #[test]
    fn merge_state_does_not_merge_delta_logs() {
        let (mut a, _) = make_doc();
        let b = a.clone();

        // Apply a delta to a.
        let signer = a.verification_methods.entries()[0].id.clone();
        let ts = HlcTimestamp {
            wall_ms: 100,
            logical: 0,
            node_id: 1,
        };
        merge_op(
            &mut a,
            DeltaOp::SetDocumentData {
                key: "k".to_owned(),
                value: serde_json::json!(1),
            },
            ts,
            &signer,
        )
        .unwrap();
        assert_eq!(a.delta_count(), 2); // genesis + 1

        // b still has only genesis.
        assert_eq!(b.delta_count(), 1);

        // merge_state should NOT merge delta logs.
        a.merge_state(b).unwrap();
        assert_eq!(
            a.delta_count(),
            2,
            "delta log must not change on state merge"
        );
    }

    // ── Verification relationship tests ─────────────────────────────────────

    #[test]
    fn resolve_default_relationship_is_authentication() {
        let (doc, _) = make_doc();
        let result = doc.resolve().unwrap();
        let resolved = result.did_document.unwrap();
        // Default genesis key should appear in authentication only.
        assert_eq!(resolved.authentication.len(), 1);
        assert!(resolved.assertion_method.is_empty());
        assert!(resolved.key_agreement.is_empty());
        assert!(resolved.capability_invocation.is_empty());
        assert!(resolved.capability_delegation.is_empty());
    }

    #[test]
    fn resolve_key_with_multiple_relationships() {
        let (mut doc, _) = make_doc();
        let signer = doc.verification_methods.entries()[0].id.clone();
        let key1_id = format!("{}#key-1", doc.did);
        let ts1 = HlcTimestamp {
            wall_ms: 10,
            logical: 0,
            node_id: 1,
        };
        merge_op(
            &mut doc,
            DeltaOp::AddVerificationMethod {
                id: key1_id.clone(),
                public_key_multibase: "zMultiRelKey".to_owned(),
                suite_type: SuiteType::default(),
                relationships: vec![
                    VerificationRelationship::Authentication,
                    VerificationRelationship::AssertionMethod,
                    VerificationRelationship::KeyAgreement,
                    VerificationRelationship::CapabilityInvocation,
                    VerificationRelationship::CapabilityDelegation,
                ],
            },
            ts1,
            &signer,
        )
        .unwrap();

        let resolved = doc.resolve().unwrap().did_document.unwrap();
        assert_eq!(resolved.verification_method.len(), 2);
        assert_eq!(resolved.authentication.len(), 2);
        assert_eq!(resolved.assertion_method.len(), 1);
        assert_eq!(resolved.assertion_method[0], Value::String(key1_id.clone()));
        assert_eq!(resolved.key_agreement.len(), 1);
        assert_eq!(resolved.key_agreement[0], Value::String(key1_id.clone()));
        assert_eq!(resolved.capability_invocation.len(), 1);
        assert_eq!(
            resolved.capability_invocation[0],
            Value::String(key1_id.clone())
        );
        assert_eq!(resolved.capability_delegation.len(), 1);
        assert_eq!(resolved.capability_delegation[0], Value::String(key1_id));
    }

    #[test]
    fn resolve_json_field_names_correct() {
        let (mut doc, _) = make_doc();
        let signer = doc.verification_methods.entries()[0].id.clone();
        let key1_id = format!("{}#key-1", doc.did);
        let ts1 = HlcTimestamp {
            wall_ms: 10,
            logical: 0,
            node_id: 1,
        };
        merge_op(
            &mut doc,
            DeltaOp::AddVerificationMethod {
                id: key1_id,
                public_key_multibase: "zJsonFieldKey".to_owned(),
                suite_type: SuiteType::default(),
                relationships: vec![
                    VerificationRelationship::AssertionMethod,
                    VerificationRelationship::KeyAgreement,
                    VerificationRelationship::CapabilityInvocation,
                    VerificationRelationship::CapabilityDelegation,
                ],
            },
            ts1,
            &signer,
        )
        .unwrap();

        let resolved = doc.resolve().unwrap().did_document.unwrap();
        let json = serde_json::to_value(&resolved).unwrap();
        assert!(
            json.get("assertionMethod").is_some(),
            "assertionMethod key must be present"
        );
        assert!(
            json.get("keyAgreement").is_some(),
            "keyAgreement key must be present"
        );
        assert!(
            json.get("capabilityInvocation").is_some(),
            "capabilityInvocation key must be present"
        );
        assert!(
            json.get("capabilityDelegation").is_some(),
            "capabilityDelegation key must be present"
        );
        assert!(json.get("assertion_method").is_none());
        assert!(json.get("key_agreement").is_none());
        assert!(json.get("capability_invocation").is_none());
        assert!(json.get("capability_delegation").is_none());
    }

    // ── DAG admission regressions ─────────────────────────────────────────────

    /// A delta concurrent with a revocation of its own signer must still be
    /// admitted: the revocation is not in the delta's causal past, so "containment,
    /// not recovery" applies. Authorisation is causal (the revocation IS a delta in
    /// the DAG), so the current-state revocation must not reject the sibling — and
    /// both delivery orders converge. This is also what makes verified bundle replay
    /// order-independent (review round 5, P2).
    #[test]
    fn concurrent_revocation_does_not_reject_sibling_signed_by_revoked_key() {
        let (mut doc, _) = make_doc();
        let key0 = doc.verification_methods.entries()[0].id.clone();
        let key1 = format!("{}#key-1", doc.did);
        merge_op(
            &mut doc,
            DeltaOp::AddVerificationMethod {
                id: key1.clone(),
                public_key_multibase: "zKey1".to_owned(),
                suite_type: SuiteType::default(),
                relationships: crate::core::delta::default_relationships(),
            },
            HlcTimestamp {
                wall_ms: 10,
                logical: 0,
                node_id: 1,
            },
            &key0,
        )
        .unwrap();
        let fork = doc.frontier(); // common parent for the two concurrent siblings

        // A: key0 revokes key1.
        let mut a = SignedDelta::unsigned(
            doc.did.clone(),
            DeltaOp::RevokeVerificationMethod {
                key_id: key1.clone(),
            },
            HlcTimestamp {
                wall_ms: 20,
                logical: 0,
                node_id: 1,
            },
            key0,
        );
        a.parents = fork.clone();
        // B: key1 adds a service, concurrent with the revocation (parents = fork,
        // NOT a — so the revocation is not in B's causal past).
        let mut b = SignedDelta::unsigned(
            doc.did.clone(),
            DeltaOp::AddServiceEndpoint {
                id: format!("{}#svc", doc.did),
                service_type: "X".to_owned(),
                endpoint: "https://e.example.com".to_owned(),
            },
            HlcTimestamp {
                wall_ms: 21,
                logical: 0,
                node_id: 1,
            },
            key1,
        );
        b.parents = fork;

        // Revocation first, then the concurrent sibling: must be admitted.
        let mut da = doc.clone();
        da.merge(a.clone()).unwrap();
        let rb = da.merge(b.clone());
        assert!(
            rb.is_ok(),
            "a delta concurrent with a revocation of its signer must be admitted, got {rb:?}"
        );

        // Reverse order converges to the same state.
        let mut db = doc;
        db.merge(b).unwrap();
        db.merge(a).unwrap();
        assert_eq!(
            da.content_hash().unwrap(),
            db.content_hash().unwrap(),
            "both delivery orders converge"
        );
    }

    /// `merge_state` must import the incoming delta history, not just the
    /// materialised state: otherwise the receiver's frontier stalls on local
    /// history and a delta parented on an imported update is held `DeltaPending`
    /// even though the state visibly converged (review round 6, P1).
    #[test]
    fn merge_state_imports_delta_history_for_later_admission() {
        // Sender A: genesis + one update, so A's frontier is past genesis.
        let (mut a, _) = make_doc();
        let signer = a.verification_methods.entries()[0].id.clone();
        merge_op(
            &mut a,
            DeltaOp::RevokeCredential {
                credential_id: "c1".to_owned(),
            },
            HlcTimestamp {
                wall_ms: 10,
                logical: 0,
                node_id: 1,
            },
            &signer,
        )
        .unwrap();
        let a_frontier = a.frontier();
        assert_ne!(
            a_frontier,
            make_doc().0.frontier(),
            "A advanced past genesis"
        );

        // Receiver B (fresh) imports A's state.
        let (mut b, _) = make_doc();
        b.merge_state(a).unwrap();
        assert_eq!(
            b.frontier(),
            a_frontier,
            "merge_state must import the frontier/history"
        );

        // A delta parented on the imported update must admit, not be held pending
        // for a parent missing from B's DAG.
        let mut peer = SignedDelta::unsigned(
            b.did.clone(),
            DeltaOp::RevokeCredential {
                credential_id: "c2".to_owned(),
            },
            HlcTimestamp {
                wall_ms: 20,
                logical: 0,
                node_id: 1,
            },
            signer,
        );
        peer.parents = a_frontier;
        let res = b.merge(peer);
        assert!(
            res.is_ok(),
            "delta parented on the imported update must admit, got {res:?}"
        );
    }

    /// A document deserialised with CRDT state but no delta log (the pre-DAG
    /// serialisation shape) must be rejected loudly, not silently rebuilt into a
    /// frozen document with an empty frontier (review round 5, P1).
    #[test]
    fn deserialize_rejects_stateful_document_without_delta_log() {
        let (doc, _) = make_doc();
        let mut v = serde_json::to_value(&doc).unwrap();
        v.as_object_mut().unwrap().remove("delta_log");
        let res: std::result::Result<Document, _> = serde_json::from_value(v);
        assert!(
            res.is_err(),
            "a non-empty document with no delta log must be rejected, not silently frozen"
        );
    }

    /// A delta signed by a real authorised key, but parented to *exclude* that
    /// key's `AddVerificationMethod` from its causal past, must be rejected — it
    /// must not be admitted just because the key is present in current state
    /// (back-parenting attack; review P1).
    #[test]
    fn back_parented_signer_is_rejected_not_admitted_via_current_state() {
        let (mut doc, genesis) = make_doc();
        let key0 = doc.verification_methods.entries()[0].id.clone();
        let key1 = format!("{}#key-1", doc.did);
        // Introduce key1 with a properly-grounded delta: its AddVM is now both in
        // current state AND a delta in the DAG.
        merge_op(
            &mut doc,
            DeltaOp::AddVerificationMethod {
                id: key1.clone(),
                public_key_multibase: "zKey1".to_owned(),
                suite_type: SuiteType::default(),
                relationships: crate::core::delta::default_relationships(),
            },
            HlcTimestamp {
                wall_ms: 10,
                logical: 0,
                node_id: 1,
            },
            &key0,
        )
        .unwrap();

        // key1 signs a delta parented ONLY on genesis, excluding its own AddVM.
        let mut evil = SignedDelta::unsigned(
            doc.did.clone(),
            DeltaOp::RevokeCredential {
                credential_id: "pwned".to_owned(),
            },
            HlcTimestamp {
                wall_ms: 20,
                logical: 0,
                node_id: 1,
            },
            key1,
        );
        evil.parents = vec![genesis.content_hash().unwrap()];

        let res = doc.merge(evil);
        assert!(
            matches!(res, Err(Error::Unauthorised(_))),
            "back-parented signer must be rejected, got {res:?}"
        );
    }
    // ── Phase 4: authenticated state sync (SPEC-036 REQ-368) ──────────────────
    mod phase4 {
        use super::*;
        use crate::core::delta::SigningKey;
        use crate::core::validate::node_id_from_pubkey;
        use base64ct::{Base64UrlUnpadded, Encoding as _};

        /// 32-byte seeds for deterministic test keys.
        const OWNER_SEED: [u8; 32] = [0x42u8; 32];
        const ATTACKER_SEED: [u8; 32] = [0x99u8; 32];

        /// A receiver/sender document whose genesis key is a real Ed25519 key.
        fn signed_doc() -> (Document, SigningKey, String, u64) {
            let sk = ed25519_dalek::SigningKey::from_bytes(&OWNER_SEED);
            let nid = node_id_from_pubkey(sk.verifying_key().as_bytes());
            let pk_mb = format!(
                "u{}",
                Base64UrlUnpadded::encode_string(sk.verifying_key().as_bytes())
            );
            let (doc, _) = Document::new(&pk_mb).unwrap();
            let key_id = doc.verification_methods.entries()[0].id.clone();
            (doc, SigningKey::Ed25519(sk), key_id, nid)
        }

        /// A fresh replica tracking the same DID (genesis only) — the receiver.
        fn fresh_receiver() -> Document {
            signed_doc().0
        }

        fn svc(doc: &Document, n: u32) -> DeltaOp {
            DeltaOp::AddServiceEndpoint {
                id: format!("{}#svc-{n}", doc.did),
                service_type: "LinkedDomains".to_owned(),
                endpoint: format!("https://e{n}.example.com"),
            }
        }

        /// Sign `op` on `doc`'s current frontier with `sk`/`nid`.
        fn signed_on(
            doc: &Document,
            op: DeltaOp,
            key_id: &str,
            nid: u64,
            sk: &SigningKey,
            wall: u64,
        ) -> SignedDelta {
            SignedDelta::new_with_parents(
                doc.did.clone(),
                op,
                HlcTimestamp {
                    wall_ms: wall,
                    logical: 0,
                    node_id: nid,
                },
                doc.frontier(),
                key_id.to_owned(),
                sk,
            )
            .unwrap()
        }

        /// Sender: genesis + three validly-signed service deltas (linear chain).
        fn populated_sender() -> (Document, SigningKey, String, u64) {
            let (mut doc, sk, key_id, nid) = signed_doc();
            for n in 1..=3u32 {
                let d = signed_on(&doc, svc(&doc, n), &key_id, nid, &sk, 1_000 + u64::from(n));
                doc.merge(d).unwrap();
            }
            (doc, sk, key_id, nid)
        }

        #[test]
        fn verified_bundle_rederives_authenticated_state() {
            let (sender, ..) = populated_sender();
            let bundle = sender.export_bundle().unwrap();

            let mut receiver = fresh_receiver();
            assert_eq!(receiver.did, sender.did);
            let applied = receiver.merge_verified_bundle(bundle).unwrap();
            assert_eq!(applied, 3, "3 non-genesis deltas applied (genesis deduped)");
            assert_eq!(
                receiver.content_hash().unwrap(),
                sender.content_hash().unwrap(),
                "verified replay re-derives byte-identical state"
            );
        }

        #[test]
        fn verified_bundle_rejects_forged_signature() {
            let (sender, _sk, key_id, nid) = populated_sender();
            let mut bundle = sender.export_bundle().unwrap();

            // A delta claiming the real authorised key id but signed by a key the
            // document never authorised. node_id is the real one, so it is the
            // *signature* check (not node binding) that must reject it.
            let attacker =
                SigningKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&ATTACKER_SEED));
            let forged = SignedDelta::new_with_parents(
                sender.did.clone(),
                svc(&sender, 99),
                HlcTimestamp {
                    wall_ms: 5_000,
                    logical: 0,
                    node_id: nid,
                },
                sender.frontier(),
                key_id,
                &attacker,
            )
            .unwrap();
            bundle.deltas.push(forged);

            let mut receiver = sender.clone();
            let before = receiver.content_hash().unwrap();
            assert!(
                receiver.merge_verified_bundle(bundle).is_err(),
                "forged signature must be rejected"
            );
            assert_eq!(
                receiver.content_hash().unwrap(),
                before,
                "receiver unchanged after rejection (atomic)"
            );
        }

        #[test]
        fn verified_bundle_rejects_tampered_op() {
            let (sender, sk, key_id, nid) = populated_sender();
            let mut bundle = sender.export_bundle().unwrap();

            // Validly sign, then mutate the op so the signature no longer covers it.
            let mut d = signed_on(&sender, svc(&sender, 7), &key_id, nid, &sk, 6_000);
            if let DeltaOp::AddServiceEndpoint { endpoint, .. } = &mut d.op {
                *endpoint = "https://evil.example.com".to_owned();
            }
            bundle.deltas.push(d);

            let mut receiver = sender.clone();
            let before = receiver.content_hash().unwrap();
            assert!(receiver.merge_verified_bundle(bundle).is_err());
            assert_eq!(receiver.content_hash().unwrap(), before);
        }

        #[test]
        fn verified_bundle_rejects_dangling_parent() {
            let (sender, ..) = populated_sender();
            let mut bundle = sender.export_bundle().unwrap();
            // Drop the middle delta; the head still references it by hash, and a
            // fresh receiver does not hold it → dangling parent.
            bundle.deltas.retain(|d| {
                !matches!(&d.op, DeltaOp::AddServiceEndpoint { id, .. } if id.ends_with("#svc-2"))
            });

            let mut receiver = fresh_receiver();
            let res = receiver.merge_verified_bundle(bundle);
            assert!(
                matches!(res, Err(Error::DeltaRejected(_))),
                "dangling parent must be rejected, got {res:?}"
            );
        }

        #[test]
        fn verified_bundle_is_order_independent() {
            let (sender, ..) = populated_sender();
            let mut bundle = sender.export_bundle().unwrap();
            bundle.deltas.reverse(); // children before parents — topo sort must fix

            let mut receiver = fresh_receiver();
            assert_eq!(receiver.merge_verified_bundle(bundle).unwrap(), 3);
            assert_eq!(
                receiver.content_hash().unwrap(),
                sender.content_hash().unwrap()
            );
        }

        #[test]
        fn verified_bundle_is_idempotent() {
            let (sender, ..) = populated_sender();
            let bundle = sender.export_bundle().unwrap();

            let mut receiver = fresh_receiver();
            assert_eq!(receiver.merge_verified_bundle(bundle.clone()).unwrap(), 3);
            let h = receiver.content_hash().unwrap();
            assert_eq!(
                receiver.merge_verified_bundle(bundle).unwrap(),
                0,
                "re-merge applies nothing"
            );
            assert_eq!(
                receiver.content_hash().unwrap(),
                h,
                "state unchanged on re-merge"
            );
        }

        #[test]
        fn verified_bundle_is_atomic_on_partial_failure() {
            let (sender, sk, key_id, nid) = populated_sender();
            let mut bundle = sender.export_bundle().unwrap();

            // One genuinely valid new delta and one forged delta, both new.
            let good = signed_on(&sender, svc(&sender, 4), &key_id, nid, &sk, 7_000);
            let attacker =
                SigningKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&ATTACKER_SEED));
            let bad = SignedDelta::new_with_parents(
                sender.did.clone(),
                svc(&sender, 5),
                HlcTimestamp {
                    wall_ms: 7_001,
                    logical: 0,
                    node_id: nid,
                },
                sender.frontier(),
                key_id,
                &attacker,
            )
            .unwrap();
            bundle.deltas.push(good);
            bundle.deltas.push(bad);

            let mut receiver = sender.clone();
            let before = receiver.content_hash().unwrap();
            let log_len = receiver.delta_count();
            assert!(receiver.merge_verified_bundle(bundle).is_err());
            assert_eq!(
                receiver.content_hash().unwrap(),
                before,
                "no partial application"
            );
            assert_eq!(receiver.delta_count(), log_len, "delta log unchanged");
        }
    }
    // ── JsonWebKey projection ────────────────────────────────────────────────

    /// A monotonically increasing timestamp, so successive test ops order.
    fn next_ts() -> HlcTimestamp {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(1);
        HlcTimestamp {
            wall_ms: N.fetch_add(1, Ordering::Relaxed),
            logical: 0,
            node_id: 0,
        }
    }

    /// Authorise `id` to assert, carrying `mb` as its key.
    fn assert_asserting(doc: &mut Document, id: &str, mb: &str) {
        doc.apply_op(
            &DeltaOp::AddVerificationMethod {
                id: id.to_owned(),
                public_key_multibase: mb.to_owned(),
                suite_type: SuiteType::Ed25519Signature2020,
                relationships: vec![VerificationRelationship::AssertionMethod],
            },
            next_ts(),
            &[],
        )
        .unwrap();
    }

    /// A key that only authenticates gets no twin.
    ///
    /// This is the property that keeps the projection from conferring authority.
    /// Genesis creates `#key-0` with `Authentication` alone, and if twinning
    /// were unconditional the resolver would hand every DID an assertion key no
    /// delta ever authorised.
    #[test]
    fn an_authentication_only_key_is_not_twinned() {
        let (doc, _) = Document::new("uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let resolved = doc.resolve().unwrap().did_document.unwrap();

        assert_eq!(resolved.verification_method.len(), 1);
        assert!(resolved.assertion_method.is_empty());
        assert!(!resolved
            .verification_method
            .iter()
            .any(|m| m.r#type == "JsonWebKey"));
    }

    /// An asserting key is twinned, at `#jwk-0`, carrying the same key material.
    #[test]
    fn an_asserting_key_is_twinned_as_a_json_web_key() {
        use base64ct::{Base64UrlUnpadded, Encoding as _};

        let raw = [0x11u8; 32];
        let mb = format!("u{}", Base64UrlUnpadded::encode_string(&raw));
        let (mut doc, _) = Document::new(&mb).unwrap();

        // A second method for the same key, authorised to assert.
        let id = format!("{}#key-1", doc.did);
        assert_asserting(&mut doc, &id, &mb);

        let resolved = doc.resolve().unwrap().did_document.unwrap();
        let twin_id = format!("{}#jwk-0", doc.did);

        let twin = resolved
            .verification_method
            .iter()
            .find(|m| m.id == twin_id)
            .expect("the asserting key is twinned at #jwk-0");

        assert_eq!(twin.r#type, "JsonWebKey");
        assert_eq!(twin.controller, doc.did.to_string());
        assert!(
            twin.public_key_multibase.is_none(),
            "a twin carries one encoding, not two"
        );

        let jwk = twin
            .public_key_jwk
            .as_ref()
            .expect("a twin carries publicKeyJwk");
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["x"], Base64UrlUnpadded::encode_string(&raw));
        assert!(
            jwk.get("d").is_none(),
            "a projection has no private component to leak"
        );

        // And it is reachable as an assertion method, which is the point.
        assert!(resolved
            .assertion_method
            .iter()
            .any(|r| r.as_str() == Some(twin_id.as_str())));
    }

    /// The DID is a hash of the genesis op. A projection computed at resolution
    /// cannot move it, and this is the assertion `ADR-010`'s pin rests on.
    #[test]
    fn the_projection_does_not_move_the_identifier() {
        use base64ct::{Base64UrlUnpadded, Encoding as _};

        let mb = format!("u{}", Base64UrlUnpadded::encode_string(&[0x22u8; 32]));
        let (mut doc, _) = Document::new(&mb).unwrap();
        let before = doc.did.to_string();

        let id = format!("{}#key-1", doc.did);
        assert_asserting(&mut doc, &id, &mb);

        let resolved = doc.resolve().unwrap().did_document.unwrap();
        assert!(resolved
            .verification_method
            .iter()
            .any(|m| m.r#type == "JsonWebKey"));
        assert_eq!(doc.did.to_string(), before);
        assert_eq!(resolved.id, before);
    }

    /// Numbering is positional among asserting keys and ordered by id, so it is
    /// a function of state rather than of the order deltas arrived.
    #[test]
    fn twins_are_numbered_by_position_not_by_source_fragment() {
        use base64ct::{Base64UrlUnpadded, Encoding as _};

        let mb = format!("u{}", Base64UrlUnpadded::encode_string(&[0x33u8; 32]));
        let (mut doc, _) = Document::new(&mb).unwrap();

        // Added out of order, and neither is `#key-0`.
        for fragment in ["#key-7", "#key-3"] {
            let id = format!("{}{fragment}", doc.did);
            assert_asserting(&mut doc, &id, &mb);
        }

        let resolved = doc.resolve().unwrap().did_document.unwrap();
        let twins: Vec<&str> = resolved
            .verification_method
            .iter()
            .filter(|m| m.r#type == "JsonWebKey")
            .map(|m| m.id.as_str())
            .collect();

        // `#key-3` sorts before `#key-7`, so it takes `#jwk-0` whichever order
        // the deltas arrived in.
        assert_eq!(
            twins,
            vec![format!("{}#jwk-0", doc.did), format!("{}#jwk-1", doc.did)]
        );
    }

    /// A revoked key is not twinned, because it is not projected at all.
    #[test]
    fn a_revoked_asserting_key_loses_its_twin() {
        use base64ct::{Base64UrlUnpadded, Encoding as _};

        let mb = format!("u{}", Base64UrlUnpadded::encode_string(&[0x44u8; 32]));
        let (mut doc, _) = Document::new(&mb).unwrap();
        let id = format!("{}#key-1", doc.did);

        assert_asserting(&mut doc, &id, &mb);
        assert!(doc
            .resolve()
            .unwrap()
            .did_document
            .unwrap()
            .verification_method
            .iter()
            .any(|m| m.r#type == "JsonWebKey"));

        doc.apply_op(
            &DeltaOp::RevokeVerificationMethod { key_id: id },
            next_ts(),
            &[],
        )
        .unwrap();

        let resolved = doc.resolve().unwrap().did_document.unwrap();
        assert!(!resolved
            .verification_method
            .iter()
            .any(|m| m.r#type == "JsonWebKey"));
    }
}
