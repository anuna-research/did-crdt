//! Typed CRDT field wrappers for the DID document model.
//!
//! Each field is a thin wrapper over a primitive CRDT from the `crdts` crate,
//! enriched with DID-specific invariants (deactivation latch, rotation seq
//! check, etc.).
//!
//! | Field               | CRDT Type    | Semantics                              |
//! |---------------------|--------------|----------------------------------------|
//! | verificationMethods | G-Set        | Grow-only set of verification methods  |
//! | serviceEndpoints    | OR-Set       | Add/remove with causal context         |
//! | documentData        | LWW-Map      | Per-field last-writer-wins register    |
//! | activeKey           | Max-Register | Highest seq wins, tiebreak on key hash |
//! | alsoKnownAs         | LWW-Register | Whole set replaced; re-add must stay possible |
//! | revocations         | G-Set        | Grow-only set of revoked credential IDs|
//! | revokedVMs          | G-Set        | Grow-only set of revoked key IDs (2P-Set remove half) |
//! | deactivated         | Max-Register | Boolean latch — once true, stays true  |

use std::collections::BTreeMap;

use crdts::{CvRDT, GSet, LWWReg};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::delta::{default_relationships, SuiteType, VerificationRelationship};
use crate::core::hlc::HlcTimestamp;

/// A node identifier — the lower 64 bits of a node's public-key hash, carried
/// by [`HlcTimestamp::node_id`]. Used as the per-node key of the
/// [`ServiceEndpoints`] causal-context version vector.
pub type ActorId = u64;

// ── VerificationMethods (G-Set) ───────────────────────────────────────────────

/// A single verification-method entry in the DID document.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VerificationMethodEntry {
    /// The fragment identifier (e.g. `did:crdt:<hash>#key-1`).
    pub id: String,
    /// The public key in Multibase encoding.
    pub public_key_multibase: String,
    /// The cryptographic suite type for this key.
    ///
    /// Defaults to `Ed25519Signature2020` for backwards compatibility with
    /// entries created before this field was introduced.
    #[serde(default)]
    pub suite_type: SuiteType,
    /// The verification relationships this key participates in.
    ///
    /// Defaults to `[Authentication]` for backwards compatibility with
    /// entries created before this field was introduced.
    #[serde(default = "default_relationships")]
    pub relationships: Vec<VerificationRelationship>,
}

/// Grow-only set of verification methods.
///
/// Insertions are permanent — a key that has been added to a replica can never
/// be removed from the document's canonical set.  This upholds the audit-log
/// property: revoked keys are tracked separately in [`Revocations`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VerificationMethods(GSet<VerificationMethodEntry>);

impl VerificationMethods {
    /// Create an empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a verification method.  Duplicate insertions are no-ops.
    pub fn insert(
        &mut self,
        id: String,
        public_key_multibase: String,
        suite_type: SuiteType,
        relationships: Vec<VerificationRelationship>,
    ) {
        self.0.insert(VerificationMethodEntry {
            id,
            public_key_multibase,
            suite_type,
            relationships,
        });
    }

    /// Returns `true` if an entry whose `id` field matches `id` exists.
    pub fn contains_id(&self, id: &str) -> bool {
        self.entries().iter().any(|e| e.id == id)
    }

    /// Returns a sorted snapshot of all entries.
    pub fn entries(&self) -> Vec<VerificationMethodEntry> {
        self.0.read().into_iter().collect()
    }

    /// Merge another set into this one (set union — idempotent).
    pub fn merge(&mut self, other: Self) {
        CvRDT::merge(&mut self.0, other.0);
    }
}

// ── Revocations (G-Set) ───────────────────────────────────────────────────────

/// Grow-only set of revoked credential identifiers.
///
/// Once a credential ID is added it can never be removed, making the set
/// safe to union across replicas without coordination.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Revocations(GSet<String>);

impl Revocations {
    /// Create an empty revocation set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark `credential_id` as revoked.
    pub fn insert(&mut self, credential_id: String) {
        self.0.insert(credential_id);
    }

    /// Returns `true` if `credential_id` has been revoked.
    pub fn contains(&self, credential_id: &str) -> bool {
        self.0.contains(&credential_id.to_owned())
    }

    /// Returns a sorted snapshot of all revoked IDs.
    pub fn entries(&self) -> Vec<String> {
        self.0.read().into_iter().collect()
    }

    /// Merge another revocation set into this one (set union — idempotent).
    pub fn merge(&mut self, other: Self) {
        CvRDT::merge(&mut self.0, other.0);
    }
}

// ── RevokedVerificationMethods (G-Set — 2P-Set remove half) ──────────────────

/// Grow-only set of revoked verification method key IDs.
///
/// Together with [`VerificationMethods`] (the add half), this forms a 2P-Set:
/// `authorized = added \ revoked`.  Once a key ID is added to this set it can
/// never be removed, making the set safe to union across replicas without
/// coordination.
///
/// This solves the "G-Set means forever" problem: compromised keys can now be
/// revoked while preserving CRDT convergence guarantees.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RevokedVerificationMethods(GSet<String>);

impl RevokedVerificationMethods {
    /// Create an empty revocation set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark `key_id` as revoked.
    pub fn insert(&mut self, key_id: String) {
        self.0.insert(key_id);
    }

    /// Returns `true` if `key_id` has been revoked.
    pub fn contains(&self, key_id: &str) -> bool {
        self.0.contains(&key_id.to_owned())
    }

    /// Returns a sorted snapshot of all revoked key IDs.
    pub fn entries(&self) -> Vec<String> {
        self.0.read().into_iter().collect()
    }

    /// Merge another revocation set into this one (set union — idempotent).
    pub fn merge(&mut self, other: Self) {
        CvRDT::merge(&mut self.0, other.0);
    }
}

// ── ServiceEndpoints (ORSWOT) ─────────────────────────────────────────────────

/// A single service-endpoint entry.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServiceEntry {
    /// Fragment identifier (e.g. `did:crdt:<hash>#service-1`).
    pub id: String,
    /// Service type string (e.g. `"LinkedDomains"`).
    pub service_type: String,
    /// The endpoint URI or object, serialised as a string.
    pub endpoint: String,
}

/// A stable, globally-unique tag for a single add event: the HLC timestamp of
/// the `AddServiceEndpoint` delta that introduced it.
///
/// Because the dot is the delta's own timestamp, it is identical on every
/// replica (it travels inside the signed delta) — unlike a locally-minted
/// vector-clock dot. This is what lets a remove name *exactly* the adds it
/// observed, so a concurrent add is never mistaken for one of them.
pub type Dot = HlcTimestamp;

/// Add-wins observed-remove set of service endpoints (ORSWOT).
///
/// Each live add is keyed by its [`Dot`]. The `context` is a compact version
/// vector — `node_id → highest Dot seen from that node` — that lets
/// [`Self::merge`] distinguish "this peer saw the add and removed it" (drop)
/// from "this peer never saw the add" (keep). No per-element tombstones are
/// retained: a node's HLCs strictly increase and it chains its own deltas, so
/// holding one Dot implies holding every earlier Dot from that node, and the
/// version vector therefore has no gaps.
///
/// A remove cancels exactly the Dots it *observed* — the `AddServiceEndpoint`
/// deltas for the target id in the remove's causal past `↓R`, supplied by the
/// caller ([`crate::core::document::Document`] computes them from the delta
/// DAG). A concurrent add carries a Dot outside `↓R` and so is never cancelled:
/// add wins. Deriving the observed set from `↓R` rather than from current local
/// state is what makes delta replay a faithful CvRDT that converges identically
/// to [`Self::merge`].
#[derive(Clone, Debug, Default)]
pub struct ServiceEndpoints {
    /// Live add events: each surviving [`Dot`] mapped to the entry it added.
    live: BTreeMap<Dot, ServiceEntry>,
    /// Causal context (version vector): `node_id → highest Dot seen`.
    context: BTreeMap<u64, Dot>,
}

/// On-the-wire shape: maps with non-string keys cannot be JSON objects, so both
/// fields serialise as arrays of pairs. Replaces the former `orswot_json`
/// adapter, which existed only to coax the `crdts` crate's internal maps
/// through `serde_json`.
#[derive(Serialize, Deserialize)]
struct ServiceEndpointsRepr {
    live: Vec<(Dot, ServiceEntry)>,
    context: Vec<(u64, Dot)>,
}

impl Serialize for ServiceEndpoints {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        ServiceEndpointsRepr {
            live: self.live.iter().map(|(d, e)| (*d, e.clone())).collect(),
            context: self.context.iter().map(|(n, d)| (*n, *d)).collect(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ServiceEndpoints {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let repr = ServiceEndpointsRepr::deserialize(deserializer)?;
        Ok(ServiceEndpoints {
            live: repr.live.into_iter().collect(),
            context: repr.context.into_iter().collect(),
        })
    }
}

impl ServiceEndpoints {
    /// Create an empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply an add introduced by the delta whose timestamp is `dot`.
    pub fn apply_add(&mut self, entry: ServiceEntry, dot: Dot) {
        self.observe(dot);
        self.live.insert(dot, entry);
    }

    /// Apply a remove that observed `dots` (the add Dots for the target id in
    /// the remove's causal past), witnessed by the remove delta's `witness`
    /// timestamp.
    ///
    /// Cancels exactly the observed Dots; concurrent adds (Dots not in `dots`)
    /// are untouched, so add wins. Cancelling an already-absent Dot is a no-op.
    pub fn apply_remove(&mut self, dots: &[Dot], witness: Dot) {
        self.observe(witness);
        for d in dots {
            self.observe(*d);
            self.live.remove(d);
        }
    }

    /// Record that `dot` has been seen, advancing the per-node context.
    fn observe(&mut self, dot: Dot) {
        let slot = self.context.entry(dot.node_id).or_insert(dot);
        if dot > *slot {
            *slot = dot;
        }
    }

    /// Whether `context` has witnessed `dot` (and therefore every earlier Dot
    /// from the same node).
    fn seen(context: &BTreeMap<u64, Dot>, dot: &Dot) -> bool {
        context.get(&dot.node_id).is_some_and(|hi| dot <= hi)
    }

    /// Returns `true` if an entry with the given `id` is currently present.
    pub fn contains_id(&self, id: &str) -> bool {
        self.live.values().any(|e| e.id == id)
    }

    /// Returns a snapshot of all currently-present entries, deduplicated by
    /// value (concurrent adds may carry equal entries under distinct Dots) and
    /// sorted by `id`.
    pub fn entries(&self) -> Vec<ServiceEntry> {
        let mut seen = std::collections::HashSet::new();
        let mut v: Vec<ServiceEntry> = Vec::new();
        for e in self.live.values() {
            if seen.insert(e.clone()) {
                v.push(e.clone());
            }
        }
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }

    /// Merge another `ServiceEndpoints` into this one (state-based ORSWOT join).
    ///
    /// A Dot survives iff it is live on at least one side and not "seen and
    /// removed" on the other — i.e. a Dot the other side has witnessed
    /// (`seen`) but dropped from `live` is a genuine remove and is discarded,
    /// while a Dot the other side never witnessed is a concurrent add and is
    /// kept. The version vectors are merged pointwise.
    pub fn merge(&mut self, other: Self) {
        let mut merged: BTreeMap<Dot, ServiceEntry> = BTreeMap::new();
        for (dot, entry) in &self.live {
            if other.live.contains_key(dot) || !Self::seen(&other.context, dot) {
                merged.insert(*dot, entry.clone());
            }
        }
        for (dot, entry) in &other.live {
            if self.live.contains_key(dot) || !Self::seen(&self.context, dot) {
                merged.insert(*dot, entry.clone());
            }
        }
        for (node, dot) in other.context {
            let slot = self.context.entry(node).or_insert(dot);
            if dot > *slot {
                *slot = dot;
            }
        }
        self.live = merged;
    }
}

// ── DocumentData (LWW-Map) ────────────────────────────────────────────────────

/// Per-field last-writer-wins map for arbitrary document metadata.
///
/// Each key is associated with a [`LWWReg`] whose marker is an
/// [`HlcTimestamp`].  On merge, for every key present in both maps the entry
/// with the greater (later) timestamp wins; keys present in only one map are
/// preserved as-is.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DocumentData(BTreeMap<String, LWWReg<Value, HlcTimestamp>>);

impl DocumentData {
    /// Create an empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set `key` to `value`, witnessed by `timestamp`.
    ///
    /// If the key already exists and `timestamp` is not strictly greater than
    /// the stored timestamp the call is a no-op (stale write).
    pub fn set(&mut self, key: String, value: Value, timestamp: HlcTimestamp) {
        self.0
            .entry(key)
            .or_insert_with(|| LWWReg {
                val: Value::Null,
                marker: HlcTimestamp::default(),
            })
            .update(value, timestamp);
    }

    /// Returns the current value for `key`, if any.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.get(key).map(|r| &r.val)
    }

    /// Returns an iterator over all `(key, value)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.0.iter().map(|(k, r)| (k.as_str(), &r.val))
    }

    /// Merge another map into this one.
    ///
    /// For each key present in both maps the entry with the greater timestamp
    /// wins; entries present in only one map are simply adopted.
    pub fn merge(&mut self, other: Self) {
        for (key, reg) in other.0 {
            self.0
                .entry(key)
                .or_insert_with(|| LWWReg {
                    val: Value::Null,
                    marker: HlcTimestamp::default(),
                })
                .update(reg.val, reg.marker);
        }
    }
}

// ── ActiveKey (Max-Register) ──────────────────────────────────────────────────

/// The ordering marker for the active-key max-register.
///
/// Comparison order: primary key is the rotation sequence number `seq`
/// (higher = newer); on equal `seq` the tie is broken by the BLAKE3 hash of
/// the key reference (deterministic, replica-independent).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ActiveKeyMarker {
    /// Rotation sequence number — monotonically increasing per DID.
    pub seq: u64,
    /// BLAKE3 hash of the key reference string, used for tiebreaking.
    pub key_hash: [u8; 32],
}

impl ActiveKeyMarker {
    /// Construct a marker by hashing `key_ref` with BLAKE3.
    pub fn new(seq: u64, key_ref: &str) -> Self {
        Self {
            seq,
            key_hash: *blake3::hash(key_ref.as_bytes()).as_bytes(),
        }
    }
}

/// Max-Register holding the currently-active key reference.
///
/// The key reference with the highest (`seq`, `key_hash`) marker wins.
/// An absent active key (no rotation has occurred yet) is represented as
/// `None`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActiveKey(LWWReg<Option<String>, ActiveKeyMarker>);

impl Default for ActiveKey {
    fn default() -> Self {
        Self(LWWReg {
            val: None,
            marker: ActiveKeyMarker::default(),
        })
    }
}

impl ActiveKey {
    /// Create a register with no active key.
    pub fn new() -> Self {
        Self::default()
    }

    /// Rotate to `key_ref` at rotation sequence `seq`.
    ///
    /// No-op if `(seq, hash(key_ref))` does not exceed the stored marker
    /// (stale or duplicate rotation).
    pub fn rotate(&mut self, seq: u64, key_ref: String) {
        let marker = ActiveKeyMarker::new(seq, &key_ref);
        self.0.update(Some(key_ref), marker);
    }

    /// Return the currently-active key reference, if any.
    pub fn current(&self) -> Option<&str> {
        self.0.val.as_deref()
    }

    /// Return the rotation sequence number of the stored marker.
    pub fn seq(&self) -> u64 {
        self.0.marker.seq
    }

    /// Merge another `ActiveKey` into this one (higher marker wins).
    pub fn merge(&mut self, other: Self) {
        CvRDT::merge(&mut self.0, other.0);
    }
}

// ── Deactivated (boolean latch) ───────────────────────────────────────────────

/// Boolean latch: once set to `true` the value can never revert to `false`.
///
/// The merge semantics are pure boolean OR — if either replica has observed
/// a deactivation the merged result is deactivated.  This is the simplest
/// CRDT that satisfies the "irreversible" property without requiring a
/// monotonic marker.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Deactivated(bool);

impl Deactivated {
    /// Create a latch in the non-deactivated state.
    pub fn new() -> Self {
        Self(false)
    }

    /// Deactivate — sets the latch to `true` permanently.
    pub fn set(&mut self) {
        self.0 = true;
    }

    /// Returns `true` if the DID has been deactivated.
    pub fn is_set(&self) -> bool {
        self.0
    }

    /// Merge another latch into this one (boolean OR — idempotent).
    pub fn merge(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

// ── AlsoKnownAs (LWW-Register over the whole URI set) ─────────────────────────

/// The `alsoKnownAs` URI set, held as ONE last-writer-wins register.
///
/// A register over the whole set, rather than the grow-set-plus-tombstone-set
/// shape used for verification methods. That difference is deliberate. A 2P-Set
/// can never re-add a removed element, and the application half of this binding
/// (cbcl-bus's WebFinger store) supports reinstating a withdrawn alias. A 2P-Set
/// here would make the two halves asymmetric: a binding the holder withdrew
/// could never be restored, while the authority's could.
///
/// The cost is that concurrent writes from two devices do not union — the later
/// timestamp wins wholesale and the other device's addition is lost. That is
/// recoverable by writing again; a permanently unusable alias would not be.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AlsoKnownAs(LWWReg<Vec<String>, HlcTimestamp>);

impl AlsoKnownAs {
    /// Create an empty alias set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the set, witnessed by `timestamp`.
    ///
    /// Stale writes (a timestamp not strictly greater than the stored one) are
    /// no-ops, matching every other LWW field here.
    ///
    /// The value is canonicalised — sorted and deduplicated — so two replicas
    /// that write the same aliases in different order hold identical state and
    /// therefore produce the same content hash. Without that, `versionId` would
    /// differ between replicas that agree.
    pub fn set(&mut self, mut uris: Vec<String>, timestamp: HlcTimestamp) {
        uris.sort();
        uris.dedup();
        self.0.update(uris, timestamp);
    }

    /// The current alias set, sorted and deduplicated.
    pub fn entries(&self) -> &[String] {
        &self.0.val
    }

    /// Merge another register into this one; the later timestamp wins.
    ///
    /// Uses `update` rather than `CvRDT::merge` for the same reason
    /// [`DocumentData::merge`] does: it is defined for every input, including
    /// the equal-marker-different-value case a hostile or buggy peer can
    /// present.
    pub fn merge(&mut self, other: Self) {
        self.0.update(other.0.val, other.0.marker);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── VerificationMethods ───────────────────────────────────────────────────

    #[test]
    fn gset_insert_and_contains() {
        let mut vm = VerificationMethods::new();
        vm.insert(
            "did:crdt:aa#key-1".into(),
            "zAbc".into(),
            SuiteType::default(),
            default_relationships(),
        );
        assert!(vm.contains_id("did:crdt:aa#key-1"));
        assert!(!vm.contains_id("did:crdt:aa#key-2"));
    }

    #[test]
    fn gset_merge_union() {
        let mut a = VerificationMethods::new();
        a.insert(
            "k1".into(),
            "pub1".into(),
            SuiteType::default(),
            default_relationships(),
        );

        let mut b = VerificationMethods::new();
        b.insert(
            "k2".into(),
            "pub2".into(),
            SuiteType::default(),
            default_relationships(),
        );

        a.merge(b);
        assert!(a.contains_id("k1"));
        assert!(a.contains_id("k2"));
    }

    #[test]
    fn gset_merge_idempotent() {
        let mut a = VerificationMethods::new();
        a.insert(
            "k1".into(),
            "pub1".into(),
            SuiteType::default(),
            default_relationships(),
        );
        let snapshot = a.clone();

        a.merge(snapshot);
        assert_eq!(a.entries().len(), 1);
    }

    #[test]
    fn gset_grow_only_no_remove() {
        let mut a = VerificationMethods::new();
        a.insert(
            "k1".into(),
            "pub1".into(),
            SuiteType::default(),
            default_relationships(),
        );

        let mut b = VerificationMethods::new();
        // B merges A, then A is empty-merged — B still has k1
        b.merge(a.clone());
        b.merge(VerificationMethods::new());
        assert!(b.contains_id("k1"));
    }

    // ── Revocations ───────────────────────────────────────────────────────────

    #[test]
    fn revocations_insert_and_contains() {
        let mut r = Revocations::new();
        r.insert("cred-123".into());
        assert!(r.contains("cred-123"));
        assert!(!r.contains("cred-999"));
    }

    #[test]
    fn revocations_merge_union() {
        let mut a = Revocations::new();
        a.insert("cred-1".into());

        let mut b = Revocations::new();
        b.insert("cred-2".into());

        a.merge(b);
        assert!(a.contains("cred-1"));
        assert!(a.contains("cred-2"));
    }

    #[test]
    fn revocations_merge_idempotent() {
        let mut a = Revocations::new();
        a.insert("cred-1".into());
        let snap = a.clone();
        a.merge(snap);
        assert_eq!(a.entries().len(), 1);
    }

    // ── RevokedVerificationMethods ──────────────────────────────────────────────

    #[test]
    fn revoked_vms_insert_and_contains() {
        let mut r = RevokedVerificationMethods::new();
        r.insert("did:crdt:aa#key-1".into());
        assert!(r.contains("did:crdt:aa#key-1"));
        assert!(!r.contains("did:crdt:aa#key-0"));
    }

    #[test]
    fn revoked_vms_merge_union() {
        let mut a = RevokedVerificationMethods::new();
        a.insert("key-1".into());

        let mut b = RevokedVerificationMethods::new();
        b.insert("key-2".into());

        a.merge(b);
        assert!(a.contains("key-1"));
        assert!(a.contains("key-2"));
    }

    #[test]
    fn revoked_vms_merge_idempotent() {
        let mut a = RevokedVerificationMethods::new();
        a.insert("key-1".into());
        let snap = a.clone();
        a.merge(snap);
        assert_eq!(a.entries().len(), 1);
    }

    // ── ServiceEndpoints ──────────────────────────────────────────────────────

    fn svc(id: &str) -> ServiceEntry {
        ServiceEntry {
            id: id.to_owned(),
            service_type: "LinkedDomains".to_owned(),
            endpoint: "https://example.com".to_owned(),
        }
    }

    /// A dot at wall-clock `w` from node `n` (logical 0).
    fn dot(w: u64, n: u64) -> Dot {
        HlcTimestamp {
            wall_ms: w,
            logical: 0,
            node_id: n,
        }
    }

    #[test]
    fn orswot_add_and_contains() {
        let mut se = ServiceEndpoints::new();
        se.apply_add(svc("svc-1"), dot(1, 1));
        assert!(se.contains_id("svc-1"));
        assert!(!se.contains_id("svc-2"));
    }

    #[test]
    fn orswot_remove_observed_dot() {
        let mut se = ServiceEndpoints::new();
        let a = dot(1, 1);
        se.apply_add(svc("svc-1"), a);
        // The remove observes the add it is cancelling.
        se.apply_remove(&[a], dot(2, 1));
        assert!(!se.contains_id("svc-1"));
    }

    #[test]
    fn orswot_remove_absent_is_noop() {
        let mut se = ServiceEndpoints::new();
        se.apply_remove(&[], dot(1, 1)); // must not panic
        assert!(!se.contains_id("nonexistent"));
    }

    #[test]
    fn orswot_merge_union() {
        let mut a = ServiceEndpoints::new();
        a.apply_add(svc("svc-1"), dot(1, 1));

        let mut b = ServiceEndpoints::new();
        b.apply_add(svc("svc-2"), dot(1, 2));

        a.merge(b);
        assert!(a.contains_id("svc-1"));
        assert!(a.contains_id("svc-2"));
    }

    #[test]
    fn orswot_concurrent_add_wins_over_remove() {
        // A holds svc-1 at dot_a. B concurrently added svc-1 at its own dot_b
        // and removed *that* dot — but never observed dot_a. After merge, dot_a
        // survives because B never witnessed it: add wins.
        let dot_a = dot(1, 1);
        let mut a = ServiceEndpoints::new();
        a.apply_add(svc("svc-1"), dot_a);

        let dot_b = dot(1, 2);
        let mut b = ServiceEndpoints::new();
        b.apply_add(svc("svc-1"), dot_b);
        b.apply_remove(&[dot_b], dot(2, 2));

        a.merge(b);
        assert!(
            a.contains_id("svc-1"),
            "concurrent add must win over a remove that never saw it"
        );
    }

    #[test]
    fn orswot_observed_remove_wins_after_merge() {
        // B observed A's exact dot and removed it. After merge the entry is gone
        // on both sides: a remove that *saw* the add wins.
        let dot_a = dot(1, 1);
        let mut a = ServiceEndpoints::new();
        a.apply_add(svc("svc-1"), dot_a);

        let mut b = ServiceEndpoints::new();
        b.apply_add(svc("svc-1"), dot_a); // B saw the same add…
        b.apply_remove(&[dot_a], dot(2, 2)); // …and removed it.

        a.merge(b);
        assert!(
            !a.contains_id("svc-1"),
            "a remove that observed the add must win"
        );
    }

    #[test]
    fn orswot_merge_is_commutative_and_idempotent() {
        let dot_a = dot(1, 1);
        let dot_b = dot(1, 2);
        let mut a = ServiceEndpoints::new();
        a.apply_add(svc("svc-1"), dot_a);
        let mut b = ServiceEndpoints::new();
        b.apply_add(svc("svc-2"), dot_b);

        let mut ab = a.clone();
        ab.merge(b.clone());
        let mut ba = b.clone();
        ba.merge(a.clone());
        assert_eq!(ab.entries(), ba.entries(), "merge must be commutative");

        let mut abb = ab.clone();
        abb.merge(ab.clone());
        assert_eq!(abb.entries(), ab.entries(), "merge must be idempotent");
    }

    // ── DocumentData ──────────────────────────────────────────────────────────

    fn ts(wall: u64) -> HlcTimestamp {
        HlcTimestamp {
            wall_ms: wall,
            logical: 0,
            node_id: 0,
        }
    }

    #[test]
    fn lwwmap_set_and_get() {
        let mut d = DocumentData::new();
        d.set("name".into(), json!("Alice"), ts(100));
        assert_eq!(d.get("name"), Some(&json!("Alice")));
    }

    #[test]
    fn lwwmap_later_timestamp_wins() {
        let mut d = DocumentData::new();
        d.set("name".into(), json!("Alice"), ts(100));
        d.set("name".into(), json!("Bob"), ts(200));
        assert_eq!(d.get("name"), Some(&json!("Bob")));
    }

    #[test]
    fn lwwmap_earlier_timestamp_is_noop() {
        let mut d = DocumentData::new();
        d.set("name".into(), json!("Bob"), ts(200));
        d.set("name".into(), json!("Alice"), ts(100)); // stale
        assert_eq!(d.get("name"), Some(&json!("Bob")));
    }

    #[test]
    fn lwwmap_merge_takes_higher_timestamp() {
        let mut a = DocumentData::new();
        a.set("x".into(), json!(1), ts(10));

        let mut b = DocumentData::new();
        b.set("x".into(), json!(2), ts(20));

        a.merge(b);
        assert_eq!(a.get("x"), Some(&json!(2)));
    }

    #[test]
    fn lwwmap_merge_preserves_disjoint_keys() {
        let mut a = DocumentData::new();
        a.set("a".into(), json!(1), ts(10));

        let mut b = DocumentData::new();
        b.set("b".into(), json!(2), ts(10));

        a.merge(b);
        assert_eq!(a.get("a"), Some(&json!(1)));
        assert_eq!(a.get("b"), Some(&json!(2)));
    }

    // ── ActiveKey ─────────────────────────────────────────────────────────────

    #[test]
    fn active_key_rotate_and_current() {
        let mut k = ActiveKey::new();
        assert_eq!(k.current(), None);

        k.rotate(1, "did:crdt:aa#key-1".into());
        assert_eq!(k.current(), Some("did:crdt:aa#key-1"));
        assert_eq!(k.seq(), 1);
    }

    #[test]
    fn active_key_higher_seq_wins() {
        let mut k = ActiveKey::new();
        k.rotate(1, "key-1".into());
        k.rotate(2, "key-2".into());
        assert_eq!(k.current(), Some("key-2"));
    }

    #[test]
    fn active_key_stale_rotation_is_noop() {
        let mut k = ActiveKey::new();
        k.rotate(5, "key-5".into());
        k.rotate(3, "key-3".into()); // stale
        assert_eq!(k.current(), Some("key-5"));
    }

    #[test]
    fn active_key_merge_higher_seq_wins() {
        let mut a = ActiveKey::new();
        a.rotate(1, "key-1".into());

        let mut b = ActiveKey::new();
        b.rotate(2, "key-2".into());

        a.merge(b);
        assert_eq!(a.current(), Some("key-2"));
    }

    #[test]
    fn active_key_tiebreak_on_hash() {
        // Two replicas with the same seq — winner is determined by key hash.
        let marker_x = ActiveKeyMarker::new(1, "key-x");
        let marker_y = ActiveKeyMarker::new(1, "key-y");

        let mut a = ActiveKey::new();
        a.0.update(Some("key-x".into()), marker_x);

        let mut b = ActiveKey::new();
        b.0.update(Some("key-y".into()), marker_y);

        a.merge(b.clone());
        b.merge(a.clone());

        // Both replicas must converge to the same value.
        assert_eq!(a.current(), b.current(), "tiebreak must be deterministic");
    }

    // ── Deactivated ───────────────────────────────────────────────────────────

    #[test]
    fn latch_starts_false() {
        assert!(!Deactivated::new().is_set());
    }

    #[test]
    fn latch_set_becomes_true() {
        let mut d = Deactivated::new();
        d.set();
        assert!(d.is_set());
    }

    #[test]
    fn latch_merge_or_semantics() {
        let mut a = Deactivated::new();
        a.set();

        let b = Deactivated::new(); // false

        a.merge(b.clone());
        assert!(a.is_set(), "true merged with false must remain true");

        let mut c = Deactivated::new();
        c.merge(a.clone());
        assert!(c.is_set(), "false merged with true must become true");
    }

    #[test]
    fn latch_merge_idempotent() {
        let mut a = Deactivated::new();
        a.set();
        let snap = a.clone();
        a.merge(snap);
        assert!(a.is_set());
    }
}
