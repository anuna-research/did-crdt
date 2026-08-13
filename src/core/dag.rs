//! Delta Merkle DAG: a hash-indexed store with frontier tracking and causal
//! closure queries (SPEC-036 REQ-360/362/364).
//!
//! This module is **pure graph machinery** and carries **no authorisation
//! semantics**: it answers "what is reachable via `parents`" and "which
//! ancestors am I missing," but it never decides whether a delta is admissible.
//! That decision (Tier-1) lives in `core::validate` and is driven by
//! [`DeltaDag::closure_find`] with an authorisation predicate supplied by the
//! caller (SPEC-036 REQ-363, Increment 4).
//!
//! # Frontier
//!
//! The *frontier* is the set of held delta hashes that no held delta references
//! as a parent — the DAG's leaves. It is the handle for anti-entropy
//! reconciliation (REQ-366) and the `parents` set a new local delta commits to.
//! Frontier maintenance is order-independent: a delta may arrive before or after
//! its children and the frontier converges either way.
//!
//! # Causal closure and completeness
//!
//! The causal closure `↓D` is everything reachable from `D`'s parents. Because a
//! delta's hash commits to its parents recursively (REQ-360), `↓D` is
//! content-fixed. A closure is *complete* once every reachable hash is present;
//! [`DeltaDag::closure_find`] reports the still-missing hashes when it is not,
//! which is exactly the payload of `AdmissionResult::Unknown`.

#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::core::delta::{DeltaHash, DeltaOp, SignedDelta};
use crate::core::Result;

/// Outcome of a monotone search over a delta's causal closure.
///
/// The three variants map directly onto the admission lattice
/// (`core::admission`): `Found`/`NotFound` are resolved (stable), `Incomplete`
/// is `Unknown` carrying the missing-parent fetch list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClosureQuery {
    /// The predicate matched a delta in the (present part of the) closure. This
    /// is decisive and stable: a match cannot disappear as more ancestors
    /// arrive, so it short-circuits even if other branches are still missing.
    Found,
    /// The closure is **complete** and the predicate matched nothing.
    NotFound,
    /// The closure is incomplete; the listed ancestor hashes (sorted,
    /// deduplicated) must be obtained before the query can resolve.
    Incomplete(Vec<DeltaHash>),
}

/// A hash-indexed store of signed deltas forming a Merkle DAG.
#[derive(Debug, Default, Clone)]
pub struct DeltaDag {
    by_hash: HashMap<DeltaHash, SignedDelta>,
    /// Union of every held delta's `parents` — i.e. every hash referenced as a
    /// predecessor. The frontier is `keys(by_hash) \ referenced`.
    referenced: HashSet<DeltaHash>,
    frontier: BTreeSet<DeltaHash>,
}

impl DeltaDag {
    /// An empty DAG.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of distinct deltas held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    /// Whether the DAG holds no deltas.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    /// Whether a delta with this hash is held.
    #[must_use]
    pub fn contains(&self, h: &DeltaHash) -> bool {
        self.by_hash.contains_key(h)
    }

    /// Borrow a held delta by hash.
    #[must_use]
    pub fn get(&self, h: &DeltaHash) -> Option<&SignedDelta> {
        self.by_hash.get(h)
    }

    /// The current frontier (DAG leaves), sorted ascending.
    #[must_use]
    pub fn frontier(&self) -> Vec<DeltaHash> {
        self.frontier.iter().cloned().collect()
    }

    /// Whether the DAG holds an `AddVerificationMethod(key_id)` delta. Used to
    /// distinguish a *back-parented* delta — whose signer's authorisation exists
    /// as a delta but was deliberately excluded from `↓D` — from a key known only
    /// through a trusted state-merge import, which has no originating delta in the
    /// DAG (SPEC-036 §1b).
    #[must_use]
    pub fn has_authorising_delta(&self, key_id: &str) -> bool {
        self.by_hash
            .values()
            .any(|d| matches!(&d.op, DeltaOp::AddVerificationMethod { id, .. } if id == key_id))
    }

    /// Whether the DAG holds a `RevokeVerificationMethod(key_id)` delta. Used to
    /// tell a revocation backed by a delta (handled causally — a concurrent delta
    /// is not affected) from one present only via a trusted state-merge import
    /// (which causal cannot see, so the current-state floor must enforce it).
    #[must_use]
    pub fn has_revoking_delta(&self, key_id: &str) -> bool {
        self.by_hash.values().any(
            |d| matches!(&d.op, DeltaOp::RevokeVerificationMethod { key_id: k } if k == key_id),
        )
    }

    /// Whether the DAG holds a `Deactivate` delta. Distinguishes a deactivation
    /// backed by a delta (handled causally) from one imported via state-merge.
    #[must_use]
    pub fn has_deactivate_delta(&self) -> bool {
        self.by_hash
            .values()
            .any(|d| matches!(&d.op, DeltaOp::Deactivate))
    }

    /// Hashes referenced as a parent by some held delta but not held — i.e.
    /// ancestors this replica is still missing. Used by reconciliation to fetch
    /// them even when the advertised frontier hash is already held (SPEC-036
    /// REQ-366).
    #[must_use]
    pub fn incomplete_ancestors(&self) -> Vec<DeltaHash> {
        let mut missing: Vec<DeltaHash> = self
            .referenced
            .iter()
            .filter(|h| !self.by_hash.contains_key(*h))
            .cloned()
            .collect();
        missing.sort();
        missing
    }

    /// Insert a delta, returning its content hash. Idempotent: inserting a delta
    /// already held (by hash) is a no-op (G-Set semantics, REQ-360).
    ///
    /// Frontier maintenance is order-independent (see module docs).
    ///
    /// # Errors
    ///
    /// Returns [`crate::core::Error::Serialisation`] if the delta cannot be
    /// hashed.
    pub fn insert(&mut self, delta: SignedDelta) -> Result<DeltaHash> {
        let h = delta.content_hash()?;
        if self.by_hash.contains_key(&h) {
            return Ok(h);
        }
        // Every parent becomes referenced and therefore leaves the frontier.
        for p in &delta.parents {
            self.referenced.insert(p.clone());
            self.frontier.remove(p);
        }
        // This delta is a leaf unless something already references it.
        if !self.referenced.contains(&h) {
            self.frontier.insert(h.clone());
        }
        self.by_hash.insert(h.clone(), delta);
        Ok(h)
    }

    /// The direct parents of `delta` that are not currently held — the immediate
    /// fetch list (one hop). Transitive gaps are surfaced by
    /// [`Self::closure_find`].
    #[must_use]
    pub fn missing_parents(&self, delta: &SignedDelta) -> Vec<DeltaHash> {
        let mut missing: Vec<DeltaHash> = delta
            .parents
            .iter()
            .filter(|p| !self.by_hash.contains_key(p))
            .cloned()
            .collect();
        missing.sort();
        missing.dedup();
        missing
    }

    /// Whether the full causal closure reachable from `parents` is present.
    #[must_use]
    pub fn closure_complete(&self, parents: &[DeltaHash]) -> bool {
        matches!(
            self.closure_find(parents, |_| false),
            ClosureQuery::NotFound
        )
    }

    /// Search the causal closure reachable from `parents` for a delta satisfying
    /// `pred`, with monotone three-valued semantics (see [`ClosureQuery`]).
    ///
    /// `pred` is applied to *ancestors only* (the deltas in `↓D`); the delta
    /// being admitted is never its own authoriser. A match short-circuits to
    /// `Found` even if other branches are still missing, because a match is
    /// stable under further arrivals — this is what keeps the derived admission
    /// decision monotone (SPEC-036 REQ-363).
    #[must_use]
    pub fn closure_find<F>(&self, parents: &[DeltaHash], pred: F) -> ClosureQuery
    where
        F: Fn(&SignedDelta) -> bool,
    {
        let mut stack: Vec<DeltaHash> = parents.to_vec();
        let mut visited: HashSet<DeltaHash> = HashSet::new();
        let mut missing: Vec<DeltaHash> = Vec::new();

        while let Some(h) = stack.pop() {
            if !visited.insert(h.clone()) {
                continue;
            }
            match self.by_hash.get(&h) {
                None => missing.push(h),
                Some(d) => {
                    if pred(d) {
                        return ClosureQuery::Found;
                    }
                    for p in &d.parents {
                        if !visited.contains(p) {
                            stack.push(p.clone());
                        }
                    }
                }
            }
        }

        if missing.is_empty() {
            ClosureQuery::NotFound
        } else {
            missing.sort();
            missing.dedup();
            ClosureQuery::Incomplete(missing)
        }
    }

    /// Collect every `Some` result of `f` over the deltas in the causal closure
    /// of `parents` (`↓parents`, inclusive of the parents themselves).
    ///
    /// Used to recover the add events a remove *observed*: the observed set is
    /// order-independent and identical on every replica, because `↓parents` is
    /// fixed by the content-addressed parent hashes. Missing ancestors are
    /// skipped; call [`Self::closure_complete`] first if a complete closure is
    /// required.
    #[must_use]
    pub fn closure_collect<T, F>(&self, parents: &[DeltaHash], f: F) -> Vec<T>
    where
        F: Fn(&SignedDelta) -> Option<T>,
    {
        let mut stack: Vec<DeltaHash> = parents.to_vec();
        let mut visited: HashSet<DeltaHash> = HashSet::new();
        let mut out: Vec<T> = Vec::new();

        while let Some(h) = stack.pop() {
            if !visited.insert(h.clone()) {
                continue;
            }
            if let Some(d) = self.by_hash.get(&h) {
                if let Some(t) = f(d) {
                    out.push(t);
                }
                for p in &d.parents {
                    if !visited.contains(p) {
                        stack.push(p.clone());
                    }
                }
            }
        }

        out
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::delta::{DeltaOp, SignedDelta, SigningKey};
    use crate::core::did::Did;
    use crate::core::hlc::HlcTimestamp;
    use ed25519_dalek::SigningKey as DalekKey;

    fn did() -> Did {
        format!("did:crdt:{}", "a".repeat(64)).parse().unwrap()
    }

    fn key() -> SigningKey {
        SigningKey::Ed25519(DalekKey::from_bytes(&[5u8; 32]))
    }

    /// Build a signed delta with the given op and parents. `n` varies the
    /// timestamp so distinct deltas get distinct hashes.
    fn delta(op: DeltaOp, parents: Vec<DeltaHash>, n: u64) -> SignedDelta {
        let d = did();
        let vm = format!("{}#key-0", d);
        let ts = HlcTimestamp {
            wall_ms: n,
            logical: 0,
            node_id: 1,
        };
        SignedDelta::new_with_parents(d, op, ts, parents, vm, &key()).unwrap()
    }

    fn add_vm(id: &str) -> DeltaOp {
        use crate::core::delta::{default_relationships, SuiteType};
        DeltaOp::AddVerificationMethod {
            id: id.to_owned(),
            public_key_multibase: "uKey".to_owned(),
            suite_type: SuiteType::default(),
            relationships: default_relationships(),
        }
    }

    fn revoke_vm(id: &str) -> DeltaOp {
        DeltaOp::RevokeVerificationMethod {
            key_id: id.to_owned(),
        }
    }

    // ── frontier ────────────────────────────────────────────────────────────

    #[test]
    fn frontier_tracks_single_chain() {
        let mut dag = DeltaDag::new();
        let g = delta(add_vm("k0"), vec![], 0);
        let gh = dag.insert(g).unwrap();
        assert_eq!(dag.frontier(), vec![gh.clone()]);

        let c = delta(DeltaOp::Deactivate, vec![gh.clone()], 1);
        let ch = dag.insert(c).unwrap();
        // The child replaces its parent at the frontier.
        assert_eq!(dag.frontier(), vec![ch]);
        assert_eq!(dag.len(), 2);
    }

    #[test]
    fn frontier_is_order_independent() {
        // Insert child before parent; frontier must still converge to {child}.
        let g = delta(add_vm("k0"), vec![], 0);
        let gh = g.content_hash().unwrap();
        let c = delta(
            DeltaOp::RevokeCredential {
                credential_id: "c".into(),
            },
            vec![gh.clone()],
            1,
        );
        let ch = c.content_hash().unwrap();

        let mut dag = DeltaDag::new();
        dag.insert(c).unwrap(); // child first
        dag.insert(g).unwrap(); // parent later
        assert_eq!(dag.frontier(), vec![ch]);
        assert!(!dag.frontier().contains(&gh));
    }

    #[test]
    fn frontier_keeps_concurrent_branches() {
        let mut dag = DeltaDag::new();
        let g = delta(add_vm("k0"), vec![], 0);
        let gh = dag.insert(g).unwrap();
        // Two concurrent children of the same parent: both are leaves.
        let a = delta(
            DeltaOp::RevokeCredential {
                credential_id: "a".into(),
            },
            vec![gh.clone()],
            1,
        );
        let b = delta(
            DeltaOp::RevokeCredential {
                credential_id: "b".into(),
            },
            vec![gh.clone()],
            2,
        );
        let ah = dag.insert(a).unwrap();
        let bh = dag.insert(b).unwrap();
        let mut f = dag.frontier();
        f.sort();
        let mut expected = vec![ah, bh];
        expected.sort();
        assert_eq!(f, expected);
    }

    #[test]
    fn insert_is_idempotent() {
        let mut dag = DeltaDag::new();
        let g = delta(add_vm("k0"), vec![], 0);
        let h1 = dag.insert(g.clone()).unwrap();
        let h2 = dag.insert(g).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(dag.len(), 1);
    }

    // ── closure queries ──────────────────────────────────────────────────────

    #[test]
    fn closure_find_found_in_ancestry() {
        let mut dag = DeltaDag::new();
        let g = delta(add_vm("k0"), vec![], 0);
        let gh = dag.insert(g).unwrap();
        let d = delta(add_vm("k1"), vec![gh.clone()], 1);
        let dh = dag.insert(d).unwrap();

        // Is AddVM("k0") in the closure of the latest delta? Yes (it's the root).
        let q = dag.closure_find(&[dh], |x| {
            matches!(&x.op,
            DeltaOp::AddVerificationMethod { id, .. } if id == "k0")
        });
        assert_eq!(q, ClosureQuery::Found);
    }

    #[test]
    fn closure_find_notfound_when_complete() {
        let mut dag = DeltaDag::new();
        let g = delta(add_vm("k0"), vec![], 0);
        let gh = dag.insert(g).unwrap();

        // Is there a revocation of k0 in this complete closure? No.
        let q = dag.closure_find(&[gh], |x| {
            matches!(&x.op,
            DeltaOp::RevokeVerificationMethod { key_id } if key_id == "k0")
        });
        assert_eq!(q, ClosureQuery::NotFound);
    }

    #[test]
    fn closure_find_incomplete_reports_missing() {
        // A delta whose parent is absent: the query cannot resolve.
        let dag = DeltaDag::new();
        let missing = DeltaHash("deadbeef".into());
        let q = dag.closure_find(std::slice::from_ref(&missing), |_| true);
        assert_eq!(q, ClosureQuery::Incomplete(vec![missing]));
    }

    #[test]
    fn closure_find_found_short_circuits_incomplete_branch() {
        // One parent present and matching, another absent: Found wins, because a
        // match is stable regardless of the missing branch (monotonicity).
        let mut dag = DeltaDag::new();
        let g = delta(revoke_vm("k0"), vec![], 0);
        let gh = dag.insert(g).unwrap();
        let absent = DeltaHash("ffff".into());

        let q = dag.closure_find(&[gh, absent], |x| {
            matches!(&x.op,
            DeltaOp::RevokeVerificationMethod { key_id } if key_id == "k0")
        });
        assert_eq!(q, ClosureQuery::Found);
    }

    #[test]
    fn closure_complete_reflects_presence() {
        let mut dag = DeltaDag::new();
        let g = delta(add_vm("k0"), vec![], 0);
        let gh = dag.insert(g).unwrap();
        let d = delta(DeltaOp::Deactivate, vec![gh.clone()], 1);
        let dh = d.content_hash().unwrap();

        // Closure of d is incomplete until d's parent chain is fully present.
        assert!(dag.closure_complete(&[gh]));
        // d itself not yet inserted, but its parents (gh) are present:
        assert!(dag.closure_complete(&d.parents));
        // A dangling parent makes it incomplete.
        assert!(!dag.closure_complete(&[DeltaHash("nope".into())]));
        let _ = dh;
    }

    #[test]
    fn missing_parents_lists_absent_only() {
        let mut dag = DeltaDag::new();
        let g = delta(add_vm("k0"), vec![], 0);
        let gh = dag.insert(g).unwrap();
        let absent = DeltaHash("aaaa".into());
        let child = delta(DeltaOp::Deactivate, vec![gh.clone(), absent.clone()], 1);
        assert_eq!(dag.missing_parents(&child), vec![absent]);
    }
}
