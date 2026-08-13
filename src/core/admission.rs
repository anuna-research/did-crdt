//! Three-valued delta-admission result lattice.
//!
//! This module provides the *pure algebra* behind delta admission: a flat
//! knowledge lattice
//!
//! ```text
//!      Valid          Invalid
//!        \              /
//!         \            /
//!          ⊥ (Unknown)
//! ```
//!
//! with `Unknown` (⊥) below two incomparable top elements.
//!
//! # Why three values
//!
//! Two-valued admission (accept / reject) conflates two distinct situations:
//!
//! 1. **The causal predecessors are not all observed yet.** The decision is
//!    *undecidable* with the current closure, not a violation. This is
//!    [`AdmissionResult::Unknown`], which carries the **missing parent hashes**
//!    so the sync layer knows exactly what to fetch (SPEC-036 REQ-364/366).
//! 2. **The delta is genuinely forbidden** (DID mismatch, document deactivated,
//!    stale rotation, signer revoked in the delta's causal past). This is
//!    [`AdmissionResult::Invalid`].
//!
//! Separating them makes the admission decision *monotone*: as a delta's causal
//! closure `↓D` completes, a result can only move *upward* from `Unknown` to
//! `Valid` or `Invalid`, and a resolved result is stable.
//!
//! # Role under the Merkle DAG
//!
//! Once deltas commit to their causal predecessors (SPEC-036), the **DAG**
//! supplies the monotonicity directly: `↓D` is content-fixed, so the
//! authorisation decision is a query over a frozen set. This lattice is then the
//! *typed, mechanizable codomain* for that query and the algebra
//! ([`AdmissionResult::meet`]) for composing the conjunctive sub-checks
//! (signature ∧ key-present ∧ ¬deactivated ∧ ¬revoked ∧ seq-ok) in an
//! order-independent way. It deliberately provides only `meet` (conjunction):
//! did-crdt has no disjunctive admission rule, so the dual `join` is omitted
//! until one exists (SPEC-035, design note on lattice scope).
//!
//! # Scope
//!
//! This module is the *pure lattice type only*. It introduces **no** new trust
//! decision and changes no admission behaviour on its own; wiring it into the
//! authorisation path (`core::validate`) is a Tier-1 change gated on security
//! review (SPEC-032 §16).

#![forbid(unsafe_code)]

use crate::core::delta::DeltaHash;

/// A stable, terminal reason a delta is not admissible.
///
/// Every variant denotes a decision that does **not** become `Valid` under
/// further delivery. Note that "predecessors not yet observed" is **not** a
/// variant here: that case is [`AdmissionResult::Unknown`], not `Invalid`.
///
/// Under the Merkle DAG (SPEC-036 REQ-363), [`Self::Revoked`] is decided against
/// the delta's content-fixed causal past `↓D`, so it too is monotone — it is no
/// longer the order-dependent residual it was at SPEC-035 Level 0.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum RejectReason {
    /// The delta targets a different DID than the document.
    DidMismatch,
    /// The document's deactivation latch is set; no further mutations admitted.
    Deactivated,
    /// Only `AddVerificationMethod` is permitted on a genesis (empty) document.
    GenesisOpNotAllowed,
    /// The signing key was never introduced anywhere in the delta's (complete)
    /// causal past `↓D`, so no ancestor authorises it.
    SignerNotAuthorised,
    /// A `RotateKey` whose sequence does not exceed the current rotation.
    StaleRotation,
    /// The signing key is revoked within the delta's causal past `↓D`.
    Revoked,
    /// The cryptographic signature did not verify, or key/signature bytes could
    /// not be decoded, or the bound `node_id` did not match the signer.
    BadSignature,
    /// The serialised delta exceeds the per-delta size limit.
    TooLarge,
}

/// Three-valued delta-admission result (SPEC-035 §2, SPEC-036 REQ-363).
///
/// A flat lattice: `Unknown` (⊥) is below both `Valid` and `Invalid`, which are
/// incomparable.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AdmissionResult {
    /// ⊥ — the delta's causal closure is incomplete; undecidable with the
    /// current state. Carries the **missing parent hashes** still needed to
    /// resolve (the fetch list for reconciliation). Resolves *upward* as those
    /// predecessors arrive.
    Unknown(Vec<DeltaHash>),
    /// The signing key is present in `↓D` and not revoked there, and the
    /// operation is permitted.
    Valid,
    /// Terminal, stable rejection.
    Invalid(RejectReason),
}

impl AdmissionResult {
    /// Lattice **meet** (greatest lower bound) — conjunction.
    ///
    /// Composes the conjunctive admission sub-checks with the correct
    /// short-circuit semantics:
    /// - `Invalid ⊓ _ = Invalid` / `_ ⊓ Invalid = Invalid` (absorbing)
    /// - `Unknown ⊓ Unknown = Unknown(missingₐ ∪ missing_b)` (still undecided;
    ///   waiting on the union of both sub-checks' predecessors)
    /// - `Unknown ⊓ Valid = Unknown` (one sub-check undecided)
    /// - `Valid ⊓ Valid = Valid`
    ///
    /// `meet` is commutative, associative, and idempotent (the missing-parent
    /// payload merges as a set union, which has the same laws), so the order in
    /// which sub-checks are combined does not affect the result.
    #[must_use]
    pub fn meet(self, other: AdmissionResult) -> AdmissionResult {
        use AdmissionResult::{Invalid, Unknown, Valid};
        match (self, other) {
            // Both invalid: pick the smaller reason deterministically so meet is
            // commutative (a.meet(b) == b.meet(a)) regardless of operand order.
            (Invalid(a), Invalid(b)) => Invalid(a.min(b)),
            (Invalid(r), _) | (_, Invalid(r)) => Invalid(r),
            (Unknown(mut a), Unknown(b)) => {
                merge_missing(&mut a, b);
                Unknown(a)
            }
            (Unknown(a), Valid) | (Valid, Unknown(a)) => Unknown(a),
            (Valid, Valid) => Valid,
        }
    }

    /// Threshold test (Kuper's LVar threshold read): has the lattice crossed out
    /// of `Unknown` into `{Valid, Invalid}`?
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        !matches!(self, AdmissionResult::Unknown(_))
    }

    /// Stability test — identical to [`Self::is_resolved`]. Once resolved, the
    /// result is permanent under store growth (monotonicity).
    #[must_use]
    pub fn is_stable(&self) -> bool {
        self.is_resolved()
    }

    /// The missing parent hashes if this result is `Unknown`, else empty.
    ///
    /// This is the actionable reconciliation handle: the set of delta hashes the
    /// replica must obtain before the decision can resolve (SPEC-036 REQ-366).
    #[must_use]
    pub fn missing(&self) -> &[DeltaHash] {
        match self {
            AdmissionResult::Unknown(m) => m,
            _ => &[],
        }
    }
}

/// Merge `b` into `a` as a sorted, deduplicated set of missing parent hashes.
fn merge_missing(a: &mut Vec<DeltaHash>, b: Vec<DeltaHash>) {
    a.extend(b);
    a.sort();
    a.dedup();
}

impl PartialOrd for AdmissionResult {
    /// Flat-lattice ordering: `Unknown < Valid`, `Unknown < Invalid`; `Valid`
    /// and `Invalid` are incomparable. Any two `Unknown` values occupy the same
    /// lattice position (`Equal`), as do any two `Invalid` values: the
    /// missing-parent list and the reject reason are diagnostic payloads, not
    /// lattice coordinates.
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        use core::cmp::Ordering;
        use AdmissionResult::{Invalid, Unknown, Valid};
        match (self, other) {
            (Unknown(_), Unknown(_)) | (Valid, Valid) | (Invalid(_), Invalid(_)) => {
                Some(Ordering::Equal)
            }
            (Unknown(_), _) => Some(Ordering::Less),
            (_, Unknown(_)) => Some(Ordering::Greater),
            (Valid, Invalid(_)) | (Invalid(_), Valid) => None,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    fn h(s: &str) -> DeltaHash {
        DeltaHash(s.to_owned())
    }

    /// Representative inhabitants of the lattice carrier. The lattice is finite
    /// up to the (diagnostic-only) payloads, so exhaustive enumeration over
    /// these three values is a complete check of the algebra.
    fn reps() -> Vec<AdmissionResult> {
        vec![
            AdmissionResult::Unknown(vec![]),
            AdmissionResult::Valid,
            // Two distinct Invalid reasons, so the commutativity/associativity
            // checks exercise the both-Invalid arm of meet.
            AdmissionResult::Invalid(RejectReason::Deactivated),
            AdmissionResult::Invalid(RejectReason::Revoked),
        ]
    }

    #[test]
    fn meet_invalid_is_commutative_across_distinct_reasons() {
        let a = AdmissionResult::Invalid(RejectReason::Revoked);
        let b = AdmissionResult::Invalid(RejectReason::Deactivated);
        assert_eq!(
            a.clone().meet(b.clone()),
            b.meet(a),
            "meet must not depend on order"
        );
    }

    // ── lattice laws: meet ──────────────────────────────────────────────────

    #[test]
    fn meet_is_commutative_associative_idempotent() {
        for a in reps() {
            assert_eq!(a.clone().meet(a.clone()), a, "meet idempotent");
            for b in reps() {
                assert_eq!(
                    a.clone().meet(b.clone()),
                    b.clone().meet(a.clone()),
                    "meet commutative"
                );
                for c in reps() {
                    assert_eq!(
                        a.clone().meet(b.clone()).meet(c.clone()),
                        a.clone().meet(b.clone().meet(c.clone())),
                        "meet associative"
                    );
                }
            }
        }
    }

    #[test]
    fn invalid_absorbs_meet() {
        let bad = AdmissionResult::Invalid(RejectReason::Revoked);
        for a in reps() {
            assert!(
                matches!(a.meet(bad.clone()), AdmissionResult::Invalid(_)),
                "Invalid is absorbing for meet"
            );
        }
    }

    #[test]
    fn unknown_meet_unions_missing_parents() {
        let r = AdmissionResult::Unknown(vec![h("aa"), h("bb")])
            .meet(AdmissionResult::Unknown(vec![h("bb"), h("cc")]));
        // Missing parents accumulate as a sorted, deduplicated union.
        assert_eq!(r, AdmissionResult::Unknown(vec![h("aa"), h("bb"), h("cc")]));
    }

    #[test]
    fn unknown_meet_valid_keeps_missing() {
        let r = AdmissionResult::Unknown(vec![h("aa")]).meet(AdmissionResult::Valid);
        assert_eq!(r, AdmissionResult::Unknown(vec![h("aa")]));
        assert_eq!(
            AdmissionResult::Valid.meet(AdmissionResult::Unknown(vec![h("aa")])),
            AdmissionResult::Unknown(vec![h("aa")])
        );
    }

    // ── ordering ────────────────────────────────────────────────────────────

    #[test]
    fn flat_lattice_ordering() {
        use core::cmp::Ordering;
        let unknown = AdmissionResult::Unknown(vec![]);
        let valid = AdmissionResult::Valid;
        let invalid = AdmissionResult::Invalid(RejectReason::DidMismatch);

        assert_eq!(unknown.partial_cmp(&valid), Some(Ordering::Less));
        assert_eq!(unknown.partial_cmp(&invalid), Some(Ordering::Less));
        assert_eq!(valid.partial_cmp(&unknown), Some(Ordering::Greater));
        assert_eq!(invalid.partial_cmp(&unknown), Some(Ordering::Greater));
        // Valid and Invalid are incomparable.
        assert_eq!(valid.partial_cmp(&invalid), None);
        assert_eq!(invalid.partial_cmp(&valid), None);
        // Two Unknowns with different missing sets share a lattice position.
        assert_eq!(
            AdmissionResult::Unknown(vec![h("aa")])
                .partial_cmp(&AdmissionResult::Unknown(vec![h("bb")])),
            Some(Ordering::Equal)
        );
    }

    #[test]
    fn is_resolved_and_missing() {
        assert!(!AdmissionResult::Unknown(vec![h("aa")]).is_resolved());
        assert!(AdmissionResult::Valid.is_resolved());
        assert!(AdmissionResult::Invalid(RejectReason::TooLarge).is_resolved());
        // missing() exposes the fetch list only for Unknown.
        assert_eq!(
            AdmissionResult::Unknown(vec![h("aa")]).missing(),
            &[h("aa")]
        );
        assert!(AdmissionResult::Valid.missing().is_empty());
        for a in reps() {
            assert_eq!(a.is_resolved(), a.is_stable());
        }
    }

    // ── monotone presence model (SPEC-036 REQ-363, presence component) ───────
    //
    // A toy admission decision over the monotone presence component: a delta is
    // `Unknown` (with the introducing key's hash as the missing parent) until
    // that key is observed, then `Valid`. Models the property the paper claims —
    // admission moves only upward as the closure completes — without touching
    // the Tier-1 trust path.

    fn verify_presence(key: &str, observed: &BTreeSet<String>) -> AdmissionResult {
        if observed.contains(key) {
            AdmissionResult::Valid
        } else {
            AdmissionResult::Unknown(vec![h(key)])
        }
    }

    #[test]
    fn presence_resolves_upward() {
        let key = "did:crdt:abc#key-0".to_owned();
        let empty = BTreeSet::new();
        let mut seen = BTreeSet::new();
        seen.insert(key.clone());

        let before = verify_presence(&key, &empty);
        let after = verify_presence(&key, &seen);
        assert!(!before.is_resolved());
        assert_eq!(after, AdmissionResult::Valid);
        assert!(before < after, "result must move strictly upward");
    }

    proptest! {
        /// Store growth never lowers the admission result: for any key and any
        /// `s1 ⊆ s2`, `verify_presence(key, s1) ≤ verify_presence(key, s2)`.
        /// This is the monotone lattice-homomorphism property for the presence
        /// component (SPEC-036 REQ-363).
        #[test]
        fn presence_is_monotone_under_growth(
            universe in prop::collection::btree_set("[a-z]{1,6}", 0..8),
            extra in prop::collection::btree_set("[a-z]{1,6}", 0..8),
            key in "[a-z]{1,6}",
        ) {
            let s1 = universe.clone();
            let mut s2 = universe;
            s2.extend(extra);

            let r1 = verify_presence(&key, &s1);
            let r2 = verify_presence(&key, &s2);

            prop_assert!(
                r1.partial_cmp(&r2) != Some(core::cmp::Ordering::Greater),
                "presence verify regressed under store growth: {r1:?} -> {r2:?}"
            );
            if r1.is_resolved() {
                prop_assert_eq!(r1, r2, "resolved result not stable under growth");
            }
        }
    }
}
