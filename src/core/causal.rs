//! Causal admission verification (SPEC-036 REQ-363).
//!
//! # Tier-1 status
//!
//! This module implements the causal-authorisation **decision** that the Merkle
//! DAG enables. It is the heart of the trust boundary and therefore Tier-1
//! (SPEC-032 §16): it MUST receive cross-model adversarial review and human
//! domain-expert sign-off before it is wired into the live admission path
//! (`Document::merge` / `core::validate::check_authorisation`).
//!
//! It is deliberately provided here as a **self-contained, side-effect-free
//! function over the DAG**, leaving the existing two-valued trust path
//! untouched. Integrating it (sourcing signature keys from `↓D`, composing with
//! the local signature / DID-match / size / `RotateKey` sequence checks via
//! `AdmissionResult::meet`, and replacing `check_authorisation`) is the
//! review-gated follow-up.
//!
//! # What it decides
//!
//! Given a delta `D` and the DAG it lands in, [`verify_causal`] answers, against
//! `D`'s content-fixed causal past `↓D` (not current state):
//!
//! - **`Unknown(missing)`** — `↓D` is incomplete; the listed ancestors must be
//!   fetched before the decision can resolve.
//! - **`Invalid(Revoked)`** — a revocation of the signing key is in `↓D`.
//! - **`Invalid(Deactivated)`** — a deactivation is in `↓D`.
//! - **`Invalid(SignerNotAuthorised)`** — `↓D` is complete and never introduced
//!   the signing key.
//! - **`Valid`** — `↓D` is complete, introduces the signing key, and contains
//!   neither its revocation nor a deactivation.
//!
//! Because `↓D` is content-fixed (REQ-360), this decision is **monotone**:
//! completing the closure moves `Unknown` upward and never reverses a resolved
//! result. A revocation that is *not* in `↓D` (concurrent or later) never
//! affects `D` — "containment, not recovery" — which is what promotes the
//! `Revoked` case from the SPEC-035 §2.2 residual to a monotone decision.
//!
//! This module decides only **causal authorisation**. Signature validity, DID
//! match, the 64 KiB size gate, and the `RotateKey` sequence check are local
//! (non-causal) and are composed in by the caller during integration.

#![forbid(unsafe_code)]

use crate::core::admission::{AdmissionResult, RejectReason};
use crate::core::dag::DeltaDag;
use crate::core::delta::{DeltaHash, DeltaOp, SignedDelta};

/// Decide the causal authorisation of `delta` against its closure in `dag`
/// (SPEC-036 REQ-363). See the module docs for the result semantics.
///
/// `dag` MUST hold (at least) the ancestors of `delta`; `delta` itself need not
/// be inserted. The signing key is taken from
/// `delta.proof.verification_method`.
#[must_use]
pub fn verify_causal(delta: &SignedDelta, dag: &DeltaDag) -> AdmissionResult {
    let signer = delta.proof.verification_method.as_str();

    // Genesis: a delta with no causal predecessors. This is admissible ONLY
    // when the DAG is empty (there is no prior history). A rootless delta on a
    // non-empty DAG is a genesis-impersonation attempt — it would let a
    // self-signed key-add bypass the rule that an existing authorised key must
    // introduce new keys — so it is rejected as ungrounded.
    if delta.parents.is_empty() {
        if !dag.is_empty() {
            return AdmissionResult::Invalid(RejectReason::SignerNotAuthorised);
        }
        // Genuine genesis: the only admissible operation is the
        // self-bootstrapping AddVerificationMethod whose signing key is the very
        // key it introduces.
        return match &delta.op {
            DeltaOp::AddVerificationMethod { id, .. } if id == signer => AdmissionResult::Valid,
            DeltaOp::AddVerificationMethod { .. } => {
                AdmissionResult::Invalid(RejectReason::SignerNotAuthorised)
            }
            _ => AdmissionResult::Invalid(RejectReason::GenesisOpNotAllowed),
        };
    }

    // Single traversal of ↓D collecting the three authorisation facts plus any
    // missing ancestors. A present revocation or deactivation is decisive
    // (stable under further arrivals); otherwise an incomplete closure forces
    // Unknown, because the missing branch could hold a revocation, a
    // deactivation, or the key's introduction.
    let facts = scan_closure(dag, &delta.parents, signer);

    if facts.revoked {
        AdmissionResult::Invalid(RejectReason::Revoked)
    } else if facts.deactivated {
        AdmissionResult::Invalid(RejectReason::Deactivated)
    } else if !facts.missing.is_empty() {
        AdmissionResult::Unknown(facts.missing)
    } else if !facts.signer_added {
        // Complete closure that never introduced the signing key.
        AdmissionResult::Invalid(RejectReason::SignerNotAuthorised)
    } else {
        AdmissionResult::Valid
    }
}

/// Authorisation facts gathered from a single pass over `↓D`.
struct ClosureFacts {
    /// The signing key is introduced by some ancestor.
    signer_added: bool,
    /// The signing key is revoked by some (present) ancestor.
    revoked: bool,
    /// Some (present) ancestor deactivates the DID.
    deactivated: bool,
    /// Ancestors referenced but not present (sorted, deduplicated).
    missing: Vec<DeltaHash>,
}

/// One depth-first pass over the closure reachable from `parents`, collecting
/// authorisation facts about `signer`. Unlike three separate
/// [`DeltaDag::closure_find`] calls, this visits each ancestor once.
fn scan_closure(dag: &DeltaDag, parents: &[DeltaHash], signer: &str) -> ClosureFacts {
    use std::collections::HashSet;

    let mut stack: Vec<DeltaHash> = parents.to_vec();
    let mut visited: HashSet<DeltaHash> = HashSet::new();
    let mut facts = ClosureFacts {
        signer_added: false,
        revoked: false,
        deactivated: false,
        missing: Vec::new(),
    };

    while let Some(h) = stack.pop() {
        if !visited.insert(h.clone()) {
            continue;
        }
        match dag.get(&h) {
            None => facts.missing.push(h),
            Some(d) => {
                match &d.op {
                    DeltaOp::AddVerificationMethod { id, .. } if id == signer => {
                        facts.signer_added = true;
                    }
                    DeltaOp::RevokeVerificationMethod { key_id } if key_id == signer => {
                        facts.revoked = true;
                    }
                    DeltaOp::Deactivate => facts.deactivated = true,
                    _ => {}
                }
                for p in &d.parents {
                    if !visited.contains(p) {
                        stack.push(p.clone());
                    }
                }
            }
        }
    }

    facts.missing.sort();
    facts.missing.dedup();
    facts
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::dag::DeltaDag;
    use crate::core::delta::{default_relationships, SigningKey, SuiteType};
    use crate::core::did::Did;
    use crate::core::hlc::HlcTimestamp;
    use ed25519_dalek::SigningKey as DalekKey;

    fn did() -> Did {
        format!("did:crdt:{}", "a".repeat(64)).parse().unwrap()
    }

    fn key0() -> String {
        format!("{}#key-0", did())
    }

    fn signing() -> SigningKey {
        SigningKey::Ed25519(DalekKey::from_bytes(&[5u8; 32]))
    }

    /// A delta signed by `key-0` with the given op and parents.
    fn signed(op: DeltaOp, parents: Vec<DeltaHash>, n: u64) -> SignedDelta {
        let ts = HlcTimestamp {
            wall_ms: n,
            logical: 0,
            node_id: 1,
        };
        SignedDelta::new_with_parents(did(), op, ts, parents, key0(), &signing()).unwrap()
    }

    /// The genesis AddVerificationMethod that introduces `key-0`.
    fn genesis_op() -> DeltaOp {
        DeltaOp::AddVerificationMethod {
            id: key0(),
            public_key_multibase: "uKey".to_owned(),
            suite_type: SuiteType::default(),
            relationships: default_relationships(),
        }
    }

    #[test]
    fn genesis_self_bootstrap_is_valid() {
        let g = signed(genesis_op(), vec![], 0);
        let dag = DeltaDag::new();
        assert_eq!(verify_causal(&g, &dag), AdmissionResult::Valid);
    }

    #[test]
    fn rootless_delta_on_nonempty_dag_is_rejected() {
        // A parents-less self-signed AddVerificationMethod is genesis ONLY on an
        // empty DAG. On a populated DAG it must NOT be admitted (would bypass
        // "an existing key authorises new keys").
        let mut dag = DeltaDag::new();
        dag.insert(signed(genesis_op(), vec![], 0)).unwrap();
        // Same self-signed genesis-shaped delta, but the DAG is now non-empty.
        let rootless = signed(genesis_op(), vec![], 9);
        assert_eq!(
            verify_causal(&rootless, &dag),
            AdmissionResult::Invalid(RejectReason::SignerNotAuthorised)
        );
    }

    #[test]
    fn genesis_non_add_is_rejected() {
        let g = signed(DeltaOp::Deactivate, vec![], 0);
        let dag = DeltaDag::new();
        assert_eq!(
            verify_causal(&g, &dag),
            AdmissionResult::Invalid(RejectReason::GenesisOpNotAllowed)
        );
    }

    #[test]
    fn key_added_in_closure_is_valid() {
        let mut dag = DeltaDag::new();
        let g = signed(genesis_op(), vec![], 0);
        let gh = dag.insert(g).unwrap();
        // A later op signed by key-0, with genesis in its past.
        let d = signed(
            DeltaOp::RevokeCredential {
                credential_id: "c".into(),
            },
            vec![gh],
            1,
        );
        assert_eq!(verify_causal(&d, &dag), AdmissionResult::Valid);
    }

    #[test]
    fn revocation_in_causal_past_is_invalid() {
        // genesis(add key-0) <- revoke(key-0) <- D(signed by key-0)
        let mut dag = DeltaDag::new();
        let g = signed(genesis_op(), vec![], 0);
        let gh = dag.insert(g).unwrap();
        let r = signed(
            DeltaOp::RevokeVerificationMethod { key_id: key0() },
            vec![gh],
            1,
        );
        let rh = dag.insert(r).unwrap();
        let d = signed(DeltaOp::Deactivate, vec![rh], 2);
        assert_eq!(
            verify_causal(&d, &dag),
            AdmissionResult::Invalid(RejectReason::Revoked),
            "a revocation in ↓D must reject the delta"
        );
    }

    #[test]
    fn concurrent_revocation_not_in_past_does_not_affect_delta() {
        // genesis <- D            (D's past: {genesis})
        // genesis <- revoke       (concurrent with D, NOT in ↓D)
        // Containment, not recovery: D stays Valid.
        let mut dag = DeltaDag::new();
        let g = signed(genesis_op(), vec![], 0);
        let gh = dag.insert(g).unwrap();
        let d = signed(
            DeltaOp::RevokeCredential {
                credential_id: "c".into(),
            },
            vec![gh.clone()],
            1,
        );
        let _revoke = dag
            .insert(signed(
                DeltaOp::RevokeVerificationMethod { key_id: key0() },
                vec![gh],
                2,
            ))
            .unwrap();
        assert_eq!(verify_causal(&d, &dag), AdmissionResult::Valid);
    }

    #[test]
    fn incomplete_closure_is_unknown_with_missing() {
        // D references a parent the DAG does not hold.
        let dag = DeltaDag::new();
        let missing = DeltaHash("deadbeef".into());
        let d = signed(DeltaOp::Deactivate, vec![missing.clone()], 1);
        assert_eq!(
            verify_causal(&d, &dag),
            AdmissionResult::Unknown(vec![missing])
        );
    }

    #[test]
    fn unknown_resolves_to_valid_when_ancestor_arrives() {
        // Build genesis, but verify D before inserting genesis, then after.
        let g = signed(genesis_op(), vec![], 0);
        let gh = g.content_hash().unwrap();
        let d = signed(
            DeltaOp::RevokeCredential {
                credential_id: "c".into(),
            },
            vec![gh.clone()],
            1,
        );

        let mut dag = DeltaDag::new();
        // Before the ancestor arrives: Unknown, asking for genesis.
        assert_eq!(
            verify_causal(&d, &dag),
            AdmissionResult::Unknown(vec![gh.clone()])
        );
        // After it arrives: resolves upward to Valid (monotone).
        dag.insert(g).unwrap();
        assert_eq!(verify_causal(&d, &dag), AdmissionResult::Valid);
    }

    #[test]
    fn complete_closure_without_signer_is_unauthorised() {
        // Genesis introduces a *different* key; D is signed by key-0, which is
        // never added in its complete past.
        let other_genesis = DeltaOp::AddVerificationMethod {
            id: format!("{}#key-9", did()),
            public_key_multibase: "uKey".to_owned(),
            suite_type: SuiteType::default(),
            relationships: default_relationships(),
        };
        let mut dag = DeltaDag::new();
        let g = signed(other_genesis, vec![], 0);
        let gh = dag.insert(g).unwrap();
        let d = signed(DeltaOp::Deactivate, vec![gh], 1);
        assert_eq!(
            verify_causal(&d, &dag),
            AdmissionResult::Invalid(RejectReason::SignerNotAuthorised)
        );
    }

    #[test]
    fn deactivation_in_past_is_invalid() {
        let mut dag = DeltaDag::new();
        let g = signed(genesis_op(), vec![], 0);
        let gh = dag.insert(g).unwrap();
        let deact = signed(DeltaOp::Deactivate, vec![gh], 1);
        let dh = dag.insert(deact).unwrap();
        let d = signed(
            DeltaOp::RevokeCredential {
                credential_id: "c".into(),
            },
            vec![dh],
            2,
        );
        assert_eq!(
            verify_causal(&d, &dag),
            AdmissionResult::Invalid(RejectReason::Deactivated)
        );
    }
}
