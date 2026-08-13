//! Anti-entropy reconciliation over the delta Merkle DAG (SPEC-036 REQ-365/366).
//!
//! Two replicas converge by exchanging **frontiers** and transferring
//! **causal-closure bundles** for the deltas the other lacks. This is pure data
//! movement built on [`DeltaDag`] — it carries **no authorisation semantics**
//! (the admission decision is `core::causal`, Tier-1). Merge is set union over
//! the DAG: commutative, associative, idempotent.
//!
//! # Tamper-evidence
//!
//! A bundle is as trustworthy as the Merkle DAG: altering any delta changes its
//! content hash, so a child that referenced the original now dangles and
//! [`DeltaDag::merge_bundle`] rejects the bundle. A bundle does **not** prove it
//! is the *only* history — an adversary may omit concurrent branches — but
//! completeness within the bundle (no dangling references, given what the
//! receiver already holds) is verifiable.

#![forbid(unsafe_code)]

use std::collections::HashSet;

use crate::core::dag::DeltaDag;
use crate::core::delta::{DeltaHash, SignedDelta};
use crate::core::{Error, Result};

/// A self-verifying slice of history: the deltas in `↓target` (plus `target`)
/// that the recipient is expected to lack (SPEC-036 REQ-365).
///
/// When produced with a non-empty `stop` set (the recipient's frontier), the
/// bundle is pruned to the deltas *between* `target` and what the recipient
/// already holds — transfer proportional to the divergence, not the history.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClosureBundle {
    /// The head delta this bundle was extracted for.
    pub target: DeltaHash,
    /// The deltas carried. Order is unspecified; [`DeltaDag::merge_bundle`]
    /// applies them order-independently.
    pub deltas: Vec<SignedDelta>,
}

impl DeltaDag {
    /// The hashes this replica needs after a frontier exchange (REQ-366): the
    /// advertised `remote_frontier` hashes it does not hold, **plus** its own
    /// incomplete ancestors — hashes referenced as a parent but not yet held.
    ///
    /// The second set matters when a child arrived before its parents: this
    /// replica holds the advertised frontier hash but its closure is still
    /// incomplete, so a frontier-only diff would request nothing and the absent
    /// ancestors would never be fetched, leaving future deltas pending.
    #[must_use]
    pub fn missing_from_frontier(&self, remote_frontier: &[DeltaHash]) -> Vec<DeltaHash> {
        let mut m: Vec<DeltaHash> = remote_frontier
            .iter()
            .filter(|h| !self.contains(h))
            .cloned()
            .collect();
        m.extend(self.incomplete_ancestors());
        m.sort();
        m.dedup();
        m
    }

    /// Extract the causal-closure bundle for `target`, omitting any branch the
    /// recipient already has (`stop`, typically the recipient's frontier).
    ///
    /// Traversal descends from `target` through `parents` but never enters a
    /// `stop` hash (the recipient holds it and its closure), yielding a bundle
    /// proportional to the divergence (REQ-365/366).
    ///
    /// # Errors
    ///
    /// [`Error::DeltaRejected`] if `target` or a required ancestor is not held
    /// (the local closure is incomplete, so no sound bundle can be built).
    pub fn extract_closure(&self, target: &DeltaHash, stop: &[DeltaHash]) -> Result<ClosureBundle> {
        let stop: HashSet<&DeltaHash> = stop.iter().collect();
        let mut visited: HashSet<DeltaHash> = HashSet::new();
        let mut deltas: Vec<SignedDelta> = Vec::new();
        let mut stack: Vec<DeltaHash> = vec![target.clone()];

        while let Some(h) = stack.pop() {
            if stop.contains(&h) || !visited.insert(h.clone()) {
                continue;
            }
            let d = self.get(&h).ok_or_else(|| {
                Error::DeltaRejected(format!("cannot extract closure: missing delta {h}"))
            })?;
            deltas.push(d.clone());
            for p in &d.parents {
                if !visited.contains(p) {
                    stack.push(p.clone());
                }
            }
        }

        Ok(ClosureBundle {
            target: target.clone(),
            deltas,
        })
    }

    /// The held deltas a peer advertising `peer_frontier` is missing: this
    /// replica's history minus the peer's causal closure (SPEC-036 REQ-366,
    /// frontier exchange + closure transfer). Cost is proportional to the
    /// divergence, not the whole history; an empty result means the peer is
    /// already up to date. The responder side of reconciliation.
    ///
    /// # Errors
    ///
    /// [`Error::DeltaRejected`] if a local head is unexpectedly absent, or
    /// [`Error::Serialisation`] if a delta cannot be hashed.
    pub fn deltas_for_peer(&self, peer_frontier: &[DeltaHash]) -> Result<Vec<SignedDelta>> {
        let mut seen: HashSet<DeltaHash> = HashSet::new();
        let mut out: Vec<SignedDelta> = Vec::new();
        for head in self.frontier() {
            // Skip heads the peer already holds (nothing new above them).
            if peer_frontier.contains(&head) {
                continue;
            }
            for d in self.extract_closure(&head, peer_frontier)?.deltas {
                if seen.insert(d.content_hash()?) {
                    out.push(d);
                }
            }
        }
        Ok(out)
    }

    /// Verify and merge a bundle into this DAG, returning the number of deltas
    /// newly added (REQ-365). Idempotent: deltas already held are skipped.
    ///
    /// Verification: every parent of every bundled delta must resolve either
    /// within the bundle or in the deltas already held. A dangling reference
    /// means the bundle was tampered with or is missing a branch the receiver
    /// also lacks; the merge is rejected and the DAG is left unchanged.
    ///
    /// # Errors
    ///
    /// [`Error::DeltaRejected`] on a dangling parent; [`Error::Serialisation`]
    /// if a delta cannot be hashed.
    pub fn merge_bundle(&mut self, bundle: &ClosureBundle) -> Result<usize> {
        // Every delta the bundle carries, by its own content hash.
        let mut bundle_hashes: HashSet<DeltaHash> = HashSet::new();
        for d in &bundle.deltas {
            bundle_hashes.insert(d.content_hash()?);
        }
        // The bundle MUST actually contain its claimed target. Without this, a
        // tampered target (its content hash changed, but it is a leaf so nothing
        // references it) would be accepted under the requested hash, defeating
        // the bundle's tamper-evidence.
        if !bundle_hashes.contains(&bundle.target) {
            return Err(Error::DeltaRejected(format!(
                "bundle does not contain its target {}",
                bundle.target
            )));
        }
        // No bundled delta may reference a parent that resolves neither in the
        // bundle nor in what we already hold.
        for d in &bundle.deltas {
            for p in &d.parents {
                if !self.contains(p) && !bundle_hashes.contains(p) {
                    return Err(Error::DeltaRejected(format!(
                        "bundle has a dangling parent {p}: tampered or incomplete"
                    )));
                }
            }
        }
        let before = self.len();
        for d in &bundle.deltas {
            self.insert(d.clone())?;
        }
        Ok(self.len() - before)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::dag::DeltaDag;
    use crate::core::delta::{DeltaOp, SignedDelta, SigningKey};
    use crate::core::did::Did;
    use crate::core::hlc::HlcTimestamp;
    use ed25519_dalek::SigningKey as DalekKey;

    fn did() -> Did {
        format!("did:crdt:{}", "a".repeat(64)).parse().unwrap()
    }

    fn signed(op: DeltaOp, parents: Vec<DeltaHash>, n: u64) -> SignedDelta {
        let vm = format!("{}#key-0", did());
        let ts = HlcTimestamp {
            wall_ms: n,
            logical: 0,
            node_id: 1,
        };
        let key = SigningKey::Ed25519(DalekKey::from_bytes(&[5u8; 32]));
        SignedDelta::new_with_parents(did(), op, ts, parents, vm, &key).unwrap()
    }

    fn rc(id: &str) -> DeltaOp {
        DeltaOp::RevokeCredential {
            credential_id: id.to_owned(),
        }
    }

    /// genesis <- a <- b chain; returns (dag, [hg, ha, hb]).
    fn chain() -> (DeltaDag, Vec<DeltaHash>) {
        use crate::core::delta::{default_relationships, SuiteType};
        let mut dag = DeltaDag::new();
        let g = signed(
            DeltaOp::AddVerificationMethod {
                id: format!("{}#key-0", did()),
                public_key_multibase: "uKey".to_owned(),
                suite_type: SuiteType::default(),
                relationships: default_relationships(),
            },
            vec![],
            0,
        );
        let hg = dag.insert(g).unwrap();
        let a = signed(rc("a"), vec![hg.clone()], 1);
        let ha = dag.insert(a).unwrap();
        let b = signed(rc("b"), vec![ha.clone()], 2);
        let hb = dag.insert(b).unwrap();
        (dag, vec![hg, ha, hb])
    }

    #[test]
    fn extract_full_closure_round_trips() {
        let (src, hs) = chain();
        let bundle = src.extract_closure(&hs[2], &[]).unwrap();
        assert_eq!(bundle.deltas.len(), 3, "full closure of head = whole chain");

        let mut dst = DeltaDag::new();
        let added = dst.merge_bundle(&bundle).unwrap();
        assert_eq!(added, 3);
        assert_eq!(dst.frontier(), vec![hs[2].clone()]);
    }

    #[test]
    fn extract_stops_at_recipient_frontier() {
        let (src, hs) = chain();
        // Recipient already holds up to `a` (frontier = {ha}); only `b` is new.
        let bundle = src.extract_closure(&hs[2], &[hs[1].clone()]).unwrap();
        assert_eq!(
            bundle.deltas.len(),
            1,
            "diff-proportional: only the new delta"
        );
        assert_eq!(bundle.deltas[0].content_hash().unwrap(), hs[2]);
    }

    #[test]
    fn merge_pruned_bundle_resolves_against_local_store() {
        let (src, hs) = chain();
        // Receiver has genesis + a; gets pruned bundle for head b.
        let mut dst = DeltaDag::new();
        dst.insert(src.get(&hs[0]).unwrap().clone()).unwrap();
        dst.insert(src.get(&hs[1]).unwrap().clone()).unwrap();
        let bundle = src.extract_closure(&hs[2], &dst.frontier()).unwrap();
        let added = dst.merge_bundle(&bundle).unwrap();
        assert_eq!(added, 1);
        assert_eq!(dst.frontier(), vec![hs[2].clone()]);
    }

    #[test]
    fn merge_bundle_is_idempotent() {
        let (src, hs) = chain();
        let bundle = src.extract_closure(&hs[2], &[]).unwrap();
        let mut dst = DeltaDag::new();
        assert_eq!(dst.merge_bundle(&bundle).unwrap(), 3);
        assert_eq!(
            dst.merge_bundle(&bundle).unwrap(),
            0,
            "re-merge adds nothing"
        );
    }

    #[test]
    fn tampered_delta_is_rejected_as_dangling() {
        let (src, hs) = chain();
        let mut bundle = src.extract_closure(&hs[2], &[]).unwrap();
        // Tamper: mutate the middle delta's op. Its content hash now differs, so
        // the child that referenced the original hash dangles.
        for d in &mut bundle.deltas {
            if let DeltaOp::RevokeCredential { credential_id } = &d.op {
                if credential_id == "a" {
                    d.op = rc("TAMPERED");
                }
            }
        }
        let mut dst = DeltaDag::new();
        let err = dst.merge_bundle(&bundle).unwrap_err();
        assert!(
            matches!(err, Error::DeltaRejected(_)),
            "tamper must be rejected"
        );
    }

    #[test]
    fn tampered_target_is_rejected() {
        // Mutating the target (a leaf) changes its content hash but leaves all
        // its parent references valid and nothing references it — so only the
        // explicit target-membership check catches it.
        let (src, hs) = chain();
        let mut bundle = src.extract_closure(&hs[2], &[]).unwrap();
        let target = hs[2].clone();
        for d in &mut bundle.deltas {
            if d.content_hash().unwrap() == target {
                d.op = rc("TAMPERED-TARGET");
            }
        }
        let mut dst = DeltaDag::new();
        let err = dst.merge_bundle(&bundle).unwrap_err();
        assert!(
            matches!(err, Error::DeltaRejected(_)),
            "tampered target must be rejected"
        );
    }

    #[test]
    fn missing_from_frontier_includes_incomplete_ancestors() {
        // A child held with an absent parent: even if the peer advertises only
        // the child (which we hold), we must still request the absent ancestor.
        let mut dag = DeltaDag::new();
        let absent = DeltaHash("absent000".into());
        let child = signed(rc("child"), vec![absent.clone()], 1);
        let child_hash = dag.insert(child).unwrap();

        let missing = dag.missing_from_frontier(&[child_hash]);
        assert!(
            missing.contains(&absent),
            "must request the absent ancestor behind the held child"
        );
    }

    #[test]
    fn extract_missing_target_errors() {
        let dag = DeltaDag::new();
        let err = dag
            .extract_closure(&DeltaHash("nope".into()), &[])
            .unwrap_err();
        assert!(matches!(err, Error::DeltaRejected(_)));
    }

    #[test]
    fn two_replicas_reconcile_to_convergence() {
        // A and B share genesis, then diverge on concurrent branches; after a
        // bidirectional frontier exchange + bundle transfer they converge.
        use crate::core::delta::{default_relationships, SuiteType};
        let g = signed(
            DeltaOp::AddVerificationMethod {
                id: format!("{}#key-0", did()),
                public_key_multibase: "uKey".to_owned(),
                suite_type: SuiteType::default(),
                relationships: default_relationships(),
            },
            vec![],
            0,
        );
        let hg = g.content_hash().unwrap();

        let mut a = DeltaDag::new();
        let mut b = DeltaDag::new();
        a.insert(g.clone()).unwrap();
        b.insert(g).unwrap();

        // A adds its own delta; B adds a concurrent one.
        a.insert(signed(rc("from-a"), vec![hg.clone()], 1)).unwrap();
        b.insert(signed(rc("from-b"), vec![hg.clone()], 2)).unwrap();

        // Exchange frontiers and reconcile both directions.
        let a_needs = a.missing_from_frontier(&b.frontier());
        for h in &a_needs {
            let bundle = b.extract_closure(h, &a.frontier()).unwrap();
            a.merge_bundle(&bundle).unwrap();
        }
        let b_needs = b.missing_from_frontier(&a.frontier());
        for h in &b_needs {
            let bundle = a.extract_closure(h, &b.frontier()).unwrap();
            b.merge_bundle(&bundle).unwrap();
        }

        // Converged: identical size and frontier.
        assert_eq!(a.len(), 3);
        assert_eq!(b.len(), 3);
        let mut fa = a.frontier();
        let mut fb = b.frontier();
        fa.sort();
        fb.sort();
        assert_eq!(fa, fb, "replicas must converge to the same frontier");
    }
}
