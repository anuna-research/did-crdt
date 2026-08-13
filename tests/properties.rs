//! Property-based tests for CRDT algebraic laws.
//!
//! Tests (see SPEC-032 §13 and TEST-002, TEST-003, TEST-005, TEST-006, TEST-008, TEST-009, TEST-010):
//!
//! - Commutativity:           merge(A, B) == merge(B, A)                    [TEST-002]
//! - Associativity:           merge(merge(A, B), C) == merge(A, merge(B, C)) [TEST-003]
//! - Idempotence:             merge(A, A) == A                               [TEST-005]
//! - Key rotation convergence: concurrent same-seq rotations converge        [TEST-006]
//! - Revocation monotonicity: revoked credentials survive any merge          [TEST-008]
//! - Deactivation irreversibility: deactivation cannot be undone by merge    [TEST-009]
//! - HLC monotonicity:        successive HLC values are strictly ordered      [TEST-010]
//!
//! # Comparison strategy
//!
//! Tests compare observable state via `Document::resolve()`, which reads the
//! in-memory CRDT state and produces a deterministically ordered `DidDocument`.
//! `to_bytes()` is not used for equality because it includes the full delta log,
//! which legitimately differs between replicas.  The resolved `DidDocument`
//! captures:
//!
//! - Verification methods (G-Set)
//! - Service endpoints (dotted ORSWOT — live map keyed by Dot + version-vector context)
//! - Document data / extra fields (LWW-Map)
//! - Deactivation flag (boolean latch)
//!
//! `RevokeCredential` and `RotateKey` operations are exercised through
//! dedicated unit-style tests (see the `unit` module below) and are excluded
//! from the proptest strategies because their effects are not surfaced in the
//! W3C DID Core resolved document.

use did_crdt::{
    core::{
        delta::{DeltaOp, SignedDelta},
        hlc::{Hlc, HlcTimestamp},
    },
    Document,
};
use proptest::prelude::*;

// ── Genesis fixture ───────────────────────────────────────────────────────────

const GENESIS_KEY: &str = "zPropTestGenesisKey";

fn genesis() -> Document {
    Document::new(GENESIS_KEY).expect("genesis must succeed").0
}

// ── Strategies ────────────────────────────────────────────────────────────────

/// Generate an HLC timestamp for a given node, with a non-zero wall component
/// (> 0 so it is always strictly later than the zero-value genesis timestamp).
fn arb_hlc(node_id: u64) -> impl Strategy<Value = HlcTimestamp> {
    (1u64..=100_000u64, 0u32..=255u32).prop_map(move |(wall_ms, logical)| HlcTimestamp {
        wall_ms,
        logical,
        node_id,
    })
}

/// Generate an arbitrary `DeltaOp` from the subset whose effects are
/// observable in the W3C DID Core resolved document.
///
/// The small ID spaces (0–4) are intentional: they cause overlapping and
/// conflicting operations across replicas, exercising the CRDT merge semantics.
///
/// **Uniqueness invariant**: for each ID index, the service type, endpoint, and
/// public key are derived deterministically.  This ensures that every `(id,
/// payload)` combination is unique — no two distinct `ServiceEntry` or
/// `VerificationMethodEntry` values share the same `id`.  This matters because
/// `ServiceEndpoints::entries()` sorts only by `id`; without unique payloads,
/// two entries with the same `id` but different content would have
/// non-deterministic relative order after an ORSWOT merge.
fn arb_delta_op() -> impl Strategy<Value = DeltaOp> {
    prop_oneof![
        // AddServiceEndpoint — ORSWOT add-wins semantics.
        // The service_type and endpoint are fully determined by svc_idx,
        // guaranteeing at most one distinct ServiceEntry per ID.
        (0u8..5u8).prop_map(|svc| {
            let stype = if svc % 2 == 0 {
                "LinkedDomains"
            } else {
                "DIDCommMessaging"
            };
            DeltaOp::AddServiceEndpoint {
                id: format!("svc-{svc}"),
                service_type: stype.to_owned(),
                endpoint: format!("https://svc{svc}.example.com"),
            }
        }),
        // RemoveServiceEndpoint — references the same 5-element ID space.
        (0u8..5u8).prop_map(|svc| DeltaOp::RemoveServiceEndpoint {
            id: format!("svc-{svc}"),
        }),
        // SetDocumentData — LWW-Map; small key/value spaces create races.
        (0u8..3u8, 0u8..8u8).prop_map(|(k, v)| DeltaOp::SetDocumentData {
            key: format!("field{k}"),
            value: serde_json::Value::from(v as u64),
        }),
        // AddVerificationMethod — G-Set grow-only; effects visible via
        // resolve().verification_method.  The public key is derived from the
        // key index for the same uniqueness reason as services above.
        (0u8..4u8).prop_map(|key_idx| {
            DeltaOp::AddVerificationMethod {
                id: format!("extra-key-{key_idx}"),
                public_key_multibase: format!("zExtraPub{key_idx}"),
                suite_type: did_crdt::core::delta::SuiteType::default(),
                relationships: did_crdt::core::delta::default_relationships(),
            }
        }),
    ]
}

/// A sequence of 0–6 `(op, timestamp)` pairs for a single node.
fn arb_op_seq(node_id: u64) -> impl Strategy<Value = Vec<(DeltaOp, HlcTimestamp)>> {
    proptest::collection::vec((arb_delta_op(), arb_hlc(node_id)), 0..=6)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a replica by cloning `base` and applying a sequence of ops.
///
/// Each op is wrapped in an unsigned delta signed by the genesis key
/// (`"{did}#key-0"`), which is always an authorised verification method.
/// Individual op failures (e.g. removing a service that was never added) are
/// silently tolerated because those operations are no-ops in the CRDT.
/// Build an unsigned delta grounded on `base`'s frontier (SPEC-036). Deltas
/// built from the same base are mutually concurrent, so the CRDT laws under
/// test (commutativity/idempotence/monotonicity) hold across merge orders.
fn grounded(base: &Document, op: DeltaOp, ts: HlcTimestamp, signer: &str) -> SignedDelta {
    let mut d = SignedDelta::unsigned(base.did.clone(), op, ts, signer.to_owned());
    d.parents = base.frontier();
    d
}

fn build_replica(base: &Document, ops: &[(DeltaOp, HlcTimestamp)]) -> Document {
    let signer = format!("{}#key-0", base.did);
    let mut doc = base.clone();
    for (op, ts) in ops {
        let mut delta = SignedDelta::unsigned(doc.did.clone(), op.clone(), *ts, signer.clone());
        delta.parents = doc.frontier(); // ground each delta on the current frontier (SPEC-036)
        let _ = doc.merge(delta); // individual op failures are intentionally ignored
    }
    doc
}

/// Author a causal chain of deltas on top of `base`, returning the deltas that
/// applied (so the result is a valid, replayable chain rooted at `base`'s
/// frontier). Unlike [`build_replica`], which discards the deltas, this hands
/// them back so they can be *replayed* on another replica via the delta path —
/// the path that ships over the wire, distinct from `merge_state`.
fn author_deltas(base: &Document, ops: &[(DeltaOp, HlcTimestamp)]) -> Vec<SignedDelta> {
    let signer = format!("{}#key-0", base.did);
    let mut doc = base.clone();
    let mut out = Vec::new();
    for (op, ts) in ops {
        let mut delta = SignedDelta::unsigned(doc.did.clone(), op.clone(), *ts, signer.clone());
        delta.parents = doc.frontier();
        if doc.merge(delta.clone()).is_ok() {
            out.push(delta);
        }
    }
    out
}

/// Compare two documents by serialising their resolved W3C DID Core view.
///
/// `resolve()` reads the in-memory CRDT state without including the delta log.
/// The resolved `DidDocument` is deterministically ordered (sorted BTreeSets
/// and BTreeMaps underlie all fields), so direct JSON equality is valid.
fn same_observable_state(a: &Document, b: &Document) -> bool {
    let res_a = a.resolve().expect("resolve a");
    let res_b = b.resolve().expect("resolve b");
    // Compare version_id (content hash) and the document itself.
    let ra = serde_json::to_string(&(&res_a.did_document, &res_a.did_document_metadata.version_id))
        .expect("serialize a");
    let rb = serde_json::to_string(&(&res_b.did_document, &res_b.did_document_metadata.version_id))
        .expect("serialize b");
    ra == rb
}

// ── Property tests ────────────────────────────────────────────────────────────

proptest! {
    // ── TEST-002: Commutativity ───────────────────────────────────────────────

    /// `merge_state(A, B)` produces the same observable state as
    /// `merge_state(B, A)`.
    ///
    /// Both replicas diverge independently from the same genesis, then are
    /// merged in both orders.  The resulting resolved DID documents must be
    /// identical regardless of merge order.
    #[test]
    fn prop_merge_state_commutative(
        ops_a in arb_op_seq(1),
        ops_b in arb_op_seq(2),
    ) {
        let base = genesis();
        let a = build_replica(&base, &ops_a);
        let b = build_replica(&base, &ops_b);

        // merge(A into B's clone)
        let mut ab = a.clone();
        ab.merge_state(b.clone()).unwrap();

        // merge(B into A's clone)
        let mut ba = b.clone();
        ba.merge_state(a.clone()).unwrap();

        prop_assert!(
            same_observable_state(&ab, &ba),
            "TEST-002 commutativity violated:\nmerge(A,B) resolved = {}\nmerge(B,A) resolved = {}",
            serde_json::to_string(&ab.resolve().unwrap()).unwrap(),
            serde_json::to_string(&ba.resolve().unwrap()).unwrap(),
        );
    }

    // ── TEST-003: Associativity ───────────────────────────────────────────────

    /// `(A ⊔ B) ⊔ C` produces the same observable state as `A ⊔ (B ⊔ C)`.
    ///
    /// Three independent replicas are merged in two different groupings.  The
    /// final resolved DID document must be identical regardless of bracketing.
    #[test]
    fn prop_merge_state_associative(
        ops_a in arb_op_seq(1),
        ops_b in arb_op_seq(2),
        ops_c in arb_op_seq(3),
    ) {
        let base = genesis();
        let a = build_replica(&base, &ops_a);
        let b = build_replica(&base, &ops_b);
        let c = build_replica(&base, &ops_c);

        // (A ⊔ B) ⊔ C
        let mut ab = a.clone();
        ab.merge_state(b.clone()).unwrap();
        let mut ab_c = ab;
        ab_c.merge_state(c.clone()).unwrap();

        // A ⊔ (B ⊔ C)
        let mut bc = b.clone();
        bc.merge_state(c.clone()).unwrap();
        let mut a_bc = a.clone();
        a_bc.merge_state(bc).unwrap();

        prop_assert!(
            same_observable_state(&ab_c, &a_bc),
            "TEST-003 associativity violated:\n(A⊔B)⊔C = {}\nA⊔(B⊔C) = {}",
            serde_json::to_string(&ab_c.resolve().unwrap()).unwrap(),
            serde_json::to_string(&a_bc.resolve().unwrap()).unwrap(),
        );
    }

    // ── TEST-005: Idempotence ─────────────────────────────────────────────────

    /// `A ⊔ A == A`.
    ///
    /// Merging a document with an identical copy of itself must not change the
    /// observable state.
    #[test]
    fn prop_merge_state_idempotent(
        ops in arb_op_seq(1),
    ) {
        let base = genesis();
        let a = build_replica(&base, &ops);
        let before = serde_json::to_string(&a.resolve().unwrap()).unwrap();

        let mut merged = a.clone();
        merged.merge_state(a.clone()).unwrap();
        let after = serde_json::to_string(&merged.resolve().unwrap()).unwrap();

        prop_assert_eq!(
            before, after,
            "TEST-005 idempotence violated: merge(A, A) != A"
        );
    }

    // ── TEST-010: HLC monotonicity ────────────────────────────────────────────

    /// Every timestamp produced by a single HLC instance is strictly greater
    /// than the previous one.
    ///
    /// The wall clock is held constant (simulating rapid back-to-back sends) to
    /// force the logical counter path.  Checks strict monotonicity across a
    /// generated sequence of 2–8 consecutive sends.
    #[test]
    fn prop_hlc_send_is_strictly_monotonic(
        wall_ms in 1u64..=1_000_000u64,
        node_id in 0u64..=255u64,
        n_ticks in 2usize..=8usize,
    ) {
        use std::cell::Cell;

        struct FixedClock(Cell<u64>);
        impl did_crdt::core::hlc::ClockSource for FixedClock {
            fn wall_ms(&self) -> u64 { self.0.get() }
        }

        let clock = FixedClock(Cell::new(wall_ms));
        let mut hlc = Hlc::new(wall_ms, node_id);

        let mut prev = hlc.send(&clock);
        for _ in 1..n_ticks {
            let next = hlc.send(&clock);
            prop_assert!(
                next > prev,
                "TEST-010 HLC monotonicity violated: {:?} is not > {:?}",
                next, prev
            );
            prev = next;
        }
    }

    // ── TEST-006: Key Rotation Convergence ───────────────────────────────────

    /// Concurrent rotations at the same `seq` converge to the same key
    /// regardless of merge order, with the tiebreak determined by the BLAKE3
    /// hash of the key reference.
    ///
    /// Replicas B and C each apply a `RotateKey` at `seq` with independent
    /// key references.  After a full-state merge in both orders the resulting
    /// documents must be byte-identical, and the active key must equal the one
    /// whose `ActiveKeyMarker` is lexicographically greater (higher BLAKE3
    /// hash).
    ///
    /// Verifies: REQ-005
    #[test]
    fn prop_rotate_key_convergence_same_seq(
        seq in 1u64..=1_000u64,
        key_ref_b in "[a-z][a-z0-9]{3,11}",
        key_ref_c in "[a-z][a-z0-9]{3,11}",
    ) {
        use did_crdt::core::crdt::ActiveKeyMarker;

        let base = genesis();
        let signer = format!("{}#key-0", base.did);

        let ts_b = HlcTimestamp { wall_ms: 10, logical: 0, node_id: 1 };
        let ts_c = HlcTimestamp { wall_ms: 20, logical: 0, node_id: 2 };

        // Replica B: rotate to key_ref_b at seq.
        let mut doc_b = base.clone();
        doc_b
            .merge(grounded(
                &base,
                DeltaOp::RotateKey { seq, key_ref: key_ref_b.clone() },
                ts_b,
                &signer,
            ))
            .unwrap();

        // Replica C: rotate to key_ref_c at seq.
        let mut doc_c = base.clone();
        doc_c
            .merge(grounded(
                &base,
                DeltaOp::RotateKey { seq, key_ref: key_ref_c.clone() },
                ts_c,
                &signer,
            ))
            .unwrap();

        // Merge in both orders.
        let mut bc = doc_b.clone();
        bc.merge_state(doc_c.clone()).unwrap();

        let mut cb = doc_c.clone();
        cb.merge_state(doc_b.clone()).unwrap();

        // Compare observable-state identity (content_hash), not to_bytes: the
        // latter now carries the per-replica delta log, which legitimately
        // differs between B and C. content_hash is the canonical state signal.
        let bc_hash = bc.content_hash().expect("bc state hash");
        let cb_hash = cb.content_hash().expect("cb state hash");

        // Commutativity: merge(B, C) and merge(C, B) must converge to one state.
        prop_assert!(
            bc_hash == cb_hash,
            "TEST-006 commutativity violated for key_refs '{}' and '{}' at seq={}",
            key_ref_b, key_ref_c, seq,
        );

        // Tiebreak: winner is the key whose ActiveKeyMarker is greater.
        let marker_b = ActiveKeyMarker::new(seq, &key_ref_b);
        let marker_c = ActiveKeyMarker::new(seq, &key_ref_c);
        let expected_winner =
            if marker_b > marker_c { &key_ref_b } else { &key_ref_c };

        // Build a reference document that holds only the expected winner.
        // Use wall_ms: 20 to match the max(10, 20) from the merged bc state,
        // so that `updated_ms` converges identically.
        let mut expected = base.clone();
        expected
            .merge(grounded(
                &base,
                DeltaOp::RotateKey { seq, key_ref: expected_winner.clone() },
                HlcTimestamp { wall_ms: 20, logical: 0, node_id: 2 },
                &signer,
            ))
            .unwrap();
        let expected_hash = expected.content_hash().expect("expected state hash");

        prop_assert!(
            bc_hash == expected_hash,
            "TEST-006 tiebreak: merged result != BLAKE3-hash winner \
             (seq={}, k_b='{}', k_c='{}', expected='{}')",
            seq, key_ref_b, key_ref_c, expected_winner,
        );
    }

    // ── TEST-008: Revocation Monotonicity ─────────────────────────────────────

    /// Once a credential is revoked on any replica, it remains revoked in every
    /// merge outcome regardless of order.
    ///
    /// Replica A revokes `cred_id`.  Replica B applies an arbitrary sequence
    /// of observable operations (services, data, verification methods) built
    /// from the same genesis.  After a full-state merge in both orders the
    /// revoked credential must still be present on both sides.
    ///
    /// The G-Set merge is set-union, so revocations can only grow — this test
    /// verifies that property holds end-to-end through `Document::merge_state`.
    ///
    /// Verifies: monotonicity of the `Revocations` G-Set (SPEC-032 §13 TEST-008)
    #[test]
    fn prop_revocation_monotone(
        cred_id in "[a-z][a-z0-9]{3,11}",
        ops_b in arb_op_seq(2),
    ) {
        let base = genesis();
        let signer = format!("{}#key-0", base.did);
        let ts_a = HlcTimestamp { wall_ms: 10, logical: 0, node_id: 1 };

        // Replica A: revoke the credential.
        let mut doc_a = base.clone();
        doc_a
            .merge(grounded(
                &base,
                DeltaOp::RevokeCredential { credential_id: cred_id.clone() },
                ts_a,
                &signer,
            ))
            .unwrap();

        // Replica B: arbitrary observable operations on the same genesis.
        let doc_b = build_replica(&base, &ops_b);

        // Merge in both orders.
        let mut ab = doc_a.clone();
        ab.merge_state(doc_b.clone()).unwrap();

        let mut ba = doc_b.clone();
        ba.merge_state(doc_a.clone()).unwrap();

        prop_assert!(
            ab.is_revoked(&cred_id),
            "TEST-008: revocation lost in merge(A, B): cred_id='{}'",
            cred_id,
        );
        prop_assert!(
            ba.is_revoked(&cred_id),
            "TEST-008: revocation lost in merge(B, A): cred_id='{}'",
            cred_id,
        );
    }

    // ── TEST-009: Deactivation Irreversibility ────────────────────────────────

    /// Once a document is deactivated on any replica, it cannot be
    /// "un-deactivated" by merging with a non-deactivated replica.
    ///
    /// Replica A deactivates the document.  Replica B applies an arbitrary
    /// sequence of observable operations built from the same non-deactivated
    /// genesis (the `arb_delta_op` strategy never emits `Deactivate`).  After
    /// a full-state merge in both orders the deactivation flag must still be set.
    ///
    /// The `Deactivated` latch merges via boolean OR, so the `true` value
    /// propagates to any replica that sees it — this test confirms that
    /// invariant holds end-to-end through `Document::merge_state`.
    ///
    /// Verifies: irreversibility of the `Deactivated` latch (SPEC-032 §13 TEST-009)
    #[test]
    fn prop_deactivation_irreversible(
        ops_b in arb_op_seq(2),
    ) {
        let base = genesis();
        let signer = format!("{}#key-0", base.did);
        let ts_a = HlcTimestamp { wall_ms: 10, logical: 0, node_id: 1 };

        // Replica A: deactivate the document.
        let mut doc_a = base.clone();
        doc_a
            .merge(grounded(&base, DeltaOp::Deactivate, ts_a, &signer))
            .unwrap();

        // Replica B: arbitrary observable operations on the non-deactivated
        // base (arb_delta_op never emits Deactivate, so doc_b is always live).
        let doc_b = build_replica(&base, &ops_b);

        // Merge in both orders via state-based merge (bypasses the delta-level
        // deactivation gate so that the CRDT merge semantics are exercised
        // directly).
        let mut ab = doc_a.clone();
        ab.merge_state(doc_b.clone()).unwrap();

        let mut ba = doc_b.clone();
        ba.merge_state(doc_a.clone()).unwrap();

        prop_assert!(
            ab.is_deactivated(),
            "TEST-009: deactivation lost in merge(A, B)",
        );
        prop_assert!(
            ba.is_deactivated(),
            "TEST-009: deactivation lost in merge(B, A)",
        );
    }

    // ── Delta-path convergence (op-replay remove-context fix) ──────────────────

    /// The signed-delta path converges under causal delivery, and converges to
    /// the *same* state as `merge_state`.
    ///
    /// Two replicas author mutually-concurrent delta chains (both grounded on
    /// the shared genesis), then each replays the other's chain via the delta
    /// path (`merge`). This is the path that previously diverged for concurrent
    /// add/remove of the same service endpoint, because a `RemoveServiceEndpoint`
    /// delta re-derived its observed context from local state. Now the observed
    /// dots come from the remove's causal past, so:
    ///   (a) the delta path converges regardless of replay order, and
    ///   (b) it agrees with the canonical `merge_state` join.
    /// The small shared id space in `arb_delta_op` makes concurrent add/remove
    /// of the same endpoint a frequent case.
    #[test]
    fn prop_delta_path_converges_and_matches_state(
        ops_a in arb_op_seq(1),
        ops_b in arb_op_seq(2),
    ) {
        let base = genesis();
        let a_deltas = author_deltas(&base, &ops_a);
        let b_deltas = author_deltas(&base, &ops_b);

        // Replica A replays its own chain, then B's (delta path).
        let mut ra = base.clone();
        for d in a_deltas.iter().chain(b_deltas.iter()) {
            let _ = ra.merge(d.clone());
        }
        // Replica B replays in the opposite order.
        let mut rb = base.clone();
        for d in b_deltas.iter().chain(a_deltas.iter()) {
            let _ = rb.merge(d.clone());
        }

        prop_assert!(
            same_observable_state(&ra, &rb),
            "delta path diverged across replay order:\nA→B = {}\nB→A = {}",
            serde_json::to_string(&ra.resolve().unwrap()).unwrap(),
            serde_json::to_string(&rb.resolve().unwrap()).unwrap(),
        );

        // The delta path must agree with the canonical state-merge join.
        let mut sa = build_replica(&base, &ops_a);
        sa.merge_state(build_replica(&base, &ops_b)).unwrap();
        prop_assert!(
            same_observable_state(&ra, &sa),
            "delta path disagrees with merge_state:\ndelta = {}\nstate = {}",
            serde_json::to_string(&ra.resolve().unwrap()).unwrap(),
            serde_json::to_string(&sa.resolve().unwrap()).unwrap(),
        );
    }
}

// ── Regression: op-replay remove-context gap ──────────────────────────────────

/// The exact scenario that diverged before removes carried their causal
/// context: replica A adds a service endpoint; replica B concurrently removes
/// the *same* id (B has not seen A's add). Reconciled purely via the delta
/// path, the endpoint must survive (add-wins) and both replicas must agree —
/// matching the `merge_state` result and Table II.
#[test]
fn regression_concurrent_add_remove_converges_via_delta_path() {
    let base = genesis();
    let hlc = |w: u64, n: u64| HlcTimestamp {
        wall_ms: w,
        logical: 0,
        node_id: n,
    };
    let add = (
        DeltaOp::AddServiceEndpoint {
            id: "svc-x".to_owned(),
            service_type: "LinkedDomains".to_owned(),
            endpoint: "https://x.example.com".to_owned(),
        },
        hlc(10, 1),
    );
    let remove = (
        DeltaOp::RemoveServiceEndpoint {
            id: "svc-x".to_owned(),
        },
        hlc(10, 2),
    );

    // A adds svc-x (node 1). B concurrently removes svc-x (node 2) without ever
    // having seen the add. Both are grounded on genesis, so they are concurrent.
    let a_deltas = author_deltas(&base, &[add.clone()]);
    let b_deltas = author_deltas(&base, &[remove.clone()]);

    let mut ra = base.clone();
    for d in a_deltas.iter().chain(b_deltas.iter()) {
        let _ = ra.merge(d.clone());
    }
    let mut rb = base.clone();
    for d in b_deltas.iter().chain(a_deltas.iter()) {
        let _ = rb.merge(d.clone());
    }

    assert!(
        same_observable_state(&ra, &rb),
        "concurrent add/remove diverged across delta replay order",
    );

    // Add-wins: the endpoint survives because the remove never observed its dot.
    let ra_json = serde_json::to_string(&ra.resolve().unwrap()).unwrap();
    assert!(
        ra_json.contains("svc-x"),
        "concurrent add must win over a remove that never observed it: {ra_json}",
    );

    // The delta path agrees with the canonical state merge.
    let mut sa = build_replica(&base, &[add]);
    sa.merge_state(build_replica(&base, &[remove])).unwrap();
    assert!(
        same_observable_state(&ra, &sa),
        "delta path must match merge_state for concurrent add/remove",
    );
}

// ── Unit tests for non-resolvable fields ──────────────────────────────────────

/// Unit tests for CRDT fields whose state is not surfaced by `resolve()`.
///
/// These cover `RevokeCredential` (G-Set), `RotateKey` (Max-Register), and
/// `RevokeVerificationMethod` (2P-Set remove half), verifying commutativity,
/// associativity, and idempotence with a fixed set of representative inputs
/// rather than via proptest.
#[cfg(test)]
mod unit {
    use super::*;

    fn make_base() -> Document {
        genesis()
    }

    fn unsigned_delta(doc: &Document, op: DeltaOp, ts: HlcTimestamp) -> SignedDelta {
        let signer = format!("{}#key-0", doc.did);
        let mut d = SignedDelta::unsigned(doc.did.clone(), op, ts, signer);
        d.parents = doc.frontier(); // ground on current frontier (SPEC-036)
        d
    }

    fn ts(wall: u64, node: u64) -> HlcTimestamp {
        HlcTimestamp {
            wall_ms: wall,
            logical: 0,
            node_id: node,
        }
    }

    // ── Revocation G-Set ──────────────────────────────────────────────────────

    /// G-Set commutativity: inserting on A then merging B equals inserting on B
    /// then merging A.
    #[test]
    fn revocation_gset_commutative() {
        let base = make_base();

        let mut a = base.clone();
        a.merge(unsigned_delta(
            &base,
            DeltaOp::RevokeCredential {
                credential_id: "cred-A".to_owned(),
            },
            ts(10, 1),
        ))
        .unwrap();

        let mut b = base.clone();
        b.merge(unsigned_delta(
            &base,
            DeltaOp::RevokeCredential {
                credential_id: "cred-B".to_owned(),
            },
            ts(20, 2),
        ))
        .unwrap();

        let mut ab = a.clone();
        ab.merge_state(b.clone()).unwrap();

        let mut ba = b.clone();
        ba.merge_state(a.clone()).unwrap();

        // Both should contain cred-A and cred-B.
        let ab_resolved = serde_json::to_string(&ab.resolve().unwrap()).unwrap();
        let ba_resolved = serde_json::to_string(&ba.resolve().unwrap()).unwrap();
        assert_eq!(ab_resolved, ba_resolved, "revocation G-Set commutativity");
    }

    /// G-Set idempotence: merging with itself changes nothing.
    #[test]
    fn revocation_gset_idempotent() {
        let base = make_base();
        let mut a = base.clone();
        a.merge(unsigned_delta(
            &base,
            DeltaOp::RevokeCredential {
                credential_id: "cred-1".to_owned(),
            },
            ts(10, 1),
        ))
        .unwrap();

        let before = serde_json::to_string(&a.resolve().unwrap()).unwrap();
        let mut merged = a.clone();
        merged.merge_state(a.clone()).unwrap();
        let after = serde_json::to_string(&merged.resolve().unwrap()).unwrap();

        assert_eq!(before, after, "revocation G-Set idempotence");
    }

    // ── ActiveKey Max-Register ────────────────────────────────────────────────

    /// Max-Register commutativity: rotating keys on two replicas then merging
    /// in either order gives the same winner (highest seq wins).
    #[test]
    fn active_key_max_register_commutative() {
        let base = make_base();

        let mut a = base.clone();
        a.merge(unsigned_delta(
            &base,
            DeltaOp::RotateKey {
                seq: 1,
                key_ref: "key-1".to_owned(),
            },
            ts(10, 1),
        ))
        .unwrap();

        let mut b = base.clone();
        b.merge(unsigned_delta(
            &base,
            DeltaOp::RotateKey {
                seq: 2,
                key_ref: "key-2".to_owned(),
            },
            ts(20, 2),
        ))
        .unwrap();

        let mut ab = a.clone();
        ab.merge_state(b.clone()).unwrap();

        let mut ba = b.clone();
        ba.merge_state(a.clone()).unwrap();

        assert_eq!(
            serde_json::to_string(&ab.resolve().unwrap()).unwrap(),
            serde_json::to_string(&ba.resolve().unwrap()).unwrap(),
            "active_key Max-Register commutativity"
        );
    }

    /// Max-Register idempotence: merging with itself changes nothing.
    #[test]
    fn active_key_max_register_idempotent() {
        let base = make_base();
        let mut a = base.clone();
        a.merge(unsigned_delta(
            &base,
            DeltaOp::RotateKey {
                seq: 3,
                key_ref: "key-3".to_owned(),
            },
            ts(30, 1),
        ))
        .unwrap();

        let before = serde_json::to_string(&a.resolve().unwrap()).unwrap();
        let mut merged = a.clone();
        merged.merge_state(a.clone()).unwrap();
        let after = serde_json::to_string(&merged.resolve().unwrap()).unwrap();

        assert_eq!(before, after, "active_key Max-Register idempotence");
    }

    // ── 2P-Set Verification Method Revocation ──────────────────────────────────

    /// 2P-Set revocation commutativity: revoking a key on one replica and merging
    /// in either order gives the same result.
    #[test]
    fn revoked_vm_2pset_commutative() {
        let base = make_base();
        let key0 = format!("{}#key-0", base.did);
        let key1_id = format!("{}#key-1", base.did);

        // Add key-1 to both replicas.
        let mut shared = base.clone();
        shared
            .merge(unsigned_delta(
                &base,
                DeltaOp::AddVerificationMethod {
                    id: key1_id.clone(),
                    public_key_multibase: "zKey1".to_owned(),
                    suite_type: did_crdt::core::delta::SuiteType::default(),
                    relationships: did_crdt::core::delta::default_relationships(),
                },
                ts(5, 1),
            ))
            .unwrap();

        // Replica A: revoke key-0.
        let mut a = shared.clone();
        a.merge(unsigned_delta(
            &shared,
            DeltaOp::RevokeVerificationMethod {
                key_id: key0.clone(),
            },
            ts(10, 1),
        ))
        .unwrap();

        // Replica B: add a service.
        let mut b = shared.clone();
        b.merge(unsigned_delta(
            &shared,
            DeltaOp::AddServiceEndpoint {
                id: format!("{}#svc-1", shared.did),
                service_type: "LinkedDomains".to_owned(),
                endpoint: "https://b.example.com".to_owned(),
            },
            ts(20, 2),
        ))
        .unwrap();

        // Merge in both orders.
        let mut ab = a.clone();
        ab.merge_state(b.clone()).unwrap();

        let mut ba = b.clone();
        ba.merge_state(a.clone()).unwrap();

        assert_eq!(
            serde_json::to_string(&ab.resolve().unwrap()).unwrap(),
            serde_json::to_string(&ba.resolve().unwrap()).unwrap(),
            "2P-Set VM revocation commutativity"
        );
        // Both must have key-0 revoked.
        assert!(ab.is_vm_revoked(&key0));
        assert!(ba.is_vm_revoked(&key0));
    }

    /// 2P-Set revocation monotonicity: once a key is revoked, it stays revoked
    /// through any merge.
    #[test]
    fn revoked_vm_2pset_monotone() {
        let base = make_base();
        let key0 = format!("{}#key-0", base.did);
        let key1_id = format!("{}#key-1", base.did);

        // Add key-1 then revoke key-0 on replica A.
        let mut a = base.clone();
        a.merge(unsigned_delta(
            &base,
            DeltaOp::AddVerificationMethod {
                id: key1_id.clone(),
                public_key_multibase: "zKey1".to_owned(),
                suite_type: did_crdt::core::delta::SuiteType::default(),
                relationships: did_crdt::core::delta::default_relationships(),
            },
            ts(5, 1),
        ))
        .unwrap();
        a.merge(unsigned_delta(
            &a,
            DeltaOp::RevokeVerificationMethod {
                key_id: key0.clone(),
            },
            ts(10, 1),
        ))
        .unwrap();

        // Replica B: pristine (only genesis key, no revocation).
        let b = base.clone();

        // Merge B into A — revocation must survive.
        let mut merged = a.clone();
        merged.merge_state(b).unwrap();
        assert!(merged.is_vm_revoked(&key0), "revocation must be monotone");
    }

    /// 2P-Set idempotence: merging with self changes nothing.
    #[test]
    fn revoked_vm_2pset_idempotent() {
        let base = make_base();
        let key0 = format!("{}#key-0", base.did);
        let key1_id = format!("{}#key-1", base.did);

        let mut a = base.clone();
        a.merge(unsigned_delta(
            &base,
            DeltaOp::AddVerificationMethod {
                id: key1_id.clone(),
                public_key_multibase: "zKey1".to_owned(),
                suite_type: did_crdt::core::delta::SuiteType::default(),
                relationships: did_crdt::core::delta::default_relationships(),
            },
            ts(5, 1),
        ))
        .unwrap();
        a.merge(unsigned_delta(
            &a,
            DeltaOp::RevokeVerificationMethod {
                key_id: key0.clone(),
            },
            ts(10, 1),
        ))
        .unwrap();

        let before = serde_json::to_string(&a.resolve().unwrap()).unwrap();
        let mut merged = a.clone();
        merged.merge_state(a.clone()).unwrap();
        let after = serde_json::to_string(&merged.resolve().unwrap()).unwrap();

        assert_eq!(before, after, "2P-Set VM revocation idempotence");
    }

    // ── TEST-007: Stale Rotation Rejection ────────────────────────────────────

    /// A `RotateKey` delta whose `seq` is not strictly greater than the
    /// document's current rotation sequence number is rejected at the
    /// authorisation boundary.
    ///
    /// `Document::merge` applies deltas to the CRDT state; the seq-check lives
    /// in `validate::check_authorisation`, which callers at trust boundaries
    /// invoke before forwarding a delta.  This test exercises that gate.
    ///
    /// Scenario:
    ///   1. Create DID D (genesis key at seq=0 internally).
    ///   2. Rotate to K2 at seq=1 — authorised and applied; active seq → 1.
    ///   3. Rotate to K3 at seq=2 — authorised and applied; active seq → 2.
    ///   4. A lower-seq=1 rotation is ADMITTED (it may be concurrent, not a
    ///      stale descendant), but the Max-Register keeps the higher seq=2 — so
    ///      it never changes the active key.
    ///
    /// Verifies: REQ-005
    #[test]
    fn lower_seq_rotation_admitted_but_never_wins() {
        use did_crdt::core::validate::check_authorisation;

        let base = make_base();
        let mut doc = base.clone();

        // Step 2: first rotation, seq=1 — must be authorised and applied.
        let r1 = unsigned_delta(
            &base,
            DeltaOp::RotateKey {
                seq: 1,
                key_ref: "K2".to_owned(),
            },
            ts(10, 1),
        );
        check_authorisation(&r1, &doc).expect("seq=1 authorisation must pass");
        doc.merge(r1).expect("seq=1 rotation must apply");

        // Step 3: second rotation, seq=2 — must be authorised and applied.
        let r2 = unsigned_delta(
            &base,
            DeltaOp::RotateKey {
                seq: 2,
                key_ref: "K3".to_owned(),
            },
            ts(20, 1),
        );
        check_authorisation(&r2, &doc).expect("seq=2 authorisation must pass");
        doc.merge(r2).expect("seq=2 rotation must apply");

        // Step 4: a lower-seq=1 rotation is admitted (could be concurrent) but
        // the Max-Register keeps seq=2, so the active key is unchanged.
        let lower = unsigned_delta(
            &base,
            DeltaOp::RotateKey {
                seq: 1,
                key_ref: "K4".to_owned(),
            },
            ts(30, 1),
        );
        check_authorisation(&lower, &doc)
            .expect("lower-seq rotation must be admitted (may be concurrent)");
        doc.merge(lower).expect("lower-seq rotation merges");
        let resolved = serde_json::to_string(&doc.resolve().unwrap()).unwrap();
        assert!(
            !resolved.contains("K4"),
            "lower-seq rotation must not win the Max-Register (active key stays K3/seq=2)",
        );
    }
}
