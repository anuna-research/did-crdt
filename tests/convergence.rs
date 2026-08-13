//! Multi-replica convergence tests.
//!
//! Tests (see SPEC-032 §13 and TEST-015, TEST-016, TEST-017):
//!
//! - Two replicas exchanging disjoint deltas converge to identical state.
//! - Replicas operating offline independently then merging converge correctly.
//! - All permutations of a delta set produce the same final state (commutativity
//!   + associativity together imply order-independence).
//! - A delta received multiple times produces the same state as receiving it
//!   once (idempotence).

use did_crdt::{
    core::{
        delta::{default_relationships, DeltaOp, SignedDelta, SuiteType},
        hlc::HlcTimestamp,
    },
    Document,
};

// ── Helpers ─────────────────────────────────────────────────────────────────

const GENESIS_KEY: &str = "zConvergenceTestKey";

fn genesis() -> Document {
    Document::new(GENESIS_KEY).expect("genesis must succeed").0
}

fn signer(doc: &Document) -> String {
    format!("{}#key-0", doc.did)
}

fn ts(wall: u64, node: u64) -> HlcTimestamp {
    HlcTimestamp {
        wall_ms: wall,
        logical: 0,
        node_id: node,
    }
}

fn unsigned_delta(doc: &Document, op: DeltaOp, timestamp: HlcTimestamp) -> SignedDelta {
    // Ground the delta on the document's current frontier (SPEC-036). Deltas
    // built from the same base are mutually concurrent (all parent genesis), so
    // the delta path admits them in any order; cross-replica convergence uses
    // the order-free state-merge path.
    let mut d = SignedDelta::unsigned(doc.did.clone(), op, timestamp, signer(doc));
    d.parents = doc.frontier();
    d
}

/// Compare two documents by their resolved W3C DID Core view.
///
/// Uses `resolve()` rather than `to_bytes()` / `content_hash()` because
/// `to_bytes()` includes the full delta log, which legitimately differs between
/// replicas; the resolved `DidDocument` captures the canonical observable state.
fn assert_converged(a: &Document, b: &Document) {
    let ra = a.resolve().expect("resolve a");
    let rb = b.resolve().expect("resolve b");
    assert_eq!(
        ra.did_document_metadata.version_id, rb.did_document_metadata.version_id,
        "version_id must match after convergence"
    );
    let da = ra.did_document.as_ref().expect("document a");
    let db = rb.did_document.as_ref().expect("document b");
    let ja = serde_json::to_string(da).expect("serialize a");
    let jb = serde_json::to_string(db).expect("serialize b");
    assert_eq!(
        ja, jb,
        "resolved documents must be identical after convergence"
    );
}

// ── Test 1: Disjoint deltas converge ────────────────────────────────────────

/// Two replicas from the same genesis apply disjoint deltas (a service
/// endpoint on replica A, document data on replica B). After state-based
/// merge in both directions, both replicas must produce identical resolve()
/// output containing both mutations.
#[test]
fn disjoint_deltas_converge() {
    let base = genesis();
    let did = base.did.clone();

    let mut replica_a = base.clone();
    let mut replica_b = base.clone();

    // Replica A: add a service endpoint.
    let delta_a = unsigned_delta(
        &base,
        DeltaOp::AddServiceEndpoint {
            id: format!("{did}#svc-a"),
            service_type: "LinkedDomains".to_owned(),
            endpoint: "https://a.example.com".to_owned(),
        },
        ts(100, 1),
    );
    replica_a.merge(delta_a).expect("replica A: add service");

    // Replica B: set document data.
    let delta_b = unsigned_delta(
        &base,
        DeltaOp::SetDocumentData {
            key: "name".to_owned(),
            value: serde_json::json!("replica-b-value"),
        },
        ts(200, 2),
    );
    replica_b.merge(delta_b).expect("replica B: set data");

    // State-based merge in both directions.
    let mut merged_a = replica_a.clone();
    merged_a.merge_state(replica_b.clone()).expect("A merges B");

    let mut merged_b = replica_b.clone();
    merged_b.merge_state(replica_a.clone()).expect("B merges A");

    // Both must converge to the same state.
    assert_converged(&merged_a, &merged_b);

    // Both mutations must be present.
    let result = merged_a.resolve().expect("resolve merged");
    let doc = result.did_document.as_ref().expect("document");
    assert_eq!(
        doc.service.len(),
        1,
        "service endpoint from A must be present"
    );
    assert_eq!(
        doc.extra.get("name"),
        Some(&serde_json::json!("replica-b-value")),
        "document data from B must be present"
    );
}

// ── Test 2: All permutations converge ───────────────────────────────────────

/// Generate 4 deltas and apply them in every permutation order to fresh
/// Document clones. All 24 permutations must produce the same resolved state.
/// This proves commutativity + associativity together (order-independence).
#[test]
fn all_permutations_converge() {
    let base = genesis();
    let did = base.did.clone();

    // Build 4 distinct deltas with unique timestamps.
    let deltas = [unsigned_delta(
            &base,
            DeltaOp::AddServiceEndpoint {
                id: format!("{did}#svc-0"),
                service_type: "LinkedDomains".to_owned(),
                endpoint: "https://svc0.example.com".to_owned(),
            },
            ts(100, 1),
        ),
        unsigned_delta(
            &base,
            DeltaOp::SetDocumentData {
                key: "field-a".to_owned(),
                value: serde_json::json!(42),
            },
            ts(200, 2),
        ),
        unsigned_delta(
            &base,
            DeltaOp::AddVerificationMethod {
                id: format!("{did}#key-extra"),
                public_key_multibase: "zPermTestKey".to_owned(),
                suite_type: SuiteType::default(),
                relationships: default_relationships(),
            },
            ts(300, 3),
        ),
        unsigned_delta(
            &base,
            DeltaOp::SetDocumentData {
                key: "field-b".to_owned(),
                value: serde_json::json!("hello"),
            },
            ts(400, 4),
        )];

    // Generate all 24 permutations of indices [0,1,2,3].
    let indices: Vec<usize> = (0..4).collect();
    let permutations = permutations_of(&indices);
    assert_eq!(permutations.len(), 24);

    // Apply each permutation to a fresh clone and collect resolved states.
    let mut resolved_states: Vec<String> = Vec::new();
    for perm in &permutations {
        let mut doc = base.clone();
        for &idx in perm {
            let _ = doc.merge(deltas[idx].clone()); // some may no-op
        }
        let result = doc.resolve().expect("resolve");
        let serialized = serde_json::to_string(&(
            &result.did_document,
            &result.did_document_metadata.version_id,
        ))
        .expect("serialize");
        resolved_states.push(serialized);
    }

    // All must be identical.
    let first = &resolved_states[0];
    for (i, state) in resolved_states.iter().enumerate().skip(1) {
        assert_eq!(first, state, "permutation {i} diverged from permutation 0");
    }
}

/// Generate all permutations of a slice.
fn permutations_of<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut result = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let mut rest: Vec<T> = items.to_vec();
        rest.remove(i);
        for mut perm in permutations_of(&rest) {
            perm.insert(0, item.clone());
            result.push(perm);
        }
    }
    result
}

// ── Test 3: Duplicate delivery is idempotent ────────────────────────────────

/// Applying the same delta twice to a replica must produce the same state
/// as applying it once.
#[test]
fn duplicate_delivery_is_idempotent() {
    let base = genesis();
    let did = base.did.clone();

    let delta = unsigned_delta(
        &base,
        DeltaOp::AddServiceEndpoint {
            id: format!("{did}#svc-dup"),
            service_type: "DIDCommMessaging".to_owned(),
            endpoint: "https://dup.example.com".to_owned(),
        },
        ts(100, 1),
    );

    // Apply once.
    let mut once = base.clone();
    once.merge(delta.clone()).expect("first apply");

    let state_once =
        serde_json::to_string(&once.resolve().expect("resolve once")).expect("serialize once");

    // Apply twice.
    let mut twice = base.clone();
    twice.merge(delta.clone()).expect("first apply");
    twice
        .merge(delta.clone())
        .expect("second apply (duplicate)");

    let state_twice =
        serde_json::to_string(&twice.resolve().expect("resolve twice")).expect("serialize twice");

    assert_eq!(
        state_once, state_twice,
        "duplicate delta delivery must be idempotent"
    );

    // Also verify via state-based merge: merging with self is idempotent.
    let mut self_merged = once.clone();
    self_merged.merge_state(once.clone()).expect("self merge");
    let state_self = serde_json::to_string(&self_merged.resolve().expect("resolve self"))
        .expect("serialize self");
    assert_eq!(
        state_once, state_self,
        "state-based self-merge must be idempotent"
    );
}

/// Verify idempotence across multiple delta types, not just services.
#[test]
fn duplicate_delivery_idempotent_mixed_ops() {
    let base = genesis();
    let did = base.did.clone();

    let deltas = vec![
        unsigned_delta(
            &base,
            DeltaOp::SetDocumentData {
                key: "dup-key".to_owned(),
                value: serde_json::json!("val"),
            },
            ts(100, 1),
        ),
        unsigned_delta(
            &base,
            DeltaOp::AddVerificationMethod {
                id: format!("{did}#key-dup"),
                public_key_multibase: "zDupKey".to_owned(),
                suite_type: SuiteType::default(),
                relationships: default_relationships(),
            },
            ts(200, 2),
        ),
        unsigned_delta(
            &base,
            DeltaOp::RevokeCredential {
                credential_id: "cred-dup".to_owned(),
            },
            ts(300, 3),
        ),
    ];

    // Apply all deltas once.
    let mut once = base.clone();
    for d in &deltas {
        let _ = once.merge(d.clone());
    }
    let state_once =
        serde_json::to_string(&once.resolve().expect("resolve once")).expect("serialize once");

    // Apply all deltas twice each.
    let mut twice = base.clone();
    for d in &deltas {
        let _ = twice.merge(d.clone());
        let _ = twice.merge(d.clone()); // duplicate
    }
    let state_twice =
        serde_json::to_string(&twice.resolve().expect("resolve twice")).expect("serialize twice");

    assert_eq!(
        state_once, state_twice,
        "duplicate delivery of mixed ops must be idempotent"
    );
}

// ── Test 4: Offline replicas merge correctly ────────────────────────────────

/// Three replicas diverge independently then merge all pairs.
///
/// - Replica A: deltas 1, 2 (service endpoint + document data)
/// - Replica B: deltas 3, 4 (document data + verification method)
/// - Replica C: delta 5 (service endpoint)
///
/// After merging all pairs via merge_state, all three must converge to
/// an identical resolved state containing every mutation.
#[test]
fn offline_replicas_merge_correctly() {
    let base = genesis();
    let did = base.did.clone();

    // ── Replica A: deltas 1, 2 ──────────────────────────────────────────────
    let mut replica_a = base.clone();
    replica_a
        .merge(unsigned_delta(
            &base,
            DeltaOp::AddServiceEndpoint {
                id: format!("{did}#svc-a"),
                service_type: "LinkedDomains".to_owned(),
                endpoint: "https://a.example.com".to_owned(),
            },
            ts(100, 1),
        ))
        .expect("A: delta 1");
    replica_a
        .merge(unsigned_delta(
            &base,
            DeltaOp::SetDocumentData {
                key: "from-a".to_owned(),
                value: serde_json::json!("alpha"),
            },
            ts(200, 1),
        ))
        .expect("A: delta 2");

    // ── Replica B: deltas 3, 4 ──────────────────────────────────────────────
    let mut replica_b = base.clone();
    replica_b
        .merge(unsigned_delta(
            &base,
            DeltaOp::SetDocumentData {
                key: "from-b".to_owned(),
                value: serde_json::json!("beta"),
            },
            ts(300, 2),
        ))
        .expect("B: delta 3");
    replica_b
        .merge(unsigned_delta(
            &base,
            DeltaOp::AddVerificationMethod {
                id: format!("{did}#key-b"),
                public_key_multibase: "zReplicaBKey".to_owned(),
                suite_type: SuiteType::default(),
                relationships: default_relationships(),
            },
            ts(400, 2),
        ))
        .expect("B: delta 4");

    // ── Replica C: delta 5 ──────────────────────────────────────────────────
    let mut replica_c = base.clone();
    replica_c
        .merge(unsigned_delta(
            &base,
            DeltaOp::AddServiceEndpoint {
                id: format!("{did}#svc-c"),
                service_type: "DIDCommMessaging".to_owned(),
                endpoint: "https://c.example.com".to_owned(),
            },
            ts(500, 3),
        ))
        .expect("C: delta 5");

    // ── Merge all pairs ─────────────────────────────────────────────────────
    // A merges B and C.
    replica_a
        .merge_state(replica_b.clone())
        .expect("A merges B");
    replica_a
        .merge_state(replica_c.clone())
        .expect("A merges C");

    // B merges A (which now has C) — gets everything.
    replica_b
        .merge_state(replica_a.clone())
        .expect("B merges A+C");

    // C merges A (which now has B) — gets everything.
    replica_c
        .merge_state(replica_a.clone())
        .expect("C merges A+B");

    // ── Assert convergence ──────────────────────────────────────────────────
    assert_converged(&replica_a, &replica_b);
    assert_converged(&replica_b, &replica_c);
    assert_converged(&replica_a, &replica_c);

    // Verify all 5 delta effects are present.
    let result = replica_a.resolve().expect("resolve merged");
    let doc = result.did_document.as_ref().expect("document");

    // 2 service endpoints (from A and C).
    assert_eq!(doc.service.len(), 2, "must have 2 service endpoints");

    // 2 verification methods: genesis key-0 + key-b from replica B.
    assert_eq!(
        doc.verification_method.len(),
        2,
        "must have 2 verification methods"
    );

    // 2 document data entries (from-a and from-b).
    assert_eq!(
        doc.extra.get("from-a"),
        Some(&serde_json::json!("alpha")),
        "data from replica A must be present"
    );
    assert_eq!(
        doc.extra.get("from-b"),
        Some(&serde_json::json!("beta")),
        "data from replica B must be present"
    );
}

/// Three replicas merge in all possible pair orderings and still converge.
/// This is the strongest form of the offline-merge test: it verifies that
/// the final state is independent of the order replicas discover each other.
#[test]
fn offline_replicas_all_merge_orders_converge() {
    let base = genesis();
    let did = base.did.clone();

    // Build three divergent replicas.
    let build_replicas = || {
        let mut a = base.clone();
        a.merge(unsigned_delta(
            &base,
            DeltaOp::SetDocumentData {
                key: "src".to_owned(),
                value: serde_json::json!("a"),
            },
            ts(100, 1),
        ))
        .unwrap();

        let mut b = base.clone();
        b.merge(unsigned_delta(
            &base,
            DeltaOp::SetDocumentData {
                key: "src-b".to_owned(),
                value: serde_json::json!("b"),
            },
            ts(200, 2),
        ))
        .unwrap();

        let mut c = base.clone();
        c.merge(unsigned_delta(
            &base,
            DeltaOp::AddServiceEndpoint {
                id: format!("{did}#svc-c"),
                service_type: "LinkedDomains".to_owned(),
                endpoint: "https://c.example.com".to_owned(),
            },
            ts(300, 3),
        ))
        .unwrap();

        (a, b, c)
    };

    // Merge order 1: A<-B, A<-C, B<-A, C<-A
    let (mut a1, mut b1, mut c1) = build_replicas();
    a1.merge_state(b1.clone()).unwrap();
    a1.merge_state(c1.clone()).unwrap();
    b1.merge_state(a1.clone()).unwrap();
    c1.merge_state(a1.clone()).unwrap();

    // Merge order 2: B<-C, B<-A, A<-B, C<-B
    let (mut a2, mut b2, mut c2) = build_replicas();
    b2.merge_state(c2.clone()).unwrap();
    b2.merge_state(a2.clone()).unwrap();
    a2.merge_state(b2.clone()).unwrap();
    c2.merge_state(b2.clone()).unwrap();

    // Merge order 3: C<-A, C<-B, A<-C, B<-C
    let (mut a3, mut b3, mut c3) = build_replicas();
    c3.merge_state(a3.clone()).unwrap();
    c3.merge_state(b3.clone()).unwrap();
    a3.merge_state(c3.clone()).unwrap();
    b3.merge_state(c3.clone()).unwrap();

    // All final states must be identical.
    assert_converged(&a1, &a2);
    assert_converged(&a2, &a3);
    assert_converged(&b1, &b2);
    assert_converged(&b2, &b3);
    assert_converged(&c1, &c2);
    assert_converged(&c2, &c3);
}

// ── Test 5: the delta path requires causal order (DAG model) ────────────────

/// Order-independence lives on the state-merge path. The signed-delta path,
/// under the Merkle-DAG model (SPEC-036 REQ-363), requires *causal* order: a
/// delta whose causal predecessor has not arrived is not applied but returns
/// `DeltaPending` listing the missing ancestor. Delivering the predecessor and
/// re-submitting then succeeds (Reject/retry policy), and the replica converges
/// with the author.
#[test]
fn delta_path_requires_causal_order_and_resolves_on_delivery() {
    use did_crdt::core::Error;

    let base = genesis();

    // Author builds a causal CHAIN: d2 is grounded on d1 (not concurrent).
    let mut author = base.clone();
    let d1 = unsigned_delta(
        &author,
        DeltaOp::SetDocumentData {
            key: "a".to_owned(),
            value: serde_json::json!(1),
        },
        ts(100, 1),
    );
    author.merge(d1.clone()).expect("author applies d1");
    let d2 = unsigned_delta(
        &author,
        DeltaOp::SetDocumentData {
            key: "b".to_owned(),
            value: serde_json::json!(2),
        },
        ts(200, 1),
    );
    author.merge(d2.clone()).expect("author applies d2");
    let d1_hash = d1.content_hash().expect("d1 hash");

    // A fresh replica receives d2 BEFORE d1: undecidable, so it is held
    // (DeltaPending), not applied, and it names d1 as the missing ancestor.
    let mut replica = base.clone();
    match replica.merge(d2.clone()) {
        Err(Error::DeltaPending { missing }) => {
            assert!(
                missing.contains(&d1_hash),
                "must report d1 as the missing ancestor"
            );
        }
        other => panic!("expected DeltaPending for out-of-causal-order delta, got {other:?}"),
    }

    // Deliver in causal order (Reject/retry): d1 then re-submit d2. Both apply,
    // and the replica converges with the author.
    replica.merge(d1).expect("d1 applies");
    replica
        .merge(d2)
        .expect("d2 applies once its predecessor is present");
    assert_converged(&author, &replica);
}
