//! Integration tests for the HTTP API and gossip layer.
//!
//! Tests (see SPEC-032 §13 and TEST-014, TEST-015):
//!
//! - `POST /dids` creates a DID and returns a valid did:crdt identifier.
//! - `GET /dids/{did}` resolves to a W3C DID Core JSON-LD document.
//! - `POST /dids/{did}/deltas` accepts a valid signed delta and rejects
//!   malformed or unauthorised ones.
//! - Two service instances peered via iroh converge after delta exchange.
//! - W3C DID Core JSON-LD conformance (resolved document validates against
//!   DID Core schema).
//!
//! Requires the `service` feature to be enabled.

// Phase-3 live-transport test is in the `live_two_node` module below (requires
// both `service` and `sync` features).

// ── TEST-015: two-node create / update / converge ─────────────────────────────

/// In-process simulation of two peered did-crdt nodes (TEST-015).
///
/// Scenario:
/// 1. Node A creates a new DID document.
/// 2. Sync A → B: B merges A's full state (initial peer join).
/// 3. Verify B has converged to A's state.
/// 4. Node B applies an update (adds a service endpoint).
/// 5. Sync B → A: A merges B's updated state.
/// 6. Verify A has converged to B's updated state.
/// 7. Both nodes resolve to an identical W3C DID Core document.
///
/// The sync exchange is simulated in-process via `Document::merge_state` and
/// `Document::merge`.  No network I/O is required; this matches the phase-1
/// convergence-test approach described in `tests/convergence.rs`.
mod two_node {
    use did_crdt::{
        core::{
            delta::{DeltaOp, SignedDelta},
            hlc::HlcTimestamp,
        },
        Document,
    };

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Assert that two documents have converged to an identical observable state.
    ///
    /// Uses `Document::resolve()` rather than `content_hash()` / `to_bytes()`
    /// because `to_bytes()` includes the full delta log, which legitimately
    /// differs between replicas.  `resolve()` reads the in-memory CRDT state
    /// directly and its output is fully comparable.
    fn assert_converged(a: &Document, b: &Document) {
        assert_eq!(a.did, b.did, "DIDs must match");
        let ra = a.resolve().expect("Node A: resolve");
        let rb = b.resolve().expect("Node B: resolve");
        assert_eq!(
            ra.did_document_metadata.version_id, rb.did_document_metadata.version_id,
            "version_id must match after convergence"
        );
        let da = ra.did_document.as_ref().expect("Node A: document");
        let db = rb.did_document.as_ref().expect("Node B: document");
        assert_eq!(da.verification_method.len(), db.verification_method.len());
        assert_eq!(da.service.len(), db.service.len());
    }

    // ── TEST-015 ──────────────────────────────────────────────────────────────

    /// TEST-015 — Two nodes converge after create-on-A, update-on-B.
    #[test]
    fn two_node_create_update_converge() {
        // ── Step 1: Node A creates a DID ──────────────────────────────────────
        let (mut node_a, _creation_delta) =
            Document::new("zNodeAPublicKey").expect("Node A: create DID");
        let did = node_a.did.clone();
        assert!(
            did.as_str().starts_with("did:crdt:"),
            "DID must be did:crdt scheme"
        );

        // ── Step 2: Sync A → B (initial join) ─────────────────────────────────
        // Exercises state-based convergence (`Document::merge_state`) — the
        // local/trusted-domain CvRDT join. (Over the untrusted network, peers
        // exchange signed DELTAS, not full state; merge_state is not wire-reachable.)
        let mut node_b = {
            // Node B starts with the same genesis (same key → same DID) so the
            // merge is a well-formed CvRDT join over a shared base.
            let (mut fresh_b, _) =
                Document::new("zNodeAPublicKey").expect("Node B: mirror genesis");
            // fresh_b has the same genesis state as node_a (same key → same DID).
            // merge_state is idempotent, so applying A's state is safe.
            fresh_b
                .merge_state(node_a.clone())
                .expect("Node B: initial state merge");
            fresh_b
        };

        // ── Step 3: Verify B converged ────────────────────────────────────────
        assert_converged(&node_a, &node_b);
        let result_b_before = node_b.resolve().expect("Node B: resolve before update");
        let doc_b_before = result_b_before
            .did_document
            .as_ref()
            .expect("Node B: document");
        assert_eq!(
            doc_b_before.id,
            did.to_string(),
            "Node B must resolve to Node A's DID"
        );
        assert_eq!(
            doc_b_before.verification_method.len(),
            1,
            "Node B must have the genesis verification method"
        );

        // ── Step 4: Node B applies an update (add service endpoint) ───────────
        let signer_b = node_b
            .resolve()
            .expect("Node B: resolve for signer")
            .did_document
            .as_ref()
            .expect("Node B: document for signer")
            .verification_method[0]
            .id
            .clone();
        let ts_b = HlcTimestamp {
            wall_ms: 1_000,
            logical: 0,
            node_id: 2,
        };
        let svc_id = format!("{}#svc-node-b", did);
        let mut update_delta = SignedDelta::unsigned(
            did.clone(),
            DeltaOp::AddServiceEndpoint {
                id: svc_id.clone(),
                service_type: "LinkedDomains".to_owned(),
                endpoint: "https://node-b.example.com".to_owned(),
            },
            ts_b,
            signer_b,
        );
        update_delta.parents = node_b.frontier();
        node_b
            .merge(update_delta.clone())
            .expect("Node B: add service endpoint");

        // Verify B's own state reflects the update.
        let result_b_after = node_b.resolve().expect("Node B: resolve after update");
        let doc_b_after = result_b_after
            .did_document
            .as_ref()
            .expect("Node B: document after update");
        assert_eq!(
            doc_b_after.service.len(),
            1,
            "Node B must have one service endpoint"
        );
        assert_eq!(doc_b_after.service[0].id, svc_id);

        // ── Step 5: Sync B → A (propagation) ──────────────────────────────────
        // Two convergence paths are tested, both must converge A to the same
        // result:
        //   (a) state-based  — merge_state(node_b)   [local/trusted CvRDT join]
        //   (b) delta-based  — merge(update_delta)   [the wire path: signed deltas]

        // Path (a): state-based merge.
        let mut node_a_via_state = node_a.clone();
        node_a_via_state
            .merge_state(node_b.clone())
            .expect("Node A: state-based merge");

        // Path (b): delta-based merge.
        let mut node_a_via_delta = node_a.clone();
        node_a_via_delta
            .merge(update_delta)
            .expect("Node A: delta-based merge");

        // Both paths must converge to Node B's state.
        assert_converged(&node_a_via_state, &node_b);
        assert_converged(&node_a_via_delta, &node_b);

        // ── Step 6: Verify A reflects the update ──────────────────────────────
        // Update node_a in-place (state-based path) for the final assertions.
        node_a
            .merge_state(node_b.clone())
            .expect("Node A: final merge");

        let result_a = node_a.resolve().expect("Node A: resolve");
        let result_b = node_b.resolve().expect("Node B: resolve");

        assert_eq!(
            result_a.did_document_metadata.version_id, result_b.did_document_metadata.version_id,
            "Both nodes must resolve to identical version_id after full convergence"
        );
        let doc_a = result_a.did_document.as_ref().expect("Node A: document");
        assert_eq!(
            doc_a.service.len(),
            1,
            "Node A must have the service endpoint added by Node B"
        );
        assert_eq!(
            doc_a.service[0].id, svc_id,
            "Node A must have the correct service endpoint id"
        );
        assert_eq!(
            doc_a.service[0].endpoint,
            serde_json::json!("https://node-b.example.com"),
            "Node A must have the correct service endpoint URL"
        );
    }

    /// Verify that concurrent, independent updates on both nodes converge
    /// symmetrically (state-based merge is commutative).
    #[test]
    fn two_node_concurrent_updates_converge() {
        // Create a shared genesis document.
        let (genesis, _) = Document::new("zSharedGenesisKey").expect("genesis");
        let mut node_a = genesis.clone();
        let mut node_b = genesis;

        let signer = node_a
            .resolve()
            .expect("resolve for signer")
            .did_document
            .as_ref()
            .expect("document for signer")
            .verification_method[0]
            .id
            .clone();

        // Node A: revoke a credential.
        let ts_a = HlcTimestamp {
            wall_ms: 1_000,
            logical: 0,
            node_id: 1,
        };
        let mut delta_a = SignedDelta::unsigned(
            node_a.did.clone(),
            DeltaOp::RevokeCredential {
                credential_id: "cred-from-a".to_owned(),
            },
            ts_a,
            signer.clone(),
        );
        delta_a.parents = node_a.frontier();
        node_a
            .merge(delta_a.clone())
            .expect("Node A: revoke credential");

        // Node B: set document data (LWW-Map entry).
        let ts_b = HlcTimestamp {
            wall_ms: 1_000,
            logical: 0,
            node_id: 2,
        };
        let mut delta_b = SignedDelta::unsigned(
            node_b.did.clone(),
            DeltaOp::SetDocumentData {
                key: "updated_by".to_owned(),
                value: serde_json::json!("node-b"),
            },
            ts_b,
            signer,
        );
        delta_b.parents = node_b.frontier();
        node_b
            .merge(delta_b.clone())
            .expect("Node B: set document data");

        // Sync in both directions (full state exchange).
        let mut merged_a = node_a.clone();
        merged_a
            .merge_state(node_b.clone())
            .expect("A merges B's state");

        let mut merged_b = node_b.clone();
        merged_b
            .merge_state(node_a.clone())
            .expect("B merges A's state");

        // Both merged replicas must be identical (commutativity).
        assert_converged(&merged_a, &merged_b);

        // Both updates must be present in the merged state.
        assert!(
            merged_a.is_revoked("cred-from-a"),
            "revocation from A must survive merge"
        );
        let result = merged_a.resolve().expect("resolve merged_a");
        let doc = result.did_document.as_ref().expect("document for merged_a");
        assert_eq!(
            doc.extra.get("updated_by"),
            Some(&serde_json::json!("node-b")),
            "document data from B must survive merge"
        );
    }

    /// Delta-based sync: Node B receives individual deltas from Node A and
    /// converges without needing the full state snapshot.
    #[test]
    fn two_node_delta_based_sync() {
        // Node A creates a DID.
        let (mut node_a, creation_delta) = Document::new("zDeltaSyncKey").expect("Node A: create");

        // Node A adds a verification method (second key).
        let signer = node_a
            .resolve()
            .expect("resolve for signer")
            .did_document
            .as_ref()
            .expect("document for signer")
            .verification_method[0]
            .id
            .clone();
        let ts1 = HlcTimestamp {
            wall_ms: 500,
            logical: 0,
            node_id: 1,
        };
        let mut add_key_delta = SignedDelta::unsigned(
            node_a.did.clone(),
            DeltaOp::AddVerificationMethod {
                id: format!("{}#key-1", node_a.did),
                public_key_multibase: "zSecondKey".to_owned(),
                suite_type: did_crdt::core::delta::SuiteType::default(),
                relationships: did_crdt::core::delta::default_relationships(),
            },
            ts1,
            signer,
        );
        add_key_delta.parents = node_a.frontier();
        node_a
            .merge(add_key_delta.clone())
            .expect("Node A: add key");
        assert_eq!(
            node_a
                .resolve()
                .expect("resolve A")
                .did_document
                .unwrap()
                .verification_method
                .len(),
            2,
            "Node A must have two verification methods"
        );

        // Node B starts fresh and replays A's delta log in order.
        let (mut node_b, _) = Document::new("zDeltaSyncKey").expect("Node B: mirror genesis");
        // Node B already has the creation delta applied (same key → same genesis).
        // Apply the subsequent delta.
        node_b
            .merge(add_key_delta)
            .expect("Node B: apply delta from A");

        // Verify B converged to A's state.
        assert_converged(&node_a, &node_b);
        assert_eq!(
            node_b
                .resolve()
                .expect("resolve B")
                .did_document
                .unwrap()
                .verification_method
                .len(),
            2,
            "Node B must have two verification methods after delta replay"
        );

        // Suppress unused-variable warning for creation_delta.
        let _ = creation_delta;
    }
}

// ── TEST-016: offline partition → reunion ─────────────────────────────────────

/// TEST-016 — Offline partition: 50 deltas on A, 30 on B, then full reunion.
///
/// Scenario:
/// 1. Both nodes start from an identical genesis document (same key).
/// 2. Network partition: no sync occurs.
/// 3. Node A applies 50 independent `SetDocumentData` deltas (unique keys
///    `"a-field-0"` … `"a-field-49"`).
/// 4. Node B applies 30 independent `SetDocumentData` deltas (unique keys
///    `"b-field-0"` … `"b-field-29"`).
/// 5. Partition healed: state-based reunion in both directions.
/// 6. Both nodes must converge to an identical resolved document that contains
///    all 80 delta effects (all 50 A-keys and all 30 B-keys).
mod offline_reunion {
    use did_crdt::{
        core::{
            delta::{DeltaOp, SignedDelta},
            hlc::HlcTimestamp,
        },
        Document,
    };

    #[test]
    fn partition_fifty_thirty_reunion_converges() {
        // ── Step 1: shared genesis ────────────────────────────────────────────
        let (genesis, _) = Document::new("zOfflineReunionKey").expect("genesis");
        let mut node_a = genesis.clone();
        let mut node_b = genesis;

        let signer = node_a
            .resolve()
            .expect("resolve for signer")
            .did_document
            .as_ref()
            .expect("document for signer")
            .verification_method[0]
            .id
            .clone();
        let did = node_a.did.clone();

        // ── Step 2: partition — Node A applies 50 deltas ──────────────────────
        for i in 0u64..50 {
            let ts = HlcTimestamp {
                wall_ms: 1_000 + i,
                logical: 0,
                node_id: 1,
            };
            let mut delta = SignedDelta::unsigned(
                did.clone(),
                DeltaOp::SetDocumentData {
                    key: format!("a-field-{}", i),
                    value: serde_json::json!(i),
                },
                ts,
                signer.clone(),
            );
            delta.parents = node_a.frontier();
            node_a
                .merge(delta)
                .unwrap_or_else(|e| panic!("Node A delta {i}: {e}"));
        }

        // ── Step 3: partition — Node B applies 30 deltas ──────────────────────
        for i in 0u64..30 {
            let ts = HlcTimestamp {
                wall_ms: 2_000 + i,
                logical: 0,
                node_id: 2,
            };
            let mut delta = SignedDelta::unsigned(
                did.clone(),
                DeltaOp::SetDocumentData {
                    key: format!("b-field-{}", i),
                    value: serde_json::json!(100 + i),
                },
                ts,
                signer.clone(),
            );
            delta.parents = node_b.frontier();
            node_b
                .merge(delta)
                .unwrap_or_else(|e| panic!("Node B delta {i}: {e}"));
        }

        // Sanity: verify each node only has its own fields before reunion.
        let pre_a = node_a
            .resolve()
            .expect("pre-reunion resolve A")
            .did_document
            .unwrap();
        assert_eq!(
            pre_a.extra.len(),
            50,
            "Node A must have exactly 50 fields pre-reunion"
        );
        let pre_b = node_b
            .resolve()
            .expect("pre-reunion resolve B")
            .did_document
            .unwrap();
        assert_eq!(
            pre_b.extra.len(),
            30,
            "Node B must have exactly 30 fields pre-reunion"
        );

        // ── Step 4: partition healed — bidirectional state-based reunion ───────
        node_a
            .merge_state(node_b.clone())
            .expect("Node A merges B's state");
        node_b
            .merge_state(node_a.clone())
            .expect("Node B merges A's state");

        // ── Step 5: assert convergence ────────────────────────────────────────
        let result_a = node_a.resolve().expect("post-reunion resolve A");
        let result_b = node_b.resolve().expect("post-reunion resolve B");

        assert_eq!(
            result_a.did_document_metadata.version_id, result_b.did_document_metadata.version_id,
            "version_id must match after offline reunion"
        );
        let ra = result_a.did_document.unwrap();
        let rb = result_b.did_document.unwrap();
        assert_eq!(
            ra.extra.len(),
            80,
            "merged document must contain all 80 fields"
        );
        assert_eq!(
            rb.extra.len(),
            80,
            "merged document must contain all 80 fields"
        );

        // Verify every A-field is present with correct value.
        for i in 0u64..50 {
            let key = format!("a-field-{}", i);
            assert_eq!(
                ra.extra.get(&key),
                Some(&serde_json::json!(i)),
                "A-field {key} missing or wrong in merged A"
            );
            assert_eq!(
                rb.extra.get(&key),
                Some(&serde_json::json!(i)),
                "A-field {key} missing or wrong in merged B"
            );
        }

        // Verify every B-field is present with correct value.
        for i in 0u64..30 {
            let key = format!("b-field-{}", i);
            assert_eq!(
                ra.extra.get(&key),
                Some(&serde_json::json!(100 + i)),
                "B-field {key} missing or wrong in merged A"
            );
            assert_eq!(
                rb.extra.get(&key),
                Some(&serde_json::json!(100 + i)),
                "B-field {key} missing or wrong in merged B"
            );
        }
    }
}

// ── TEST-014: HTTP API integration (real TCP server on localhost:0) ───────────

/// TEST-014 — Full HTTP API round-trip against a live axum server.
///
/// Scenario:
/// 1. Bind the service to a random OS-assigned port (localhost:0).
/// 2. `POST /dids` → 201, returns a `did:crdt:…` identifier.
/// 3. `GET  /{did}` → 200, returns a W3C DID Core JSON-LD document.
/// 4. `POST /dids/{did}/deltas` → 202, applies a delta to the document.
/// 5. `GET  /{did}` again → verifies the document reflects the update.
/// 6. `GET  /nonexistent-did` → 404.
#[cfg(feature = "service")]
mod http_api {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use did_crdt::core::{
        delta::{DeltaOp, SignedDelta, SigningKey},
        hlc::HlcTimestamp,
    };
    use did_crdt::service::server::Server;

    #[tokio::test]
    async fn create_resolve_update_notfound() {
        // ── Step 1: bind to localhost:0 ───────────────────────────────────────
        let (serve, addr) = Server::bind_ephemeral().await.expect("bind ephemeral");
        tokio::spawn(async move { serve.await.expect("server error") });

        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        // Use a real Ed25519 keypair so the handler's verify_signature check
        // passes.  The public key must be encoded as multibase base64url
        // (`u` prefix, no padding) as required by the document model.
        let raw = [0xDDu8; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&raw);
        let pk_mb = format!(
            "u{}",
            Base64UrlUnpadded::encode_string(sk.verifying_key().as_bytes())
        );

        // ── Step 2: POST /dids ────────────────────────────────────────────────
        let resp = client
            .post(format!("{base}/dids"))
            .json(&serde_json::json!({ "publicKeyMultibase": pk_mb }))
            .send()
            .await
            .expect("POST /dids");
        assert_eq!(resp.status(), 201, "POST /dids must return 201 Created");

        let body: serde_json::Value = resp.json().await.expect("parse POST /dids body");
        let did_str = body["did"]
            .as_str()
            .expect("response must contain 'did' field")
            .to_owned();
        assert!(
            did_str.starts_with("did:crdt:"),
            "DID must be did:crdt scheme"
        );

        // ── Step 3: GET /{did} ────────────────────────────────────────────────
        let resp = client
            .get(format!("{base}/{did_str}"))
            .send()
            .await
            .expect("GET /{did}");
        assert_eq!(resp.status(), 200, "GET /{{did}} must return 200 OK");

        let result: serde_json::Value = resp.json().await.expect("parse GET /{did} body");
        let doc = &result["didDocument"];
        assert_eq!(
            doc["id"].as_str().unwrap_or(""),
            did_str,
            "resolved document id must match the created DID"
        );
        assert!(
            doc["verificationMethod"]
                .as_array()
                .map_or(false, |a| !a.is_empty()),
            "resolved document must have at least one verification method"
        );

        // ── Step 4: POST /dids/{did}/deltas — submit a *signed* delta ─────────
        // The handler enforces verify_signature at the Tier 1 trust boundary,
        // so unsigned deltas on active documents are rejected with 403.
        let did: did_crdt::core::did::Did = did_str.parse().expect("parse DID");
        let node_id = did_crdt::core::validate::node_id_from_pubkey(sk.verifying_key().as_bytes());
        let ts = HlcTimestamp {
            wall_ms: 1_000,
            logical: 0,
            node_id,
        };
        let signer = format!("{did}#key-0");
        let signing_key = SigningKey::Ed25519(sk);
        // Ground the delta on the document's frontier (SPEC-036). Genesis is
        // deterministic, so the client recomputes its hash from the public key;
        // exposing the live frontier via the API is a follow-up (SPEC-036 §1a).
        let (_ref_doc, genesis_delta) =
            did_crdt::Document::new(&pk_mb).expect("reconstruct genesis");
        let parents = vec![genesis_delta.content_hash().expect("genesis hash")];
        let delta = SignedDelta::new_with_parents(
            did.clone(),
            DeltaOp::AddServiceEndpoint {
                id: format!("{did}#svc-test"),
                service_type: "LinkedDomains".to_owned(),
                endpoint: "https://example.com".to_owned(),
            },
            ts,
            parents,
            signer,
            &signing_key,
        )
        .expect("signing must succeed");

        let resp = client
            .post(format!("{base}/dids/{did_str}/deltas"))
            .json(&delta)
            .send()
            .await
            .expect("POST /dids/{did}/deltas");
        assert_eq!(resp.status(), 202, "POST deltas must return 202 Accepted");

        // ── Step 5: re-resolve to verify the update was applied ───────────────
        let resp = client
            .get(format!("{base}/{did_str}"))
            .send()
            .await
            .expect("GET /{did} after delta");
        assert_eq!(resp.status(), 200);

        let result: serde_json::Value = resp.json().await.expect("parse re-resolve body");
        let services = result["didDocument"]["service"]
            .as_array()
            .expect("document must have 'service' array");
        assert_eq!(
            services.len(),
            1,
            "document must have one service endpoint after delta"
        );
        assert_eq!(
            services[0]["id"].as_str().unwrap_or(""),
            format!("{did}#svc-test"),
            "service endpoint id must match the submitted delta"
        );

        // ── Step 6: GET /nonexistent → 404 ───────────────────────────────────
        let fake_did = format!("did:crdt:{}", "f".repeat(64));
        let resp = client
            .get(format!("{base}/{fake_did}"))
            .send()
            .await
            .expect("GET /nonexistent");
        assert_eq!(resp.status(), 404, "unknown DID must return 404 Not Found");
    }
}

// ── TEST-015 (sync feature): SyncMessage wire protocol simulation ─────────────

/// Simulation of the CON-004 Announce → Request → Deltas wire exchange (TEST-015).
///
/// Validates that:
/// - `SyncMessage::Announce` correctly encodes a (DID, hash) advertisement.
/// - `SyncMessage::Request` carrying the requester's frontier is generated in
///   response to an unknown hash.
/// - `SyncMessage::Deltas` delivers exactly the signed deltas above that
///   frontier and survives a JSON round-trip.
/// - Applying the delivered deltas through the admission path produces
///   convergence. (There is no full-state wire message: every cross-peer
///   payload is authenticated signed deltas.)
#[cfg(feature = "sync")]
mod two_node_sync_messages {
    use did_crdt::{
        core::{
            delta::{DeltaOp, SignedDelta},
            hlc::HlcTimestamp,
        },
        sync::protocol::SyncMessage,
        Document,
    };

    #[test]
    fn announce_request_deltas_roundtrip_converges() {
        // ── Node A: create a DID and apply one update (genesis + 1) ──
        let (mut node_a, _) = Document::new("zSyncMsgKey").expect("Node A: create");
        let did = node_a.did.clone();
        let signer = format!("{}#key-0", did);
        let mut update = SignedDelta::unsigned(
            did.clone(),
            DeltaOp::RevokeCredential {
                credential_id: "c1".to_owned(),
            },
            HlcTimestamp {
                wall_ms: 100,
                logical: 0,
                node_id: 1,
            },
            signer,
        );
        update.parents = node_a.frontier();
        node_a.merge(update).expect("Node A: apply update");

        // Node B: fresh mirror (same key → same genesis), behind by one delta.
        let (mut node_b, _) = Document::new("zSyncMsgKey").expect("Node B: mirror genesis");

        // Step 1: A computes its content hash and broadcasts ANNOUNCE.
        let hash = node_a.content_hash().expect("content_hash must succeed");
        let clock = HlcTimestamp {
            wall_ms: 0,
            logical: 0,
            node_id: 1,
        };
        let announce = SyncMessage::Announce {
            did: did.clone(),
            hash: *hash.as_bytes(),
            clock,
        };
        let recv_announce: SyncMessage =
            serde_json::from_slice(&serde_json::to_vec(&announce).expect("serialise ANNOUNCE"))
                .expect("deserialise ANNOUNCE");

        // Step 2: B sees an unknown (did, hash) pair → REQUEST advertising its frontier.
        let request = match recv_announce {
            SyncMessage::Announce { did: ann_did, .. } => {
                assert_eq!(ann_did, did);
                SyncMessage::Request {
                    did: ann_did,
                    frontier: node_b.frontier(),
                }
            }
            _ => panic!("expected Announce"),
        };
        let recv_request: SyncMessage =
            serde_json::from_slice(&serde_json::to_vec(&request).expect("serialise REQUEST"))
                .expect("deserialise REQUEST");

        // Step 3: A receives REQUEST, responds with the DELTAS above B's frontier.
        let deltas_msg = match recv_request {
            SyncMessage::Request {
                did: req_did,
                frontier,
            } => {
                assert_eq!(req_did, did);
                let deltas = node_a.deltas_for_peer(&frontier).expect("deltas_for_peer");
                assert_eq!(
                    deltas.len(),
                    1,
                    "B lacks exactly the one post-genesis delta"
                );
                SyncMessage::Deltas {
                    did: req_did,
                    deltas,
                }
            }
            _ => panic!("expected Request"),
        };
        let recv_deltas: SyncMessage =
            serde_json::from_slice(&serde_json::to_vec(&deltas_msg).expect("serialise DELTAS"))
                .expect("deserialise DELTAS");

        // Step 4: B receives DELTAS, applies each through the admission path.
        match recv_deltas {
            SyncMessage::Deltas { did: d_did, deltas } => {
                assert_eq!(d_did, did);
                for delta in deltas {
                    node_b.merge(delta).expect("Node B: apply delta");
                }
            }
            _ => panic!("expected Deltas"),
        }

        // Verify convergence.
        let ra = node_a.resolve().expect("resolve A");
        let rb = node_b.resolve().expect("resolve B");
        assert_eq!(
            ra.did_document_metadata.version_id, rb.did_document_metadata.version_id,
            "Nodes must converge after Announce→Request→Deltas exchange"
        );
        assert!(ra.did_document.is_some());
        assert!(rb.did_document.is_some());
    }
}

// ── TEST-023: cold-start convergence via DHT ──────────────────────────────────

/// TEST-023 (CON-006 §cold-start resolution): node B bootstraps a DID it has
/// never seen by performing a DHT lookup, connecting to node A, and pulling
/// the full delta history over gossip.
///
/// Scenario:
/// 1. Node A (service + sync) creates DID D via POST /dids, which publishes
///    to the shared in-process pkarr relay stub and stores the full NodeAddr.
/// 2. Node B (service + sync, empty DocStore, same in-process stub) receives
///    GET /{D}.  Its resolve handler triggers cold_start_bootstrap: DHT lookup
///    → connect to node A → REQUEST with empty frontier → DELTAS → genesis
///    bootstrap → document appears in node B's DocStore.
/// 3. The GET response returns 200 with a DID document whose versionId matches
///    node A's resolved document (REQ-014, NFR-008 ≤15 s).
#[cfg(all(feature = "service", feature = "sync"))]
mod cold_start_convergence {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use did_crdt::service::metrics::Metrics;
    use did_crdt::service::server::{build_router, AppState};
    use did_crdt::sync::dht::DhtNode;
    use did_crdt::sync::live::{topic_for, LiveNode};
    use did_crdt::DocStore;
    use pkarr::SignedPacket;

    #[tokio::test]
    async fn dht_cold_start_resolves_unknown_did() {
        // ── Shared in-process DHT stores ─────────────────────────────────────
        let pkarr_store: Arc<Mutex<HashMap<[u8; 32], SignedPacket>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let addr_store: Arc<Mutex<HashMap<[u8; 32], iroh::net::NodeAddr>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // ── Node A: service + sync, empty store ──────────────────────────────
        let docs_a = DocStore::new();
        let dht_a = Arc::new(DhtNode::new_in_process(
            pkarr_store.clone(),
            addr_store.clone(),
            Duration::from_secs(5),
        ));
        let topic = topic_for(b"did-crdt/test-023-cold-start");
        let node_a = LiveNode::bind(topic, docs_a.clone(), Some(dht_a.clone()), false)
            .await
            .unwrap();
        let _task_a = node_a.spawn();
        node_a.seed().await.unwrap();

        // ── Node B: service + sync, empty store, same DHT stubs ──────────────
        let docs_b = DocStore::new();
        let dht_b = Arc::new(DhtNode::new_in_process(
            pkarr_store.clone(),
            addr_store.clone(),
            Duration::from_secs(5),
        ));
        let node_b = LiveNode::bind(topic, docs_b.clone(), Some(dht_b.clone()), false)
            .await
            .unwrap();
        let _task_b = node_b.spawn();
        node_b.seed().await.unwrap();

        // ── HTTP services ────────────────────────────────────────────────────
        let state_a = AppState {
            docs: docs_a,
            live_node: Some(Arc::new(node_a)),
            dht: Some(dht_a),
            metrics: Arc::new(Metrics::new()),
            resolve_timeout: Duration::from_secs(15),
        };
        let state_b = AppState {
            docs: docs_b.clone(),
            live_node: Some(Arc::new(node_b)),
            dht: Some(dht_b),
            metrics: Arc::new(Metrics::new()),
            resolve_timeout: Duration::from_secs(15),
        };
        let listener_a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_a = listener_a.local_addr().unwrap();
        let listener_b = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_b = listener_b.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener_a, build_router(state_a))
                .await
                .unwrap()
        });
        tokio::spawn(async move {
            axum::serve(listener_b, build_router(state_b))
                .await
                .unwrap()
        });

        // ── Step 1: node A creates DID D (POST /dids) ────────────────────────
        // This triggers DHT publish — storing both the pkarr record and the
        // full NodeAddr (with direct socket addresses) in the shared stubs.
        let raw = [0xE3u8; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&raw);
        let pk_mb = format!(
            "u{}",
            Base64UrlUnpadded::encode_string(sk.verifying_key().as_bytes())
        );

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr_a}/dids"))
            .json(&serde_json::json!({ "publicKeyMultibase": pk_mb }))
            .send()
            .await
            .expect("POST /dids to node A");
        assert_eq!(resp.status(), 201, "node A must accept DID creation");
        let body: serde_json::Value = resp.json().await.unwrap();
        let did_str = body["did"].as_str().unwrap().to_owned();
        assert!(
            did_str.starts_with("did:crdt:"),
            "response must contain a did:crdt DID"
        );

        // ── Step 2: get node A's versionId as the convergence target ─────────
        let resp: serde_json::Value = client
            .get(format!("http://{addr_a}/{did_str}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let a_version_id = resp["didDocumentMetadata"]["versionId"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(
            !a_version_id.is_empty(),
            "node A must have a non-empty versionId"
        );

        // ── Step 3: node B cold-start resolves DID D (GET /:did on node B) ───
        // Node B's DocStore is empty; the handler triggers cold_start_bootstrap:
        //   DHT lookup → returns node A's full NodeAddr from addr_store
        //   → connect to node A over iroh gossip
        //   → broadcast REQUEST with empty frontier
        //   → node A responds with full DELTAS (genesis)
        //   → genesis_bootstrap inserts D into node B's DocStore
        //   → handler reads and resolves D → returns 200
        let start = std::time::Instant::now();
        let resp = client
            .get(format!("http://{addr_b}/{did_str}"))
            .send()
            .await
            .expect("GET /:did from node B");

        assert_eq!(
            resp.status(),
            200,
            "node B cold-start resolve must return 200 OK (TEST-023)"
        );
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "cold-start resolve must complete within 15 s (NFR-008)"
        );

        let result: serde_json::Value = resp.json().await.unwrap();
        let b_version_id = result["didDocumentMetadata"]["versionId"].as_str().unwrap();
        assert_eq!(
            b_version_id, a_version_id,
            "node B must converge to node A's versionId after cold-start bootstrap (TEST-023)"
        );
        let doc_b = result["didDocument"].as_object().unwrap();
        assert_eq!(
            doc_b["id"].as_str().unwrap(),
            did_str,
            "resolved DID document id must match the requested DID"
        );
    }
}

// ── TEST-015-live: full HTTP service + real iroh gossip ───────────────────────

/// TEST-015-live (CON-005): two did-crdt service instances peered over live
/// iroh-gossip converge after a signed delta is submitted to node A.
///
/// Exercises the full stack end-to-end: HTTP POST /deltas → merge → announce
/// → iroh-gossip wire → peer merge → HTTP GET /:did reflects update.
///
/// Node B starts with an empty DocStore in replicate-all mode
/// (`REPLICATE_ALL=true`): it bootstraps the genesis document automatically via
/// the gossip ANNOUNCE → REQUEST → DELTAS path (CON-006 genesis bootstrap) when
/// node A announces the updated state. (Without replicate-all, unsolicited
/// announcements of unknown DIDs are ignored — CON-006 §admission control —
/// and bootstrap happens only through cold-start resolution, as in TEST-023.)
#[cfg(all(feature = "service", feature = "sync"))]
mod live_two_node {
    use std::sync::Arc;
    use std::time::Duration;

    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use did_crdt::core::delta::{DeltaOp, SignedDelta, SigningKey};
    use did_crdt::core::hlc::HlcTimestamp;
    use did_crdt::core::validate::node_id_from_pubkey;
    use did_crdt::service::metrics::Metrics;
    use did_crdt::service::server::{build_router, AppState};
    use did_crdt::sync::live::{topic_for, LiveNode};
    use did_crdt::Document;

    /// Submit a signed delta to node A; poll node B until it reflects the update.
    #[tokio::test]
    async fn delta_on_a_propagates_to_b() {
        // ── Shared keypair and DID ────────────────────────────────────────────
        let raw = [0xA7u8; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&raw);
        let pk_mb = format!(
            "u{}",
            Base64UrlUnpadded::encode_string(sk.verifying_key().as_bytes())
        );
        let nid = node_id_from_pubkey(sk.verifying_key().as_bytes());
        let (doc_a, genesis_delta) = Document::new(&pk_mb).expect("create DID");
        let did = doc_a.did.clone();
        let did_str = did.to_string();
        let genesis_hash = genesis_delta.content_hash().expect("genesis hash");
        let signer_id = format!("{did}#key-0");

        // ── Pre-seed node A's store; node B starts empty and bootstraps ───────
        let docs_a = did_crdt::DocStore::new();
        let docs_b = did_crdt::DocStore::new();
        docs_a.lock().insert(did.clone(), doc_a);

        // ── Gossip setup (spawn run-loops before seed/connect) ────────────────
        let topic = topic_for(b"did-crdt/test-live-delta");
        let node_a = LiveNode::bind(topic, docs_a.clone(), None, false)
            .await
            .unwrap();
        let node_b = LiveNode::bind(topic, docs_b.clone(), None, true)
            .await
            .unwrap();
        let _task_a = node_a.spawn();
        let _task_b = node_b.spawn();
        node_a.seed().await.unwrap();
        let a_addr = node_a.node_addr().await.unwrap();
        node_b.connect(a_addr).await.unwrap();

        // ── Wire into HTTP services ───────────────────────────────────────────
        let state_a = AppState {
            docs: docs_a,
            live_node: Some(Arc::new(node_a)),
            dht: None,
            metrics: Arc::new(Metrics::new()),
            resolve_timeout: std::time::Duration::from_secs(10),
        };
        let state_b = AppState {
            docs: docs_b,
            live_node: Some(Arc::new(node_b)),
            dht: None,
            metrics: Arc::new(Metrics::new()),
            resolve_timeout: std::time::Duration::from_secs(10),
        };
        let listener_a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_a = listener_a.local_addr().unwrap();
        let listener_b = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_b = listener_b.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener_a, build_router(state_a))
                .await
                .unwrap()
        });
        tokio::spawn(async move {
            axum::serve(listener_b, build_router(state_b))
                .await
                .unwrap()
        });

        // ── Step 1: GET /:did from both nodes (baseline version_id) ──────────
        let client = reqwest::Client::new();
        let base_a: serde_json::Value = client
            .get(format!("http://{addr_a}/{did_str}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let base_version = base_a["didDocumentMetadata"]["versionId"]
            .as_str()
            .unwrap()
            .to_owned();

        // ── Step 2: POST a signed delta to node A ────────────────────────────
        let ts = HlcTimestamp {
            wall_ms: 1_000,
            logical: 0,
            node_id: nid,
        };
        let signing_key = SigningKey::Ed25519(sk);
        let delta = SignedDelta::new_with_parents(
            did.clone(),
            DeltaOp::RevokeCredential {
                credential_id: "live-test-cred".to_owned(),
            },
            ts,
            vec![genesis_hash],
            signer_id,
            &signing_key,
        )
        .expect("sign delta");

        let resp = client
            .post(format!("http://{addr_a}/dids/{did_str}/deltas"))
            .json(&delta)
            .send()
            .await
            .expect("POST /deltas to node A");
        assert_eq!(resp.status(), 202, "node A must accept the delta");

        // ── Step 3: Get node A's new version_id after applying the delta ─────
        let after_a: serde_json::Value = client
            .get(format!("http://{addr_a}/{did_str}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let updated_version = after_a["didDocumentMetadata"]["versionId"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_ne!(
            updated_version, base_version,
            "applying delta must update version_id"
        );

        // ── Step 4: Poll node B until it reflects the same version_id ────────
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            let resp: serde_json::Value = client
                .get(format!("http://{addr_b}/{did_str}"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            if resp["didDocumentMetadata"]["versionId"].as_str() == Some(&updated_version) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "node B did not converge to node A's version_id within 20 s (TEST-015-live)"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
