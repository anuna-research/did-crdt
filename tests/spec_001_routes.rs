//! The three routes selfsame SPEC-001 §6.12 places on this service.
//!
//! `selfsame-rendezvous` is the reference implementation of these contracts
//! ("so the contracts can be exercised end to end here before they are
//! upstreamed"); this is the upstreaming its `SIMPLIFY` note names, driven by
//! selfsame `IMPL-008` `ADR-913`. The rows mirror the reference semantics:
//!
//! ```text
//!   PUT/GET /rendezvous/{slot}    CON-002  blind mailbox: single-write,
//!                                          read-once, 600 s lifetime
//!   GET     /dids/{did}/closure   CON-005  signed deltas, not a document
//! ```
//!
//! The blind mailbox makes no trust decision and holds no key; a slot is
//! 26 characters of RFC 4648 lowercase base32, anything else is refused
//! before it reaches the store.

#![cfg(feature = "service")]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64ct::Encoding as _;
use did_crdt::service::server::{build_router, AppState};
use tower::ServiceExt as _;

fn router() -> axum::Router {
    build_router(AppState::new())
}

fn slot(fill: char) -> String {
    std::iter::repeat(fill).take(26).collect()
}

async fn put_slot(router: &axum::Router, slot: &str, body: &[u8]) -> StatusCode {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/rendezvous/{slot}"))
                .body(Body::from(body.to_vec()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

async fn get_slot(router: &axum::Router, slot: &str) -> (StatusCode, Vec<u8>) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/rendezvous/{slot}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, body.to_vec())
}

// ── CON-002: the blind mailbox ──────────────────────────────────────────────

#[tokio::test]
async fn a_slot_is_single_write_and_read_once() {
    let router = router();
    let address = slot('a');

    assert_eq!(put_slot(&router, &address, b"ciphertext").await, StatusCode::CREATED);
    // Single-write: the mailbox is immutable once written.
    assert_eq!(put_slot(&router, &address, b"overwrite").await, StatusCode::CONFLICT);

    let (status, body) = get_slot(&router, &address).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"ciphertext");
    // Read-once: a leaked address is stale almost immediately.
    assert_eq!(get_slot(&router, &address).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn slots_outside_the_grammar_are_refused() {
    let router = router();
    // Too short, uppercase, a digit outside 2-7.
    for bad in ["abc", &slot('A'), &slot('1')] {
        assert_eq!(
            put_slot(&router, bad, b"x").await,
            StatusCode::BAD_REQUEST,
            "{bad} must be refused before it reaches the store"
        );
    }
    // A traversal probe never matches the single-segment route at all: the
    // router answers 404 before the handler exists to be probed.
    assert_eq!(
        put_slot(&router, "../../../../etc/passwd", b"x").await,
        StatusCode::NOT_FOUND
    );
    // A well-formed but unwritten slot is simply absent.
    assert_eq!(get_slot(&router, &slot('b')).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn empty_and_oversized_bodies_are_refused() {
    let router = router();
    assert_eq!(put_slot(&router, &slot('c'), b"").await, StatusCode::BAD_REQUEST);
    let oversized = vec![0u8; 4097];
    assert_eq!(put_slot(&router, &slot('d'), &oversized).await, StatusCode::BAD_REQUEST);
    // The cap itself is admitted.
    let exactly = vec![0u8; 4096];
    assert_eq!(put_slot(&router, &slot('e'), &exactly).await, StatusCode::CREATED);
}

// ── CON-005: signed-closure resolution ──────────────────────────────────────

#[tokio::test]
async fn the_closure_route_returns_signed_deltas_not_a_document() {
    let router = router();

    // Unknown DID: absent, not empty.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/dids/did:crdt:{}/closure", "0".repeat(64)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Create a DID through the service's own front door.
    let key = [7u8; 32];
    let public_key_multibase = format!(
        "u{}",
        base64ct::Base64UrlUnpadded::encode_string(&key)
    );
    let created = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dids")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "publicKeyMultibase": public_key_multibase }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(created.status().is_success(), "create_did: {}", created.status());
    let created_body = axum::body::to_bytes(created.into_body(), usize::MAX).await.unwrap();
    let created_json: serde_json::Value = serde_json::from_slice(&created_body).unwrap();
    let did = created_json
        .pointer("/didDocument/id")
        .or_else(|| created_json.pointer("/did"))
        .and_then(|v| v.as_str())
        .expect("created DID in response")
        .to_owned();

    // The closure: signed deltas the verifier can replay, never a resolved
    // document with the signatures stripped.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/dids/{did}/closure"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let deltas = json["deltas"].as_array().expect("a deltas array");
    assert!(!deltas.is_empty(), "the genesis delta is part of the closure");
    for delta in deltas {
        // A SignedDelta carries its `proof`; a resolved document's
        // verification methods carry none — this is the row that catches a
        // handler quietly returning the projection instead.
        assert!(
            delta.get("proof").is_some(),
            "every closure entry carries its proof: {delta}"
        );
    }
}
