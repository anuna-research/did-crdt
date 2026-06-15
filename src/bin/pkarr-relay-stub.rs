//! Minimal in-process pkarr relay stub for cross-process E2E tests.
//!
//! Implements the two-endpoint pkarr relay protocol over HTTP:
//!   PUT /<pubkey>  — store a signed packet payload (body bytes)
//!   GET /<pubkey>  — retrieve it; 404 if not found
//!
//! The pubkey in the URL is a zbase32-encoded Ed25519 public key — treated as
//! an opaque string key; no decoding is performed server-side.
//!
//! On startup prints "READY http://127.0.0.1:<port>" to stdout so shell scripts
//! can capture the bound port.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};

type Store = Arc<Mutex<HashMap<String, Vec<u8>>>>;

async fn put_packet(
    Path(pubkey): Path<String>,
    State(store): State<Store>,
    body: Bytes,
) -> StatusCode {
    store.lock().unwrap().insert(pubkey, body.to_vec());
    StatusCode::OK
}

async fn get_packet(
    Path(pubkey): Path<String>,
    State(store): State<Store>,
) -> impl IntoResponse {
    match store.lock().unwrap().get(&pubkey) {
        Some(bytes) => (StatusCode::OK, bytes.clone()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[tokio::main]
async fn main() {
    let store: Store = Arc::new(Mutex::new(HashMap::new()));
    let app = Router::new()
        .route("/:pubkey", get(get_packet).put(put_packet))
        .with_state(store);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    println!("READY http://127.0.0.1:{port}");
    axum::serve(listener, app).await.unwrap();
}
