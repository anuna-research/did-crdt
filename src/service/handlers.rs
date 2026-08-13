//! axum route handlers for the DID resolution HTTP API.
//!
//! Each handler maps directly to one endpoint in the DID Resolution spec and
//! the did-crdt service API (see SPEC-032 §7 REQ-012 / CON-003).
//!
//! | Method | Path              | Handler          |
//! |--------|-------------------|------------------|
//! | POST   | /dids             | [`create_did`]   |
//! | GET    | /:did             | [`resolve_did`]  |
//! | POST   | /dids/:did/deltas | [`submit_delta`] |
//! | GET    | /metrics          | [`get_metrics`]  |

use std::time::Instant;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};

use crate::core::{
    delta::{SignedDelta, MAX_DELTA_SIZE},
    did::Did,
    document::Document,
    resolve::ResolutionResult,
    validate, Error,
};

use super::server::AppState;

// ── Request / response bodies ─────────────────────────────────────────────────

/// Body for `POST /dids`.
#[derive(Debug, Deserialize)]
pub struct CreateDidBody {
    /// Public key in Multibase encoding (e.g. `z<base58btc-bytes>`).
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

/// Response body for `POST /dids` (201 Created).
#[derive(Debug, Serialize)]
pub struct CreateDidResponse {
    pub did: String,
    pub document: ResolutionResult,
}

// ── Error helper ──────────────────────────────────────────────────────────────

fn core_error_response(err: Error) -> Response {
    match err {
        Error::InvalidDid(_) | Error::Serialisation(_) => {
            (StatusCode::BAD_REQUEST, err.to_string()).into_response()
        }
        Error::InvalidSignature | Error::Unauthorised(_) => {
            (StatusCode::FORBIDDEN, err.to_string()).into_response()
        }
        Error::DeltaRejected(_) => (StatusCode::CONFLICT, err.to_string()).into_response(),
        // Causal predecessors not yet available: the delta is not invalid, only
        // undecidable. 409 signals the client to deliver the missing ancestors
        // (listed in the body) and re-submit (SPEC-036 REQ-363, Reject policy).
        Error::DeltaPending { .. } => (StatusCode::CONFLICT, err.to_string()).into_response(),
        Error::DeltaTooLarge { .. } => {
            (StatusCode::PAYLOAD_TOO_LARGE, err.to_string()).into_response()
        }
    }
}

// ── POST /dids ────────────────────────────────────────────────────────────────

/// Create a new DID document from a public key.
///
/// Accepts `{ "publicKeyMultibase": "z..." }` and returns 201 with the new
/// DID string and its resolved W3C DID document.
pub async fn create_did(
    State(state): State<AppState>,
    Json(body): Json<CreateDidBody>,
) -> Response {
    let (doc, _creation_delta) = match Document::new(&body.public_key_multibase) {
        Ok(pair) => pair,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };

    let did = doc.did.clone();
    let did_str = did.to_string();

    let resolution_result = match doc.resolve() {
        Ok(r) => r,
        Err(err) => return core_error_response(err),
    };

    let state_bytes = doc.to_bytes().map(|b| b.len() as i64).unwrap_or(0);
    state
        .metrics
        .record_delta_accepted(&truncate_did(&did_str), state_bytes);

    state.docs.lock().insert(did.clone(), doc);

    // Announce the new DID to peers so they can reconcile (CON-004 step 4).
    #[cfg(feature = "sync")]
    if let Some(node) = &state.live_node {
        if let Err(e) = node.announce(&did).await {
            eprintln!("did-crdt: announce failed for {did}: {e}");
        }
    }

    // DHT publication — this node is now a first-time holder (CON-006 trigger 1).
    // Runs in the background: publication is best-effort and non-fatal, so a
    // slow or unreachable relay must not delay the HTTP response. Repeat POSTs
    // for the same DID are deduplicated inside DhtNode::publish.
    #[cfg(feature = "sync")]
    if let (Some(dht), Some(live_node)) = (&state.dht, &state.live_node) {
        let dht = dht.clone();
        let live_node = live_node.clone();
        let did = did.clone();
        tokio::spawn(async move {
            match live_node.node_addr().await {
                Ok(node_addr) => {
                    if let Err(e) = dht.publish(&did, &node_addr).await {
                        eprintln!("did-crdt: DHT publish failed for {did}: {e}");
                    }
                }
                Err(e) => {
                    eprintln!("did-crdt: could not get node addr for DHT publish of {did}: {e}");
                }
            }
        });
    }

    (
        StatusCode::CREATED,
        Json(CreateDidResponse {
            did: did_str,
            document: resolution_result,
        }),
    )
        .into_response()
}

// ── GET /:did ─────────────────────────────────────────────────────────────────

/// Resolve a DID to a W3C DID document.
///
/// - 200 with DID document on success
/// - 404 if not found in local state
/// - 410 Gone if the DID is deactivated
pub async fn resolve_did(State(state): State<AppState>, Path(did_str): Path<String>) -> Response {
    let start = Instant::now();

    let did: Did = match did_str.parse() {
        Ok(d) => d,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid DID format").into_response(),
    };

    // If not locally held, attempt cold-start bootstrap via DHT (CON-006).
    #[cfg(feature = "sync")]
    {
        let not_held = !state.docs.lock().contains_key(&did);
        if not_held {
            if let (Some(node), Some(_dht)) = (&state.live_node, &state.dht) {
                match node.cold_start_bootstrap(&did, state.resolve_timeout).await {
                    Ok(()) => {}
                    Err(e) => {
                        eprintln!("did-crdt: cold-start failed for {did}: {e}");
                        return StatusCode::NOT_FOUND.into_response();
                    }
                }
            } else {
                return StatusCode::NOT_FOUND.into_response();
            }
        }
    }

    let (result, elapsed, field_count) = {
        let guard = state.docs.lock();
        let Some(doc) = guard.get(&did) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let result = match doc.resolve() {
            Ok(r) => r,
            Err(err) => return core_error_response(err),
        };
        let elapsed = start.elapsed().as_secs_f64();
        let field_count = result
            .did_document
            .as_ref()
            .map(|d| d.verification_method.len() + d.service.len() + d.extra.len())
            .unwrap_or(0);
        (result, elapsed, field_count)
    };

    state.metrics.observe_resolution(elapsed, field_count);

    // Stamp this node's identity, if it claims one. Done HERE rather than in
    // `Document::resolve` because the core has no idea which node it is running
    // in — and a library caller resolving locally has no resolver to name.
    //
    // `clone` per response is a short string on a path that has just walked a
    // CRDT and serialised a document.
    let mut result = result;
    result.did_resolution_metadata.resolver_id = state.resolver_id.clone();
    let result = result;

    if result.did_document_metadata.deactivated {
        return (StatusCode::GONE, Json(result)).into_response();
    }

    (StatusCode::OK, Json(result)).into_response()
}

// ── POST /dids/:did/deltas ────────────────────────────────────────────────────

/// Submit a signed delta for a DID.
///
/// - 202 Accepted on success
/// - 400 if the path DID mismatches the delta DID or the DID is unknown
/// - 403 if signature verification fails or the signer is not authorised
/// - 409 if the delta is structurally rejected (deactivated DID, etc.)
pub async fn submit_delta(
    State(state): State<AppState>,
    Path(did_str): Path<String>,
    Json(delta): Json<SignedDelta>,
) -> Response {
    // Size gate — reject oversized deltas early (ADR-004, 64 KiB limit).
    if let Ok(bytes) = serde_json::to_vec(&delta) {
        if bytes.len() > MAX_DELTA_SIZE {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "delta too large: {} bytes exceeds maximum {} bytes",
                    bytes.len(),
                    MAX_DELTA_SIZE
                ),
            )
                .into_response();
        }
    }

    if delta.did.to_string() != did_str {
        return (
            StatusCode::BAD_REQUEST,
            "DID in path does not match DID in delta",
        )
            .into_response();
    }

    let did = delta.did.clone();

    // Acquire the lock, run all synchronous checks and the merge, then
    // release before any async operations (CON-005).
    let (merge_result, state_bytes) = {
        let mut guard = state.docs.lock();
        let Some(doc) = guard.get_mut(&did) else {
            state.metrics.record_delta_rejected("unknown_did");
            return StatusCode::NOT_FOUND.into_response();
        };

        // ── Trust-boundary checks ────────────────────────────────────────────
        // Out-of-order delivery FIRST: if the delta's causal predecessors are not
        // all present, it is undecidable — hold it for retry. This must precede
        // signature verification, because a delta signed by a key introduced by a
        // not-yet-delivered AddVerificationMethod cannot be verified (the key is not
        // in the current document) and would otherwise be wrongly rejected as a bad
        // signature, breaking the key-transition retry protocol (SPEC-036 REQ-363).
        let missing = doc.missing_parents(&delta);
        if !missing.is_empty() {
            state.metrics.record_delta_rejected("pending");
            let body = serde_json::json!({
                "error": "delta_pending",
                "missing": missing.iter().map(|h| h.to_string()).collect::<Vec<_>>(),
            });
            return (StatusCode::CONFLICT, Json(body)).into_response();
        }
        // Cryptographic signature verification (the closure is complete, so the
        // signing key is resolvable). `merge()` does the current-state authorisation.
        if let Err(err) = validate::verify_signature(&delta, doc) {
            state.metrics.record_delta_rejected("invalid_signature");
            return (StatusCode::FORBIDDEN, err.to_string()).into_response();
        }
        // ────────────────────────────────────────────────────────────────────

        let result = doc.merge(delta);
        let bytes = if result.is_ok() {
            doc.to_bytes().map(|b| b.len() as i64).unwrap_or(0)
        } else {
            0
        };
        (result, bytes)
        // lock released here — no async operations held the mutex
    };

    match merge_result {
        Ok(()) => {
            state
                .metrics
                .record_delta_accepted(&truncate_did(&did_str), state_bytes);
            // Announce the updated state to peers so they can reconcile (CON-004 step 4).
            #[cfg(feature = "sync")]
            if let Some(node) = &state.live_node {
                if let Err(e) = node.announce(&did).await {
                    eprintln!("did-crdt: announce failed for {did}: {e}");
                }
            }
            StatusCode::ACCEPTED.into_response()
        }
        Err(Error::DeltaPending { missing }) => {
            // Undecidable: the delta's causal predecessors have not arrived.
            // Return the missing ancestor hashes so the client can fetch them and
            // retry (SPEC-036 REQ-363/366).
            state.metrics.record_delta_rejected("pending");
            let body = serde_json::json!({
                "error": "delta_pending",
                "missing": missing.iter().map(|h| h.to_string()).collect::<Vec<_>>(),
            });
            (StatusCode::CONFLICT, Json(body)).into_response()
        }
        Err(err) => {
            let reason = match &err {
                Error::DeltaRejected(msg) if msg.contains("deactivated") => "deactivated_did",
                Error::DeltaRejected(msg) if msg.contains("seq") => "stale_rotation",
                Error::Unauthorised(_) => "unauthorised",
                _ => "rejected",
            };
            state.metrics.record_delta_rejected(reason);
            core_error_response(err)
        }
    }
}

// ── GET /metrics ──────────────────────────────────────────────────────────────

/// Expose all prometheus metrics in the text exposition format.
pub async fn get_metrics(State(state): State<AppState>) -> String {
    state.metrics.encode()
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Return up to 16 characters of the method-specific ID to use as a metric
/// label, avoiding unbounded cardinality.
fn truncate_did(did_str: &str) -> String {
    let id = did_str.strip_prefix("did:crdt:").unwrap_or(did_str);
    id.chars().take(16).collect()
}
