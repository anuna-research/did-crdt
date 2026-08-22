//! The selfsame SPEC-001 CON-002 blind mailbox.
//!
//! SPEC-001 §6.12 places the rendezvous on *"the `did-crdt` service
//! (existing)"*; `selfsame-rendezvous` was the reference implementation "so
//! the contracts can be exercised end to end here before they are upstreamed",
//! and this module is that upstreaming (selfsame `IMPL-008` `ADR-913`).
//!
//! # The one thing this server must not do
//!
//! **It makes no trust decision.** CON-002: the mailbox *"sees `H(s)` and
//! ciphertext"* and *"MUST NOT inspect the ciphertext or hold any key"*. Every
//! refusal below is structural — grammar, size, occupancy — and carries no
//! diagnostic, because CON-002's error model gives a prober nothing to work
//! with and the server has made no decision to explain.
//!
//! # Semantics, unchanged from the reference
//!
//! - **Single-write**: a slot, once written, is immutable — what stops the
//!   operator, or anyone who guesses an address, from overwriting a record
//!   mid-exchange.
//! - **Read-once**: a read consumes the slot, so a leaked address is stale
//!   almost immediately. Not a security control on its own — the AEAD is —
//!   but it bounds the window.
//! - **600-second lifetime**, swept on every request, so an idle server needs
//!   no background task.
//!
// SIMPLIFY: in-memory storage — a mailbox entry lives at most 600 s and an
// interrupted ceremony is restarted with a fresh code, so process-lifetime
// storage matches the artefact's own lifetime; move slots into the SPEC-034
// persistence layer only if operational evidence shows restarts eating live
// ceremonies (trace: selfsame SPEC-001 CON-002).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

// The rendezvous is a cross-origin write target: a browser at an application's
// origin (e.g. chat.anuna.io) PUTs the sealed offer here. The mailbox is a blind
// carrier of opaque single-write/read-once ciphertext — CORS is not what
// protects a slot (the AEAD is), and the addresses are unguessable — so a
// permissive policy is correct and necessary. Every response carries it, and a
// preflight OPTIONS is answered directly.
fn cors_headers() -> [(axum::http::HeaderName, &'static str); 3] {
    use axum::http::header::{
        ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    };
    [
        (ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
        (ACCESS_CONTROL_ALLOW_METHODS, "GET, PUT, OPTIONS"),
        (ACCESS_CONTROL_ALLOW_HEADERS, "content-type"),
    ]
}

/// `OPTIONS /rendezvous/{slot}` — CORS preflight, answered directly so a
/// cross-origin PUT is not blocked before it reaches [`put_slot`].
pub async fn preflight_slot() -> Response {
    (StatusCode::NO_CONTENT, cors_headers()).into_response()
}

/// Maximum accepted rendezvous body (CON-002).
pub const MAX_SLOT_BYTES: usize = 4096;

/// Slot lifetime in seconds (CON-002).
pub const SLOT_TTL_SECONDS: u64 = 600;

/// A stored mailbox entry.
struct Slot {
    ciphertext: Vec<u8>,
    stored_at: u64,
    read: bool,
}

/// The mailbox store. Deliberately holds no key material of any kind.
#[derive(Clone, Default)]
pub struct Mailbox {
    inner: Arc<Mutex<HashMap<String, Slot>>>,
}

impl Mailbox {
    /// An empty mailbox.
    pub fn new() -> Self {
        Self::default()
    }

    fn sweep(slots: &mut HashMap<String, Slot>, now: u64) {
        slots.retain(|_, s| now.saturating_sub(s.stored_at) < SLOT_TTL_SECONDS);
    }
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// A slot is 26 characters of RFC 4648 lowercase base32 (128 bits).
///
/// Validated so a path traversal, an oversized key, or a probe with a
/// human-meaningful name is refused before it reaches the map.
fn is_well_formed_slot(slot: &str) -> bool {
    slot.len() == 26
        && slot
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}

/// `PUT /rendezvous/{slot}` — single-write, 201 | 409 | 400.
pub async fn put_slot(
    State(mailbox): State<Mailbox>,
    Path(slot): Path<String>,
    body: Bytes,
) -> Response {
    let status = if !is_well_formed_slot(&slot) || body.is_empty() || body.len() > MAX_SLOT_BYTES {
        StatusCode::BAD_REQUEST
    } else {
        let now = now_seconds();
        let mut slots = mailbox.inner.lock().unwrap_or_else(|p| p.into_inner());
        Mailbox::sweep(&mut slots, now);
        if slots.contains_key(&slot) {
            StatusCode::CONFLICT
        } else {
            slots.insert(slot, Slot { ciphertext: body.to_vec(), stored_at: now, read: false });
            StatusCode::CREATED
        }
    };
    (status, cors_headers()).into_response()
}

/// `GET /rendezvous/{slot}` — read-once, 200 | 404.
pub async fn get_slot(
    State(mailbox): State<Mailbox>,
    Path(slot): Path<String>,
) -> Response {
    if !is_well_formed_slot(&slot) {
        return (StatusCode::NOT_FOUND, cors_headers()).into_response();
    }
    let now = now_seconds();
    let mut slots = mailbox.inner.lock().unwrap_or_else(|p| p.into_inner());
    Mailbox::sweep(&mut slots, now);
    match slots.get_mut(&slot) {
        Some(entry) if !entry.read => {
            entry.read = true;
            (StatusCode::OK, cors_headers(), entry.ciphertext.clone()).into_response()
        }
        _ => (StatusCode::NOT_FOUND, cors_headers()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_grammar_is_exactly_lowercase_base32() {
        assert!(is_well_formed_slot(&"a".repeat(26)));
        assert!(is_well_formed_slot("abcdefghijklmnopqrstuvwxyz"));
        assert!(is_well_formed_slot(&"2".repeat(26)));
        assert!(!is_well_formed_slot(&"a".repeat(25)));
        assert!(!is_well_formed_slot(&"a".repeat(27)));
        assert!(!is_well_formed_slot(&"A".repeat(26)));
        assert!(!is_well_formed_slot(&"1".repeat(26)));
        assert!(!is_well_formed_slot(""));
    }

    #[test]
    fn the_sweep_honours_the_lifetime() {
        let mut slots = HashMap::new();
        slots.insert(
            "a".repeat(26),
            Slot { ciphertext: vec![1], stored_at: 0, read: false },
        );
        Mailbox::sweep(&mut slots, SLOT_TTL_SECONDS - 1);
        assert_eq!(slots.len(), 1, "inside the lifetime the slot survives");
        Mailbox::sweep(&mut slots, SLOT_TTL_SECONDS);
        assert!(slots.is_empty(), "at the lifetime the slot is gone");
    }
}
