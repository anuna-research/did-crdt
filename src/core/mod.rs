//! Pure core — zero I/O, zero unsafe, no async runtime.
//!
//! All modules in this tree MUST NOT import from `tokio`, `iroh`, `axum`,
//! `std::net`, `std::fs`, or any async crate. They are compile-checked by the
//! `cargo build --no-default-features` CI step.

#![forbid(unsafe_code)]

pub mod admission;
pub mod causal;
pub mod crdt;
pub mod dag;
pub mod delta;
pub mod recon;
pub mod did;
pub mod document;
pub mod hlc;
pub mod resolve;
pub mod validate;

// ── shared error type ─────────────────────────────────────────────────────────

/// Errors produced by the pure core.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid did:crdt identifier: {0}")]
    InvalidDid(String),

    #[error("invalid signature")]
    InvalidSignature,

    #[error("authorisation denied: {0}")]
    Unauthorised(String),

    #[error("serialisation error: {0}")]
    Serialisation(#[from] serde_json::Error),

    #[error("delta rejected: {0}")]
    DeltaRejected(String),

    /// The delta's causal closure is incomplete: it cannot be admitted yet, but
    /// MAY be re-submitted once the listed ancestor deltas arrive (SPEC-036
    /// REQ-363; the Reject/retransmit policy of SPEC-035 OQ-1). This is a
    /// non-fatal, retryable refusal, distinct from [`Error::DeltaRejected`].
    #[error("delta pending: {} causal predecessor(s) not yet available", .missing.len())]
    DeltaPending { missing: Vec<crate::core::delta::DeltaHash> },

    #[error("delta too large: {size} bytes exceeds maximum {max} bytes")]
    DeltaTooLarge { size: usize, max: usize },
}

pub type Result<T> = std::result::Result<T, Error>;
