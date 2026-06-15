//! Pluggable anchoring trait.
//!
//! An `Anchor` implementation takes a snapshot hash and submits it to an
//! external timestamping or anchoring service, returning an opaque receipt
//! that can be stored alongside the document state.

/// An opaque anchoring receipt.  The format is specific to the anchoring
/// backend (transaction ID, TSA token, Merkle proof, etc.).
pub type AnchorReceipt = Vec<u8>;

/// Pluggable external anchoring.
///
/// Implementations are expected to be async and may involve network I/O.
/// They live outside the pure core and MUST NOT be imported from `core::`.
pub trait Anchor: Send + Sync {
    /// Submit a BLAKE3 snapshot hash to the anchoring backend.
    ///
    /// Returns an opaque `AnchorReceipt` on success.
    fn anchor(
        &self,
        snapshot_hash: &[u8; 32],
    ) -> impl std::future::Future<Output = Result<AnchorReceipt, AnchorError>> + Send;
}

/// Errors produced by anchoring backends.
#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    #[error("anchoring backend unreachable: {0}")]
    Unreachable(String),
    #[error("anchoring rejected: {0}")]
    Rejected(String),
    #[error("anchoring timed out")]
    Timeout,
}
