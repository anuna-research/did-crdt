//! `did-crdt` — Coordination-free decentralised identifiers via signed CRDTs.
//!
//! # Feature flags
//!
//! | Feature   | Enables                                              |
//! |-----------|------------------------------------------------------|
//! | (default) | Pure core — no I/O, no async runtime                 |
//! | `sync`    | iroh-based P2P delta propagation and blob storage    |
//! | `service` | axum HTTP server for DID resolution                  |
//! | `anchor`  | Pluggable external anchoring trait                   |

pub mod core;

#[cfg(feature = "sync")]
pub mod sync;

#[cfg(feature = "service")]
pub mod service;

#[cfg(feature = "anchor")]
pub mod anchor;

// ── shared types ─────────────────────────────────────────────────────────────

/// Shared, mutex-guarded per-DID document store used by both the sync and
/// service layers so they operate on the same in-memory state.
///
/// Uses a newtype so `.lock()` can recover from mutex poisoning without
/// cascading panics across all request handlers.
#[cfg(any(feature = "sync", feature = "service"))]
#[derive(Clone)]
pub struct DocStore(
    std::sync::Arc<
        std::sync::Mutex<
            std::collections::HashMap<crate::core::did::Did, crate::core::document::Document>,
        >,
    >,
);

#[cfg(any(feature = "sync", feature = "service"))]
impl DocStore {
    /// Create a new, empty document store.
    pub fn new() -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::new(),
        )))
    }

    /// Acquire the mutex, recovering from poisoning rather than propagating a
    /// panic to every subsequent caller.
    pub fn lock(
        &self,
    ) -> std::sync::MutexGuard<
        '_,
        std::collections::HashMap<crate::core::did::Did, crate::core::document::Document>,
    > {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[cfg(any(feature = "sync", feature = "service"))]
impl Default for DocStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── public re-exports ─────────────────────────────────────────────────────────

pub use crate::core::{
    crdt::VerificationMethodEntry,
    delta::{SignedDelta, SuiteType, VerificationRelationship},
    did::Did,
    document::Document,
    resolve::{DidDocument, ResolutionResult},
};
