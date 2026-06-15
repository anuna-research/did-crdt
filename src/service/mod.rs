//! axum HTTP server for DID resolution and delta submission.
//!
//! Enabled by the `service` feature flag (implies `sync`).  Exposes:
//!
//! - `POST /dids`              — create a new DID
//! - `GET  /{did}`             — resolve a DID to a W3C DID Document
//! - `POST /dids/{did}/deltas` — submit a signed delta
//! - `GET  /metrics`           — prometheus metrics endpoint

pub mod handlers;
pub mod metrics;
pub mod server;
