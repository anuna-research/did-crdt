//! axum HTTP server for DID resolution and delta submission.
//!
//! Enabled by the `service` feature flag (implies `sync`).  Exposes:
//!
//! - `POST /dids`              — create a new DID
//! - `GET  /{did}`             — resolve a DID to a W3C DID Document
//! - `POST /dids/{did}/deltas` — submit a signed delta
//! - `GET  /dids/{did}/closure` — signed-delta closure (selfsame SPEC-001 CON-005)
//! - `PUT/GET /rendezvous/{slot}` — blind mailbox (selfsame SPEC-001 CON-002)
//! - `GET  /metrics`           — prometheus metrics endpoint

pub mod handlers;
pub mod metrics;
pub mod rendezvous;
pub mod server;
