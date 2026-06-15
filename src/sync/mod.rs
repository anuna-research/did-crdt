//! P2P delta propagation and blob storage via iroh.
//!
//! Enabled by the `sync` feature flag.  This module introduces I/O and an
//! async runtime dependency (`tokio`) and MUST NOT be imported from the pure
//! core.

pub mod dht;
pub mod gossip;
pub mod live;
pub mod protocol;
pub mod store;
