//! Pluggable external anchoring trait.
//!
//! Enabled by the `anchor` feature flag.  Anchoring is optional and provides
//! proof-of-existence at a specific wall-clock time for jurisdictions that
//! require it (see SPEC-032 §18 open question 7).
//!
//! Implementors can anchor to any external system (blockchain, transparency
//! log, RFC 3161 TSA) by implementing the `Anchor` trait defined in
//! `anchor::traits`.

pub mod traits;
