//! Example: two-device sync simulation.
//!
//! Simulates the SPEC-032 §6.2 happy path: two in-process replicas make
//! independent updates then exchange deltas and verify convergence.
//!
//! Run with:
//!   cargo run --example multi_device

fn main() {
    // TODO(phase-1): create two Document replicas sharing the same DID,
    // apply disjoint updates, exchange deltas via Document::merge(), and
    // assert that both replicas resolve to identical documents.
    println!("TODO: implement multi_device example (phase-1)");
}
