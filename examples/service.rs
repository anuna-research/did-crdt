//! Example: standalone resolver service.
//!
//! Starts a did-crdt HTTP service on localhost:8080 and peers with an optional
//! remote node.  Demonstrates the SPEC-032 §6.4 happy path end-to-end.
//!
//! Requires the `service` feature:
//!   cargo run --example service --features service

fn main() {
    // TODO(phase-3): parse CLI args (--port, --peers), initialise the iroh
    // endpoint, start the axum server, and block until Ctrl-C.
    println!("TODO: implement service example (phase-3, requires --features service)");
}
