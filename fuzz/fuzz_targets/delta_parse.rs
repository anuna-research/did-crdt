//! Fuzz target: delta deserialisation.
//!
//! Exercises `SignedDelta` deserialisation with arbitrary bytes to ensure
//! the parser never panics or produces undefined behaviour on malformed input.
//!
//! Run with:
//!   cargo fuzz run delta_parse
//!
//! See SPEC-032 §13 (Signature validation / fuzzing).

#![no_main]

use did_crdt::core::delta::{DeltaOp, DeltaProof, SignedDelta};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Attempt to parse as UTF-8 first; non-UTF-8 bytes will simply be Err.
    if let Ok(s) = std::str::from_utf8(data) {
        // Primary target: full SignedDelta round-trip.
        let _: Result<SignedDelta, _> = serde_json::from_str(s);

        // Also exercise sub-type parsers independently.
        let _: Result<DeltaOp, _> = serde_json::from_str(s);
        let _: Result<DeltaProof, _> = serde_json::from_str(s);
    }

    // Always try raw byte deserialisation for SignedDelta.
    let _: Result<SignedDelta, _> = serde_json::from_slice(data);
});
