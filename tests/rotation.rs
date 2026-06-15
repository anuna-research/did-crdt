//! Key rotation scenario tests.
//!
//! Tests (see SPEC-032 §13 and TEST-006, TEST-007):
//!
//! - Happy path:           rotate K1 → K2; K2 becomes active; K1 cannot sign
//!                         non-rotation fields with seq < active seq.
//! - Concurrent rotation:  two devices produce rotate(K1→K2) and rotate(K1→K3)
//!                         concurrently; tiebreak is deterministic (max key hash).
//! - Stale rotation:       rotation delta with seq ≤ active seq is rejected.
//! - Recovery:             K1 can sign a rotation to K3 at seq ≥ 3.

// TODO(phase-1): implement key rotation integration tests.
