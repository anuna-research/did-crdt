//! Fuzz regression tests for delta deserialisation.
//!
//! These tests pin inputs discovered during the cargo-fuzz run
//! (corpus/delta_parse, 30 s / ~4 M iterations, no crashes found).
//! They guard against future regressions: any panic in `serde_json`
//! deserialisation of `SignedDelta`, `DeltaOp`, or `DeltaProof` is a bug.
//!
//! See SPEC-032 §13.

use did_crdt::core::delta::{DeltaOp, DeltaProof, SignedDelta};

/// Deserialise `s` as all three delta types; assert no panic occurs.
fn assert_no_panic(s: &str) {
    let _: Result<SignedDelta, _> = serde_json::from_str(s);
    let _: Result<DeltaOp, _> = serde_json::from_str(s);
    let _: Result<DeltaProof, _> = serde_json::from_str(s);
}

/// Same check for raw bytes (may not be valid UTF-8).
fn assert_no_panic_bytes(data: &[u8]) {
    let _: Result<SignedDelta, _> = serde_json::from_slice(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let _: Result<DeltaOp, _> = serde_json::from_str(s);
        let _: Result<DeltaProof, _> = serde_json::from_str(s);
    }
}

// ── Empty / trivial ──────────────────────────────────────────────────────────

#[test]
fn empty_bytes() {
    assert_no_panic_bytes(b"");
}

#[test]
fn empty_string() {
    assert_no_panic("");
}

#[test]
fn null_literal() {
    assert_no_panic("null");
}

#[test]
fn bare_number() {
    assert_no_panic("42");
}

// ── Structurally malformed JSON ───────────────────────────────────────────────

#[test]
fn empty_object() {
    assert_no_panic("{}");
}

#[test]
fn empty_array() {
    assert_no_panic("[]");
}

#[test]
fn unclosed_object() {
    assert_no_panic("{");
}

#[test]
fn unclosed_string() {
    assert_no_panic("\"");
}

#[test]
fn nested_empty_object() {
    assert_no_panic(r#"{".":{} }"#);
}

#[test]
fn array_of_object() {
    assert_no_panic(r#"[{"type":"deactivate"}]"#);
}

// ── Numeric edge cases discovered in corpus ──────────────────────────────────

#[test]
fn very_large_integer() {
    assert_no_panic(r#"{"seq":99999999999999999999999999999}"#);
}

#[test]
fn large_float_in_nested_array() {
    assert_no_panic(
        r#"{".":[4.22,20.22,2922220.22,8521865,292222,20.22,22,20.22,20.22,22922220.22]}"#,
    );
}

#[test]
fn float_with_exponent() {
    assert_no_panic(r#"{"seq":99999999989918705854e1}"#);
}

// ── DeltaOp – well-formed variants ──────────────────────────────────────────

#[test]
fn deactivate_op() {
    let result: Result<DeltaOp, _> = serde_json::from_str(r#"{"type":"deactivate"}"#);
    assert!(result.is_ok());
}

#[test]
fn add_verification_method_op() {
    let result: Result<DeltaOp, _> = serde_json::from_str(
        r#"{"type":"add_verification_method","id":"did:crdt:aa#key-0","public_key_multibase":"z6Mk"}"#,
    );
    assert!(result.is_ok());
}

#[test]
fn revoke_credential_op() {
    let result: Result<DeltaOp, _> =
        serde_json::from_str(r#"{"type":"revoke_credential","credential_id":"cred-1"}"#);
    assert!(result.is_ok());
}

#[test]
fn rotate_key_op() {
    let result: Result<DeltaOp, _> =
        serde_json::from_str(r#"{"type":"rotate_key","seq":1,"key_ref":"did:crdt:aa#key-1"}"#);
    assert!(result.is_ok());
}

#[test]
fn set_document_data_op() {
    let result: Result<DeltaOp, _> = serde_json::from_str(
        r#"{"type":"set_document_data","key":"name","value":"Alice"}"#,
    );
    assert!(result.is_ok());
}

// ── DeltaOp – malformed / unknown variants ───────────────────────────────────

#[test]
fn unknown_op_type() {
    let result: Result<DeltaOp, _> = serde_json::from_str(r#"{"type":"unknown_op"}"#);
    assert!(result.is_err());
}

#[test]
fn op_missing_type_field() {
    let result: Result<DeltaOp, _> = serde_json::from_str(r#"{"id":"foo"}"#);
    assert!(result.is_err());
}

#[test]
fn op_type_is_null() {
    assert_no_panic(r#"{"type":null}"#);
}

#[test]
fn op_type_is_number() {
    assert_no_panic(r#"{"type":0}"#);
}

// ── SignedDelta – partial / malformed ────────────────────────────────────────

#[test]
fn signed_delta_missing_required_fields() {
    let result: Result<SignedDelta, _> =
        serde_json::from_str(r#"{"did":"did:crdt:abc"}"#);
    assert!(result.is_err());
}

#[test]
fn signed_delta_invalid_did_format() {
    // SignedDelta.did must be `did:crdt:<64-hex>` — a short value is rejected.
    let result: Result<SignedDelta, _> = serde_json::from_str(
        r#"{"did":"did:crdt:tooshort","timestamp":{"wall_ms":0,"logical":0,"node_id":0},
           "op":{"type":"deactivate"},
           "proof":{"type":"Ed25519Signature2020","verification_method":"did:crdt:tooshort#key-0",
                    "created":"1970-01-01T00:00:00.000Z","proof_value":""}}"#,
    );
    assert!(result.is_err());
}

// ── Binary / non-UTF-8 ───────────────────────────────────────────────────────

#[test]
fn non_utf8_bytes() {
    assert_no_panic_bytes(&[0xFF, 0xFE, 0x00, 0x01]);
}

#[test]
fn null_byte() {
    assert_no_panic_bytes(&[0x00]);
}

#[test]
fn high_bytes() {
    assert_no_panic_bytes(&[0x80, 0x81, 0x82, 0x83]);
}
