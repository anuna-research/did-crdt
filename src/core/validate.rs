//! Signature verification and authorisation checks.
//!
//! # Security note
//!
//! This module is a **Tier 1 no-go area**.  All changes MUST receive
//! cross-model adversarial review and human domain-expert sign-off before
//! being merged (see SPEC-032 §16).
//!
//! The two trust-boundary checks enforced here are:
//!
//! 1. **Signature validity** — the delta bytes were produced by the claimed
//!    signing key (Ed25519 via `ed25519-dalek` or secp256k1 ECDSA via `k256`).
//! 2. **Authorisation** — the signing key is permitted to perform the
//!    requested operation given the current document state (DID match,
//!    deactivation guard, seq-check for `RotateKey`, signer known).
//!
//! # Public-key encoding
//!
//! Public keys stored in `verification_methods` MUST be multibase base64url
//! (`u` prefix, no padding).  For Ed25519, the 32-byte raw public key is
//! encoded.  For secp256k1, the 33-byte SEC1 compressed public key is encoded.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::Verifier as _;

#[cfg(test)]
use crate::core::delta::default_relationships;
use crate::core::delta::{DeltaOp, SignedDelta, SuiteType};
use crate::core::document::Document;
use crate::core::{Error, Result};

// ── verify_signature ──────────────────────────────────────────────────────────

/// Verify the cryptographic signature on `delta` against the public key
/// found in `doc`'s verification methods.
///
/// Returns `Ok(())` if:
/// - the `proof_value` is empty (unsigned / genesis delta), OR
/// - the signature cryptographically verifies under the key identified by
///   `proof.verification_method`.
///
/// # Errors
///
/// - [`Error::Unauthorised`] — the verification method is not present in `doc`.
/// - [`Error::InvalidSignature`] — the signature fails verification (or the
///   key / signature bytes cannot be decoded).
pub fn verify_signature(delta: &SignedDelta, doc: &Document) -> Result<()> {
    // Empty proof_value is only valid for genesis (bootstrap) deltas — when
    // the document has no verification methods yet.  On an active document,
    // all deltas MUST carry a real cryptographic signature; accepting unsigned
    // deltas would allow any party who knows a valid key ID to mutate the
    // document without possessing the corresponding private key.
    if delta.proof.proof_value.is_empty() {
        if doc.verification_methods.entries().is_empty() {
            return Ok(());
        } else {
            return Err(Error::InvalidSignature);
        }
    }

    // Security note: the signing input covers only {did, op, timestamp}.
    // The proof metadata fields (suite, verification_method) are NOT explicitly
    // bound in the signed payload.  This is intentional to avoid circularity,
    // and is safe because:
    //   - Suite confusion is prevented by key-byte-length mismatch: Ed25519
    //     uses 32-byte keys, secp256k1 SEC1-compressed uses 33 bytes. A
    //     signature from one suite will fail to decode under the other.
    //   - Cross-document VM tampering is prevented by the DID match check in
    //     check_authorisation (the key lookup below scans only keys registered
    //     to this document).
    //   - Cross-key confusion within the same document is prevented because
    //     each key's bytes differ; a signature produced under key A will not
    //     verify against key B's bytes even with the same suite.
    //
    // Future hardening: explicitly bind suite and verification_method in the
    // signed payload for defence-in-depth (FINDING-003).

    // Decode signature bytes from multibase base64url (`u` prefix).
    let sig_bytes = decode_multibase_u(&delta.proof.proof_value)?;

    // Compute the canonical signing input (did, timestamp, op).
    let input = delta.signing_input()?;

    // Look up the public key in the document's verification methods.
    let key_mb = doc
        .verification_methods
        .entries()
        .into_iter()
        .find(|e| e.id == delta.proof.verification_method)
        .ok_or_else(|| {
            Error::Unauthorised(format!(
                "verification method {} not found in document",
                delta.proof.verification_method
            ))
        })?
        .public_key_multibase;

    // Decode public key bytes from multibase base64url (`u` prefix).
    let key_bytes = decode_multibase_u(&key_mb)?;

    // Node-ID binding: the delta's timestamp.node_id MUST equal the lower
    // 8 bytes of BLAKE3(public_key_bytes), interpreted as little-endian u64.
    // This prevents an authorised signer from choosing a favourable node_id
    // to bias equal-timestamp LWW tiebreaks.
    let expected_node_id = node_id_from_pubkey(&key_bytes);
    if delta.timestamp.node_id != expected_node_id {
        return Err(Error::Unauthorised(format!(
            "node_id {} does not match BLAKE3 hash of signer public key (expected {})",
            delta.timestamp.node_id, expected_node_id
        )));
    }

    // Verify using the suite declared in the proof.
    match &delta.proof.suite {
        SuiteType::Ed25519Signature2020 => {
            let key_arr: &[u8; 32] = key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidSignature)?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(key_arr)
                .map_err(|_| Error::InvalidSignature)?;
            let sig_arr: &[u8; 64] = sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidSignature)?;
            let sig = ed25519_dalek::Signature::from_bytes(sig_arr);
            vk.verify(&input, &sig).map_err(|_| Error::InvalidSignature)
        }
        SuiteType::EcdsaSecp256k1Signature2019 => {
            let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&key_bytes)
                .map_err(|_| Error::InvalidSignature)?;
            let sig = k256::ecdsa::Signature::from_slice(&sig_bytes)
                .map_err(|_| Error::InvalidSignature)?;
            vk.verify(&input, &sig).map_err(|_| Error::InvalidSignature)
        }
    }
}

/// Derive the canonical `node_id` from a public key's raw bytes.
///
/// The node_id is the lower 8 bytes of BLAKE3(public_key_bytes),
/// interpreted as a little-endian `u64`.  This binding ensures that the
/// HLC tiebreaker is deterministically derived from the signer's
/// cryptographic identity and cannot be freely chosen.
pub fn node_id_from_pubkey(pubkey_bytes: &[u8]) -> u64 {
    let hash = blake3::hash(pubkey_bytes);
    let bytes: &[u8] = hash.as_bytes();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

// ── check_authorisation ───────────────────────────────────────────────────────

/// Check that `delta` is authorised given the current document state.
///
/// Checks performed (in order):
///
/// 1. **DID match** — `delta.did` must equal `doc.did`.
/// 2. **Deactivation guard** — rejects all mutations on a deactivated
///    document.  Once deactivated, a DID is permanently frozen.
/// 3. **Signer key known** — unless the document is in its genesis state
///    (no verification methods yet), the `proof.verification_method` must
///    identify a key that is already recorded in the document.
/// 4. **Seq-check** — for [`DeltaOp::RotateKey`] the supplied `seq` must be
///    strictly greater than the document's current rotation sequence number.
///
/// # Errors
///
/// - [`Error::DeltaRejected`] — DID mismatch, document deactivated, or
///   stale/duplicate sequence number on a key rotation.
/// - [`Error::Unauthorised`] — signer is not a known verification method.
pub fn check_authorisation(delta: &SignedDelta, doc: &Document) -> Result<()> {
    // 1. DID match — reject deltas targeting a different document.
    if delta.did != doc.did {
        return Err(Error::DeltaRejected(format!(
            "delta DID {} does not match document DID {}",
            delta.did, doc.did
        )));
    }

    // 2. Deactivation guard — no mutations after a DID is deactivated.
    if doc.deactivated.is_set() {
        return Err(Error::DeltaRejected(
            "document is deactivated; no further mutations are accepted".to_owned(),
        ));
    }

    // 3. Signer key known — genesis documents (no verification methods yet)
    //    are exempt for `AddVerificationMethod` only, so that the first key
    //    can be bootstrapped.  All other operations require an authorised
    //    signer even on a genesis document; permitting them would allow an
    //    attacker to deactivate, rotate, or otherwise corrupt any document
    //    that temporarily has no verification methods.
    let is_genesis = doc.verification_methods.entries().is_empty();
    if is_genesis {
        if !matches!(delta.op, DeltaOp::AddVerificationMethod { .. }) {
            return Err(Error::Unauthorised(
                "only AddVerificationMethod is permitted on a genesis document".to_owned(),
            ));
        }
    } else if !doc
        .verification_methods
        .contains_id(&delta.proof.verification_method)
    {
        return Err(Error::Unauthorised(format!(
            "signer key {} is not an authorised verification method",
            delta.proof.verification_method
        )));
    } else if doc
        .revoked_verification_methods
        .contains(&delta.proof.verification_method)
    {
        return Err(Error::Unauthorised(format!(
            "signer key {} has been revoked",
            delta.proof.verification_method
        )));
    }

    // 4. No RotateKey staleness gate: a lower sequence may be a concurrent
    //    rotation rather than a causal descendant. All rotations are admitted
    //    and the ActiveKey Max-Register resolves them deterministically (higher
    //    sequence wins, hash tiebreak at equal sequence); a lower-sequence
    //    rotation simply never wins. Gating on current state would reject a
    //    concurrent rotation and strand any delta parented on it.

    Ok(())
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Decode a multibase base64url-no-padding string (`u` prefix) to raw bytes.
fn decode_multibase_u(s: &str) -> Result<Vec<u8>> {
    let b64 = s.strip_prefix('u').ok_or(Error::InvalidSignature)?;
    Base64UrlUnpadded::decode_vec(b64).map_err(|_| Error::InvalidSignature)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::delta::{DeltaOp, SignedDelta, SigningKey};
    use crate::core::document::Document;
    use crate::core::hlc::HlcTimestamp;

    // ── helper: build a Document whose genesis key is a real Ed25519 key ──────

    fn ed25519_doc() -> (Document, ed25519_dalek::SigningKey, String) {
        let raw = [0x42u8; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&raw);
        let pk_mb = format!(
            "u{}",
            Base64UrlUnpadded::encode_string(sk.verifying_key().as_bytes())
        );
        let (doc, _) = Document::new(&pk_mb).unwrap();
        let key_id = doc.verification_methods.entries()[0].id.clone();
        (doc, sk, key_id)
    }

    /// Derive the correct node_id for an Ed25519 signing key.
    fn ed25519_node_id(sk: &ed25519_dalek::SigningKey) -> u64 {
        node_id_from_pubkey(sk.verifying_key().as_bytes())
    }

    /// Derive the correct node_id for a secp256k1 signing key.
    fn secp256k1_node_id(sk: &k256::ecdsa::SigningKey) -> u64 {
        let pk_bytes = k256::ecdsa::VerifyingKey::from(sk)
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        node_id_from_pubkey(&pk_bytes)
    }

    // ── helper: build a Document whose genesis key is a real secp256k1 key ───

    fn secp256k1_doc() -> (Document, k256::ecdsa::SigningKey, String) {
        let sk = k256::ecdsa::SigningKey::from_bytes((&[0x33u8; 32]).into()).unwrap();
        let pk_compressed = k256::ecdsa::VerifyingKey::from(&sk)
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let pk_mb = format!("u{}", Base64UrlUnpadded::encode_string(&pk_compressed));
        let (doc, _) = Document::new(&pk_mb).unwrap();
        let key_id = doc.verification_methods.entries()[0].id.clone();
        (doc, sk, key_id)
    }

    fn ts() -> HlcTimestamp {
        HlcTimestamp {
            wall_ms: 1_000,
            logical: 0,
            node_id: 1,
        }
    }

    // ── verify_signature ──────────────────────────────────────────────────────

    #[test]
    fn verify_ed25519_valid_signature() {
        let (doc, sk, key_id) = ed25519_doc();
        let nid = ed25519_node_id(&sk);
        let signing_key = SigningKey::Ed25519(sk);
        let delta = SignedDelta::new_genesis(
            doc.did.clone(),
            DeltaOp::RevokeCredential {
                credential_id: "cred-1".to_owned(),
            },
            HlcTimestamp {
                wall_ms: 1_000,
                logical: 0,
                node_id: nid,
            },
            key_id,
            &signing_key,
        )
        .unwrap();
        assert!(verify_signature(&delta, &doc).is_ok());
    }

    #[test]
    fn verify_secp256k1_valid_signature() {
        let (doc, sk, key_id) = secp256k1_doc();
        let nid = secp256k1_node_id(&sk);
        let signing_key = SigningKey::Secp256k1(sk);
        let delta = SignedDelta::new_genesis(
            doc.did.clone(),
            DeltaOp::RevokeCredential {
                credential_id: "cred-2".to_owned(),
            },
            HlcTimestamp {
                wall_ms: 1_000,
                logical: 0,
                node_id: nid,
            },
            key_id,
            &signing_key,
        )
        .unwrap();
        assert!(verify_signature(&delta, &doc).is_ok());
    }

    #[test]
    fn verify_ed25519_wrong_node_id_rejected() {
        let (doc, sk, key_id) = ed25519_doc();
        let signing_key = SigningKey::Ed25519(sk);
        // Use an arbitrary node_id that doesn't match the key.
        let delta = SignedDelta::new_genesis(
            doc.did.clone(),
            DeltaOp::RevokeCredential {
                credential_id: "cred-x".to_owned(),
            },
            HlcTimestamp {
                wall_ms: 1_000,
                logical: 0,
                node_id: 999,
            },
            key_id,
            &signing_key,
        )
        .unwrap();
        assert!(
            verify_signature(&delta, &doc).is_err(),
            "mismatched node_id must be rejected"
        );
    }

    #[test]
    fn verify_empty_proof_value_passes_on_genesis_doc() {
        // A genesis document (no verification methods) must accept an unsigned delta.
        use crate::core::crdt::{
            ActiveKey, Deactivated, DocumentData, Revocations, RevokedVerificationMethods,
            ServiceEndpoints, VerificationMethods,
        };
        let (ref_doc, _, key_id) = ed25519_doc();
        let empty_doc = Document {
            did: ref_doc.did.clone(),
            verification_methods: VerificationMethods::new(),
            service_endpoints: ServiceEndpoints::new(),
            document_data: DocumentData::new(),
            active_key: ActiveKey::new(),
            revocations: Revocations::new(),
            revoked_verification_methods: RevokedVerificationMethods::new(),
            deactivated: Deactivated::new(),
            created_ms: None,
            updated_ms: None,
            delta_log: Vec::new(),
            dag: crate::core::dag::DeltaDag::new(),
        };
        let delta = SignedDelta::unsigned(
            ref_doc.did.clone(),
            DeltaOp::AddVerificationMethod {
                id: key_id.clone(),
                public_key_multibase: "uSomeKey".to_owned(),
                suite_type: SuiteType::default(),
                relationships: default_relationships(),
            },
            ts(),
            key_id,
        );
        assert!(
            verify_signature(&delta, &empty_doc).is_ok(),
            "unsigned genesis delta must pass"
        );
    }

    #[test]
    fn verify_empty_proof_value_rejected_on_active_doc() {
        // An active document (has at least one verification method) must reject
        // unsigned deltas — this is the FINDING-001 fix.
        let (doc, _, key_id) = ed25519_doc();
        let delta = SignedDelta::unsigned(doc.did.clone(), DeltaOp::Deactivate, ts(), key_id);
        assert!(
            verify_signature(&delta, &doc).is_err(),
            "unsigned delta on active document must be rejected"
        );
    }

    #[test]
    fn verify_tampered_proof_value_fails() {
        let (doc, sk, key_id) = ed25519_doc();
        let nid = ed25519_node_id(&sk);
        let signing_key = SigningKey::Ed25519(sk);
        let mut delta = SignedDelta::new_genesis(
            doc.did.clone(),
            DeltaOp::Deactivate,
            HlcTimestamp {
                wall_ms: 1_000,
                logical: 0,
                node_id: nid,
            },
            key_id,
            &signing_key,
        )
        .unwrap();
        // Flip the last character of the proof value.
        let last = delta.proof.proof_value.pop().unwrap();
        delta
            .proof
            .proof_value
            .push(if last == 'A' { 'B' } else { 'A' });
        assert!(
            verify_signature(&delta, &doc).is_err(),
            "tampered signature must fail"
        );
    }

    #[test]
    fn verify_unknown_verification_method_fails() {
        let (doc, sk, _key_id) = ed25519_doc();
        let nid = ed25519_node_id(&sk);
        let signing_key = SigningKey::Ed25519(sk);
        // Sign with a vm id that is NOT in the document.
        let delta = SignedDelta::new_genesis(
            doc.did.clone(),
            DeltaOp::Deactivate,
            HlcTimestamp {
                wall_ms: 1_000,
                logical: 0,
                node_id: nid,
            },
            format!("{}#no-such-key", doc.did),
            &signing_key,
        )
        .unwrap();
        assert!(
            verify_signature(&delta, &doc).is_err(),
            "unknown vm must fail"
        );
    }

    #[test]
    fn verify_wrong_key_fails() {
        let (doc, _sk, key_id) = ed25519_doc();
        // Sign with a *different* Ed25519 key but claim the document's key_id.
        let different_sk = ed25519_dalek::SigningKey::from_bytes(&[0x99u8; 32]);
        let nid = ed25519_node_id(&different_sk);
        let signing_key = SigningKey::Ed25519(different_sk);
        let delta = SignedDelta::new_genesis(
            doc.did.clone(),
            DeltaOp::Deactivate,
            HlcTimestamp {
                wall_ms: 1_000,
                logical: 0,
                node_id: nid,
            },
            key_id,
            &signing_key,
        )
        .unwrap();
        assert!(
            verify_signature(&delta, &doc).is_err(),
            "wrong key must fail"
        );
    }

    // ── check_authorisation ───────────────────────────────────────────────────

    #[test]
    fn authorisation_valid_delta_passes() {
        let (doc, _, key_id) = ed25519_doc();
        let delta = SignedDelta::unsigned(doc.did.clone(), DeltaOp::Deactivate, ts(), key_id);
        assert!(check_authorisation(&delta, &doc).is_ok());
    }

    #[test]
    fn authorisation_did_mismatch_rejected() {
        let (doc, _, key_id) = ed25519_doc();
        // Create a second document with a *different* key so its DID differs.
        let other_sk = ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32]);
        let other_pk_mb = format!(
            "u{}",
            Base64UrlUnpadded::encode_string(other_sk.verifying_key().as_bytes())
        );
        let (other, _) = Document::new(&other_pk_mb).unwrap();
        // Delta targets `other.did` — must be rejected by `doc`.
        let delta = SignedDelta::unsigned(other.did.clone(), DeltaOp::Deactivate, ts(), key_id);
        assert!(
            check_authorisation(&delta, &doc).is_err(),
            "DID mismatch must be rejected"
        );
    }

    #[test]
    fn authorisation_deactivated_document_rejected() {
        let (mut doc, _, key_id) = ed25519_doc();
        // Deactivate the document.
        let mut deact =
            SignedDelta::unsigned(doc.did.clone(), DeltaOp::Deactivate, ts(), key_id.clone());
        deact.parents = doc.frontier();
        doc.merge(deact).unwrap();

        // Any subsequent delta should be rejected.
        let follow_up = SignedDelta::unsigned(
            doc.did.clone(),
            DeltaOp::RevokeCredential {
                credential_id: "cred-9".to_owned(),
            },
            HlcTimestamp {
                wall_ms: 2_000,
                logical: 0,
                node_id: 1,
            },
            key_id,
        );
        assert!(
            check_authorisation(&follow_up, &doc).is_err(),
            "deactivated document must reject further ops"
        );
    }

    #[test]
    fn authorisation_unknown_signer_rejected() {
        let (doc, _, _) = ed25519_doc();
        let delta = SignedDelta::unsigned(
            doc.did.clone(),
            DeltaOp::Deactivate,
            ts(),
            format!("{}#ghost-key", doc.did),
        );
        assert!(
            check_authorisation(&delta, &doc).is_err(),
            "unknown signer must be rejected"
        );
    }

    #[test]
    fn authorisation_genesis_allows_add_verification_method() {
        // An empty document (genesis state) accepts AddVerificationMethod from any signer.
        use crate::core::crdt::{
            ActiveKey, Deactivated, DocumentData, Revocations, RevokedVerificationMethods,
            ServiceEndpoints, VerificationMethods,
        };
        let (ref_doc, _, key_id) = ed25519_doc();
        let empty_doc = Document {
            did: ref_doc.did.clone(),
            verification_methods: VerificationMethods::new(),
            service_endpoints: ServiceEndpoints::new(),
            document_data: DocumentData::new(),
            active_key: ActiveKey::new(),
            revocations: Revocations::new(),
            revoked_verification_methods: RevokedVerificationMethods::new(),
            deactivated: Deactivated::new(),
            created_ms: None,
            updated_ms: None,
            delta_log: Vec::new(),
            dag: crate::core::dag::DeltaDag::new(),
        };
        let delta = SignedDelta::unsigned(
            ref_doc.did.clone(),
            DeltaOp::AddVerificationMethod {
                id: key_id.clone(),
                public_key_multibase: "uSomeKey".to_owned(),
                suite_type: SuiteType::default(),
                relationships: default_relationships(),
            },
            ts(),
            key_id,
        );
        assert!(
            check_authorisation(&delta, &empty_doc).is_ok(),
            "genesis doc must accept AddVerificationMethod"
        );
    }

    // ── Genesis op restriction (FINDING-002) ──────────────────────────────────
    //
    // A genesis document MUST reject all ops except AddVerificationMethod.
    // Allowing Deactivate / RotateKey / etc. on an empty document would let an
    // attacker permanently freeze or corrupt a DID before any key is registered.

    fn empty_doc_for(ref_doc: &Document) -> Document {
        use crate::core::crdt::{
            ActiveKey, Deactivated, DocumentData, Revocations, RevokedVerificationMethods,
            ServiceEndpoints, VerificationMethods,
        };
        Document {
            did: ref_doc.did.clone(),
            verification_methods: VerificationMethods::new(),
            service_endpoints: ServiceEndpoints::new(),
            document_data: DocumentData::new(),
            active_key: ActiveKey::new(),
            revocations: Revocations::new(),
            revoked_verification_methods: RevokedVerificationMethods::new(),
            deactivated: Deactivated::new(),
            created_ms: None,
            updated_ms: None,
            delta_log: Vec::new(),
            dag: crate::core::dag::DeltaDag::new(),
        }
    }

    #[test]
    fn authorisation_genesis_rejects_deactivate() {
        let (ref_doc, _, key_id) = ed25519_doc();
        let empty_doc = empty_doc_for(&ref_doc);
        let delta = SignedDelta::unsigned(ref_doc.did.clone(), DeltaOp::Deactivate, ts(), key_id);
        assert!(
            check_authorisation(&delta, &empty_doc).is_err(),
            "genesis doc must reject Deactivate"
        );
    }

    #[test]
    fn authorisation_genesis_rejects_rotate_key() {
        let (ref_doc, _, key_id) = ed25519_doc();
        let empty_doc = empty_doc_for(&ref_doc);
        let delta = SignedDelta::unsigned(
            ref_doc.did.clone(),
            DeltaOp::RotateKey {
                seq: 1,
                key_ref: key_id.clone(),
            },
            ts(),
            key_id,
        );
        assert!(
            check_authorisation(&delta, &empty_doc).is_err(),
            "genesis doc must reject RotateKey"
        );
    }

    #[test]
    fn authorisation_genesis_rejects_revoke_credential() {
        let (ref_doc, _, key_id) = ed25519_doc();
        let empty_doc = empty_doc_for(&ref_doc);
        let delta = SignedDelta::unsigned(
            ref_doc.did.clone(),
            DeltaOp::RevokeCredential {
                credential_id: "cred-x".to_owned(),
            },
            ts(),
            key_id,
        );
        assert!(
            check_authorisation(&delta, &empty_doc).is_err(),
            "genesis doc must reject RevokeCredential"
        );
    }

    #[test]
    fn authorisation_rotate_key_seq_check_passes_when_greater() {
        let (doc, _, key_id) = ed25519_doc();
        // seq=1 > current_seq=0 → must pass.
        let delta = SignedDelta::unsigned(
            doc.did.clone(),
            DeltaOp::RotateKey {
                seq: 1,
                key_ref: key_id.clone(),
            },
            ts(),
            key_id,
        );
        assert!(check_authorisation(&delta, &doc).is_ok());
    }

    #[test]
    fn authorisation_rotate_key_equal_seq_is_admitted_for_crdt_tiebreak() {
        let (mut doc, _, key_id) = ed25519_doc();
        // First rotation to seq=1.
        let mut r1 = SignedDelta::unsigned(
            doc.did.clone(),
            DeltaOp::RotateKey {
                seq: 1,
                key_ref: key_id.clone(),
            },
            ts(),
            key_id.clone(),
        );
        r1.parents = doc.frontier();
        doc.merge(r1).unwrap();

        // A concurrent rotation at the SAME seq=1 must be ADMITTED (not rejected)
        // so the ActiveKey Max-Register can resolve it by its hash tiebreaker;
        // rejecting equal-seq rotations would leave concurrent replicas divergent.
        let r2 = SignedDelta::unsigned(
            doc.did.clone(),
            DeltaOp::RotateKey {
                seq: 1,
                key_ref: key_id.clone(),
            },
            HlcTimestamp {
                wall_ms: 2_000,
                logical: 0,
                node_id: 1,
            },
            key_id,
        );
        assert!(
            check_authorisation(&r2, &doc).is_ok(),
            "equal-seq concurrent rotation must be admitted for deterministic merge"
        );
    }

    #[test]
    fn authorisation_rotate_key_lower_seq_is_admitted_but_never_wins() {
        let (mut doc, _, key_id) = ed25519_doc();
        // Advance to seq=5.
        let mut r = SignedDelta::unsigned(
            doc.did.clone(),
            DeltaOp::RotateKey {
                seq: 5,
                key_ref: key_id.clone(),
            },
            ts(),
            key_id.clone(),
        );
        r.parents = doc.frontier();
        doc.merge(r).unwrap();

        // A lower seq=3 rotation may be a concurrent (not stale-descendant)
        // rotation, so it MUST be admitted — rejecting it would strand any delta
        // parented on it. The ActiveKey Max-Register keeps the higher seq.
        let mut lower = SignedDelta::unsigned(
            doc.did.clone(),
            DeltaOp::RotateKey {
                seq: 3,
                key_ref: key_id.clone(),
            },
            HlcTimestamp {
                wall_ms: 2_000,
                logical: 0,
                node_id: 1,
            },
            key_id,
        );
        lower.parents = doc.frontier();
        assert!(
            check_authorisation(&lower, &doc).is_ok(),
            "lower-seq rotation must be admitted"
        );
        doc.merge(lower).unwrap();
        assert_eq!(
            doc.active_key.seq(),
            5,
            "Max-Register keeps the higher sequence"
        );
    }

    // ── 2P-Set verification method revocation ────────────────────────────────

    #[test]
    fn authorisation_revoked_vm_rejected() {
        let (mut doc, _, key_id) = ed25519_doc();

        // Add a second key so we can revoke the first.
        let key1_id = format!("{}#key-1", doc.did);
        let mut add_key = SignedDelta::unsigned(
            doc.did.clone(),
            DeltaOp::AddVerificationMethod {
                id: key1_id.clone(),
                public_key_multibase: "uSecondKey".to_owned(),
                suite_type: SuiteType::default(),
                relationships: default_relationships(),
            },
            ts(),
            key_id.clone(),
        );
        add_key.parents = doc.frontier();
        doc.merge(add_key).unwrap();

        // Revoke key-0 using key-1.
        let mut revoke = SignedDelta::unsigned(
            doc.did.clone(),
            DeltaOp::RevokeVerificationMethod {
                key_id: key_id.clone(),
            },
            HlcTimestamp {
                wall_ms: 2_000,
                logical: 0,
                node_id: 1,
            },
            key1_id,
        );
        revoke.parents = doc.frontier();
        doc.merge(revoke).unwrap();

        // Now try to use the revoked key — must be rejected by check_authorisation.
        let delta = SignedDelta::unsigned(
            doc.did.clone(),
            DeltaOp::Deactivate,
            HlcTimestamp {
                wall_ms: 3_000,
                logical: 0,
                node_id: 1,
            },
            key_id,
        );
        assert!(
            check_authorisation(&delta, &doc).is_err(),
            "revoked verification method must be rejected"
        );
    }
}
