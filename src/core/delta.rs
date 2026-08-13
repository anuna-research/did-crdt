//! Signed delta construction and canonical JSON serialisation.
//!
//! Every mutation to a DID document is represented as a [`SignedDelta`] — a
//! payload describing the field change together with a Linked-Data Proof
//! (CON-002) produced by the authorised key and an HLC timestamp.
//!
//! # Canonical JSON
//!
//! The signing input is the *canonical* JSON serialisation of the delta's
//! `(did, timestamp, op)` payload: object keys are sorted lexicographically
//! at every nesting level and no extra whitespace is emitted.  This ensures
//! the bytes-to-sign are identical on all platforms and serialisation orders.
//!
//! # Signature suites
//!
//! Two suites are supported:
//!
//! - [`SuiteType::Ed25519Signature2020`] — deterministic EdDSA over Curve25519
//!   via `ed25519-dalek`.  Proof value: 64-byte signature encoded as
//!   multibase base64url (no padding, `u` prefix).
//!
//! - [`SuiteType::EcdsaSecp256k1Signature2019`] — RFC 6979 deterministic
//!   ECDSA over secp256k1 via `k256`.  Proof value: compact r‖s (64 bytes)
//!   encoded as multibase base64url (no padding, `u` prefix).

/// Maximum serialised delta size in bytes (64 KiB), per ADR-004.
pub const MAX_DELTA_SIZE: usize = 65_536;

use base64ct::{Base64UrlUnpadded, Encoding as _};
use k256::ecdsa::signature::Signer as _;
use serde::{Deserialize, Serialize};

use crate::core::did::Did;
use crate::core::hlc::HlcTimestamp;
use crate::core::Result;

// ── SuiteType ─────────────────────────────────────────────────────────────────

/// Supported Linked-Data Proof signature suites.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SuiteType {
    #[default]
    Ed25519Signature2020,
    EcdsaSecp256k1Signature2019,
}

impl SuiteType {
    /// Return the W3C verification method type string for this suite.
    pub fn verification_method_type(&self) -> &'static str {
        match self {
            Self::Ed25519Signature2020 => "Ed25519VerificationKey2020",
            Self::EcdsaSecp256k1Signature2019 => "EcdsaSecp256k1VerificationKey2019",
        }
    }
}

// ── DeltaProof ───────────────────────────────────────────────────────────────

/// A Linked-Data Proof attached to a [`SignedDelta`] (see CON-002).
///
/// The `proof_value` is a multibase base64url-encoded signature over the
/// canonical JSON of `{did, timestamp, op}`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeltaProof {
    /// Signature suite identifier.
    #[serde(rename = "type")]
    pub suite: SuiteType,
    /// DID URL of the verification method that produced this proof
    /// (e.g. `did:crdt:<hash>#key-0`).
    pub verification_method: String,
    /// ISO 8601 creation timestamp (derived from the HLC wall component).
    pub created: String,
    /// Multibase base64url-encoded signature (`u` prefix, no padding).
    pub proof_value: String,
}

// ── VerificationRelationship ──────────────────────────────────────────────────

/// W3C DID Core 1.1 verification relationships.
///
/// Each verification method can be associated with one or more relationships
/// that describe the intended use of the key.  When no relationships are
/// specified, `Authentication` is used as the default for backwards
/// compatibility.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VerificationRelationship {
    Authentication,
    AssertionMethod,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
}

/// Default verification relationships for backwards compatibility.
///
/// Keys created before the `relationships` field was introduced are treated
/// as authentication keys.
pub fn default_relationships() -> Vec<VerificationRelationship> {
    vec![VerificationRelationship::Authentication]
}

// ── DeltaOp ───────────────────────────────────────────────────────────────────

/// The field-level operation carried by a delta.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DeltaOp {
    /// Add a verification method to the grow-only set.
    AddVerificationMethod {
        id: String,
        public_key_multibase: String,
        /// The cryptographic suite used by this key.  Defaults to Ed25519
        /// for backwards compatibility with deltas created before this field
        /// was introduced.
        #[serde(default)]
        suite_type: SuiteType,
        /// The verification relationships this key participates in.
        /// Defaults to `[Authentication]` for backwards compatibility.
        #[serde(default = "default_relationships")]
        relationships: Vec<VerificationRelationship>,
    },
    /// Add a service endpoint (OR-Set insert).
    AddServiceEndpoint {
        id: String,
        service_type: String,
        endpoint: String,
    },
    /// Remove a service endpoint (OR-Set remove).
    RemoveServiceEndpoint { id: String },
    /// Replace the `alsoKnownAs` URI set (LWW-Register over the whole set).
    ///
    /// Replacement, not add/remove: the register holds the whole set so a
    /// withdrawn alias can be reinstated later. An empty vector withdraws every
    /// alias, which is the holder's half of unbinding an account.
    SetAlsoKnownAs { uris: Vec<String> },
    /// Set a key in the document data LWW-Map.
    SetDocumentData {
        key: String,
        value: serde_json::Value,
    },
    /// Rotate the active key (Max-Register update).
    RotateKey { seq: u64, key_ref: String },
    /// Add a credential ID to the revocation G-Set.
    RevokeCredential { credential_id: String },
    /// Revoke a verification method key (2P-Set remove half).
    ///
    /// The key ID must be a full DID-URL fragment (e.g. `did:crdt:<hash>#key-1`).
    /// Once revoked, the key remains in the verification methods G-Set (audit log)
    /// but is excluded from the authorized set: `authorized = added \ revoked`.
    RevokeVerificationMethod { key_id: String },
    /// Deactivate the DID (boolean latch — irreversible).
    Deactivate,
}

// ── SigningKey ────────────────────────────────────────────────────────────────

/// A signing keypair for producing delta proofs.
///
/// Holds the private signing key in-memory.  Callers are responsible for
/// secure key storage and zeroisation; this type does not implement `Clone`
/// to reduce accidental key copies.
pub enum SigningKey {
    /// Ed25519 private key (via `ed25519-dalek`).
    Ed25519(ed25519_dalek::SigningKey),
    /// secp256k1 ECDSA private key (via `k256`).
    Secp256k1(k256::ecdsa::SigningKey),
}

impl SigningKey {
    /// Return the [`SuiteType`] that this key will produce.
    pub fn suite_type(&self) -> SuiteType {
        match self {
            Self::Ed25519(_) => SuiteType::Ed25519Signature2020,
            Self::Secp256k1(_) => SuiteType::EcdsaSecp256k1Signature2019,
        }
    }
}

// ── DeltaHash ─────────────────────────────────────────────────────────────────

/// Content identity of a delta: the lowercase hex encoding of the BLAKE3-256
/// hash of its canonical serialisation (SPEC-036 REQ-360).
///
/// A `DeltaHash` is the node identity in the delta Merkle DAG. Because the
/// canonical serialisation includes a delta's `parents`, the hash commits to the
/// delta's entire causal closure recursively: equal hash implies equal causal
/// history. The derived `Ord` gives the canonical (byte-wise) ordering used to
/// keep parent sets deterministic (REQ-361).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeltaHash(pub String);

impl core::fmt::Display for DeltaHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

// ── SignedDelta ───────────────────────────────────────────────────────────────

/// A mutation to a DID document, signed by the authorised key.
///
/// Fully self-contained: any node holding the target DID's current state can
/// validate and merge this delta without additional context.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedDelta {
    /// The DID this delta targets.
    pub did: Did,
    /// HLC timestamp of the mutation.
    pub timestamp: HlcTimestamp,
    /// The field operation.
    pub op: DeltaOp,
    /// Causal predecessors: the content hashes of the deltas this one was
    /// created on top of (the observed frontier), sorted ascending and
    /// deduplicated (SPEC-036 REQ-361). The genesis delta has an empty set.
    ///
    /// `parents` is covered by the signature (REQ-369): it is part of
    /// [`SignedDelta::signing_input`], so a delta cannot be re-parented without
    /// invalidating its proof.
    #[serde(default)]
    pub parents: Vec<DeltaHash>,
    /// Linked-Data Proof (suite, verification method, and signature).
    pub proof: DeltaProof,
}

impl SignedDelta {
    // ── construction ─────────────────────────────────────────────────────────

    /// Construct and sign a **genesis** delta — one with no causal parents
    /// (`parents == []`).
    ///
    /// This is valid ONLY for the genesis delta (and for tests that exercise
    /// signature verification in isolation). A post-genesis update signed with an
    /// empty parent set is rejected by [`Document::merge`] as an ungrounded
    /// root on a non-empty DAG; such updates MUST be built with
    /// [`Self::new_with_parents`], committing to the current frontier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialisation`] if the payload cannot be serialised.
    pub fn new_genesis(
        did: Did,
        op: DeltaOp,
        timestamp: HlcTimestamp,
        verification_method: String,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        Self::new_with_parents(
            did,
            op,
            timestamp,
            Vec::new(),
            verification_method,
            signing_key,
        )
    }

    /// Construct and sign a new delta committing to the given causal `parents`
    /// (SPEC-036). The `parents` set is sorted and deduplicated before signing,
    /// and is covered by the signature (REQ-369).
    ///
    /// [`SignedDelta::new_genesis`] is the special case `parents == []` used for
    /// the genesis delta and for tests that do not exercise the DAG.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialisation`] if the payload cannot be serialised.
    pub fn new_with_parents(
        did: Did,
        op: DeltaOp,
        timestamp: HlcTimestamp,
        mut parents: Vec<DeltaHash>,
        verification_method: String,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        canonicalise_parents(&mut parents);
        let input = Self::compute_signing_input(&did, &timestamp, &op, &parents)?;
        let created = ms_to_iso8601(timestamp.wall_ms);

        let (suite, proof_value) = match signing_key {
            SigningKey::Ed25519(sk) => {
                use ed25519_dalek::Signer as _;
                let sig: ed25519_dalek::Signature = sk.sign(&input);
                let encoded = format!(
                    "u{}",
                    Base64UrlUnpadded::encode_string(sig.to_bytes().as_ref())
                );
                (SuiteType::Ed25519Signature2020, encoded)
            }
            SigningKey::Secp256k1(sk) => {
                let sig: k256::ecdsa::Signature = sk.sign(&input);
                let encoded = format!(
                    "u{}",
                    Base64UrlUnpadded::encode_string(sig.to_bytes().as_ref())
                );
                (SuiteType::EcdsaSecp256k1Signature2019, encoded)
            }
        };

        Ok(Self {
            did,
            timestamp,
            op,
            parents,
            proof: DeltaProof {
                suite,
                verification_method,
                created,
                proof_value,
            },
        })
    }

    /// Create an **unsigned** delta for genesis operations and tests.
    ///
    /// The `proof_value` is left empty; callers that need verified signatures
    /// MUST use [`SignedDelta::new_genesis`] or [`SignedDelta::new_with_parents`].
    pub fn unsigned(
        did: Did,
        op: DeltaOp,
        timestamp: HlcTimestamp,
        verification_method: String,
    ) -> Self {
        Self {
            proof: DeltaProof {
                suite: SuiteType::Ed25519Signature2020,
                verification_method,
                created: ms_to_iso8601(timestamp.wall_ms),
                proof_value: String::new(),
            },
            did,
            timestamp,
            op,
            parents: Vec::new(),
        }
    }

    // ── canonical serialisation ───────────────────────────────────────────────

    /// Return the canonical JSON bytes that are (or should be) signed.
    ///
    /// The input covers `{did, timestamp, op}` — the proof itself is excluded
    /// to avoid circularity.  Keys are sorted lexicographically at every
    /// nesting level for determinism.
    pub fn signing_input(&self) -> Result<Vec<u8>> {
        Self::compute_signing_input(&self.did, &self.timestamp, &self.op, &self.parents)
    }

    /// Return this delta's content identity (SPEC-036 REQ-360): the lowercase
    /// hex BLAKE3-256 of the **signed payload** (`did`, `timestamp`, `op`,
    /// `parents`) — exactly the bytes covered by the signature.
    ///
    /// The proof is deliberately **excluded** from identity. Were unsigned proof
    /// fields (e.g. `created`) included, an attacker could mutate them while
    /// keeping a valid signature and mint unlimited distinct `DeltaHash`es —
    /// hence unlimited DAG leaves and log entries — for a single signed mutation.
    /// The signer is still bound: `timestamp.node_id` is derived from the
    /// signer's public key (see `validate::node_id_from_pubkey`), so two deltas
    /// from different signers necessarily differ in their signed payload.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialisation`] if the payload cannot be serialised.
    pub fn content_hash(&self) -> Result<DeltaHash> {
        let input = self.signing_input()?;
        Ok(DeltaHash(blake3::hash(&input).to_hex().to_string()))
    }

    // ── private helpers ──────────────────────────────────────────────────────

    fn compute_signing_input(
        did: &Did,
        ts: &HlcTimestamp,
        op: &DeltaOp,
        parents: &[DeltaHash],
    ) -> Result<Vec<u8>> {
        // `parents` is included so the signature covers the delta's causal
        // position (SPEC-036 REQ-369). Callers pass a canonicalised set; the
        // genesis/legacy path passes an empty slice.
        let payload = serde_json::json!({
            "did": did,
            "op":  op,
            "parents": parents,
            "timestamp": ts,
        });
        Ok(canonical_json(&payload).into_bytes())
    }
}

/// Sort a parent-hash set ascending and remove duplicates, so that two replicas
/// that observed the same frontier in any order produce identical, canonical
/// `parents` (SPEC-036 REQ-361).
fn canonicalise_parents(parents: &mut Vec<DeltaHash>) {
    parents.sort();
    parents.dedup();
}

// ── canonical_json ────────────────────────────────────────────────────────────

/// Serialise a JSON value to its canonical form.
///
/// All object keys are sorted lexicographically at every nesting level.
/// No extra whitespace is emitted.  Arrays and scalar values are passed
/// through unchanged (array element order is preserved).
pub fn canonical_json(v: &serde_json::Value) -> String {
    use serde_json::Value;
    match v {
        Value::Object(map) => {
            let mut pairs: Vec<(&String, &Value)> = map.iter().collect();
            pairs.sort_by_key(|(k, _)| k.as_str());
            let inner = pairs
                .into_iter()
                .map(|(k, val)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).expect("string serialisation is infallible"),
                        canonical_json(val)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{}}}", inner)
        }
        Value::Array(arr) => {
            let inner = arr.iter().map(canonical_json).collect::<Vec<_>>().join(",");
            format!("[{}]", inner)
        }
        other => serde_json::to_string(other).expect("scalar serialisation is infallible"),
    }
}

// ── ISO 8601 helper ───────────────────────────────────────────────────────────

/// Convert a Unix millisecond timestamp to an ISO 8601 / RFC 3339 string.
///
/// Uses the proleptic Gregorian calendar algorithm from Howard Hinnant's
/// "chrono-Compatible Low-Level Date Algorithms" (civil_from_days).
pub(crate) fn ms_to_iso8601(wall_ms: u64) -> String {
    let secs = wall_ms / 1000;
    let ms = wall_ms % 1000;
    let (y, mo, d, h, mi, s) = secs_to_civil(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y, mo, d, h, mi, s, ms
    )
}

fn secs_to_civil(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let days = secs / 86_400;
    let time = secs % 86_400;
    let h = time / 3_600;
    let mi = (time % 3_600) / 60;
    let s = time % 60;

    // Proleptic Gregorian calendar from days-since-epoch (1970-01-01).
    // Reference: https://howardhinnant.github.io/date_algorithms.html#civil_from_days
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    (year, month, day, h, mi, s)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── canonical_json ────────────────────────────────────────────────────────

    #[test]
    fn canonical_json_sorts_keys() {
        let v = serde_json::json!({"z": 1, "a": 2, "m": 3});
        let s = canonical_json(&v);
        assert_eq!(s, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn canonical_json_sorts_nested_keys() {
        let v = serde_json::json!({"b": {"y": 1, "x": 2}, "a": true});
        let s = canonical_json(&v);
        assert_eq!(s, r#"{"a":true,"b":{"x":2,"y":1}}"#);
    }

    #[test]
    fn canonical_json_preserves_array_order() {
        let v = serde_json::json!([3, 1, 2]);
        assert_eq!(canonical_json(&v), "[3,1,2]");
    }

    #[test]
    fn canonical_json_scalar_types() {
        assert_eq!(canonical_json(&serde_json::Value::Null), "null");
        assert_eq!(canonical_json(&serde_json::json!(true)), "true");
        assert_eq!(canonical_json(&serde_json::json!(42)), "42");
        assert_eq!(canonical_json(&serde_json::json!("hello")), "\"hello\"");
    }

    #[test]
    fn canonical_json_is_deterministic() {
        let v = serde_json::json!({"did": "did:crdt:abc", "op": {"type": "deactivate"}, "ts": [1, 0, 0]});
        let a = canonical_json(&v);
        let b = canonical_json(&v);
        assert_eq!(a, b);
    }

    // ── ms_to_iso8601 ─────────────────────────────────────────────────────────

    #[test]
    fn iso8601_epoch() {
        assert_eq!(ms_to_iso8601(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn iso8601_known_date() {
        // 2026-03-10T12:00:00.500Z  →  Unix epoch 1741608000500 ms
        // Verify manually: 2026-03-10 = 20 494 days from 1970-01-01
        // 20494 * 86400 = 1 770 681 600 secs + 12*3600 = 1 770 724 800
        let ms = 1_770_724_800_500u64;
        let s = ms_to_iso8601(ms);
        assert!(s.ends_with("Z"), "must be UTC: {s}");
        assert!(s.starts_with("20"), "should be a modern date: {s}");
    }

    // ── SignedDelta::unsigned ─────────────────────────────────────────────────

    #[test]
    fn unsigned_has_empty_proof_value() {
        let did: Did = format!("did:crdt:{}", "a".repeat(64)).parse().unwrap();
        let ts = HlcTimestamp {
            wall_ms: 1_000,
            logical: 0,
            node_id: 1,
        };
        let op = DeltaOp::Deactivate;
        let delta = SignedDelta::unsigned(did.clone(), op, ts, format!("{}#key-0", did));
        assert!(delta.proof.proof_value.is_empty());
        assert_eq!(delta.proof.suite, SuiteType::Ed25519Signature2020);
    }

    // ── SignedDelta::signing_input ────────────────────────────────────────────

    #[test]
    fn signing_input_is_canonical_and_deterministic() {
        let did: Did = format!("did:crdt:{}", "b".repeat(64)).parse().unwrap();
        let ts = HlcTimestamp {
            wall_ms: 5_000,
            logical: 2,
            node_id: 7,
        };
        let op = DeltaOp::Deactivate;
        let delta = SignedDelta::unsigned(did.clone(), op, ts, format!("{}#key-0", did));
        let input = delta.signing_input().unwrap();
        // Must be valid UTF-8 JSON with sorted keys at top level.
        let s = std::str::from_utf8(&input).unwrap();
        // Top-level keys must be in sorted order: "did" < "op" < "timestamp"
        let did_pos = s.find("\"did\"").unwrap();
        let op_pos = s.find("\"op\"").unwrap();
        let ts_pos = s.find("\"timestamp\"").unwrap();
        assert!(did_pos < op_pos, "\"did\" must precede \"op\"");
        assert!(op_pos < ts_pos, "\"op\" must precede \"timestamp\"");
    }

    #[test]
    fn signing_input_changes_with_different_ops() {
        let did: Did = format!("did:crdt:{}", "c".repeat(64)).parse().unwrap();
        let ts = HlcTimestamp {
            wall_ms: 0,
            logical: 0,
            node_id: 0,
        };
        let d1 = SignedDelta::unsigned(
            did.clone(),
            DeltaOp::Deactivate,
            ts,
            format!("{}#key-0", did),
        );
        let d2 = SignedDelta::unsigned(
            did.clone(),
            DeltaOp::RevokeCredential {
                credential_id: "cred-1".to_owned(),
            },
            ts,
            format!("{}#key-0", did),
        );
        assert_ne!(d1.signing_input().unwrap(), d2.signing_input().unwrap());
    }

    // ── SignedDelta::content_hash (SPEC-036 REQ-360) ─────────────────────────

    #[test]
    fn content_hash_is_deterministic_and_hex() {
        let did: Did = format!("did:crdt:{}", "e".repeat(64)).parse().unwrap();
        let ts = HlcTimestamp {
            wall_ms: 1_000,
            logical: 0,
            node_id: 1,
        };
        let delta = SignedDelta::unsigned(
            did.clone(),
            DeltaOp::Deactivate,
            ts,
            format!("{}#key-0", did),
        );
        let h1 = delta.content_hash().unwrap();
        let h2 = delta.content_hash().unwrap();
        assert_eq!(h1, h2, "content hash must be deterministic");
        // BLAKE3-256 hex is 64 lowercase hex chars.
        assert_eq!(h1.0.len(), 64);
        assert!(h1
            .0
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }

    #[test]
    fn content_hash_distinguishes_distinct_deltas() {
        let did: Did = format!("did:crdt:{}", "f".repeat(64)).parse().unwrap();
        let ts = HlcTimestamp {
            wall_ms: 0,
            logical: 0,
            node_id: 0,
        };
        let vm = format!("{}#key-0", did);
        let d1 = SignedDelta::unsigned(did.clone(), DeltaOp::Deactivate, ts, vm.clone());
        let d2 = SignedDelta::unsigned(
            did.clone(),
            DeltaOp::RevokeCredential {
                credential_id: "cred-1".to_owned(),
            },
            ts,
            vm,
        );
        assert_ne!(
            d1.content_hash().unwrap(),
            d2.content_hash().unwrap(),
            "different ops must yield different content hashes"
        );
    }

    // ── parents: canonicalisation + signature coverage (REQ-361/369) ─────────

    #[test]
    fn new_with_parents_canonicalises_parent_set() {
        use ed25519_dalek::SigningKey as DalekKey;
        let sk = SigningKey::Ed25519(DalekKey::from_bytes(&[7u8; 32]));
        let did: Did = format!("did:crdt:{}", "a".repeat(64)).parse().unwrap();
        let ts = HlcTimestamp {
            wall_ms: 1,
            logical: 0,
            node_id: 1,
        };
        let vm = format!("{}#key-0", did);
        // Unsorted, with a duplicate.
        let parents = vec![
            DeltaHash("cc".into()),
            DeltaHash("aa".into()),
            DeltaHash("cc".into()),
            DeltaHash("bb".into()),
        ];
        let d =
            SignedDelta::new_with_parents(did, DeltaOp::Deactivate, ts, parents, vm, &sk).unwrap();
        assert_eq!(
            d.parents,
            vec![
                DeltaHash("aa".into()),
                DeltaHash("bb".into()),
                DeltaHash("cc".into())
            ],
            "parents must be sorted and deduplicated"
        );
    }

    #[test]
    fn signing_input_covers_parents() {
        use ed25519_dalek::SigningKey as DalekKey;
        let sk = SigningKey::Ed25519(DalekKey::from_bytes(&[8u8; 32]));
        let did: Did = format!("did:crdt:{}", "b".repeat(64)).parse().unwrap();
        let ts = HlcTimestamp {
            wall_ms: 1,
            logical: 0,
            node_id: 1,
        };
        let vm = format!("{}#key-0", did);
        let d0 = SignedDelta::new_with_parents(
            did.clone(),
            DeltaOp::Deactivate,
            ts,
            vec![],
            vm.clone(),
            &sk,
        )
        .unwrap();
        let d1 = SignedDelta::new_with_parents(
            did,
            DeltaOp::Deactivate,
            ts,
            vec![DeltaHash("aa".into())],
            vm,
            &sk,
        )
        .unwrap();
        // Different parents ⇒ different signed bytes ⇒ different signature.
        assert_ne!(
            d0.signing_input().unwrap(),
            d1.signing_input().unwrap(),
            "parents must be covered by the signing input"
        );
        assert_ne!(d0.proof.proof_value, d1.proof.proof_value);
    }

    // ── SignedDelta::new with Ed25519 ─────────────────────────────────────────

    #[test]
    fn ed25519_sign_and_proof_structure() {
        use ed25519_dalek::SigningKey as DalekKey;
        let raw = [1u8; 32];
        let sk = DalekKey::from_bytes(&raw);
        let signing_key = SigningKey::Ed25519(sk);

        let did: Did = format!("did:crdt:{}", "d".repeat(64)).parse().unwrap();
        let ts = HlcTimestamp {
            wall_ms: 1_000,
            logical: 0,
            node_id: 1,
        };
        let vm = format!("{}#key-0", did);
        let delta = SignedDelta::new_genesis(
            did.clone(),
            DeltaOp::Deactivate,
            ts,
            vm.clone(),
            &signing_key,
        )
        .unwrap();

        assert_eq!(delta.proof.suite, SuiteType::Ed25519Signature2020);
        assert_eq!(delta.proof.verification_method, vm);
        assert!(
            delta.proof.proof_value.starts_with('u'),
            "must be multibase base64url"
        );
        // 64-byte Ed25519 sig → base64url(64) = 86 chars + 'u' prefix = 87
        assert_eq!(delta.proof.proof_value.len(), 87);
    }

    #[test]
    fn ed25519_signing_is_deterministic() {
        let did: Did = format!("did:crdt:{}", "e".repeat(64)).parse().unwrap();
        let ts = HlcTimestamp {
            wall_ms: 1_000,
            logical: 0,
            node_id: 1,
        };
        let vm = format!("{}#key-0", did);

        // Ed25519 is deterministic — same key + same message → same signature.
        let make = || {
            let sk2 = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
            let key = SigningKey::Ed25519(sk2);
            SignedDelta::new_genesis(did.clone(), DeltaOp::Deactivate, ts, vm.clone(), &key)
                .unwrap()
                .proof
                .proof_value
        };
        assert_eq!(make(), make());
    }

    // ── SignedDelta::new with secp256k1 ───────────────────────────────────────

    #[test]
    fn secp256k1_sign_and_proof_structure() {
        let sk = k256::ecdsa::SigningKey::from_bytes((&[3u8; 32]).into()).unwrap();
        let signing_key = SigningKey::Secp256k1(sk);

        let did: Did = format!("did:crdt:{}", "f".repeat(64)).parse().unwrap();
        let ts = HlcTimestamp {
            wall_ms: 2_000,
            logical: 0,
            node_id: 2,
        };
        let vm = format!("{}#key-0", did);
        let delta = SignedDelta::new_genesis(
            did.clone(),
            DeltaOp::Deactivate,
            ts,
            vm.clone(),
            &signing_key,
        )
        .unwrap();

        assert_eq!(delta.proof.suite, SuiteType::EcdsaSecp256k1Signature2019);
        assert_eq!(delta.proof.verification_method, vm);
        assert!(
            delta.proof.proof_value.starts_with('u'),
            "must be multibase base64url"
        );
        // 64-byte compact secp256k1 sig → base64url(64) = 86 + 'u' = 87
        assert_eq!(delta.proof.proof_value.len(), 87);
    }
}
