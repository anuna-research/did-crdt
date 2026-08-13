//! CRDT state → W3C DID Core JSON-LD document projection.
//!
//! Takes the current snapshot of the typed CRDT fields and produces a
//! standards-compliant DID document that can be returned verbatim to DID
//! resolvers.
//!
//! # Resolution result
//!
//! Per DID Core 1.1 §7.1, resolution returns a three-part tuple:
//!
//! - [`DidResolutionMetadata`] — metadata about the resolution process itself.
//! - [`DidDocument`] — the resolved DID document (or `None` if deactivated).
//! - [`DidDocumentMetadata`] — metadata about the DID document.
//!
//! These are bundled together in [`ResolutionResult`].
//!
//! Reference: W3C DID Core 1.1 — <https://www.w3.org/TR/did-1.1/>

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::did::Did;

// ── DidResolutionMetadata ────────────────────────────────────────────────────

/// Metadata about the resolution process itself (DID Core 1.1 §7.1.1).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DidResolutionMetadata {
    /// The MIME type of the resolved representation.
    #[serde(rename = "contentType")]
    pub content_type: String,
}

// ── DidDocumentMetadata ─────────────────────────────────────────────────────

/// Metadata about the DID document as defined in W3C DID Core 1.1 §7.1.3.
///
/// This is included alongside the DID document in the resolution result and
/// describes the current state of the document rather than its contents.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DidDocumentMetadata {
    /// `true` if the DID has been permanently deactivated.
    ///
    /// Once set this value can never revert to `false` (monotonic latch).
    pub deactivated: bool,

    /// Content-addressed version identifier for the current CRDT state.
    ///
    /// Computed as the hex-encoded BLAKE3 hash of the serialised CRDT state
    /// snapshot.  Changes whenever any CRDT field is mutated.
    #[serde(rename = "versionId")]
    pub version_id: String,

    /// ISO 8601 timestamp of when the DID document was created (genesis delta).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    /// ISO 8601 timestamp of the most recent update to the DID document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,

    /// The public key from which this DID's identifier was derived.
    ///
    /// A method-specific property, carried in `didDocumentMetadata` because it
    /// describes the DID rather than the resolution that produced it: it is
    /// invariant across resolutions, resolvers, and time, which is precisely
    /// what `didResolutionMetadata` is not for.
    ///
    /// It exists so a verifier can recompute the identifier for itself instead
    /// of trusting the resolver — the derivation is a hash of this one input.
    /// Once the genesis key is revoked it is filtered out of `verificationMethod`
    /// (2P-Set), so without this property the document stops carrying the input
    /// its own identifier is built from.
    ///
    /// Omitted when the resolver could not establish it. Per DID Resolution 1.0
    /// metadata properties are optional, and absence means "not established" —
    /// never "checked, and it failed".
    #[serde(
        rename = "genesisPublicKeyMultibase",
        skip_serializing_if = "Option::is_none"
    )]
    pub genesis_public_key_multibase: Option<String>,
}

// ── ResolutionResult ────────────────────────────────────────────────────────

/// The three-part resolution result as defined by DID Core 1.1 §7.1.
///
/// Wraps the DID document together with resolution metadata and document
/// metadata into a single envelope that DID resolvers can return directly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolutionResult {
    /// Metadata about the resolution process.
    #[serde(rename = "didResolutionMetadata")]
    pub did_resolution_metadata: DidResolutionMetadata,

    /// The resolved DID document, or `None` if the DID is deactivated.
    #[serde(rename = "didDocument")]
    pub did_document: Option<DidDocument>,

    /// Metadata about the DID document.
    #[serde(rename = "didDocumentMetadata")]
    pub did_document_metadata: DidDocumentMetadata,
}

// ── DidDocument ─────────────────────────────────────────────────────────────

/// A W3C DID Core JSON-LD document.
///
/// Field names use the camelCase convention mandated by DID Core.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<Value>,

    pub id: String,

    #[serde(
        rename = "verificationMethod",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub verification_method: Vec<VerificationMethod>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<Value>,

    #[serde(
        rename = "assertionMethod",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub assertion_method: Vec<Value>,

    #[serde(
        rename = "keyAgreement",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub key_agreement: Vec<Value>,

    #[serde(
        rename = "capabilityInvocation",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub capability_invocation: Vec<Value>,

    #[serde(
        rename = "capabilityDelegation",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub capability_delegation: Vec<Value>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<ServiceEndpoint>,

    /// Arbitrary extra fields set via the LWW-Map `documentData` CRDT.
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, Value>,
}

impl DidDocument {
    /// Return the DID Core `@context` values required for a `did:crdt` document.
    pub fn base_context() -> Vec<Value> {
        vec![
            Value::String("https://www.w3.org/ns/did/v1".to_owned()),
            Value::String("https://w3id.org/security/suites/ed25519-2020/v1".to_owned()),
        ]
    }

    /// Construct a minimal empty document for a given DID.
    pub fn empty(did: &Did) -> Self {
        Self {
            context: Self::base_context(),
            id: did.to_string(),
            verification_method: Vec::new(),
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            key_agreement: Vec::new(),
            capability_invocation: Vec::new(),
            capability_delegation: Vec::new(),
            service: Vec::new(),
            extra: Default::default(),
        }
    }
}

/// A verification method entry in a DID document.
///
/// Exactly one key encoding is present. `publicKeyMultibase` is what a
/// `did:crdt` delta carries; `publicKeyJwk` appears only on the projected
/// `JsonWebKey` twins described on [`JsonWebKey2020`], and DID Core forbids a
/// method from carrying both.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    pub r#type: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase", skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
    #[serde(rename = "publicKeyJwk", skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<Value>,
}

/// The verification-method `type` of a projected JWK twin.
pub const JSON_WEB_KEY_TYPE: &str = "JsonWebKey";

/// The fragment prefix a projected twin uses, against `#key-` for the method it
/// projects.
pub const JWK_FRAGMENT_PREFIX: &str = "#jwk-";

/// Marker for the documentation of the JWK projection.
///
/// # Why the twins exist
///
/// The W3C VC JOSE/COSE controlled-identifier profile requires an issuer's key
/// to resolve as `type: JsonWebKey` with `publicKeyJwk`. A `did:crdt` delta
/// carries `publicKeyMultibase` and a suite type, so a document built only from
/// deltas can never satisfy that profile — and a verifier following it refuses
/// every credential the DID issues.
///
/// The projection closes that without touching anything signed: it is computed
/// at resolution from state that already exists, so no delta changes, no
/// signature changes, and **the bytes that derive the identifier are untouched**.
///
/// # Why only assertion keys are twinned
///
/// A twin is emitted only for a method already in `assertionMethod`, and it
/// inherits that relationship and no other.
///
/// The alternative — twinning every key and placing the twin in
/// `assertionMethod` because that is what JWKs are *for* — would let the
/// resolver grant an authority no delta ever expressed. A key authorised to
/// authenticate would silently become able to make statements for the DID. A
/// resolver that can widen authority is the substitution the whole signed-closure
/// design exists to prevent, and it would be worse here than elsewhere because
/// the widening looks like a rendering detail.
///
/// So the projection can only ever restate an authority the deltas already
/// carry. A DID whose keys never assert gets no twins, and a credential it
/// issues is refused — correctly.
///
/// # Numbering
///
/// Twins are numbered by position among assertion-capable methods, ordered by
/// method id, so the first is `#jwk-0`. The index is deliberately *not* copied
/// from the source fragment: `#key-3` may be the only asserting key, and a
/// consumer looking for the issuer's key should find it at `#jwk-0` rather than
/// having to know which delta happened to create it.
#[derive(Clone, Copy, Debug)]
pub struct JsonWebKey2020;

/// A service endpoint entry in a DID document.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub id: String,
    pub r#type: String,
    #[serde(rename = "serviceEndpoint")]
    pub endpoint: Value,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Returns a real `Did` by deriving one from a stable creation hash.
    fn test_did() -> Did {
        let hash = blake3::hash(b"resolve-test-did");
        Did::from_creation_hash(&hash)
    }

    // ── base_context ──────────────────────────────────────────────────────────

    #[test]
    fn base_context_has_two_entries() {
        let ctx = DidDocument::base_context();
        assert_eq!(ctx.len(), 2);
    }

    #[test]
    fn base_context_first_is_did_v1() {
        let ctx = DidDocument::base_context();
        assert_eq!(
            ctx[0],
            Value::String("https://www.w3.org/ns/did/v1".to_owned())
        );
    }

    #[test]
    fn base_context_second_is_ed25519_suite() {
        let ctx = DidDocument::base_context();
        assert_eq!(
            ctx[1],
            Value::String("https://w3id.org/security/suites/ed25519-2020/v1".to_owned())
        );
    }

    // ── empty() ───────────────────────────────────────────────────────────────

    #[test]
    fn empty_sets_id_from_did() {
        let did = test_did();
        let doc = DidDocument::empty(&did);
        assert_eq!(doc.id, did.to_string());
    }

    #[test]
    fn empty_has_base_context() {
        let doc = DidDocument::empty(&test_did());
        assert_eq!(doc.context, DidDocument::base_context());
    }

    #[test]
    fn empty_has_no_verification_methods() {
        let doc = DidDocument::empty(&test_did());
        assert!(doc.verification_method.is_empty());
        assert!(doc.authentication.is_empty());
    }

    #[test]
    fn empty_has_no_services() {
        let doc = DidDocument::empty(&test_did());
        assert!(doc.service.is_empty());
    }

    // ── JSON-LD serialisation ─────────────────────────────────────────────────

    #[test]
    fn serialises_context_as_at_context() {
        let doc = DidDocument::empty(&test_did());
        let json = serde_json::to_value(&doc).unwrap();
        assert!(
            json.get("@context").is_some(),
            "@context key must be present"
        );
        assert!(
            json.get("context").is_none(),
            "bare 'context' key must not appear"
        );
    }

    #[test]
    fn serialises_verification_method_camel_case() {
        let did = test_did();
        let mut doc = DidDocument::empty(&did);
        doc.verification_method.push(VerificationMethod {
            id: format!("{}#key-0", did),
            r#type: "Ed25519VerificationKey2020".to_owned(),
            controller: did.to_string(),
            public_key_multibase: Some("zFakeKey".to_owned()),
            public_key_jwk: None,
        });
        let json = serde_json::to_value(&doc).unwrap();
        assert!(
            json.get("verificationMethod").is_some(),
            "verificationMethod must be present when non-empty"
        );
        assert!(
            json.get("verification_method").is_none(),
            "snake_case key must not appear"
        );
    }

    #[test]
    fn omits_empty_arrays_from_json() {
        let doc = DidDocument::empty(&test_did());
        let json = serde_json::to_value(&doc).unwrap();
        // Empty optional arrays must be omitted per skip_serializing_if.
        assert!(json.get("verificationMethod").is_none());
        assert!(json.get("authentication").is_none());
        assert!(json.get("assertionMethod").is_none());
        assert!(json.get("keyAgreement").is_none());
        assert!(json.get("capabilityInvocation").is_none());
        assert!(json.get("capabilityDelegation").is_none());
        assert!(json.get("service").is_none());
    }

    // ── ResolutionResult serialisation ─────────────────────────────────────────

    #[test]
    #[test]
    fn resolution_result_has_three_parts() {
        let result = ResolutionResult {
            did_resolution_metadata: DidResolutionMetadata {
                content_type: "application/did+ld+json".to_owned(),
            },
            did_document: Some(DidDocument::empty(&test_did())),
            did_document_metadata: DidDocumentMetadata::default(),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(json.get("didResolutionMetadata").is_some());
        assert!(json.get("didDocument").is_some());
        assert!(json.get("didDocumentMetadata").is_some());
    }

    #[test]
    fn resolution_result_deactivated_null_document() {
        let result = ResolutionResult {
            did_resolution_metadata: DidResolutionMetadata {
                content_type: "application/did+ld+json".to_owned(),
            },
            did_document: None,
            did_document_metadata: DidDocumentMetadata {
                deactivated: true,
                version_id: "abc".to_owned(),
                created: None,
                updated: None,
                genesis_public_key_multibase: None,
            },
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(json["didDocument"].is_null());
        assert_eq!(json["didDocumentMetadata"]["deactivated"], json!(true));
    }

    #[test]
    fn metadata_created_updated_omitted_when_none() {
        let meta = DidDocumentMetadata::default();
        let json = serde_json::to_value(&meta).unwrap();
        assert!(
            json.get("created").is_none(),
            "created should be omitted when None"
        );
        assert!(
            json.get("updated").is_none(),
            "updated should be omitted when None"
        );
    }

    #[test]
    fn metadata_created_updated_present_when_set() {
        let meta = DidDocumentMetadata {
            deactivated: false,
            version_id: "v1".to_owned(),
            created: Some("2026-01-01T00:00:00.000Z".to_owned()),
            updated: Some("2026-03-10T12:00:00.000Z".to_owned()),
            genesis_public_key_multibase: None,
        };
        let json = serde_json::to_value(&meta).unwrap();
        assert_eq!(json["created"], json!("2026-01-01T00:00:00.000Z"));
        assert_eq!(json["updated"], json!("2026-03-10T12:00:00.000Z"));
    }

    #[test]
    fn metadata_genesis_key_wire_spelling_and_omission() {
        // The rename is what a verifier reads. A Rust-side rename that silently
        // changed the JSON key would break every consumer while every test that
        // only touches the struct stayed green.
        let meta = DidDocumentMetadata {
            genesis_public_key_multibase: Some("zEd25519TestKey".to_owned()),
            ..Default::default()
        };
        let json = serde_json::to_value(&meta).unwrap();
        assert_eq!(
            json.get("genesisPublicKeyMultibase"),
            Some(&json!("zEd25519TestKey"))
        );

        // Absent, not null: `None` must not serialise as an explicit JSON null,
        // which a consumer could read as an established negative result.
        let json = serde_json::to_value(&DidDocumentMetadata::default()).unwrap();
        assert!(json.get("genesisPublicKeyMultibase").is_none());
    }

    #[test]
    fn metadata_version_id_is_string() {
        let meta = DidDocumentMetadata {
            version_id: "abc123".to_owned(),
            ..Default::default()
        };
        let json = serde_json::to_value(&meta).unwrap();
        assert_eq!(json.get("versionId"), Some(&json!("abc123")));
    }

    #[test]
    fn metadata_version_id_key_is_camel_case() {
        let meta = DidDocumentMetadata {
            version_id: "v1".to_owned(),
            ..Default::default()
        };
        let json = serde_json::to_value(&meta).unwrap();
        assert!(json.get("versionId").is_some());
        assert!(json.get("version_id").is_none());
    }

    #[test]
    fn service_endpoint_key_is_service_endpoint() {
        let did = test_did();
        let mut doc = DidDocument::empty(&did);
        doc.service.push(ServiceEndpoint {
            id: format!("{}#svc-0", did),
            r#type: "LinkedDomains".to_owned(),
            endpoint: Value::String("https://example.com".to_owned()),
        });
        let json = serde_json::to_value(&doc).unwrap();
        let svcs = json.get("service").unwrap().as_array().unwrap();
        assert!(
            svcs[0].get("serviceEndpoint").is_some(),
            "endpoint must serialise as serviceEndpoint"
        );
        assert!(svcs[0].get("endpoint").is_none());
    }

    #[test]
    fn public_key_multibase_key_is_camel_case() {
        let did = test_did();
        let mut doc = DidDocument::empty(&did);
        doc.verification_method.push(VerificationMethod {
            id: format!("{}#key-0", did),
            r#type: "Ed25519VerificationKey2020".to_owned(),
            controller: did.to_string(),
            public_key_multibase: Some("zAbc".to_owned()),
            public_key_jwk: None,
        });
        let json = serde_json::to_value(&doc).unwrap();
        let vm = &json["verificationMethod"][0];
        assert!(vm.get("publicKeyMultibase").is_some());
        assert!(vm.get("public_key_multibase").is_none());
    }

    // ── deserialisation roundtrip ─────────────────────────────────────────────

    #[test]
    fn serde_roundtrip_empty() {
        let did = test_did();
        let doc = DidDocument::empty(&did);
        let json = serde_json::to_string(&doc).unwrap();
        let recovered: DidDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.id, doc.id);
        assert_eq!(recovered.context, doc.context);
    }

    #[test]
    fn serde_roundtrip_with_verification_method() {
        let did = test_did();
        let mut doc = DidDocument::empty(&did);
        doc.verification_method.push(VerificationMethod {
            id: format!("{}#key-0", did),
            r#type: "Ed25519VerificationKey2020".to_owned(),
            controller: did.to_string(),
            public_key_multibase: Some("zTestKey".to_owned()),
            public_key_jwk: None,
        });
        doc.authentication
            .push(Value::String(format!("{}#key-0", did)));

        let json = serde_json::to_string(&doc).unwrap();
        let recovered: DidDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.verification_method.len(), 1);
        assert_eq!(recovered.authentication.len(), 1);
    }

    #[test]
    fn serde_roundtrip_resolution_result() {
        let did = test_did();
        let result = ResolutionResult {
            did_resolution_metadata: DidResolutionMetadata {
                content_type: "application/did+ld+json".to_owned(),
            },
            did_document: Some(DidDocument::empty(&did)),
            did_document_metadata: DidDocumentMetadata {
                deactivated: false,
                version_id: "deadbeef".to_owned(),
                created: Some("2026-01-01T00:00:00.000Z".to_owned()),
                updated: None,
                genesis_public_key_multibase: None,
            },
        };
        let json = serde_json::to_string(&result).unwrap();
        let recovered: ResolutionResult = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.did_document.unwrap().id, did.to_string());
        assert_eq!(recovered.did_document_metadata.version_id, "deadbeef");
        assert_eq!(
            recovered.did_document_metadata.created,
            Some("2026-01-01T00:00:00.000Z".to_owned())
        );
    }
}
