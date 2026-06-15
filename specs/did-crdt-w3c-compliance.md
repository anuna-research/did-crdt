---
title: "SPEC-033: did-crdt W3C DID Core Compliance Amendments"
id: SPEC-033
version: 0.1.0
status: draft
created: 2026-03-10
last_updated: 2026-03-10
authors: Anuna Research
reviewers: Engineering, Security, Protocol Design
audience: stakeholders, engineers, protocol designers
parent: SPEC-032
references:
  - "SPEC-032: did-crdt — Coordination-Free Decentralised Identifiers via Signed CRDTs"
  - "SPEC-031: Signed CRDTs as Coordination-Free DID Registry (research/field-notes/signed-crdt-did-registry.md)"
  - "W3C DID Core v1.0: w3.org/TR/did-core (W3C Recommendation, 19 July 2022)"
  - "W3C DID Resolution v0.3: w3c-ccg.github.io/did-resolution"
  - "W3C DID Specification Registries: w3.org/TR/did-spec-registries"
  - "CALM Theorem: arXiv:1901.01930 (Hellerstein & Alvaro, 2019)"
---

# SPEC-033: did-crdt W3C DID Core Compliance Amendments

| Field | Value |
|---|---|
| Document ID | SPEC-033 |
| Title | did-crdt W3C DID Core Compliance Amendments |
| Version | 0.1.0 |
| Status | Draft |
| Created | 2026-03-10 |
| Last Updated | 2026-03-10 |
| Authors | Anuna Research |
| Reviewers | Engineering, Security, Protocol Design |
| Parent | SPEC-032 |

---

## 1. Executive Summary

This specification amends SPEC-032 (did-crdt) to achieve full conformance with the W3C DID Core v1.0 Recommendation. A compliance review of SPEC-032 identified eight gaps, two of which are architectural: the grow-only set (G-Set) for verification methods prevents W3C-mandated key revocation, and the single `activeKey` Max-Register conflates five distinct verification relationships defined by the standard.

This document specifies the precise changes to SPEC-032's data model, CRDT field composition, API contracts, resolution output, and method syntax required for conformance. Each amendment is traced to the normative W3C section it satisfies, and each is verified by new or modified test specifications.

**Design constraint:** All amendments MUST preserve the core CALM theorem property — coordination-free convergence via signed CRDTs. Where W3C conformance introduces non-monotonic operations (key removal from relationships), we use OR-Sets (ORSWOT CRDTs), which are coordination-free but not grow-only. This is a relaxation of SPEC-031's original monotonicity claim, but it remains within CRDT theory — OR-Sets are proven convergent without coordination.

---

## 2. Compliance Gap Analysis

The following table summarises all gaps identified between SPEC-032 and W3C DID Core v1.0, their severity, and the amendment that addresses each.

| # | W3C Requirement | DID Core Section | SPEC-032 Status | Severity | Amendment |
|---|---|---|---|---|---|
| G-1 | Key revocation by removal from verificationMethod or verification relationships | §9.7, §9.8 | **Non-compliant** — G-Set prevents removal | High | AMD-001 |
| G-2 | Five distinct verification relationships (authentication, assertionMethod, keyAgreement, capabilityInvocation, capabilityDelegation) | §5.3–§5.8 | **Non-compliant** — only `activeKey` Max-Register | High | AMD-002 |
| G-3 | Verification method structure (id, type, controller, key material) | §5.2.1 | Missing — opaque G-Set entries | Medium | AMD-003 |
| G-4 | Service endpoint structure (id, type, serviceEndpoint) | §5.4 | Missing — opaque OR-Set entries | Medium | AMD-004 |
| G-5 | DID method-specific syntax ABNF | §8.1 | Missing | Medium | AMD-005 |
| G-6 | Resolution output: three-part result (document, resolution metadata, document metadata) | §7.1 | Partial — metadata embedded, no resolution metadata | Medium | AMD-006 |
| G-7 | Deactivated DID resolution behaviour | §8.2 | Unspecified for library API | Low | AMD-007 |
| G-8 | Privacy considerations | §10 | Missing | Medium | AMD-008 |

---

## 3. Amendments

### AMD-001: Verification Method Lifecycle — G-Set to Dual-Set Model

**Gap:** G-1 — W3C §9.7, §9.8
**Severity:** High

#### Problem

SPEC-032 models `verificationMethods` as a G-Set (grow-only set). W3C §9.8 defines key revocation as *"removing the verification method from the verificationMethod property OR removing it from the set of verification methods associated with a verification relationship."* A G-Set cannot remove elements, making revocation impossible.

#### Decision

Adopt a **dual-set model**: verification methods are stored in an OR-Set (ORSWOT) that supports both addition and removal, while a separate G-Set maintains a tamper-evident **audit log** of all keys ever associated with the DID.

This satisfies W3C revocation requirements while preserving auditability — a property the W3C recommends but does not require.

#### Revised CRDT Field

```
SPEC-032 (original):
  verificationMethods:  G-Set<VerificationMethod>

SPEC-033 (amended):
  verificationMethods:  OR-Set<VerificationMethod>   -- active methods, supports add/remove
  keyHistory:           G-Set<KeyHistoryEntry>        -- audit log, append-only
```

Where:

```rust
/// A key history entry records that a key was added or removed,
/// and when, for audit and forensic purposes.
struct KeyHistoryEntry {
    key_ref: DidUrl,          // e.g., "did:crdt:<hash>#key-2"
    event: KeyEvent,          // Added | Removed
    clock: Hlc,               // when this event occurred
    actor: DidUrl,             // which key authorised this event
}

enum KeyEvent {
    Added,
    Removed,
}
```

#### CALM Impact

OR-Sets (specifically ORSWOT — Observed-Remove Set Without Tombstones) are proven CRDTs. They are coordination-free and convergent. However, they are **not monotonic** in the strict CALM sense — removing an element can invalidate a previous conclusion ("key K is active").

This is an intentional and documented relaxation. The CALM theorem tells us that non-monotonic operations *require* coordination for consistency. For OR-Sets, this coordination is embedded in the CRDT's causal context (each remove operation carries the set of add-operations it has observed). No external coordinator is needed — the causal context travels with the delta.

**Updated claim:** All did-crdt operations are coordination-free via CRDTs. Most are monotonic (G-Set, Max-Register). Verification method removal and service endpoint removal use OR-Sets, which are coordination-free but not monotonic. The distinction matters for formal analysis but not for operational properties — convergence and conflict-freedom are preserved in all cases.

#### Requirements

```
REQ-022: Verification Method Removal

The system SHALL support removal of verification methods from the active
verificationMethods OR-Set. Removal SHALL be authorised by a delta signed
by a key that is currently in the authentication verification relationship
(AMD-002) with seq ≥ the activeKey seq.

Upon removal, the system SHALL append a KeyHistoryEntry with event=Removed
to the keyHistory G-Set.

The system SHALL NOT allow removal of the last remaining verification method.
A DID document MUST always have at least one active verification method unless
the DID is deactivated.

Trace:
- TEST-022
- TEST-023
```

```
REQ-023: Key History Audit Log

The system SHALL maintain a keyHistory G-Set that records every key addition
and removal event. This set SHALL be append-only and SHALL NOT support removal
of entries.

The keyHistory SHALL be included in the resolved DID Document Metadata
(AMD-006) as an extension property, not in the DID Document itself.

Trace:
- TEST-024
```

#### Tests

```
TEST-022: Verification Method Removal

Scenario:
1. Create DID D with key K1 (seq=1).
2. Add key K2 (seq=2), rotate activeKey to K2.
3. Remove K1 from verificationMethods, signed by K2.
4. Assert: K1 no longer in resolved verificationMethod array.
5. Assert: K1 present in keyHistory with event=Removed.
6. Assert: deltas signed by K1 are rejected (K1 no longer in verificationMethods).

Verifies: REQ-022
```

```
TEST-023: Cannot Remove Last Verification Method

Scenario:
1. Create DID D with key K1 (only key).
2. Attempt to remove K1 from verificationMethods.
3. Assert: rejected with LastKeyError.
4. Assert: K1 still present.

Verifies: REQ-022
```

```
TEST-024: Key History Append-Only

Property: For all document states S and key K,
  if KeyHistoryEntry(K, Added) ∈ S.keyHistory, then for all deltas D,
  KeyHistoryEntry(K, Added) ∈ merge(S, D).keyHistory.
Generator: Random documents with 1-20 key additions/removals.
Assertion: History entries never disappear.

Verifies: REQ-023
```

---

### AMD-002: Verification Relationships — Five OR-Set Fields

**Gap:** G-2 — W3C §5.3–§5.8
**Severity:** High

#### Problem

SPEC-032 uses a single `activeKey` Max-Register to represent which key is authoritative. W3C DID Core defines five distinct verification relationships, each serving a different purpose:

| Relationship | W3C Section | Purpose |
|---|---|---|
| `authentication` | §5.3.1 | Prove the DID subject is who they claim to be |
| `assertionMethod` | §5.4.1 | Issue verifiable credentials and assertions |
| `keyAgreement` | §5.5.1 | Establish shared secrets (e.g., Diffie-Hellman) |
| `capabilityInvocation` | §5.6.1 | Invoke cryptographic capabilities |
| `capabilityDelegation` | §5.7.1 | Delegate capabilities to others |

A single Max-Register cannot express "key K1 is used for authentication but key K2 is used for key agreement." Multi-key DID documents are a standard use case.

#### Decision

Replace the `activeKey` Max-Register with five OR-Set fields, one per verification relationship. Retain the Max-Register as an **internal authorization field** (`signingAuthority`) that determines which key(s) may sign deltas for this DID — this has no W3C equivalent but is necessary for CRDT authorization.

#### Revised CRDT Fields

```
SPEC-032 (original):
  activeKey:  Max-Register<seq, KeyRef>

SPEC-033 (amended):
  authentication:         OR-Set<DidUrl>           -- key refs for authentication
  assertionMethod:        OR-Set<DidUrl>            -- key refs for assertions/VCs
  keyAgreement:           OR-Set<DidUrl>            -- key refs for key agreement
  capabilityInvocation:   OR-Set<DidUrl>            -- key refs for capability invocation
  capabilityDelegation:   OR-Set<DidUrl>            -- key refs for capability delegation
  signingAuthority:       Max-Register<seq, DidUrl> -- internal: which key signs deltas
```

#### Key Rotation Under the New Model

Key rotation is no longer a single Max-Register operation. It is a sequence of delta operations:

1. Add new key K2 to `verificationMethods` OR-Set.
2. Add K2's ref to desired relationship OR-Sets (e.g., `authentication`, `assertionMethod`).
3. Remove K1's ref from relationship OR-Sets.
4. Optionally remove K1 from `verificationMethods` OR-Set (or retain for history).
5. Update `signingAuthority` to K2 at seq=N+1.

Steps 1–4 are relationship management (OR-Set add/remove). Step 5 is the authorization transfer (Max-Register, monotonic). These can be bundled into a single multi-delta transaction (see REQ-025).

#### Delta Authorization Rules (Revised)

SPEC-032's authorization rule was: "delta must be signed by a key with seq ≥ activeKey.seq." This is replaced with:

1. A delta modifying `verificationMethods`, any verification relationship, or `signingAuthority` MUST be signed by a key currently referenced in `signingAuthority` (the current signing authority).
2. A delta modifying `documentData` or `serviceEndpoints` MUST be signed by a key currently referenced in `signingAuthority`.
3. A delta modifying `revocations` MUST be signed by a key currently referenced in `assertionMethod` (since revocations relate to issued credentials).
4. A delta modifying `deactivated` MUST be signed by a key currently referenced in `signingAuthority`.
5. A `signingAuthority` update MUST have seq > current `signingAuthority.seq`.

#### Requirements

```
REQ-024: Verification Relationship Fields

The system SHALL maintain five OR-Set fields corresponding to the W3C DID Core
verification relationships:
- authentication (§5.3.1)
- assertionMethod (§5.4.1)
- keyAgreement (§5.5.1)
- capabilityInvocation (§5.6.1)
- capabilityDelegation (§5.7.1)

Each field SHALL contain DID URL references to verification methods present in
the verificationMethods OR-Set. Adding a reference to a key not in
verificationMethods SHALL be rejected.

Removing a key reference from a relationship OR-Set SHALL NOT remove the key
from verificationMethods — relationship membership and method existence are
independent.

Trace:
- TEST-025
- TEST-026
```

```
REQ-025: Multi-Delta Transactions

The system SHALL support atomic application of a vector of signed deltas
(a "transaction"). All deltas in a transaction share a single HLC timestamp
and are validated against the document state as it existed before the
transaction began.

This enables key rotation as an atomic operation: add new key, update
relationships, update signingAuthority — all validated against the
pre-rotation state.

If any delta in the transaction fails validation, the entire transaction
SHALL be rejected and no deltas SHALL be applied.

Trace:
- TEST-027
```

```
REQ-026: Signing Authority

The system SHALL maintain a signingAuthority Max-Register that determines
which key may sign deltas for this DID. The register value is a tuple
(seq: u64, key_ref: DidUrl).

Updates to signingAuthority MUST have seq strictly greater than the current
value. Tiebreaking (equal seq) uses lexicographic BLAKE3 hash of the
referenced public key.

The signingAuthority field SHALL NOT appear in the resolved W3C DID Document.
It is an internal CRDT field for authorization purposes only.

Trace:
- TEST-028
- TEST-029
```

```
REQ-027: Revised Delta Authorization

The system SHALL enforce the following authorization rules for delta signing:

| Target field              | Required signer                      |
|---------------------------|--------------------------------------|
| verificationMethods       | Current signingAuthority key         |
| authentication            | Current signingAuthority key         |
| assertionMethod           | Current signingAuthority key         |
| keyAgreement              | Current signingAuthority key         |
| capabilityInvocation      | Current signingAuthority key         |
| capabilityDelegation      | Current signingAuthority key         |
| signingAuthority          | Current signingAuthority key (seq+1) |
| documentData              | Current signingAuthority key         |
| serviceEndpoints          | Current signingAuthority key         |
| revocations               | Key in assertionMethod               |
| deactivated               | Current signingAuthority key         |

Trace:
- TEST-030
```

#### Tests

```
TEST-025: Verification Relationship Independence

Scenario:
1. Create DID D with key K1.
2. Add K1 to authentication and assertionMethod.
3. Add key K2 to verificationMethods.
4. Add K2 to keyAgreement only.
5. Resolve DID document.
6. Assert: K1 appears in authentication and assertionMethod arrays.
7. Assert: K2 appears in keyAgreement array only.
8. Assert: both K1 and K2 in verificationMethod array.

Verifies: REQ-024
```

```
TEST-026: Dangling Relationship Reference Rejected

Scenario:
1. Create DID D with key K1.
2. Attempt to add K2_ref to authentication without K2 in verificationMethods.
3. Assert: rejected — K2 not in verificationMethods.

Verifies: REQ-024
```

```
TEST-027: Atomic Key Rotation Transaction

Scenario:
1. Create DID D with K1 (seq=1) in authentication + assertionMethod.
2. Construct transaction:
   a. Add K2 to verificationMethods
   b. Add K2 ref to authentication
   c. Add K2 ref to assertionMethod
   d. Remove K1 ref from authentication
   e. Remove K1 ref from assertionMethod
   f. Set signingAuthority to (seq=2, K2)
3. Apply transaction atomically.
4. Assert: K2 in authentication and assertionMethod.
5. Assert: K1 NOT in authentication or assertionMethod.
6. Assert: K1 still in verificationMethods (not removed from set, only from relationships).
7. Assert: signingAuthority is K2 at seq=2.

Verifies: REQ-025
```

```
TEST-028: Signing Authority Monotonicity

Property: For all document states S and signingAuthority updates U1, U2,
  if U1.seq > U2.seq, then merge(U1, U2).signingAuthority == U1.
Generator: Random seq values.
Assertion: Higher seq always wins.

Verifies: REQ-026
```

```
TEST-029: Signing Authority Tiebreak

Scenario:
1. Create DID D with K1 (seq=1).
2. Concurrent: set signingAuthority to (seq=2, K2) and (seq=2, K3).
3. Merge both deltas.
4. Assert: winner is deterministic (BLAKE3 hash comparison).
5. Assert: same winner regardless of merge order.

Verifies: REQ-026
```

```
TEST-030: Authorization Rule Enforcement

Scenario matrix:
1. Delta targeting authentication signed by signingAuthority key → accepted.
2. Delta targeting authentication signed by non-signingAuthority key → rejected.
3. Delta targeting revocations signed by assertionMethod key → accepted.
4. Delta targeting revocations signed by authentication-only key → rejected.
5. Delta targeting signingAuthority with seq ≤ current → rejected.
6. Delta targeting signingAuthority with seq > current, signed by current → accepted.

Verifies: REQ-027
```

---

### AMD-003: Verification Method Structure

**Gap:** G-3 — W3C §5.2.1
**Severity:** Medium

#### Problem

SPEC-032 treats verification methods as opaque entries. W3C §5.2.1 requires each verification method to include `id`, `type`, and `controller`, with optional key material.

#### Decision

Define a `VerificationMethod` struct that conforms to W3C requirements.

#### Specification

```rust
/// W3C DID Core §5.2.1 compliant verification method.
struct VerificationMethod {
    /// MUST conform to DID URL syntax (§3.2).
    /// Convention: "did:crdt:<hash>#key-<n>"
    id: DidUrl,

    /// MUST reference exactly one verification method type.
    /// Registered types: w3.org/TR/did-spec-registries/#verification-method-types
    type_: VerificationMethodType,

    /// MUST conform to DID syntax (§3.1).
    /// Typically the DID that owns this document.
    controller: Did,

    /// Key material — exactly one of:
    public_key_jwk: Option<Jwk>,
    public_key_multibase: Option<String>,
}

/// Supported verification method types.
enum VerificationMethodType {
    EcdsaSecp256k1VerificationKey2019,
    Ed25519VerificationKey2020,
    JsonWebKey2020,
    Multikey,
}
```

#### Requirement

```
REQ-028: Verification Method W3C Structure

Every entry in the verificationMethods OR-Set SHALL be a VerificationMethod
containing:
- id: a DID URL conforming to §3.2, unique within the document
- type: a registered verification method type
- controller: a DID conforming to §3.1
- Exactly one of publicKeyJwk or publicKeyMultibase

The system SHALL reject addition of a VerificationMethod with a duplicate id.

Trace:
- TEST-031
```

#### Test

```
TEST-031: Verification Method Structure Validation

Scenario:
1. Create DID D.
2. Add verification method with id, type, controller, publicKeyJwk → accepted.
3. Add verification method missing type → rejected.
4. Add verification method missing controller → rejected.
5. Add verification method with neither publicKeyJwk nor publicKeyMultibase → rejected.
6. Add verification method with both publicKeyJwk and publicKeyMultibase → rejected.
7. Add verification method with duplicate id → rejected.
8. Resolve document.
9. Assert: verificationMethod array entries match W3C JSON-LD structure.

Verifies: REQ-028
```

---

### AMD-004: Service Endpoint Structure

**Gap:** G-4 — W3C §5.4
**Severity:** Medium

#### Problem

SPEC-032 places service endpoints in an OR-Set but does not define the element structure. W3C §5.4 requires `id`, `type`, and `serviceEndpoint`.

#### Specification

```rust
/// W3C DID Core §5.4 compliant service endpoint.
struct Service {
    /// MUST conform to RFC3986 URI syntax.
    /// MUST be unique within the document.
    id: Uri,

    /// MUST be a string or ordered set of strings.
    type_: OneOrMany<String>,

    /// MUST be a URI, a map, or an ordered set of URIs and/or maps.
    service_endpoint: OneOrMany<ServiceEndpointValue>,
}

enum ServiceEndpointValue {
    Uri(Uri),
    Map(BTreeMap<String, serde_json::Value>),
}
```

#### Requirement

```
REQ-029: Service Endpoint W3C Structure

Every entry in the serviceEndpoints OR-Set SHALL be a Service containing:
- id: a URI conforming to RFC3986, unique within the document
- type: one or more strings identifying the service type
- serviceEndpoint: one or more URIs or maps conforming to RFC3986

The system SHALL reject addition of a Service with a duplicate id.

Trace:
- TEST-032
```

#### Test

```
TEST-032: Service Endpoint Structure Validation

Scenario:
1. Create DID D.
2. Add service endpoint with valid id, type, serviceEndpoint → accepted.
3. Add service endpoint missing type → rejected.
4. Add service endpoint with duplicate id → rejected.
5. Remove service endpoint → accepted.
6. Resolve document.
7. Assert: service array entries match W3C JSON-LD structure.

Verifies: REQ-029
```

---

### AMD-005: DID Method Syntax (ABNF)

**Gap:** G-5 — W3C §8.1
**Severity:** Medium

#### Problem

SPEC-032 informally describes the DID format as `did:crdt:<blake3-hash>` but provides no formal ABNF as required by §8.1.

#### Specification

The `did:crdt` method conforms to the W3C DID Syntax ABNF (§3.1):

```abnf
did                = "did:" method-name ":" method-specific-id
method-name        = "crdt"
method-specific-id = 64HEXDIG
                     ; lowercase hex-encoded BLAKE3-256 hash
                     ; of the creation delta's canonical serialisation
HEXDIG             = DIGIT / "a" / "b" / "c" / "d" / "e" / "f"
```

DID URL syntax (§3.2):

```abnf
did-url            = did path-abempty [ "?" query ] [ "#" fragment ]
                     ; as per RFC3986
```

**Key reference convention:**

```
did:crdt:<hash>#key-<n>
```

Where `<n>` is a sequential integer assigned at key addition time, unique within the document. The integer is monotonically increasing — removed keys do not free their index.

#### Examples

```
DID:         did:crdt:a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890
Key ref:     did:crdt:a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890#key-1
Service ref: did:crdt:a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890#service-1
```

#### Requirement

```
REQ-030: DID Method Syntax

The system SHALL generate DIDs conforming to the ABNF above. The method-specific-id
SHALL be the lowercase hex-encoded BLAKE3-256 hash of the canonical serialisation
of the creation delta.

The system SHALL reject DIDs that do not conform to this syntax during parsing.

DID URLs SHALL support path, query, and fragment components as per RFC3986.

Trace:
- TEST-033
```

#### Test

```
TEST-033: DID Syntax Conformance

Scenario:
1. Create DID → assert format matches "did:crdt:" + 64 hex chars.
2. Parse valid DID → success.
3. Parse "did:crdt:UPPERCASE" → rejected (not lowercase).
4. Parse "did:crdt:tooshort" → rejected (not 64 chars).
5. Parse "did:crdt:<64 hex>#key-1" → valid DID URL with fragment.
6. Parse "did:crdt:<64 hex>?service=auth" → valid DID URL with query.

Verifies: REQ-030
```

---

### AMD-006: Three-Part Resolution Output

**Gap:** G-6 — W3C §7.1
**Severity:** Medium

#### Problem

SPEC-032's `resolve()` returns a DID Document with metadata embedded. W3C §7.1 specifies that DID Resolution MUST produce three distinct outputs:

1. **DID Document** — the document itself
2. **DID Resolution Metadata** — metadata about the resolution process (e.g., `contentType`)
3. **DID Document Metadata** — metadata about the document (e.g., `created`, `updated`, `versionId`, `deactivated`)

#### Specification

```rust
/// W3C DID Resolution §7.1 compliant resolution result.
struct ResolutionResult {
    did_document: Option<DidDocument>,
    did_resolution_metadata: ResolutionMetadata,
    did_document_metadata: DocumentMetadata,
}

/// Metadata about the resolution process itself.
struct ResolutionMetadata {
    /// MUST be present when did_document is present.
    content_type: Option<String>,

    /// Present when resolution fails.
    error: Option<ResolutionError>,

    /// Time taken to resolve (diagnostic).
    duration_ms: Option<u64>,
}

enum ResolutionError {
    /// DID method is not supported.
    MethodNotSupported,

    /// DID not found in local state.
    NotFound,

    /// DID document representation not supported.
    RepresentationNotSupported,

    /// Internal error during resolution.
    InternalError,
}

/// Metadata about the DID document.
struct DocumentMetadata {
    /// When the DID was created (HLC of creation delta).
    created: String,

    /// When the DID was last updated (HLC of most recent merged delta).
    updated: String,

    /// Content-addressed hash of current CRDT state (BLAKE3).
    version_id: String,

    /// Whether the DID is deactivated.
    deactivated: bool,

    /// Next update commitment (not used; reserved for compatibility).
    next_update: Option<String>,

    /// Next recovery commitment (not used; reserved for compatibility).
    next_recovery: Option<String>,

    /// Extension: key history audit log (AMD-001).
    key_history: Option<Vec<KeyHistoryEntry>>,
}
```

#### Revised API Contract (supersedes SPEC-032 CON-001 `resolve()`)

```rust
/// Resolve current CRDT state to W3C-compliant three-part result.
///
/// Replaces SPEC-032's `fn resolve(&self) -> DidDocument`
fn Document::resolve(&self) -> ResolutionResult

/// Convenience: resolve and return only the DID Document.
/// For callers that don't need metadata.
fn Document::resolve_document(&self) -> Option<DidDocument>
```

#### Revised HTTP API (supersedes SPEC-032 CON-003 response)

```
GET /{did}
Accept: application/did+ld+json

Response 200:
Content-Type: application/did+ld+json

{
  "@context": "https://w3id.org/did-resolution/v1",
  "didDocument": {
    "@context": ["https://www.w3.org/ns/did/v1", "https://did-crdt.dev/v1"],
    "id": "did:crdt:<blake3-hash>",
    "verificationMethod": [...],
    "authentication": [...],
    "assertionMethod": [...],
    "keyAgreement": [...],
    "service": [...]
  },
  "didResolutionMetadata": {
    "contentType": "application/did+ld+json",
    "duration": 2
  },
  "didDocumentMetadata": {
    "created": "2026-03-10T12:00:00Z",
    "updated": "2026-03-10T14:30:00Z",
    "versionId": "<blake3-hash>",
    "deactivated": false
  }
}
```

#### Requirement

```
REQ-031: Three-Part Resolution Output

The system SHALL return DID Resolution results as a three-part structure:
1. DID Document (or null if not found / deactivated)
2. DID Resolution Metadata (contentType, error if applicable)
3. DID Document Metadata (created, updated, versionId, deactivated)

The DID Document SHALL contain the @context property with at minimum
"https://www.w3.org/ns/did/v1".

When resolved via HTTP (feature: "service"), the response body SHALL use
the DID Resolution envelope format with didDocument, didResolutionMetadata,
and didDocumentMetadata as top-level properties.

Trace:
- TEST-034
- TEST-035
```

#### Tests

```
TEST-034: Three-Part Resolution Structure

Scenario:
1. Create DID D, apply several deltas.
2. Call document.resolve().
3. Assert: result has did_document (Some), did_resolution_metadata, did_document_metadata.
4. Assert: did_resolution_metadata.content_type == "application/did+ld+json".
5. Assert: did_document_metadata.created is valid ISO8601.
6. Assert: did_document_metadata.version_id == document.content_hash().
7. Assert: did_document_metadata.deactivated == false.

Verifies: REQ-031
```

```
TEST-035: HTTP Resolution Envelope

Scenario:
1. Start service. Create DID.
2. GET /{did}.
3. Assert: response body has "didDocument", "didResolutionMetadata", "didDocumentMetadata" keys.
4. Assert: didDocument contains "@context" with "https://www.w3.org/ns/did/v1".
5. Assert: Content-Type is "application/did+ld+json".

Verifies: REQ-031
```

---

### AMD-007: Deactivated DID Resolution Behaviour

**Gap:** G-7 — W3C §8.2
**Severity:** Low

#### Problem

W3C §8.2: *"Deactivated DIDs are no longer resolvable, or resolve to a document containing only metadata indicating the DID is deactivated."*

SPEC-032's HTTP API returns 410 for deactivated DIDs but does not specify what the library's `resolve()` returns.

#### Specification

A deactivated DID SHALL resolve to:

```rust
ResolutionResult {
    did_document: Some(DidDocument {
        context: vec!["https://www.w3.org/ns/did/v1"],
        id: did.clone(),
        // All other fields empty
        verification_method: vec![],
        authentication: vec![],
        assertion_method: vec![],
        key_agreement: vec![],
        capability_invocation: vec![],
        capability_delegation: vec![],
        service: vec![],
    }),
    did_resolution_metadata: ResolutionMetadata {
        content_type: Some("application/did+ld+json"),
        error: None,
        ..
    },
    did_document_metadata: DocumentMetadata {
        deactivated: true,
        created: <original creation time>,
        updated: <deactivation time>,
        version_id: <current hash>,
        ..
    },
}
```

The HTTP API (feature: "service") SHALL return this with status **200** (not 410), following the W3C pattern where resolution succeeds but the document metadata indicates deactivation. The previous SPEC-032 behaviour of 410 is removed.

#### Requirement

```
REQ-032: Deactivated DID Resolution

The system SHALL resolve a deactivated DID to a minimal DID Document containing
only the @context and id properties, with all verification methods, relationships,
and services empty.

The DID Document Metadata SHALL include deactivated=true.

The HTTP API SHALL return status 200 for deactivated DIDs, with the
didDocumentMetadata.deactivated field set to true.

Trace:
- TEST-036
```

#### Test

```
TEST-036: Deactivated DID Resolution

Scenario:
1. Create DID D. Apply updates.
2. Deactivate D.
3. Call document.resolve().
4. Assert: did_document is Some with id == D, empty verificationMethod.
5. Assert: did_document_metadata.deactivated == true.
6. HTTP: GET /{D} → status 200, didDocumentMetadata.deactivated == true.

Verifies: REQ-032
```

---

### AMD-008: Privacy Considerations

**Gap:** G-8 — W3C §10
**Severity:** Medium

#### Problem

W3C §10 requires DID methods to address privacy considerations. SPEC-032 has a security section but no privacy analysis.

#### Privacy Analysis

**§10.1 — Keep PII out of DID Documents:**
DID documents are public, replicated across all peers via gossip. The `did:crdt` method inherently exposes:
- Public keys (necessary for function)
- Service endpoint URIs (intentional disclosure)
- documentData fields (application-controlled)

**Mitigation:** The library SHALL emit a warning when `documentData` keys match common PII patterns (e.g., "email", "name", "phone", "address"). This is a lint-level guardrail, not an enforcement — some applications may intentionally publish such data.

**§10.2 — DID Correlation:**
A `did:crdt` identifier is a BLAKE3 hash of the creation delta. It is not derivable from the public key alone — different creation timestamps produce different hashes for the same key. However, the public key is visible in the resolved document, enabling cross-DID correlation if the same key is reused.

**Mitigation:** The library SHALL support pairwise DIDs — generating a unique DID per relationship. Documentation SHALL recommend against reusing keys across DIDs.

**§10.3 — DID Document Correlation:**
Service endpoints and documentData can be used to correlate DIDs. For example, two DIDs pointing to the same service endpoint URL are likely controlled by the same entity.

**Mitigation:** Documentation SHALL warn against using identifying service endpoints. The library does not enforce this — it is an application-level concern.

**§10.4 — Metadata Correlation:**
Gossip protocol metadata reveals which DIDs a node is interested in. An observer on the Hyperswarm/iroh network can track which nodes query or propagate which DIDs.

**Mitigation:** Future work — consider onion routing or mix-net gossip for metadata privacy. This is out of scope for SPEC-033 but noted as an open question.

**§10.5 — DID Subject Rights:**
The DID subject (controller of the signing key) can:
- Update or remove any document content (via CRDT deltas)
- Deactivate the DID entirely
- Rotate keys to revoke access

**Mitigation:** These capabilities are inherent in the CRDT model. No additional mechanism needed.

#### Requirement

```
REQ-033: PII Lint Warning

The system SHALL emit a warning-level log when a documentData delta contains
keys matching common PII patterns: "email", "name", "phone", "address",
"date_of_birth", "ssn", "passport", or any key containing "personal" or "pii".

The warning SHALL NOT prevent the delta from being applied. It is advisory.

Trace:
- TEST-037
```

```
REQ-034: Pairwise DID Support

The system SHALL support creating multiple DIDs from the same keypair
via distinct creation deltas (different HLC timestamps produce different
BLAKE3 hashes). Documentation SHALL recommend pairwise DIDs for
privacy-sensitive relationships.

Trace:
- TEST-038
```

#### Tests

```
TEST-037: PII Lint Warning

Scenario:
1. Create DID D.
2. Apply delta setting documentData["email"] = "alice@example.com".
3. Assert: delta accepted (state updated).
4. Assert: warning logged containing "PII" or "personal data".
5. Apply delta setting documentData["project_name"] = "Foo".
6. Assert: no warning logged.

Verifies: REQ-033
```

```
TEST-038: Pairwise DID Generation

Scenario:
1. Generate keypair K.
2. Create DID D1 from K at time T1.
3. Create DID D2 from K at time T2 (T2 > T1).
4. Assert: D1 != D2 (different BLAKE3 hashes due to different HLC).
5. Assert: both resolve correctly with the same public key.

Verifies: REQ-034
```

---

## 4. Revised CRDT Document Model

The complete DID document model after all amendments:

```
DIDDocument (SPEC-032 + SPEC-033) = {
  id:                     Did                          -- immutable, BLAKE3 of creation delta

  // Verification (AMD-001, AMD-002, AMD-003)
  verificationMethods:    OR-Set<VerificationMethod>   -- active methods (add/remove)
  keyHistory:             G-Set<KeyHistoryEntry>       -- audit log (append-only)
  authentication:         OR-Set<DidUrl>               -- §5.3.1 key refs
  assertionMethod:        OR-Set<DidUrl>               -- §5.4.1 key refs
  keyAgreement:           OR-Set<DidUrl>               -- §5.5.1 key refs
  capabilityInvocation:   OR-Set<DidUrl>               -- §5.6.1 key refs
  capabilityDelegation:   OR-Set<DidUrl>               -- §5.7.1 key refs
  signingAuthority:       Max-Register<seq, DidUrl>    -- internal: delta authorization

  // Services (AMD-004)
  serviceEndpoints:       OR-Set<Service>              -- §5.4 service entries

  // Data
  documentData:           LWW-Map<String, Value>       -- per-field last-writer-wins

  // Lifecycle
  revocations:            G-Set<CredentialId>           -- credential revocation (grow-only)
  deactivated:            Max-Register<0 | 1>           -- deactivation latch
}
```

### CRDT Type Summary

| CRDT Type | Fields | Monotonic? | Coordination-free? |
|---|---|---|---|
| G-Set | keyHistory, revocations | Yes | Yes (CALM) |
| OR-Set (ORSWOT) | verificationMethods, authentication, assertionMethod, keyAgreement, capabilityInvocation, capabilityDelegation, serviceEndpoints | No (supports remove) | Yes (causal context) |
| LWW-Map | documentData | No (last-writer-wins) | Yes (HLC ordering) |
| Max-Register | signingAuthority, deactivated | Yes | Yes (CALM) |

**Revised CALM statement:** All did-crdt operations are coordination-free. Operations on G-Set and Max-Register fields are additionally monotonic per the CALM theorem. Operations on OR-Set and LWW-Map fields are coordination-free via CRDT theory (causal context / clock ordering) but not strictly monotonic. No operation in the system requires blockchain, consensus protocol, or external coordinator for correctness.

---

## 5. Revised Crate Structure (Amendments Only)

Changes to SPEC-032 §17:

```
did-crdt/src/core/
  ├── crdt.rs         — ADD: OR-Set wrappers for relationships, VerificationMethod struct,
  │                     Service struct, KeyHistoryEntry, multi-delta transaction
  ├── document.rs     — MODIFY: new fields (5 relationships, keyHistory, signingAuthority),
  │                     revised merge() for new authorization rules
  ├── resolve.rs      — MODIFY: return ResolutionResult (3-part), deactivation behaviour,
  │                     W3C JSON-LD with all 5 relationship arrays
  ├── validate.rs     — MODIFY: revised authorization rules per REQ-027
  ├── did.rs          — MODIFY: formal ABNF validation, DID URL parsing
  └── privacy.rs      — ADD: PII lint checker for documentData keys

did-crdt/src/service/
  └── handlers.rs     — MODIFY: resolution envelope format, 200 for deactivated
```

---

## 6. Updated Traceability Matrix (Amendments Only)

```
REQ-022 (VM Removal)          → TEST-022, TEST-023 → crdt.rs          → OBS-003, OBS-004
REQ-023 (Key History)         → TEST-024          → crdt.rs          → OBS-006
REQ-024 (Verification Rels)   → TEST-025, TEST-026 → crdt.rs, resolve.rs → OBS-003
REQ-025 (Multi-Delta Tx)      → TEST-027          → document.rs      → OBS-003
REQ-026 (Signing Authority)   → TEST-028, TEST-029 → crdt.rs          → OBS-004
REQ-027 (Delta Authorization) → TEST-030          → validate.rs      → OBS-004
REQ-028 (VM Structure)        → TEST-031          → crdt.rs          → (compile-time)
REQ-029 (Service Structure)   → TEST-032          → crdt.rs          → (compile-time)
REQ-030 (DID Syntax ABNF)     → TEST-033          → did.rs           → (compile-time)
REQ-031 (3-Part Resolution)   → TEST-034, TEST-035 → resolve.rs, handlers.rs → OBS-002
REQ-032 (Deactivated Resolve) → TEST-036          → resolve.rs, handlers.rs → OBS-002
REQ-033 (PII Lint)            → TEST-037          → privacy.rs       → OBS-004
REQ-034 (Pairwise DIDs)       → TEST-038          → document.rs      → (no OBS)
```

---

## 7. Security Considerations (Addendum)

### Relationship Manipulation Attack

An attacker who compromises the signing authority key can remove all other keys from verification relationships and add their own. This is equivalent to a full key compromise in any DID method — the signing authority is the root of trust.

**Mitigation:** The `keyHistory` G-Set provides a tamper-evident record of all key changes. A compromised DID can be forensically analysed to identify when the compromise occurred and which keys were legitimately authorised. This does not prevent the attack but enables detection and accountability.

**Future work (noted in SPEC-032 Open Questions):** Multi-sig signing authority (M-of-N threshold) would require multiple key compromises for a full takeover. This is compatible with the CRDT model — the `signingAuthority` field would become a threshold structure rather than a single key reference.

### OR-Set Causal Context Size

OR-Set removals carry causal context (the set of add-operations observed at the time of removal). In adversarial scenarios, an attacker could inflate causal context by rapidly adding and removing keys.

**Mitigation:** Rate limiting on verification method operations at the application layer. The CRDT layer does not enforce rate limits — this is a policy decision for the service layer.

---

## 8. Impact on SPEC-032 Open Questions

| Open Question | Impact |
|---|---|
| 1. Compaction / GC | More pressing — OR-Set tombstones and keyHistory grow unboundedly. Compaction spec needed. |
| 2. Key compromise recovery | Partially addressed — keyHistory enables forensics. Multi-sig signingAuthority deferred. |
| 3. DID method registration | AMD-005 provides the ABNF. Method spec document still needed. |
| 4. WASM target | No impact — OR-Set (ORSWOT) from `crdts` crate supports WASM. |
| 5. Sybil resistance | No impact. |
| 6. Cross-method interop | AMD-003/AMD-004 align structures with W3C, improving interop surface. |
| 7. Legal timestamping | No impact. |
| 8. State size limits | More pressing — 5 additional OR-Set fields increase state size. Limits needed. |

---

## 9. Implementation Priority

Amendments should be implemented in the following order, based on severity and dependency:

| Priority | Amendment | Rationale |
|---|---|---|
| 1 | AMD-003 (VM structure) | Foundation — other amendments depend on the VerificationMethod type |
| 2 | AMD-004 (Service structure) | Foundation — Service type needed before OR-Set integration |
| 3 | AMD-005 (ABNF) | Foundation — DID parsing used everywhere |
| 4 | AMD-002 (Verification relationships) | High severity — core model change, depends on AMD-003 |
| 5 | AMD-001 (VM lifecycle) | High severity — depends on AMD-002 (relationships exist for revocation) |
| 6 | AMD-006 (3-part resolution) | Medium severity — depends on AMD-001/002 for complete output |
| 7 | AMD-007 (Deactivation resolution) | Low severity — depends on AMD-006 |
| 8 | AMD-008 (Privacy) | Medium severity — independent, can be implemented at any time |

---

**END OF SPECIFICATION**
