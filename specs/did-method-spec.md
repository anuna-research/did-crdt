---
title: "The did:crdt DID Method Specification"
version: 0.1.0
status: Draft
created: 2026-03-10
last_updated: 2026-03-10
authors: Anuna Research
---

# The `did:crdt` DID Method Specification

| Field | Value |
|---|---|
| Version | 0.1.0 |
| Status | Draft |
| Created | 2026-03-10 |
| Last Updated | 2026-03-10 |
| Authors | Anuna Research |

---

## Abstract

This document specifies the `did:crdt` Decentralised Identifier (DID) method. The method
represents each DID document as a composition of Conflict-Free Replicated Data Types (CRDTs),
enabling coordination-free creation, resolution, updating, and deactivation of DIDs without
any blockchain, consensus mechanism, or centralised coordination service. Convergence across
replicas is guaranteed by the algebraic properties of the underlying CRDTs; authorisation
is enforced by cryptographic signatures on every mutation. The method is fully compliant with
the [W3C DID Core 1.0](https://www.w3.org/TR/did-core/) specification.

---

## 1. Introduction

Existing DID methods impose significant trade-offs between decentralisation and usability.
Blockchain-anchored methods require transaction fees, confirmation delays, and continuous
online connectivity. Lightweight peer methods (`did:peer`, `did:key`) have no update or
synchronisation mechanism. Sidetree-based methods (`did:orb`) use delta vocabulary but still
require blockchain ordering for finality.

The `did:crdt` method resolves this tension. Every standard DID operation — key addition,
service endpoint management, key rotation, credential revocation, and deactivation — is
reformulated as a monotonically growing operation on a lattice-ordered data structure. The
CALM theorem (Consistency As Logical Monotonicity, [Hellerstein & Alvaro 2019]) proves that
any monotone computation can be executed without coordination and still converge to a unique,
correct result. `did:crdt` is an implementation of this proof in the domain of decentralised
identity.

### 1.1 Design Goals

- **Coordination-free convergence.** Two replicas receiving the same set of signed deltas in
  any order converge to identical DID document state. No leader election, no consensus round,
  no blockchain confirmation.
- **Offline-first.** Operations are applied locally and propagated asynchronously. A network
  partition causes a deferral, not a failure.
- **Zero fees, zero delay.** Creation and updates require no on-chain transaction.
- **W3C compliance.** Resolution produces a JSON-LD document conforming to W3C DID Core 1.0.
- **Embeddable.** The pure core has no I/O and compiles to a single Rust library usable in
  mobile, desktop, server, and WASM environments.
- **Optional blockchain anchoring.** Timestamping or notarisation can be layered on top
  without affecting merge semantics or correctness.

### 1.2 Conformance

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED,
MAY, and OPTIONAL in this document are to be interpreted as described in
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174).

An implementation is conformant if it satisfies every MUST and MUST NOT requirement in this
specification.

---

## 2. Terminology

| Term | Definition |
|---|---|
| **DID** | Decentralised Identifier as defined in [W3C DID Core 1.0](https://www.w3.org/TR/did-core/). |
| **DID Document** | The JSON-LD document resolved from a DID, containing public keys and service endpoints. |
| **CRDT** | Conflict-Free Replicated Data Type — a data structure with a merge function that is commutative, associative, and idempotent. |
| **Delta** | A single signed mutation to a DID document, encoding one field-level operation. |
| **SignedDelta** | A delta together with a Linked-Data Proof produced by an authorised key. |
| **Genesis delta** | The first delta for a DID, which adds the initial verification method and from which the DID identifier is derived. |
| **G-Set** | Grow-only Set — a CRDT set that supports only insertions; merge is set union. |
| **OR-Set (ORSWOT)** | Observed-Remove Set Without Tombstones — a CRDT set supporting both insert and remove while preserving add-wins semantics. |
| **LWW-Map** | Last-Write-Wins Map — a map whose values are replaced by the most recent write, as determined by a Hybrid Logical Clock timestamp. |
| **Max-Register** | A register whose value is the maximum-by-sequence-number write seen so far. |
| **HLC** | Hybrid Logical Clock — a timestamp combining a physical wall clock with a logical counter, used to order concurrent events. |
| **Multibase** | A self-describing base-encoding format prefix; `u` denotes base64url without padding. |
| **Multicodec** | A self-describing codec prefix; `z` denotes base58btc (used for public key encoding in W3C contexts). |
| **Linked-Data Proof** | A cryptographic proof attached to a JSON-LD document, as specified in [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/). |
| **Canonical JSON** | A deterministic JSON serialisation where object keys are sorted lexicographically at every nesting level and no extra whitespace is emitted. |

---

## 3. The `did:crdt` Method

### 3.1 Method Name

The method name that identifies this DID method is: `crdt`.

A DID that uses this method MUST begin with the prefix `did:crdt:`. The prefix is case-sensitive.

### 3.2 Method-Specific Identifier

The method-specific identifier is a 64-character lowercase hexadecimal string encoding a
256-bit BLAKE3 hash value:

```abnf
did-crdt       = "did:crdt:" method-specific-id
method-specific-id = 64HEXDIG
HEXDIG         = DIGIT / "a" / "b" / "c" / "d" / "e" / "f"
                       / "A" / "B" / "C" / "D" / "E" / "F"
```

Both uppercase and lowercase hexadecimal digits are accepted on input; conforming
implementations SHOULD produce lowercase output.

**Example:**

```
did:crdt:a3f8b2c1e4d5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1
```

### 3.3 DID Identifier Derivation

The method-specific identifier is deterministically derived from the genesis (creation) delta
as follows:

1. Construct a genesis payload tuple `(timestamp, proto_op, signer_key)`:
   - `timestamp` — an all-zero Hybrid Logical Clock timestamp:
     `{ wall_ms: 0, logical: 0, node_id: 0 }`.
   - `proto_op` — an `AddVerificationMethod` operation with the fragment `#key-0` and the
     caller's public key in multibase base64url encoding.
   - `signer_key` — the public key in multibase base64url encoding (same as in `proto_op`).
2. Serialise the tuple to compact JSON (key order is preserved by the tuple encoding).
3. Compute the BLAKE3-256 hash of the serialised bytes.
4. Encode the hash as a 64-character lowercase hexadecimal string.
5. Prepend `did:crdt:` to form the complete DID.

This derivation is **deterministic and content-addressed**: the same public key always
produces the same DID. No randomness, no registry lookup, and no network access are required.

---

## 4. CRUD Operations

### 4.1 Create

**Precondition:** The creator holds a signing keypair whose public key will be the initial
verification method.

**Procedure:**

1. Encode the public key as multibase base64url (prefix `u`, no padding):
   - For Ed25519: encode the 32-byte raw public key.
   - For secp256k1: encode the 33-byte SEC1 compressed public key.
2. Call the `Document::new(public_key_multibase)` constructor. The library:
   a. Derives the `did:crdt:<hash>` identifier as described in §3.3.
   b. Constructs a genesis `AddVerificationMethod` delta with `id = "<did>#key-0"` and
      the encoded public key.
   c. Applies the genesis delta to initialise the CRDT state (no authorisation check is
      applied to the genesis delta — see §6.3).
   d. Returns the initialised `Document` and the unsigned genesis `SignedDelta`.
3. The caller SHOULD sign the genesis delta using `SignedDelta::new` with their private key
   before broadcasting it to peers.

**Result:** A new DID with one initial verification method (`<did>#key-0`) and an empty
service endpoint set. The DID document is immediately resolvable by any party holding the
CRDT state.

**Example genesis delta (compact JSON):**

```json
{
  "did": "did:crdt:a3f8b2c1...",
  "timestamp": { "wall_ms": 0, "logical": 0, "node_id": 0 },
  "op": {
    "type": "add_verification_method",
    "id": "did:crdt:a3f8b2c1...#key-0",
    "public_key_multibase": "uBCrFw..."
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "verificationMethod": "did:crdt:a3f8b2c1...#key-0",
    "created": "1970-01-01T00:00:00.000Z",
    "proof_value": "u..."
  }
}
```

### 4.2 Read (Resolve)

**Procedure:**

1. Obtain the current CRDT state for the target DID from local storage or a peer node.
2. Call `document.resolve()`. The library projects the CRDT fields to a W3C DID Core
   JSON-LD document by:
   a. Setting `@context` to `["https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1"]`.
   b. Setting `id` to the DID string.
   c. Mapping each entry in the `verificationMethods` G-Set to a `verificationMethod` array
      entry of type `Ed25519VerificationKey2020` (or the appropriate type for secp256k1 keys).
   d. Listing every verification method ID in the `authentication` array.
   e. Mapping each entry in the `serviceEndpoints` OR-Set to a `service` array entry.
   f. Merging the `documentData` LWW-Map entries as top-level JSON properties.
   g. Setting `didDocumentMetadata.deactivated` to the value of the deactivation latch.
   h. Computing `didDocumentMetadata.versionId` as the BLAKE3-256 hex hash of the
      observable CRDT state snapshot.

**Result:** A W3C DID Core-compliant JSON-LD document. The `versionId` changes whenever any
CRDT field is mutated, providing a content-addressed version identifier.

**Example resolved document:**

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:crdt:a3f8b2c1...",
  "verificationMethod": [
    {
      "id": "did:crdt:a3f8b2c1...#key-0",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:crdt:a3f8b2c1...",
      "publicKeyMultibase": "uBCrFw..."
    }
  ],
  "authentication": [
    "did:crdt:a3f8b2c1...#key-0"
  ],
  "service": [],
  "didDocumentMetadata": {
    "deactivated": false,
    "versionId": "4f3a2b1c..."
  }
}
```

**DIF DID Resolution compatibility:** The `didDocumentMetadata` object is returned inline in
the DID document. Implementations exposing an HTTP resolution endpoint SHOULD also return it
in the resolution result wrapper as specified by the
[DIF DID Resolution specification](https://w3c-ccg.github.io/did-resolution/).

### 4.3 Update

All updates to a DID document are expressed as **signed deltas**. Each delta carries exactly
one field-level operation (`DeltaOp`) and a Linked-Data Proof.

#### 4.3.1 Supported Operations

| Operation | CRDT field | Semantics |
|---|---|---|
| `AddVerificationMethod` | G-Set | Permanently add a verification method. Keys are never removed from the set. |
| `AddServiceEndpoint` | OR-Set | Add a service endpoint (add-wins in concurrent add/remove). |
| `RemoveServiceEndpoint` | OR-Set | Remove a service endpoint by ID. |
| `SetDocumentData` | LWW-Map | Set an arbitrary key-value pair; last writer (by HLC) wins. |
| `RotateKey` | Max-Register | Advance the active key to a new key reference with a strictly greater sequence number. |
| `RevokeCredential` | G-Set | Permanently add a credential ID to the revocation set. |
| `Deactivate` | Boolean latch | Permanently deactivate the DID. Irreversible. |

#### 4.3.2 Delta Construction

To construct and apply a delta:

1. Choose the target DID and the operation.
2. Obtain the current HLC timestamp from the local clock (wall time + logical counter +
   node ID).
3. Set `verification_method` to the full DID URL of the signing key
   (e.g. `did:crdt:<hash>#key-0`).
4. Compute the **signing input**: the canonical JSON of the object
   `{"did": <did>, "op": <op>, "timestamp": <hlc>}`. Keys MUST be sorted
   lexicographically at every nesting level; no whitespace is emitted.
5. Sign the signing input bytes with the private key corresponding to the declared
   verification method.
6. Encode the signature as multibase base64url (prefix `u`, no padding).
7. Construct the `SignedDelta` object with the proof.

#### 4.3.3 Delta Application (Merge)

An implementation MUST validate a received delta before applying it:

1. **Signature verification** — verify the `proof_value` against the signing input
   computed from `{did, op, timestamp}` using the public key identified by
   `proof.verification_method`. If verification fails, reject the delta.
2. **Authorisation checks** (in order):
   a. `delta.did` MUST equal the document's DID.
   b. If the document is deactivated, reject all further deltas.
   c. Unless the document is in genesis state (no verification methods), the
      `proof.verification_method` MUST identify a key already present in the
      `verificationMethods` G-Set. In genesis state, only `AddVerificationMethod` is
      permitted (see §6.3).
   d. For `RotateKey`, the supplied `seq` MUST be strictly greater than the current
      Max-Register sequence number.
3. **CRDT merge** — apply the operation to the appropriate CRDT field.

Because CRDT merge is commutative, associative, and idempotent, deltas may be applied in any
order and any delta may be replayed without side effects.

#### 4.3.4 Concurrent Merge Semantics

| Scenario | Resolution |
|---|---|
| Two nodes add different service endpoints concurrently | Both survive (OR-Set union). |
| One node adds, one node removes the same service endpoint | Add wins (ORSWOT add-wins semantics). |
| Two nodes rotate the active key to different targets at the same sequence number | Highest key reference string wins (Max-Register lexicographic tiebreak). |
| Two nodes set the same LWW-Map key concurrently | Highest HLC timestamp wins; ties broken by node ID. |
| One node deactivates, another node performs any update | Deactivation wins. Once the boolean latch is set on any replica it propagates to all replicas on merge. |

### 4.4 Deactivate (Delete)

Deactivation is expressed as a `Deactivate` delta signed by any authorised verification
method. It is **irreversible**: the boolean latch, once set on any replica, is propagated to
all replicas on merge and no further deltas are accepted by any conforming implementation.

**Procedure:**

1. Construct a `SignedDelta` with `op = { "type": "deactivate" }`.
2. Sign with an authorised verification method key.
3. Apply via `document.merge(delta)`.

After deactivation, `document.resolve()` returns the final DID document state with
`didDocumentMetadata.deactivated = true`. The DID identifier and all historic deltas are
retained for auditability.

---

## 5. CRDT Field Specifications

### 5.1 Verification Methods — G-Set

- **Type:** Grow-only Set (G-Set).
- **Element type:** `{ id: String, public_key_multibase: String }`.
- **Merge:** Set union. Elements are identified by `id`; duplicate IDs are idempotent.
- **Constraint:** Keys MUST NOT be removed. Once added, a verification method remains in the
  set permanently. Rotation is achieved by adding a new key and updating the Max-Register
  (§5.4), not by removing the old key.

### 5.2 Service Endpoints — OR-Set (ORSWOT)

- **Type:** Observed-Remove Set Without Tombstones (ORSWOT).
- **Element type:** `{ id: String, service_type: String, endpoint: String }`.
- **Merge:** ORSWOT merge; add-wins in the case of concurrent add and remove of the same
  element.
- **Actor identity:** Each replica is assigned a unique integer actor ID (node ID from the
  HLC). The causal context tracks which adds have been observed by each actor.

### 5.3 Document Data — LWW-Map

- **Type:** Last-Write-Wins Map (LWW-Map).
- **Key type:** `String`.
- **Value type:** Any JSON value.
- **Merge:** For each key, the value with the greatest HLC timestamp wins. If two writes have
  identical HLC wall time and logical counter, the one from the node with the greater node ID
  wins.
- **Use:** Stores arbitrary application-defined metadata. Implementations MUST treat values
  as opaque JSON; no PII SHOULD be stored here (see §7).

### 5.4 Active Key — Max-Register

- **Type:** Max-Register.
- **Value type:** `{ seq: u64, key_ref: String }`.
- **Merge:** The entry with the highest `seq` wins. If two entries have the same `seq`,
  the one with the lexicographically greater `key_ref` wins.
- **Constraint:** A `RotateKey` delta MUST carry a `seq` strictly greater than the current
  register value. Deltas with `seq ≤ current` are rejected by the authorisation check.

### 5.5 Revocations — G-Set

- **Type:** Grow-only Set (G-Set).
- **Element type:** `String` (credential ID).
- **Merge:** Set union.
- **Constraint:** Revocations are permanent. Once a credential ID enters the set it cannot
  be removed.

### 5.6 Deactivated — Boolean Latch

- **Type:** Monotone boolean latch (join-semilattice with `false ⊔ true = true`).
- **Merge:** Logical OR. Once set to `true`, the value is permanent.
- **Constraint:** Any delta applied to a document with `deactivated = true` MUST be rejected.

---

## 6. Signature Suites

### 6.1 Ed25519Signature2020

- **Curve:** Curve25519 (Ed25519).
- **Library:** `ed25519-dalek` (deterministic EdDSA).
- **Public key encoding:** 32-byte raw public key, multibase base64url (`u` prefix, no padding).
- **Signature encoding:** 64-byte raw Ed25519 signature, multibase base64url (`u` prefix,
  no padding).
- **Signing input:** Canonical JSON bytes of `{"did": ..., "op": ..., "timestamp": ...}`.

### 6.2 EcdsaSecp256k1Signature2019

- **Curve:** secp256k1.
- **Library:** `k256` (RFC 6979 deterministic ECDSA).
- **Public key encoding:** 33-byte SEC1 compressed public key, multibase base64url
  (`u` prefix, no padding).
- **Signature encoding:** 64-byte compact r‖s signature, multibase base64url (`u` prefix,
  no padding).
- **Signing input:** Same canonical JSON as above.

### 6.3 Canonical JSON

The bytes to be signed are the canonical JSON serialisation of the object
`{"did": <did>, "op": <op>, "timestamp": <hlc>}`. Canonical JSON is defined as:

- Object keys are sorted lexicographically (Unicode code-point order) at every nesting level.
- No extra whitespace (no spaces or newlines).
- Array element order is preserved.
- String, number, boolean, and null values are serialised per RFC 8259.

The proof metadata fields (`suite`, `verificationMethod`, `created`) are intentionally
excluded from the signing input to avoid circularity. This is safe because:

- Suite confusion is prevented by key-byte-length mismatch (Ed25519 uses 32-byte keys;
  secp256k1 SEC1 compressed uses 33-byte keys).
- Cross-document confusion is prevented by the DID match check in the authorisation pipeline.

---

## 7. Security Considerations

### 7.1 Genesis State Attack

A document in genesis state (no verification methods yet) would, without additional
protection, accept any operation from any party — since there is no authorised key to check
against. This creates a window during which an attacker could submit a `Deactivate` or
`RotateKey` delta before the legitimate owner's genesis delta is applied.

**Mitigation:** Conforming implementations MUST enforce the following invariant:
> A document in genesis state (empty `verificationMethods` G-Set) MUST accept only
> `AddVerificationMethod` deltas. All other operations MUST be rejected with an
> `Unauthorised` error, even if the proof carries a non-empty signature.

This invariant ensures that the only way to initialise a DID is by first registering a key,
and that no destructive operation (deactivation, key rotation, credential revocation) can
be applied before a key is established.

### 7.2 Unsigned Deltas on Active Documents

An empty `proof_value` is valid only for genesis deltas on documents that have no
verification methods yet. Any delta arriving at a document with at least one verification
method MUST carry a non-empty, cryptographically valid signature.

**Mitigation:** The signature verification function MUST return an error if
`proof_value` is empty and the document has at least one verification method. Accepting
unsigned deltas would allow any party who knows a valid key ID to mutate a live document
without possessing the corresponding private key.

### 7.3 Key Rotation Sequence Attack

The Max-Register for active key rotation uses a monotonically increasing sequence number. A
delta with `seq ≤ current_seq` would be a stale or duplicate rotation that MUST be rejected
to prevent rollback to a previously superseded key.

**Mitigation:** The authorisation check MUST verify `seq > current_seq` for all `RotateKey`
deltas before applying them. An implementation that accepts equal or lower sequences could be
exploited to lock a DID into a stale key after the owner has rotated forward.

### 7.4 Replay Attacks

CRDTs are idempotent: replaying the same delta is equivalent to applying it once. However,
replaying a delta from one DID at a different DID would constitute an attack if the DID
match check were absent.

**Mitigation:** Every delta carries the target `did` field, which is included in the signing
input. The authorisation check MUST verify that `delta.did == document.did`. A delta signed
for one DID cannot be replayed against another DID because the signing input would differ,
causing signature verification to fail.

### 7.5 Concurrent Key Rotation Tiebreak

Two replicas may concurrently rotate to different keys at the same sequence number. The
Max-Register resolves the conflict deterministically by selecting the entry with the
lexicographically greater `key_ref`. This means both replicas converge to the same active key,
but neither can predict which rotation will "win" in advance.

**Mitigation:** Implementors SHOULD design key rotation workflows to use a monotonically
increasing sequence number managed by the DID controller to minimise the likelihood of
concurrent rotations. In high-security environments, key rotation SHOULD be coordinated
across devices before broadcasting deltas.

### 7.6 Deactivation Irreversibility

The `Deactivate` operation sets a boolean latch that, once set, permanently prevents all
further mutations. This is intentional and aligns with the W3C DID Core specification for
deactivated DIDs. However, an attacker who gains access to an authorised key could
deactivate a DID without the owner's consent.

**Mitigation:** Key management practices MUST ensure private keys are securely stored.
Multi-signature schemes or key threshold policies MAY be layered on top by application
developers to require approval from multiple keys before deactivation is accepted.

### 7.7 Denial of Service via Delta Flooding

An attacker who obtains a valid signing key (or exploits the genesis window) could flood a
node with large numbers of valid deltas, consuming storage and CPU.

**Mitigation:** Implementations SHOULD apply rate limiting on incoming deltas per DID per
time period. Delta size SHOULD be bounded; conforming implementations MAY reject deltas
whose serialised size exceeds a configurable maximum (recommended: 64 KiB).

### 7.8 Cryptographic Agility

The method currently supports two signature suites. Future suites may be added without
breaking the DID identifier scheme (the identifier is derived from the genesis delta payload,
not from a specific signature algorithm).

**Constraint:** Implementations MUST reject deltas whose `proof.type` is not one of the
supported suite identifiers listed in §6.

---

## 8. Privacy Considerations

### 8.1 Public Visibility of DID Documents

DID documents in the `did:crdt` method are public by design. All verification methods,
service endpoints, and document data fields are visible to any party who resolves the DID.
**No personally identifiable information (PII) SHOULD be stored in any DID document field.**

### 8.2 Correlation via Identifier

The `did:crdt` identifier is derived deterministically from the genesis public key. A single
key pair always produces the same DID. Controllers who wish to minimise correlation between
different contexts SHOULD use distinct key pairs (and thus distinct DIDs) for each context.

### 8.3 Document Data Field Opacity

The `documentData` LWW-Map accepts arbitrary JSON values. Implementors MUST treat these
values as opaque and MUST NOT interpret them. Applications that store data in this field
SHOULD document its contents to their users and MUST NOT place private keys, PII, or
sensitive data in this field.

### 8.4 Audit Trail via CRDT State

The `verificationMethods` G-Set and `revocations` G-Set are grow-only: entries are never
deleted. Any party holding the CRDT state can observe all keys ever added and all
credentials ever revoked. Controllers SHOULD be aware that the CRDT state constitutes a
permanent, append-only audit trail of all key additions and revocations.

### 8.5 Service Endpoint Privacy

Service endpoints added to the OR-Set are publicly visible to all resolvers. Controllers
SHOULD avoid embedding private network addresses or sensitive identifiers in service endpoint
URIs.

### 8.6 Key Linkage

Because all verification methods for a DID are stored in a single G-Set and are visible in
the resolved document, all public keys associated with a DID are trivially linked. Controllers
who require pseudonymity across different key generations SHOULD use separate DIDs rather than
rotating keys within a single DID.

### 8.7 Timestamp Precision and Clock Skew

The HLC timestamp embedded in each delta exposes information about the controller's local
wall-clock time with millisecond precision. This MAY allow timing analysis to correlate
mutations to physical device clocks or approximate geographic locations.

**Mitigation:** Implementations that require strong clock privacy MAY normalise the wall
component of the HLC timestamp to a coarser granularity (e.g., minute-level) before signing.

---

## 9. Reference Implementation

The reference implementation is the `did-crdt` Rust library (Rust edition 2021, MSRV 1.77).
It provides the pure-core CRDT engine with no I/O or external service dependencies and is
available under the MIT licence.

### 9.1 Core Modules

| Module | Purpose |
|---|---|
| `core::did` | `Did` type — parsing, validation, display |
| `core::hlc` | `HlcTimestamp` — Hybrid Logical Clock |
| `core::crdt` | CRDT field types — G-Set, ORSWOT, LWW-Map, Max-Register, Boolean latch |
| `core::delta` | `SignedDelta`, `DeltaOp`, `DeltaProof` — delta construction and canonical signing |
| `core::document` | `Document` — composite DID document CRDT (create, merge, resolve) |
| `core::validate` | `verify_signature`, `check_authorisation` — trust-boundary checks |
| `core::resolve` | `DidDocument`, `VerificationMethod`, `ServiceEndpoint` — W3C projection types |

### 9.2 Quick Start

```rust
use did_crdt::core::document::Document;
use did_crdt::core::validate::{verify_signature, check_authorisation};

// Create a new DID from a public key.
let (mut doc, genesis_delta) = Document::new("uBCrFw...")?;
println!("DID: {}", doc.did);

// Resolve to a W3C DID Core JSON-LD document.
let did_document = doc.resolve()?;
println!("{}", serde_json::to_string_pretty(&did_document)?);

// Receive and apply a delta from a peer.
verify_signature(&incoming_delta, &doc)?;
check_authorisation(&incoming_delta, &doc)?;
doc.merge(incoming_delta)?;

// State-based merge with another replica.
doc.merge_state(remote_replica)?;
```

### 9.3 Property-Based Tests

The reference implementation includes property-based tests (using `proptest`) that verify:

- **Commutativity:** `merge(A, merge(B, C)) = merge(merge(A, B), C)` for all delta orderings.
- **Associativity:** `merge(merge(A, B), C) = merge(A, merge(B, C))`.
- **Idempotence:** `merge(A, A) = A`.
- **Key rotation convergence:** Concurrent rotations always converge to the same active key.
- **Deactivation finality:** Once deactivated, no further mutation is accepted on any replica.

---

## 10. DID Method Registry Registration

This section provides the information required for registration in the
[W3C DID Spec Registries](https://www.w3.org/TR/did-spec-registries/).

| Field | Value |
|---|---|
| **Method name** | `crdt` |
| **Status** | Provisional |
| **DID specification** | This document |
| **Verifiable Data Registry** | None (coordination-free; any compatible peer store) |
| **Method-specific DID syntax** | `did:crdt:<64HEXDIG>` |
| **Primary implementors** | Anuna Research |
| **Reference implementation** | `did-crdt` Rust library |
| **Test suite** | Property-based tests in `tests/properties.rs` |
| **Security review** | See §7 of this document |
| **Privacy review** | See §8 of this document |

---

## 11. Normative References

| Reference | Title |
|---|---|
| [DID-CORE] | [Decentralised Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/), W3C Recommendation |
| [DID-RESOLUTION] | [DID Resolution](https://w3c-ccg.github.io/did-resolution/), W3C Draft Community Group Report |
| [DID-SPEC-REGISTRIES] | [DID Specification Registries](https://www.w3.org/TR/did-spec-registries/), W3C Note |
| [VC-DATA-MODEL] | [Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/), W3C Recommendation |
| [RFC2119] | [Key Words for Use in RFCs](https://www.rfc-editor.org/rfc/rfc2119), IETF |
| [RFC8174] | [Ambiguity of Uppercase vs Lowercase in RFC 2119](https://www.rfc-editor.org/rfc/rfc8174), IETF |
| [RFC8259] | [The JavaScript Object Notation (JSON) Data Interchange Format](https://www.rfc-editor.org/rfc/rfc8259), IETF |
| [MULTIBASE] | [Multibase](https://datatracker.ietf.org/doc/draft-multiformats-multibase/), IETF Draft |
| [BLAKE3] | [BLAKE3 Cryptographic Hash Function](https://github.com/BLAKE3-team/BLAKE3-specs/raw/master/blake3.pdf) |
| [CALM] | [Keeping CALM: When Distributed Consistency Is Easy](https://arxiv.org/abs/1901.01930), Hellerstein & Alvaro, 2019 |

## 12. Informative References

| Reference | Title |
|---|---|
| [SIDETREE] | [Sidetree Protocol](https://identity.foundation/sidetree/spec/), Decentralised Identity Foundation |
| [DID-KEY] | [The did:key Method](https://w3c-ccg.github.io/did-method-key/), W3C Community Group Draft |
| [DID-PEER] | [Peer DID Method Specification](https://identity.foundation/peer-did-method-spec/), DIF |
| [ED25519-2020] | [Ed25519 Signature 2020](https://w3c.github.io/vc-di-eddsa/#ed25519signature2020), W3C |
| [SECP256K1-2019] | [EcdsaSecp256k1 Signature 2019](https://w3c-ccg.github.io/ld-cryptosuite-registry/#ecdsasecp256k1signature2019), W3C CCG |
| [HLC] | [Logical Physical Clocks and Consistent Snapshots in Globally Distributed Databases](https://cse.buffalo.edu/tech-reports/2014-04.pdf), Kulkarni et al., 2014 |
| [ORSWOT] | [An Optimised Conflict-Free Replicated Set](https://arxiv.org/abs/1210.3368), Bieniusa et al., 2012 |
