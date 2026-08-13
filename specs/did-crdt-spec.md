---
title: "SPEC-032: did-crdt — Coordination-Free Decentralised Identifiers via Signed CRDTs"
id: SPEC-032
version: 0.3.0
status: draft
created: 2026-03-10
last_updated: 2026-08-13
authors: Anuna Research
reviewers: Engineering, Security
audience: stakeholders, engineers, protocol designers
references:
  - "SPEC-031: Signed CRDTs as Coordination-Free DID Registry (research/field-notes/signed-crdt-did-registry.md)"
  - "CALM Theorem: arXiv:1901.01930 (Hellerstein & Alvaro, 2019)"
  - "W3C DID Core: w3.org/TR/did-core"
  - "W3C Verifiable Credentials: w3.org/TR/vc-data-model-2.0"
  - "Archetech Archon: github.com/archetech/archon"
  - "DIF Sidetree Protocol: identity.foundation/sidetree/spec"
---

# SPEC-032: did-crdt — Coordination-Free Decentralised Identifiers via Signed CRDTs

| Field | Value |
|---|---|
| Document ID | SPEC-032 |
| Title | did-crdt — Coordination-Free Decentralised Identifiers via Signed CRDTs |
| Version | 0.1.0 |
| Status | Draft |
| Created | 2026-03-10 |
| Last Updated | 2026-06-11 |
| Authors | Anuna Research |
| Reviewers | Engineering, Security |
| Parent | SPEC-031 (research foundation) |

---

## 1. Executive Summary

`did-crdt` is a Rust library and optional standalone service that implements a new W3C-compliant DID method (`did:crdt`) where the DID document is modelled as a composition of signed Conflict-Free Replicated Data Types (CRDTs). The library eliminates the need for blockchain consensus, linear operation chains, or any external coordination service — convergence is guaranteed by the algebraic properties of CRDTs, and authorisation is guaranteed by cryptographic signatures.

**Why this matters:**

Existing DID methods force a choice between decentralisation and usability. Blockchain-anchored methods (`did:btc`, `did:ion`, `did:cid`) require transaction fees, confirmation delays, and online connectivity. Peer methods (`did:peer`, `did:key`) are lightweight but have no update or sync mechanism. Sidetree-based methods (`did:orb`) use CRDT vocabulary for deltas but still anchor to a blockchain for ordering.

`did-crdt` resolves this trade-off. The CALM theorem (Consistency As Logical Monotonicity) proves that every standard DID operation — including key rotation, revocation, and deactivation — can be reformulated as monotonic, meaning coordination-free implementations are provably correct. This library is the first implementation of that proof.

**What it enables:**

- Multi-device wallets that sync without conflict
- Offline-first identity that converges on reconnection
- Zero transaction fees, zero confirmation delay
- Embeddable as a library or deployable as a service
- No blockchain dependency for correctness — optional anchoring for timestamping only

---

## 2. Feature Overview

**Feature Name:** `did-crdt`
**Purpose:** Provide a coordination-free DID method as a reusable Rust library and optional service.
**User Story:** As a developer building decentralised applications, I want a DID library that handles multi-device sync and offline operation without blockchain dependencies, so that my users can manage their identity from any device without conflicts or fees.

**Acceptance Criteria:**

- [ ] Two replicas receiving the same set of signed deltas in any order converge to identical DID document state
- [ ] DID documents resolve to valid W3C DID Core-compliant JSON-LD
- [ ] Key rotation, revocation, and deactivation operate without external coordination
- [ ] The library compiles to a standalone Rust crate with no runtime I/O in the pure core
- [ ] The service mode exposes a DID resolution HTTP API compatible with the DID Resolution specification
- [ ] Property-based tests verify commutativity, associativity, and idempotence of all merge operations

**Data Classification:** Public (DID documents are public by design)
**Privacy Notes:** No PII in DID documents. Private keys never leave the client. Document data fields may contain application-specific data — the library treats them as opaque bytes.

---

## 3. Vision Statement

Build a DID library where:

- **Convergence is mathematical, not political.** CRDT merge functions guarantee identical state across replicas — no consensus protocol, no leader election, no blockchain finality.
- **Every operation is monotonic.** The CALM theorem provides a formal proof that coordination-free consistency is achievable for all DID operations. This is not an approximation or a heuristic — it is a theorem.
- **The library is the protocol.** The merge function is deterministic and pure. Any implementation that computes the same merge produces the same state. Interoperability is a mathematical property, not a conformance test.
- **Blockchain is optional infrastructure, not a correctness requirement.** Timestamping, notarisation, and censorship resistance can be layered on top without affecting merge semantics.

---

## 4. Architecture Overview

### High-Level System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        did-crdt crate                           │
│                                                                 │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                     PURE CORE                              │  │
│  │  (no I/O, no allocation side-effects, deterministic)       │  │
│  │                                                            │  │
│  │  ┌──────────┐ ┌──────────┐ ┌───────────┐ ┌─────────────┐  │  │
│  │  │ G-Set    │ │ OR-Set   │ │ LWW-Map   │ │ Max-Register│  │  │
│  │  │          │ │ (ORSWOT) │ │           │ │             │  │  │
│  │  └────┬─────┘ └────┬─────┘ └─────┬─────┘ └──────┬──────┘  │  │
│  │       │             │             │              │         │  │
│  │       └─────────────┴──────┬──────┴──────────────┘         │  │
│  │                            │                               │  │
│  │                    ┌───────▼───────┐                       │  │
│  │                    │  DIDDocument  │                       │  │
│  │                    │  (composite   │                       │  │
│  │                    │   CRDT)       │                       │  │
│  │                    └───────┬───────┘                       │  │
│  │                            │                               │  │
│  │              ┌─────────────┼─────────────┐                 │  │
│  │              │             │             │                 │  │
│  │       ┌──────▼──────┐ ┌───▼────┐ ┌──────▼──────┐         │  │
│  │       │  validate   │ │ merge  │ │  resolve    │         │  │
│  │       │  (ssi)      │ │        │ │  (to W3C)   │         │  │
│  │       └─────────────┘ └────────┘ └─────────────┘         │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                   EFFECTFUL SHELL                          │  │
│  │  (I/O, networking, persistence — optional features)        │  │
│  │                                                            │  │
│  │  ┌──────────┐  ┌────────────┐  ┌─────────────┐            │  │
│  │  │ store    │  │ sync       │  │ service     │            │  │
│  │  │ (iroh-   │  │ (iroh-     │  │ (HTTP API   │            │  │
│  │  │  blobs)  │  │  gossip)   │  │  for DID    │            │  │
│  │  │          │  │            │  │  resolution)│            │  │
│  │  └──────────┘  └────────────┘  └─────────────┘            │  │
│  └────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Dependency Graph

```
did-crdt
├── Core (default, no optional features)
│   ├── crdts          — G-Set, ORSWOT, LWW-Register, Map
│   ├── ssi            — DID document types, signature verification
│   ├── serde          — serialisation
│   └── blake3         — content-addressed hashing
│
├── Feature: "sync"
│   ├── iroh           — P2P connections (QUIC, NAT traversal)
│   ├── iroh-gossip    — gossip protocol for delta propagation
│   └── iroh-blobs     — content-addressed blob storage
│
├── Feature: "service"
│   ├── axum           — HTTP server for DID resolution API
│   └── tower          — middleware (rate limiting, tracing)
│
└── Feature: "anchor"
    └── (pluggable)    — optional blockchain timestamping
```

### Data Flow

```
                    ┌──────────┐
                    │  Client  │
                    │ (wallet, │
                    │  CLI,    │
                    │  app)    │
                    └────┬─────┘
                         │
                    sign delta
                         │
                         ▼
              ┌──────────────────┐
              │  validate(delta) │ ← pure: verify signature against
              │                  │   current verificationMethods
              └────────┬─────────┘
                       │
                  valid │ invalid → reject
                       │
                       ▼
              ┌──────────────────┐
              │  merge(state,    │ ← pure: CRDT merge function
              │        delta)    │   commutativity guarantees
              │                  │   order-independence
              └────────┬─────────┘
                       │
                       ▼
              ┌──────────────────┐
              │  resolve(state)  │ ← pure: materialise CRDT state
              │                  │   into W3C DID Document
              └────────┬─────────┘
                       │
            ┌──────────┼──────────┐
            │          │          │
            ▼          ▼          ▼
        ┌───────┐ ┌────────┐ ┌────────┐
        │ store │ │ gossip │ │ serve  │
        │ (pin  │ │ (send  │ │ (HTTP  │
        │  CID) │ │  delta │ │  DID   │
        │       │ │  to    │ │  resol-│
        │       │ │  peers)│ │  ution)│
        └───────┘ └────────┘ └────────┘
         effectful  effectful  effectful
```

---

## 5. User Profiles

### 5.1 Library Consumer

```
# User: Library Consumer
Role: Application developer integrating DID into a Rust project
Goals:
  - Create and manage DIDs without running external infrastructure
  - Sync DID state between application instances
  - Resolve DIDs to W3C-compliant documents
Constraints:
  - May be embedding in resource-constrained environments (mobile, WASM)
  - Needs the pure core without networking dependencies
  - Expects idiomatic Rust API with strong type safety
Daily workflow:
  1. Add did-crdt to Cargo.toml
  2. Create a DID with a keypair
  3. Update DID document fields (add keys, endpoints, data)
  4. Merge incoming deltas from peers
  5. Resolve DID to JSON-LD document
```

### 5.2 Service Operator

```
# User: Service Operator
Role: Infrastructure engineer running did-crdt as a standalone resolver
Goals:
  - Run a DID resolution endpoint for an organisation
  - Peer with other nodes for DID state replication
  - Monitor convergence and delta propagation
Constraints:
  - Needs HTTP API compatible with DID Resolution spec
  - Requires observability (metrics, logs, traces)
  - Must handle thousands of DIDs with acceptable latency
Daily workflow:
  1. Deploy did-crdt service (Docker or binary)
  2. Configure peering with other nodes
  3. Monitor convergence latency and delta rejection rates
  4. Resolve DIDs via HTTP API for downstream services
```

### 5.3 Protocol Designer

```
# User: Protocol Designer
Role: Researcher or standards contributor evaluating the DID method
Goals:
  - Verify CALM theorem claims against implementation
  - Assess security properties of signed CRDT approach
  - Evaluate interoperability with existing DID infrastructure
Constraints:
  - Needs formal specification of merge semantics
  - Needs property-based test results as evidence
  - Expects W3C DID Method specification document
Daily workflow:
  1. Read DID method specification
  2. Review property-based test coverage
  3. Attempt adversarial scenarios (concurrent rotations, partition healing)
  4. Evaluate against DID Core conformance criteria
```

---

## 6. Happy Paths

### 6.1 Happy Path: Create and Resolve a DID

```
Preconditions: Library imported, keypair generated
Steps:
  1. Call Document::new(keypair) → DID document with did:crdt identifier
     → Returns Document with id, initial verificationMethod, active key
  2. Call document.resolve() → W3C DID Document JSON-LD
     → Returns valid JSON-LD with @context, id, verificationMethod, authentication
  3. Serialise document state → portable bytes
     → Returns serde-compatible serialised CRDT state

Postconditions:
  - DID is a content-addressed identifier derived from creation delta
  - Document resolves to valid W3C DID Core JSON-LD
  - State is serialisable and mergeable with any other replica

Failure modes:
  - Invalid keypair (unsupported curve) → error at step 1
  - Serialisation of empty document → valid empty document, not error
```

### 6.2 Happy Path: Multi-Device Sync

```
Preconditions: DID D exists on Device A and Device B (same key material)
Steps:
  1. Device A: document.update_data("email", "alice@example.com")
     → Returns SignedDelta with HLC timestamp
  2. Device B: document.add_service_endpoint(endpoint)
     → Returns SignedDelta with HLC timestamp
  3. Device A sends delta to Device B (via gossip or manual transfer)
     → Device B calls document.merge(delta_from_A) → Ok(())
  4. Device B sends delta to Device A
     → Device A calls document.merge(delta_from_B) → Ok(())
  5. Both devices call document.resolve()
     → Both return identical DID documents containing email AND service endpoint

Postconditions:
  - Both devices have identical CRDT state
  - No data lost from either device's update
  - Content-addressed snapshot hash is identical on both devices

Failure modes:
  - Network partition persists → both devices operate independently,
    merge succeeds whenever connectivity returns
  - Delta from unknown DID → deferred until creation delta received
  - Delta with invalid signature → rejected, state unchanged
```

### 6.3 Happy Path: Key Rotation

```
Preconditions: DID D has active key K1 (seq=1)
Steps:
  1. Generate new keypair K2
  2. Call document.rotate_key(K2, signed_by: K1)
     → Creates SignedDelta setting activeKey to (seq=2, key=K2)
     → K1 remains in verificationMethods (grow-only set)
  3. Call document.resolve()
     → DID document shows K2 as active authentication key
     → K1 remains listed in verificationMethod array
  4. Attempt to create delta signed by K1 for a non-rotation field
     → Rejected: K1's seq (1) < active seq (2)

Postconditions:
  - K2 is the active key for signing future deltas
  - K1 cannot sign non-rotation deltas (enforced by seq comparison)
  - K1 can still sign a rotation to K3 at seq ≥ 3 (recovery path)

Failure modes:
  - Concurrent rotation from two devices (same K1, different targets)
    → Max-Register tiebreak: highest key hash wins, both converge
  - Rotation signed by revoked key → rejected
  - Rotation with seq ≤ current active seq → rejected
```

### 6.4 Happy Path: Service Operation

```
Preconditions: did-crdt binary compiled with "service" and "sync" features
Steps:
  1. Start service: LISTEN_ADDR=0.0.0.0:8080 did-crdt-service
     → HTTP server starts; iroh node id and peer string printed to stderr
     → e.g. "did-crdt: peer string: <NodeId>@192.0.2.1:PORT"
     (Until DHT peer discovery is implemented per CON-006, operators copy
      this string and pass it as PEERS on other nodes. Once CON-006 is in
      place, PEERS becomes optional — nodes discover each other via the DHT.)
  1b. Start a second node peered with the first:
     LISTEN_ADDR=0.0.0.0:8081 PEERS="<NodeId>@192.0.2.1:PORT" did-crdt-service
     → Peering established via iroh-gossip
  2. Client creates DID via POST /dids
     → Returns did:crdt identifier and initial document
  3. Client resolves DID via GET /dids/{did}
     → Returns W3C DID Document JSON-LD
  4. Peer node pushes deltas via gossip
     → Local state merges automatically, resolution reflects merged state
  5. Operator queries GET /metrics
     → Returns convergence latency histogram, delta counts, rejection rates

Postconditions:
  - DID resolvable from any peered node
  - Convergence observable via metrics
  - Resolution latency within NFR bounds

Failure modes:
  - Peer unreachable → gossip retries, local state unaffected
  - Malformed delta from peer → rejected, logged, counter incremented
  - Storage full → backpressure signal, deltas queued in memory
```

---

## 7. Functional Requirements

```
REQ-001: DID Creation

The system SHALL create a new DID from a cryptographic keypair by generating a
creation delta, hashing it with BLAKE3, and using the hash as the DID-specific
identifier (did:crdt:<blake3-hash>).

The creation delta SHALL include the initial public key in the verificationMethods
G-Set and set the activeKey Max-Register to (seq=1, keyRef=<initial-key>).

Trace:
- TEST-001
- CON-001
```

```
REQ-002: CRDT Document Model

The system SHALL represent each DID document as a composition of typed CRDT fields:

| Field                | CRDT Type      | Semantics                              |
|----------------------|----------------|----------------------------------------|
| verificationMethods  | G-Set          | Grow-only set of verification methods  |
| serviceEndpoints     | OR-Set (ORSWOT)| Add/remove with causal context         |
| documentData         | LWW-Map        | Per-field last-writer-wins register    |
| activeKey            | Max-Register   | Highest seq wins, tiebreak on key hash |
| revocations          | G-Set          | Grow-only set of revoked credential IDs|
| deactivated          | Max-Register   | Once 1, stays 1 (boolean latch)       |

Any two replicas receiving the same set of signed deltas SHALL converge to
identical state regardless of delta arrival order.

Trace:
- TEST-002
- TEST-003
- CON-001
```

```
REQ-003: Signed Delta

The system SHALL represent every mutation as a signed delta containing:
- Target DID
- Target field name
- CRDT operation (add, remove, set)
- Hybrid Logical Clock value
- Cryptographic proof (signature, verification method reference, timestamp)

The system SHALL reject any delta whose signature does not verify against a
key present in the target DID's verificationMethods set with seq ≥ activeKey.seq
(except for activeKey rotation deltas, which may be signed by any key in the set).

Trace:
- TEST-004
- CON-002
```

```
REQ-004: CRDT Merge

The system SHALL provide a merge function with the following algebraic properties:
- Commutativity: merge(A, B) == merge(B, A)
- Associativity: merge(merge(A, B), C) == merge(A, merge(B, C))
- Idempotence: merge(A, A) == A

The merge function SHALL accept either a single signed delta or a complete
CRDT state snapshot and produce a new state incorporating both inputs.

Trace:
- TEST-002
- TEST-003
- TEST-005
```

```
REQ-005: Key Rotation

The system SHALL model key rotation as a Max-Register operation on the
activeKey field. The register value is a tuple (seq: u64, key_ref: String).

Resolution rules:
1. Higher seq wins.
2. Equal seq: lexicographically greater BLAKE3 hash of the public key wins.

The system SHALL reject activeKey deltas signed by keys with seq < current
activeKey.seq, UNLESS the delta's seq is strictly greater than the current
activeKey.seq (allowing recovery from a higher-seq rotation).

After rotation, deltas signed by keys with seq < the new activeKey.seq SHALL
be rejected for all fields except activeKey (preserving the recovery path).

Trace:
- TEST-006
- TEST-007
```

```
REQ-006: Revocation

The system SHALL model credential revocation as a G-Set (grow-only set).
Adding a credential identifier to the revocations set SHALL be irreversible.
The system SHALL NOT provide a remove operation on this set.

Trace:
- TEST-008
```

```
REQ-007: Deactivation

The system SHALL model DID deactivation as a Max-Register with domain {0, 1}.
Once set to 1, the system SHALL reject:
- Any delta attempting to set deactivated to 0
- Any delta targeting fields other than deactivated

Trace:
- TEST-009
```

```
REQ-008: Hybrid Logical Clock

The system SHALL use Hybrid Logical Clocks (HLC) for causal ordering.
Each HLC value SHALL be a tuple (physical_ms: u64, logical: u32, node_id: String).

The system SHALL advance the local HLC:
- On every local delta creation: max(local_physical, wall_clock) + increment logical
- On every received delta: max(local, received) + increment logical

LWW-Register conflicts with equal physical_ms and logical SHALL be resolved
by lexicographic comparison of node_id.

Trace:
- TEST-010
```

```
REQ-009: W3C DID Resolution

The system SHALL resolve CRDT state into a W3C DID Core-compliant DID Document
containing:
- @context with did:crdt context URI
- id matching the DID
- verificationMethod array from the G-Set
- authentication array referencing the activeKey
- service array from the OR-Set (if non-empty)
- didDocumentMetadata with created, updated, versionId (BLAKE3 of state)

The resolved document SHALL validate against the DID Core JSON-LD schema.
This forbids duplicate members: a document carrying two `id` values does not
validate, and its meaning would be decided by the consumer's parser rather than
by this system. See BUG-001.

Trace:
- TEST-011
- TEST-025
- TEST-026
- TEST-027
- CON-003
- BUG-001
```

```
REQ-010: Content-Addressed Snapshots

The system SHALL produce a deterministic BLAKE3 hash of the serialised CRDT
state. Two replicas with identical CRDT state SHALL produce identical hashes.

When the "sync" feature is enabled, the system SHALL store snapshots as
content-addressed blobs via iroh-blobs and announce the hash via iroh-gossip.

Trace:
- TEST-012
- CON-004
```

```
REQ-011: Library API

The system SHALL expose a public Rust API that does not require any runtime,
async executor, or network connectivity for core operations (create, merge,
resolve, validate). Networking and persistence SHALL be gated behind optional
Cargo features ("sync", "service", "anchor").

Trace:
- TEST-013
```

```
REQ-012: Service Mode

When compiled with the "service" feature, the system SHALL expose an HTTP API
for DID resolution conforming to the DID Resolution specification
(GET /{did} → DID Document).

The service SHALL accept configuration for:
- Listen address and port
- Peer node addresses for iroh-gossip peering
- Storage path for local CRDT state
- Optional blockchain anchor endpoint

Implementation note (until DHT peer discovery is available per CON-006):
Peer addresses take the form <NodeId>@<ip>:<port> where NodeId is the
iroh public key. DNS hostnames are not resolved. The service prints its
own peer string to stderr at startup so operators can configure static
peering without out-of-band key exchange.
Once CON-006 is implemented: (a) PEERS becomes optional — DhtNode::lookup()
replaces manual configuration; (b) the peer-string startup banner can be
demoted from a required operator step to a diagnostic aid; (c) the
DISABLE_DHT_PUBLISH escape hatch (CON-006 §privacy) becomes the mechanism
for nodes that intentionally opt out of discovery.

Trace:
- TEST-014
- CON-003
```

```
REQ-013: DHT Peer Registration

When compiled with the "sync" feature, a service node that holds a DID SHALL
publish a DHT record advertising its iroh NodeId and direct addresses as a
peer for that DID. Publication SHALL use a keypair derived deterministically
from the DID's method-specific identifier (the BLAKE3-256 hex) as specified
in CON-006, so that any node that knows the DID can locate the record without
out-of-band coordination.

Publication SHALL occur:
- At startup, for every DID already in the local DocStore.
- After a new DID is created (POST /dids) or a delta is accepted that
  creates a new DID entry.
- On a periodic refresh cadence (default: every 60 minutes) to prevent
  DHT records from expiring.

Trace:
- TEST-022
- CON-006
```

```
REQ-014: Cold-Start DID Resolution

When compiled with the "sync" feature, a service node that receives a
resolution request for a DID not present in its local DocStore SHALL:

1. Derive the DHT lookup key from the DID's method-specific identifier
   (CON-006 §keypair derivation).
2. Query the DHT for peer records published under that key.
3. Attempt to connect to at least one returned peer.
4. Request the full delta history via the existing gossip REQUEST protocol
   (empty frontier — CON-004 step 2/3).
5. Bootstrap the local document from the received delta set (CON-006
   §genesis bootstrap).
6. Return the resolved DID document once convergence is reached, or 404
   if no peers are found and a configurable timeout (default: 10 s) elapses.

Cold-start resolution failure (no DHT peers reachable, bootstrap timeout)
SHALL NOT affect resolution of DIDs already held locally.

Trace:
- TEST-023
- CON-006
```

---

```
REQ-015: alsoKnownAs Alias Set

The system SHALL maintain a set of `alsoKnownAs` URIs as a last-writer-wins
register over the WHOLE set, and SHALL project it as the DID Core
`alsoKnownAs` property.

A SetAlsoKnownAs delta SHALL replace the set entirely. An empty vector SHALL
withdraw every alias, and a subsequent delta SHALL be able to reinstate a
previously withdrawn alias.

Two separate facts decide the CRDT, and they are worth keeping apart.

Reinstatement rules OUT a 2P-Set. The alias binding is two-party: the holder
asserts it here and the application publishes the reciprocal record. The
application half is reinstatable, so a 2P-Set -- the shape used for
verification methods -- would make the halves asymmetric, leaving a binding the
holder withdrew permanently unrestorable from one end while restorable from the
other.

The SINGLE-ALIAS shape is what makes a whole-set register admissible rather
than per-element LWW. A whole-set register replaces everything on each write,
so concurrent writes do not union -- the later timestamp wins and the other is
lost. That is acceptable only because the set holds one alias, derived from the
home DID and the account authority: one writer-of-record, one lifecycle, and
"replace the set" and "change the alias" are the same operation. With one
element the two shapes are indistinguishable.

CEILING (SIMPLIFY). A second independently-managed alias breaks this. Two
aliases with separate lifecycles reintroduce lost updates, and the write that
loses may be the one carrying the derived alias the reciprocal binding depends
on. Whole-set replacement assumes read-modify-write, which is the race CRDTs
exist to avoid. The upgrade is per-element LWW keyed on the URI, plus a
per-element delta op -- a whole-set op would have to diff against current state
and so reintroduce the read-modify-write. It also brings tombstones, which
cannot be collected without causal stability this design deliberately lacks.

The cardinality bound in CON-007 is a resource bound against replicated bloat.
It is NOT what keeps the above true: nothing mechanical enforces the
single-alias shape, which is a property of how aliases are minted.

The set SHALL be canonicalised (sorted, deduplicated) before storage, so that
replicas which agree on the aliases agree on the content hash regardless of the
order they were written in.

The alias set SHALL be part of observable state for content-addressing
purposes, so that a change to it moves `versionId`.

Every URI SHALL be recognised in full before any part of the delta is applied,
per CON-007. A delta carrying any unrecognised URI SHALL be rejected whole.

Trace:
- TEST-028
- TEST-029
- TEST-030
- CON-007
```

## 8. Non-Functional Requirements

```
NFR-001: Convergence Latency

Replicas SHALL converge to identical state WITHIN 30 seconds of receiving
the same set of deltas UNDER normal network conditions (< 500ms RTT)
WITH 99th percentile.

Trace:
- TEST-015
- OBS-001
```

```
NFR-002: Offline Tolerance

The system SHALL support unbounded offline operation. A node offline for
any duration SHALL converge to correct state on reconnection by merging
accumulated deltas WITHOUT requiring chain replay, reorg, or coordinator.

Trace:
- TEST-016
```

```
NFR-003: Multi-Device Consistency

Two or more devices sharing the same identity SHALL concurrently update
different fields of the same DID document and converge to a state containing
ALL updates WITH zero data loss.

Trace:
- TEST-017
```

```
NFR-004: Resolution Latency

Local DID resolution (CRDT state → W3C Document) SHALL complete in
≤ 1ms for documents with ≤ 100 verification methods and ≤ 1000 data fields
WITH 99th percentile.

Trace:
- TEST-018
- OBS-002
```

```
NFR-005: Merge Throughput

The merge function SHALL process ≥ 10,000 deltas per second on a single
core (Apple M1 or equivalent) for documents with ≤ 100 fields.

Trace:
- TEST-019
- OBS-003
```

```
NFR-006: Binary Size

The core library (no optional features) SHALL compile to ≤ 2MB static
library on aarch64-apple-darwin, enabling embedding in mobile and WASM targets.

Trace:
- TEST-020
```

```
NFR-007: No Unsafe in Pure Core

The pure core module SHALL contain zero `unsafe` blocks. All unsafe operations
(if any) SHALL be confined to the effectful shell and documented with
SAFETY comments.

Trace:
- TEST-021
```

```
NFR-008: Cold-Start Resolution Latency

When the "sync" feature is enabled and a functional pkarr relay is reachable,
cold-start DID resolution (DHT lookup + peer connection + genesis bootstrap)
SHALL complete in ≤ 15 seconds at the 90th percentile, given that at least
one peer holding the DID is online and responsive.

Cold-start resolution SHALL NOT block or degrade resolution of DIDs already
held locally.

Trace:
- TEST-023
- CON-006
```

---

## 9. Architecture Decision Records

```
ADR-001: Signed CRDTs Over Blockchain Consensus

## Context

DID registries conventionally use blockchain consensus for canonical ordering.
The CALM theorem (Hellerstein & Alvaro, 2019) proves that monotonic programs
admit coordination-free consistent implementations. Analysis shows all DID
operations are monotonic under appropriate CRDT modelling.

## Decision

Use signed CRDTs as the primary consistency mechanism. Blockchain is optional
infrastructure for timestamping, not a correctness requirement.

## Rationale

- CALM provides a formal proof, not a heuristic.
- Signatures provide authorisation. CRDTs provide convergence. Together they
  replace blockchain's bundled authorisation + ordering + convergence.
- Target platforms (iroh, libp2p) already provide content-addressed storage
  and gossip propagation.

## Trade-offs

### Advantages
- Zero transaction fees, zero confirmation delay
- True offline-first and multi-device operation
- Concurrent updates merge, never conflict
- Pure core is independently testable and formally verifiable

### Disadvantages
- No inherent global timestamp (mitigated by optional anchoring)
- Novel method — less ecosystem tooling than did:web or did:key
- Key rotation tiebreaking is deterministic but may surprise users
  expecting "most recent device wins"
- CRDT state grows monotonically — compaction strategy needed

## Status
Proposed.
```

```
ADR-002: Iroh Over IPFS + Hyperswarm

## Context

SPEC-031 assumed IPFS for storage and Hyperswarm for gossip, mirroring
Archon's stack. Iroh started as a Rust IPFS implementation, then narrowed
to a focused P2P content-addressed sync toolkit.

## Decision

Use iroh (iroh-blobs, iroh-gossip, iroh-net) as the single networking and
storage dependency, replacing both IPFS and Hyperswarm.

## Rationale

- Single dependency replaces two (IPFS + Hyperswarm)
- QUIC-based with built-in NAT traversal and hole punching
- Proven at scale: 200k+ concurrent connections, millions of devices
- Content-addressed blobs with BLAKE3 (faster than SHA-256)
- Explicit design philosophy: "we do transport, you bring your CRDT"
- Active Rust-first development by n0-computer

## Trade-offs

### Advantages
- Simpler dependency graph
- Better NAT traversal than raw Hyperswarm
- BLAKE3 is ~10x faster than SHA-256 for hashing
- Rust-native, no FFI boundary

### Disadvantages
- Not IPFS-compatible — can't resolve via IPFS gateways without a bridge
- Smaller ecosystem than IPFS (fewer pinning services, gateways)
- Iroh's API is still evolving (though core is stable)

## Status
Proposed.
```

```
ADR-003: Hybrid Logical Clocks Over Vector Clocks

## Context

LWW-Registers and OR-Sets require causal ordering for deterministic conflict
resolution. Options: Lamport clocks, vector clocks, HLCs.

## Decision

Use Hybrid Logical Clocks.

## Rationale

- Vector clocks grow with number of nodes — unsuitable for open peer networks
- Lamport clocks provide ordering but no wall-clock correlation
- HLCs combine physical time with logical counter: bounded size, monotonic,
  human-readable, debuggable
- Node ID component (signing key hash) provides uniqueness naturally

## Trade-offs

- Depends on loosely synchronised clocks (NTP). Skew > configured threshold
  triggers warning, not failure.
- Less formal literature than vector clocks, though well-established in
  practice (CockroachDB, AntidoteDB).

## Status
Proposed.
```

```
ADR-004: Cargo Feature Gates for Shell Components

## Context

The library serves two audiences: developers embedding DID in their apps
(need pure core only) and operators running a resolver service (need
networking + HTTP). Bundling everything increases binary size and compile
time unnecessarily.

## Decision

Gate all I/O-dependent functionality behind Cargo features:
- Default: pure core only (create, merge, resolve, validate)
- "sync": iroh-based P2P delta propagation and blob storage
- "service": HTTP API for DID resolution
- "anchor": pluggable blockchain timestamping

## Rationale

- Pure core compiles to WASM without modification
- Developers pay only for what they use
- Feature gates enforce the purity boundary at the build system level

## Status
Proposed.
```

```
ADR-005: BLAKE3 Over SHA-256 for Content Addressing

## Context

Content-addressed identifiers require a hash function. IPFS uses SHA-256.
Iroh uses BLAKE3.

## Decision

Use BLAKE3 for all content-addressed hashing (DID identifiers, snapshot
hashes, delta deduplication).

## Rationale

- BLAKE3 is ~10x faster than SHA-256 on modern hardware
- Iroh already uses BLAKE3, avoiding double-hashing
- BLAKE3 produces 256-bit digests (same security level as SHA-256)
- The `blake3` crate is well-audited and maintained

## Trade-offs

- DID identifiers will not be IPFS CIDs — interop requires a mapping layer
- Less ubiquitous than SHA-256 in existing DID tooling

## Status
Proposed.
```

```
ADR-006: pkarr-Derived Keypair for DID-Keyed DHT Discovery

## Context

Cold-start DID resolution requires a mechanism for a node that has never
seen a DID to discover which peers hold it. The paper specifies
"content-addressed routing over the iroh DHT by the DID's BLAKE3 hash"
but iroh 0.21 does not expose a traditional Kademlia DHT. Instead, iroh
uses pkarr (PublicKey Address Record, version 2.x) for node discovery:
nodes publish signed DNS-like records to mainline DHT (BitTorrent DHT) or
an HTTP relay, keyed by an Ed25519 public key.

The challenge: the DID's method-specific identifier is a BLAKE3 hash (32
bytes), not an Ed25519 public key. pkarr requires a genuine keypair for
signing records. Three approaches were evaluated:

A. Add a separate mainline/Kademlia DHT crate (e.g. the `mainline` crate)
   and use the DID hash as the info-hash for raw get_peers/announce_peer
   operations. No new keypair needed; fully decentralised.

B. Derive a deterministic Ed25519 keypair from the DID hash (using a
   domain-separated BLAKE3 hash of the DID bytes as the private key seed)
   and use the existing pkarr 2.x infrastructure (already in the Cargo.lock
   transitively from iroh-net 0.21).

C. Use a rendezvous server or DNS-SD side-channel. Rejected as centralised.

## Decision

Use approach B: a deterministic Ed25519 keypair derived from each DID's
BLAKE3 hash, with pkarr 2.x for publishing and resolution.

Keypair derivation (domain-separated to prevent cross-protocol confusion):
  seed = blake3(b"did-crdt/discovery/v1" || did_hash_bytes)
  (priv, pub) = ed25519::from_seed(seed)

The pkarr record content is a DNS TXT record under the name "_did-crdt",
encoded as one key=value attribute per DNS character string (see CON-006
§publication for the normative format):
  "_did-crdt" IN TXT "v=1" "nid=<iroh-node-id>" ["relay=<url>"] ["addrs=<a>,<b>"]

A node that holds a DID signs and publishes this record using `priv`.
Any node that knows the DID can compute `pub` and query pkarr for it.

### Amendment (2026-06-12): self-contained addressing hints

The original design encoded only the NodeId and relied on iroh's relay
(DERP) infrastructure to dial it. In practice a bare NodeId is not
dialable without a separately configured iroh discovery service, which
would reintroduce a discovery dependency this mechanism exists to remove.
The record therefore carries the publisher's relay URL and direct socket
addresses as *unauthenticated dialing hints*. Trust analysis: the hints
carry no authority — the iroh handshake authenticates the NodeId and the
document is verified end-to-end (CON-006 §genesis bootstrap) — so a forged
hint costs one failed connection attempt. Costs accepted: records can
carry stale addresses until the next refresh cycle, and publishing IP
addresses to a public DHT widens the privacy exposure already noted in
CON-006 §privacy (mitigated by DISABLE_DHT_PUBLISH). The alternative —
configuring iroh's own pkarr-based node discovery and keeping NodeId-only
records — remains viable if the hint staleness proves problematic.

## Rationale

- No new dependency: pkarr 2.3.x is already present (via iroh-net 0.21).
- pkarr 2.x supports both mainline DHT and HTTP relays; the implementation
  can use either without API changes.
- The derived keypair is intentionally public (computable from the DID).
  This is safe because pkarr records are *discovery pointers*, not trust
  anchors — authenticity is established by verifying the actual delta
  signatures, not the pkarr record.
- Multiple nodes holding the same DID can all publish records; pkarr
  merges them by last-write (highest timestamp) per key. The result is
  that the most recently updated holder is found first. This is
  acceptable for discovery.

## Trade-offs

### Advantages
- Zero additional dependencies.
- Consistent with iroh's pkarr-based discovery model.
- The derived "private" key being computable from the DID is a feature,
  not a vulnerability: any holder can register, none has sole authority.

### Disadvantages
- The deterministic private key means anyone can publish a pkarr record
  for a DID they do not hold. Mitigation: the delta signatures on the
  actual document are the real trust anchor; a false DHT pointer leads
  to a failed connection or a wrong document hash, not a security breach.
- pkarr records are eventually consistent with mainline DHT TTLs (~2 h).
  A newly created DID may take O(minutes) to be discoverable cold-start.
- Approach A (raw mainline get_peers) would be marginally more efficient
  for pure lookup (no signing overhead) and is the natural fallback if
  pkarr relay infrastructure becomes unavailable.
- Single-publisher-at-a-time: because all holders derive the same Ed25519
  keypair for a given DID, each DhtNode::publish() call overwrites the
  previous pkarr record for that key (pkarr's last-write semantics apply
  per key, not per node). Only the most recently publishing holder's NodeId
  is discoverable at any given time. If that node goes offline before the
  next 60-minute refresh, the DID becomes temporarily undiscoverable via
  DHT. Approach A (mainline get_peers) supports native multi-value
  responses and would avoid this limitation. The current encoding could be
  extended with multiple "nid=" attributes if a holder aggregates recent
  peer announcements before publishing. See OQ-13.
- Publicly-derivable signing key: any party that knows the DID can
  overwrite the record (single-writer, last-write-wins). This cannot forge
  a document (delta-chain verification) but can censor cold-start
  discovery of a known DID. See CON-006 §genesis bootstrap (security) and
  OQ-14 for the mitigation path (genesis-key-signed pointer payloads;
  announce-set rendezvous via Approach A).

## Status
Accepted. Implemented by CON-006 (with the addressing-hints amendment
above); the original NodeId-only record format was never deployed.
```

---

## 10. Contract Specifications

```
CON-001: Document — Core CRDT API

/// Create a new DID document from a keypair.
fn Document::new(keypair: &Keypair) -> Result<Document, Error>

/// Apply a signed delta to the document state.
/// Returns error if signature invalid or delta rejected.
fn Document::merge(&mut self, delta: &SignedDelta) -> Result<MergeOutcome, MergeError>

/// Merge two document states (state-based CRDT merge).
fn Document::merge_state(&mut self, other: &Document) -> Result<MergeOutcome, MergeError>

/// Resolve current CRDT state to W3C DID Document.
fn Document::resolve(&self) -> DidDocument

/// Serialise CRDT state to bytes (portable, deterministic).
fn Document::to_bytes(&self) -> Vec<u8>

/// Deserialise CRDT state from bytes.
fn Document::from_bytes(bytes: &[u8]) -> Result<Document, DeserializeError>

/// Produce content-addressed hash of current state.
fn Document::content_hash(&self) -> Blake3Hash

Pre-conditions:
- Keypair must be on a supported curve (secp256k1, Ed25519)
- SignedDelta must contain a valid proof

Post-conditions:
- After merge: state includes delta's effect if accepted
- After merge_state: state is the CRDT join of both inputs
- resolve() output validates against DID Core JSON-LD schema

Error model:
- InvalidKeypair: unsupported curve or malformed key
- InvalidSignature: proof does not verify
- DeactivatedDid: document is deactivated, delta rejected
- StaleKeyRotation: activeKey delta seq < current seq
- UnknownDid: delta targets a different DID than this document

Implements:
- REQ-001, REQ-002, REQ-004, REQ-009, REQ-010, REQ-011

Verified by:
- TEST-001 through TEST-013
```

```
CON-002: SignedDelta — Delta Format

/// Create a signed delta for a field update.
fn SignedDelta::new(
    did: &Did,
    field: Field,
    operation: CrdtOp,
    clock: &mut Hlc,
    keypair: &Keypair,
) -> Result<SignedDelta, SignError>

Serialised format (serde, deterministic):
{
  "did":       "did:crdt:<blake3-hash>",
  "field":     "documentData" | "verificationMethods" | "serviceEndpoints"
               | "activeKey" | "revocations" | "deactivated",
  "operation": {
    "type":  "add" | "remove" | "set",
    "value": <field-specific payload>
  },
  "clock":     [<physical_ms>, <logical>, "<node_id>"],
  "proof": {
    "type":              "EcdsaSecp256k1Signature2019" | "Ed25519Signature2020",
    "verificationMethod": "did:crdt:<hash>#key-<n>",
    "created":           "<ISO8601>",
    "proofValue":        "<base64url>"
  }
}

Pre-conditions:
- Keypair must correspond to a key in the target DID's verificationMethods
- Clock must be advanced before signing

Post-conditions:
- Delta is self-contained: can be validated and merged by any node
  holding the target DID's current state
- Serialisation is deterministic (sorted keys, canonical JSON)

Error model:
- SignError::InvalidKeypair: key not on supported curve
- SignError::ClockError: HLC failed to advance (system clock error)

Implements:
- REQ-003, REQ-008

Verified by:
- TEST-004, TEST-010
```

```
CON-003: HTTP Resolution API (feature: "service")

GET /{did}
Accept: application/did+ld+json

Response 200:
Content-Type: application/did+ld+json

{
  "@context": ["https://www.w3.org/ns/did/v1", "https://did-crdt.dev/v1"],
  "id": "did:crdt:<blake3-hash>",
  "verificationMethod": [...],
  "authentication": [...],
  "service": [...],
  "didDocumentMetadata": {
    "created": "<ISO8601>",
    "updated": "<ISO8601>",
    "versionId": "<blake3-hash>",
    "deactivated": false
  }
}

Response 404: DID not found in local state
Response 410: DID deactivated

POST /dids
Content-Type: application/json
Body: { "publicKeyJwk": {...} }

Response 201:
{ "did": "did:crdt:<hash>", "document": {...} }

POST /dids/{did}/deltas
Content-Type: application/json
Body: <SignedDelta>

Response 202: Delta accepted and merged
Response 400: Invalid delta format
Response 403: Signature verification failed
Response 409: Delta rejected (stale rotation, deactivated DID)

Implements:
- REQ-009, REQ-012

Verified by:
- TEST-011, TEST-014
```

```
CON-004: Sync Protocol (feature: "sync")

Message types exchanged via iroh-gossip:

ANNOUNCE { did: Did, hash: Blake3Hash, clock: Hlc }
  — "I have this DID at this state"

REQUEST { did: Did, frontier: Vec<DeltaHash> }
  — "Send me deltas for this DID above this frontier
     (empty frontier = full history; see SPEC-036 REQ-364)"

DELTAS  { did: Did, deltas: Vec<SignedDelta> }
  — "Here are signed deltas for this DID"

(STATE message deliberately absent: full CRDT state is a trusted-domain
 primitive and is not transmitted over untrusted network connections.
 Genesis bootstrap uses the empty-frontier DELTAS path — CON-006.
 See SPEC-036 §11 for the rationale.)

Protocol:
1. On connection: exchange ANNOUNCE for all locally known DIDs
2. On receiving ANNOUNCE with unknown hash: send REQUEST with local frontier
3. On receiving REQUEST: respond with DELTAS for all hashes above the frontier
4. On local delta creation: broadcast ANNOUNCE to all peers
5. Deduplication: track seen (did, hash) pairs, skip known states

Implements:
- REQ-010

Verified by:
- TEST-012, TEST-015
```

```
CON-005: Service-Sync Integration Contract (features: "service" + "sync")

When Server::run() is called:
1. A single DocStore (Arc<Mutex<HashMap<Did, Document>>>) is created and shared
   between AppState and LiveNode — one canonical in-memory store for both the
   HTTP handlers and the gossip sync loop.
2. Server::run() awaits LiveNode::bind(topic, docs.clone(), dht,
   replicate_all), then node.seed() (when no peers configured) or
   node.connect(peer_addr) for each configured peer.
3. LiveNode::spawn() is called; its JoinHandle is held for the process lifetime.
4. On successful Document::merge() in the create_did and submit_delta handlers,
   the handler calls live_node.announce(&did).await (CON-004 step 4), releasing
   the DocStore mutex before the async broadcast.
5. Deltas merged by the sync loop are immediately visible via HTTP resolution
   because both paths share the same DocStore Arc.
6. An empty peers list runs the service in standalone mode (no gossip).

Genesis bootstrap (CON-006): the gossip layer propagates delta updates to DIDs
that peers already hold, and also bootstraps brand-new DIDs on cold nodes —
but only when admitted by CON-006 §admission control: the DID must have a
pending cold-start resolution on this node (the wanted set) or the node must
be in replicate-all mode. When an admitted DELTAS message arrives for an
unknown DID, merge_inbound calls genesis_bootstrap to reconstruct and verify
the document from the full delta set; unsolicited DELTAS for unknown DIDs are
ignored. The previous workaround (requiring operators to POST /dids with the
same key on every node before exchanging deltas) has been removed from
two_node_demo.rs and TEST-015-live. The demo exercises the solicited path
(cold-start resolution); TEST-015-live runs node B in replicate-all mode to
exercise the announce-driven path.

Implements:
- REQ-012 (peer peering config), CON-004 (sync protocol step 4)

Verified by:
- TEST-015-live (tests/integration.rs::live_two_node)
```

```
CON-006: DHT Peer Discovery and Genesis Bootstrap (feature: "sync")

Paper alignment notes (§VI, "Delta Discovery"):

(1) The paper refers to "content-addressed routing over the iroh DHT by the
DID's BLAKE3 hash." CON-006 realises this via pkarr 2.x — the DHT abstraction
iroh exposes — with a deterministic Ed25519 keypair derived from the BLAKE3 hash
as the pkarr record key. See ADR-006 for the rationale (iroh 0.21 does not
expose a traditional Kademlia DHT).

(2) The paper states "genesis authenticity is established by verifying that the
BLAKE3 hash of the received public key matches the DID." This is imprecise:
per the paper's own §IV.A, the DID is BLAKE3-256(canonical_json(τ₀, op₀, key))
— a hash of the full genesis tuple, not of the key alone. CON-006 §genesis
bootstrap implements the correct check: reconstruct the genesis delta locally
from the received key via Document::new(), and verify content_hash() equality,
which re-derives the DID from the full tuple and confirms it matches the claimed
DID. The paper's §VI text has been corrected to be consistent with §IV.A.

Supersedes: the genesis gap workaround documented in CON-005 (requiring
operators to POST /dids with the same key on every node before delta
exchange). The workaround has been removed; CON-005 now defers to this
contract for genesis bootstrap.

── Keypair derivation ────────────────────────────────────────────────────

Given a DID whose method-specific identifier is did_hash (hex, 64 chars):

  discovery_seed = blake3(b"did-crdt/discovery/v1" || hex_decode(did_hash))
  (priv_key, pub_key) = ed25519_keypair_from_seed(discovery_seed)

The derived pub_key is the pkarr record key for that DID.  The priv_key
is deterministically computable by any node holding the DID string; it is
not secret.  Authentication of the actual document comes from the delta
signature chain, not from this keypair.

── Publication ───────────────────────────────────────────────────────────

fn DhtNode::publish(did: &Did, node_addr: &NodeAddr) -> anyhow::Result<bool>

Constructs a pkarr SignedPacket containing a DNS TXT record. The TXT data
consists of one or more DNS character strings, each holding a single
key=value attribute (the standard TXT attribute convention; pkarr's
attributes() parser):

  Name:  "_did-crdt"
  Class: IN
  Type:  TXT
  TTL:   3600
  Data:  "v=1"
         "nid=<iroh_node_id>"
         "relay=<relay_url>"                    (optional)
         "addrs=<sockaddr>[,<sockaddr>...]"     (optional, at most 4)

where <iroh_node_id> is the NodeId formatted as iroh's canonical string
representation (the form produced by iroh_net::NodeId::to_string()), and
relay/addrs carry the publisher's iroh home-relay URL and direct socket
addresses. All implementations MUST use this encoding (multi-string
attributes, these key names) to ensure interoperability.

Addressing hints: relay= and addrs= are UNAUTHENTICATED dialing hints, and
no trust is placed in them. The iroh connection handshake authenticates the
peer's NodeId cryptographically, and document content is authenticated
end-to-end by genesis verification (§genesis bootstrap) plus the delta
signature chain — so a forged or stale hint costs at most a failed
connection attempt, never a forged document. The hints make the record
self-contained: a resolver can dial the publisher directly (or via the
named relay for NAT traversal) without any out-of-band discovery
infrastructure. They can go stale when the publisher's network changes;
the periodic refresh (trigger 3) republishes current addresses. See
ADR-006 §amendment for the design rationale.

TTL note: the TTL field (3600 s) governs how long HTTP pkarr relay caches
serve the record before re-fetching. It is distinct from the mainline
BitTorrent DHT TTL (~2 h, implementation-defined). The 60-minute republication
cadence (trigger 3 below) is chosen to refresh before both TTLs expire.

Signs the packet with priv_key (derived from did_hash), then submits to
the configured pkarr relay (default: https://relay.pkarr.org, configurable
via DHT_RELAY_URL) and/or mainline DHT.

Publication is triggered by:
1. DID first held: when a new DID is created locally (POST /dids succeeds)
   or when a DID is cold-start bootstrapped into DocStore for the first
   time (CON-006 §genesis bootstrap, step 4). These are the first moments
   this node becomes a holder; DhtNode::publish() is called once at that
   point. Idempotent per (did, node_addr) pair: repeat publications of an
   unchanged pair within a dedup window (30 min) are skipped and return
   Ok(false), so active DIDs do not generate excessive DHT writes; a
   changed node_addr publishes immediately. Trigger-1 publication runs in
   the background — it is best-effort and MUST NOT delay the HTTP response
   or server startup.
2. Server startup — one publish call per DID already in the DocStore
   (also in the background; MUST NOT delay readiness).
3. Periodic refresh: a background task republishes every 60 minutes
   (bypassing the trigger-1 dedup window) so records do not expire before
   either TTL. The task re-resolves the node's current address each cycle
   so address changes (DHCP, network moves) propagate rather than
   republishing a stale address indefinitely.

── Lookup ────────────────────────────────────────────────────────────────

fn DhtNode::lookup(did: &Did) -> anyhow::Result<Vec<NodeAddr>>

Derives pub_key from did_hash, calls pkarr_client.resolve(pub_key), and
parses TXT records: the iroh NodeId from the "nid=" field, plus the
unauthenticated dialing hints from "relay=" and "addrs=" (malformed hints
are skipped, not fatal). Returns a list of full NodeAddr values (NodeId +
relay URL + direct addresses) for connection attempts.
Returns an empty Vec when the relay answered but holds no record for this
key. Returns an error when the relay was unreachable or the lookup
exceeded DHT_LOOKUP_TIMEOUT_MS (default 5 s) — callers and operators can
therefore distinguish "no record published" (NoPeersFound) from "discovery
infrastructure down" (DhtUnavailable, §error model).

Operators running private deployments without reachable iroh relays should
ensure nodes have directly-routable addresses (so the addrs= hints
suffice) or configure static PEERS as a fallback.

Single-publisher note: because all holders of a DID derive the same
Ed25519 keypair, each publication overwrites the previous pkarr record
for that key.  The Vec returned by lookup therefore typically contains
one NodeAddr — the most recently publishing holder.  If that node is
offline, the DID is temporarily undiscoverable via DHT until the next
holder republishes.  See ADR-006 §trade-offs and OQ-13.

── Admission control ─────────────────────────────────────────────────────

A node MUST NOT genesis-bootstrap an unknown DID from unsolicited gossip
traffic. Bootstrap is admitted only when:

(a) the DID is SOLICITED — it has a pending cold-start resolution on this
    node. Cold-start registers the DID in a shared "wanted" set before any
    network traffic and withdraws it when the attempt ends (success or
    failure); or
(b) the node runs in REPLICATE-ALL mode (env: REPLICATE_ALL=true) — an
    explicit operator opt-in for dedicated full-replica / archive nodes.

Unsolicited DELTAS for unknown DIDs are silently ignored (DocStore
unchanged), and an ANNOUNCE for an unknown, unadmitted DID is not answered
with a REQUEST — a node never asks for history it would refuse to merge.
This preserves the invariant that a gossip peer can only extend a document
the receiving node already holds or has asked for.

Rationale: anyone can mint a validly-formed genesis document for free
(keygen + one hash). Without this gate, a single peer on the shared topic
could force unbounded document storage onto every node — the storage- and
bandwidth-exhaustion scenario from ADR-003 §context. ADR-003's layered
defences (genesis PoW, gossip-ingress rate limits, invitation codes) are
specified but NOT yet implemented; until they are, admission control is
the primary flood defence, and replicate-all operators knowingly accept
the flood risk.

── Cold-start resolution flow ────────────────────────────────────────────

When a resolve_did HTTP handler receives a request for a DID not in the
local DocStore:

1. Register did in the wanted set (§admission control). The entry is
   withdrawn when the cold-start attempt ends, on every path.
2. Call DhtNode::lookup(did) → [peer_addr, ...].
   (Sub-timeout: DHT_LOOKUP_TIMEOUT_MS, default 5 s.)
3. For each peer_addr (in order), attempt to bootstrap, bounding each
   attempt with a per-peer sub-timeout (4 s) so one dead peer cannot
   consume the whole budget:
   a. Call LiveNode::connect(peer_addr).
   b. Send REQUEST { did, frontier: [] } — empty frontier requests the
      full delta history (CON-004 step 2; SPEC-036 REQ-366 degenerate case).
      Re-broadcast the REQUEST every ~1 s while waiting, in case the first
      send raced the gossip-swarm join and was dropped.
   c. Await a DELTAS response and run genesis bootstrap (§genesis bootstrap).
      The received DELTAS batch is a Causal-Closure Bundle per SPEC-036 REQ-365,
      topologically sorted; the causal merge path (step 5 of §genesis bootstrap)
      handles any misordering defensively via its existing retry loop.
   d. On success: the DID is now in DocStore; proceed to step 5.
   e. On failure (connection refused, sub-timeout elapsed, or
      BootstrapFailed / PartialHistory error): record the failure and try
      the next peer_addr.
4. If the lookup found no peers, errored, or all peer attempts failed,
   and budget remains: pause briefly (~500 ms) and retry from step 2.
   Retrying the lookup covers a freshly created DID whose background DHT
   publication (§publication trigger 1) races the first resolve, and
   transient relay failures.
5. Resolve and return the document once the DID appears in DocStore.
   Return 404 if RESOLVE_TIMEOUT_MS (default: 10 s, total budget for
   steps 1–4) elapses first, logging the last recorded failure.
   Cold-start failure SHALL NOT affect resolution of DIDs already held locally.

Timeout budget: RESOLVE_TIMEOUT_MS bounds the whole flow;
DHT_LOOKUP_TIMEOUT_MS bounds each lookup inside it (both configurable via
env). The fixed per-peer sub-timeout (4 s) bounds each connect +
REQUEST/DELTAS attempt so that, within the default 10 s budget, at least
two peer attempts (or lookup retry rounds) are possible.

── Genesis bootstrap (extension to merge_inbound) ────────────────────────

When merge_inbound receives a DELTAS message for a DID not in DocStore,
and the DID is admitted by §admission control (otherwise the message is
ignored and DocStore is unchanged):

1. Find the genesis delta: the unique delta in the set with an empty
   parents list.
   - If none is present, return PartialHistory — partial histories cannot
     bootstrap a document.
   - If more than one delta has an empty parents list, return BootstrapFailed
     — a valid DID has exactly one genesis delta; multiple genesis-like deltas
     indicate a malformed or malicious batch.
2. Extract the public key: the genesis delta's op MUST be
   AddVerificationMethod { public_key_multibase, .. }.  Any other op
   type is invalid for a genesis delta; return BootstrapFailed.
3. Reconstruct and verify: call Document::new(public_key_multibase)
   locally.  This deterministically produces (reconstructed_doc,
   computed_genesis_delta).  Verify:
     a. reconstructed_doc.did == DELTAS.did
        (the DID hash binds the full genesis tuple — wrong key → wrong DID)
     b. computed_genesis_delta.content_hash() == received_genesis.content_hash()
        (proves the received genesis delta is authentic for this DID)
   If either check fails, return BootstrapFailed and discard the entire batch.
4. Insert reconstructed_doc into DocStore.  This is also the moment
   DhtNode::publish() is called (CON-006 §publication trigger 1), since
   the node is now a holder of this DID for the first time.
   If publish() fails (relay unreachable, network error), the DocStore
   insertion is NOT rolled back — the document is retained, and the
   server-startup trigger (trigger 2) and periodic refresh (trigger 3) will
   eventually publish the DHT record.  A publish failure here is logged as a
   warning but does not fail the bootstrap.
   SPEC-034 note: once SQLite persistence is implemented, this insertion must
   go through the SPEC-034 DocStore write path rather than the raw in-memory
   HashMap, so that the on-insert publish hook fires correctly.
5. Apply all remaining deltas from the batch via the normal causal merge
   path (merge_inbound's existing retry loop).

Security: checks (a) and (b) ensure that a malicious peer cannot inject a
document for a DID it does not control.  The DID hash commits to the full
genesis tuple (τ₀, op₀, key), not to the key alone; the public key anchors
all subsequent delta signatures.  No trusted state is transmitted — only
signed deltas.  §admission control bounds the resource cost: integrity
checks reject forged documents, admission control rejects unsolicited
valid ones.

Discovery-layer availability limitation: the pkarr keypair is derived from
the public DID string, so it is computable by anyone — including
non-holders. Two consequences must be distinguished:
- Redirection (record points at a malicious or dead node): cannot forge a
  document — genesis verification plus the signature chain reject anything
  the true controller did not author. Costs a failed connection attempt.
- Erasure / censorship: an adversary who knows a DID can continuously
  overwrite its single-writer pkarr record, suppressing cold-start
  discovery of that DID. This is a publish-rate race the defender cannot
  reliably win. It affects FIRST CONTACT only — nodes already holding the
  document, in the gossip mesh, or with static PEERS are unaffected, and
  document integrity is never at risk.
Mitigations (future work, see OQ-14): (i) sign the pointer payload
(nid/relay/addrs + a freshness timestamp) with the genesis key, so
resolvers reject pointers the DID's controller did not authorise —
prevents redirection but not erasure; (ii) an announce-set rendezvous over
mainline DHT get_peers/announce_peer keyed by the DID hash, where many
announcers coexist and honest entries cannot be erased — degrades the
attack from censorship to noise. The trade-off is inherent to rendezvous
keys publicly derivable from the identifier alone: the DID is a hash, so
no controller key is knowable before bootstrap.

Limitation: the causal merge path (step 5) has a known op-replay gap for
concurrent add/remove of service endpoints — a RemoveServiceEndpoint delta
replays against the receiver's current state rather than its original
observed ORSWOT context (SPEC-036 §11, op-replay remove-context gap).
This is a pre-existing limitation of the op-replay path, not specific to
genesis bootstrap.

── Error model ───────────────────────────────────────────────────────────

- DhtUnavailable: pkarr relay unreachable or lookup timed out — surfaced
  as a lookup *error*, distinct from an empty result, so logs distinguish
  a dead relay from an unpublished DID.  Cold-start retries within the
  budget (§cold-start step 4); resolution returns 404 after timeout.
- NoPeersFound: relay answered but holds no record for this DID hash —
  surfaced as an empty lookup result.  Cold-start retries within the
  budget; resolution returns 404 after timeout.
- BootstrapFailed: received DELTAS but genesis verification failed — checks
  (a) or (b) did not pass, the genesis delta's op was not AddVerificationMethod,
  or more than one genesis-like delta was present.  Log the failure, discard
  the batch, try the next peer.
- PartialHistory: DELTAS received but no genesis delta present (empty parents
  list absent).  Discard; try the next peer or wait for a subsequent ANNOUNCE
  cycle.

Not an error: unsolicited DELTAS for an unknown DID (§admission control)
is ignored silently — logging it would let a flood fill the logs.

── Privacy note ──────────────────────────────────────────────────────────

Publishing a DID→NodeId mapping to a public DHT reveals that this node
holds the DID — and, with the relay/addrs hints, the node's relay home and
IP addresses.  Operators with privacy requirements may disable DHT
publication (DISABLE_DHT_PUBLISH=true) and rely on manual PEERS
configuration or in-network gossip propagation only.  See OQ-11 for a more
principled privacy model.

── Pre-conditions ────────────────────────────────────────────────────────

- did is a valid did:crdt identifier (did:crdt:<64-hex-chars>).
- DhtNode is initialised with a reachable pkarr relay endpoint and/or a
  mainline DHT client.
- For genesis bootstrap: the caller has already received a DELTAS batch
  containing at least one delta for a DID not present in DocStore, and the
  DID is admitted by §admission control (wanted set or replicate-all).

── Post-conditions ───────────────────────────────────────────────────────

publish():
- Returns Ok(true): a pkarr SignedPacket for pub_key(did) is stored at the
  relay advertising this node's NodeId and addressing hints.
- Returns Ok(false): an identical (did, node_addr) record was already
  published within the dedup window; nothing was sent.
- Failure is non-fatal (see §genesis bootstrap step 4 and §publication
  trigger 3).

lookup():
- Returns a (possibly empty) Vec<NodeAddr> — NodeId plus relay/addrs hints
  — of nodes known to hold the DID.  An empty Vec means the relay holds no
  record (NoPeersFound); infrastructure failures are errors, not empty
  results (§error model).

genesis bootstrap:
- On success: reconstructed_doc is in DocStore and DhtNode::publish() has
  been called.  All remaining deltas in the batch have been submitted to
  merge_inbound's retry loop.
- On PartialHistory or BootstrapFailed: DocStore is unchanged.

Implements:
- REQ-013, REQ-014
- Permanent fix for genesis gap documented in CON-005.

Verified by:
- TEST-022, TEST-023, TEST-024
```

---

```
CON-007: alsoKnownAs URI Set — Recogniser

/// Recognise an alsoKnownAs URI set before any of it is applied.
fn validate::recognise_also_known_as(uris: &[String]) -> Result<()>

Grammar (ABNF), deliberately narrower than RFC 3986:

  set     = 0*32( uri )                     ; distinct, each 1..=512 bytes
  uri     = scheme ":" 1*( %x21-7E )        ; no space, no control characters
  scheme  = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )

Pre-conditions:
- None. This is a total recogniser over arbitrary input, and is the trust
  boundary for this field.

Post-conditions:
- Ok(()) implies every entry is an absolute URI of printable ASCII, the set is
  within its cardinality bound, and no entry exceeds its length bound.
- Err implies NO part of the delta has been applied. Recognition happens in
  Document::merge before apply_op, so a set containing one bad entry rejects
  the whole delta rather than admitting the good entries.

Error model:
- DeltaRejected: cardinality bound exceeded, entry length outside 1..=512,
  missing or malformed scheme, or an empty / non-printable body.

Why narrower than RFC 3986. These strings are republished by verifiers into
documents consumed by software this project does not control. The recogniser
therefore fails closed: it admits the absolute-URI forms the binding actually
uses (acct:, https:, did:) and refuses anything it cannot classify, rather than
accepting whatever a permissive parser happens to tolerate. Widening the
grammar later is a compatible change; narrowing it would not be.

Rejecting relative references is the substantive restriction. An alias is a
claim about an identity somewhere else, and a relative reference has no meaning
without a base the document does not carry.

The bounds are bounds, not considered maxima: the set is replicated to every
peer holding the DID, so an unbounded list is a cheap way to make other people
store data.

Implements:
- REQ-015
```

## 11. Test Specifications

### Property-Based Tests (Pure Core)

```
TEST-001: DID Creation Determinism

Property: For all keypairs K, Document::new(K).content_hash() is deterministic.
Generator: Random secp256k1 and Ed25519 keypairs.
Assertion: Two calls with the same keypair produce the same hash.

Verifies: REQ-001
```

```
TEST-002: Merge Commutativity

Property: For all document states A, B derived from the same DID,
  merge(A, B) == merge(B, A).
Generator: Random sequences of 1-50 signed deltas, split into two
  subsets applied in different orders.
Assertion: Final states are byte-identical.

Verifies: REQ-002, REQ-004
```

```
TEST-003: Merge Associativity

Property: For all delta sets X, Y, Z,
  merge(merge(X, Y), Z) == merge(X, merge(Y, Z)).
Generator: Three random delta sets (5-20 deltas each).
Assertion: Final states are byte-identical.

Verifies: REQ-002, REQ-004
```

```
TEST-004: Signature Rejection

Scenario:
1. Create DID D with key K1.
2. Generate delta for D signed by unrelated key K_attacker.
3. Call document.merge(delta).
4. Assert: returns Err(InvalidSignature).
5. Assert: document state unchanged.

Verifies: REQ-003
```

```
TEST-005: Merge Idempotence

Property: For all document states S and deltas D,
  merge(merge(S, D), D) == merge(S, D).
Generator: Random documents with 1-100 applied deltas.
Assertion: Re-applying any delta does not change state.

Verifies: REQ-004
```

```
TEST-006: Key Rotation Convergence

Property: For all pairs of concurrent rotations (K1→K2, K1→K3) at same seq,
  the tiebreak produces the same winner regardless of merge order.
Generator: Random keypair triples.
Assertion:
  - merge(rotate_to_K2, rotate_to_K3) == merge(rotate_to_K3, rotate_to_K2)
  - Winner is determined by BLAKE3 hash comparison.

Verifies: REQ-005
```

```
TEST-007: Stale Rotation Rejection

Scenario:
1. Create DID D with K1 (seq=1).
2. Rotate to K2 (seq=2), signed by K1.
3. Attempt rotation to K3 (seq=1), signed by K1.
4. Assert: rejected (seq ≤ current active seq).

Verifies: REQ-005
```

```
TEST-008: Revocation Monotonicity

Property: For all document states S and credential ID C,
  if C ∈ S.revocations, then for all deltas D,
  C ∈ merge(S, D).revocations.
Generator: Random documents with 1-50 revocations, random deltas.
Assertion: Revoked credentials never leave the set.

Verifies: REQ-006
```

```
TEST-009: Deactivation Irreversibility

Scenario:
1. Create DID D. Deactivate.
2. Generate delta setting deactivated = 0.
3. Assert: rejected.
4. Generate delta updating documentData.
5. Assert: rejected with DeactivatedDid error.

Verifies: REQ-007
```

```
TEST-010: HLC Monotonicity

Property: For all sequences of local operations and received deltas,
  the local HLC is strictly monotonically increasing.
Generator: Interleaved local operations and received deltas with
  random physical timestamps (including past, present, future).
Assertion: Each successive HLC value > previous.

Verifies: REQ-008
```

```
TEST-011: W3C DID Document Validity

Property: For all valid document states S, resolve(S) produces a
  JSON-LD document that validates against the DID Core schema.
Generator: Random documents with 0-50 verification methods,
  0-20 service endpoints, 0-100 data fields.
Assertion: JSON-LD validates. Required fields present. @context correct.

Verifies: REQ-009
```

```
TEST-012: Snapshot Determinism

Property: For all delta sets S, two replicas that have merged the same
  set of deltas produce identical content_hash() values.
Generator: Random delta sets (10-100 deltas), applied in random orders
  to two independent Document instances.
Assertion: content_hash() values are identical.

Verifies: REQ-010
```

```
TEST-013: Pure Core No-IO

Verification: Static analysis / compilation test.
Compile the pure core module with #![no_std] (or verify no imports from
std::fs, std::net, std::io, tokio, iroh).
Assertion: Compilation succeeds without I/O imports.

Verifies: REQ-011
```

### Integration Tests

```
TEST-014: HTTP Resolution Endpoint

Scenario:
1. Start service on localhost:0 (random port).
2. POST /dids with a public key → 201, receive DID.
3. GET /{did} → 200, receive valid DID Document.
4. POST /dids/{did}/deltas with valid signed delta → 202.
5. GET /{did} → 200, document reflects delta.
6. GET /nonexistent → 404.

Verifies: REQ-012
```

```
TEST-015: Two-Node Gossip Convergence (in-process simulation)

Scenario:
1. Create two Document instances sharing the same DID.
2. Apply deltas to node A.
3. Merge A's state into B via Document::merge_state().
4. Apply further deltas to B.
5. Merge B's state back into A.
6. Assert: both nodes have identical resolved DID documents.

Implementation: tests/integration.rs::two_node (in-process, no real network)
Verifies: NFR-001 (CRDT convergence guarantee)
```

```
TEST-015-live: Two-Node Live Transport Convergence (CON-005)

Scenario:
1. Create the genesis DID on node A only (POST /dids). Node B starts with
   an empty DocStore in replicate-all mode (REPLICATE_ALL=true) and
   bootstraps automatically when node A announces the updated state over
   gossip (CON-006 genesis bootstrap via the announce-driven path; the
   solicited cold-start path is covered by TEST-023, and the
   unsolicited-ignored default by TEST-024 scenario E).
2. Connect them via live iroh-gossip.
3. POST a signed delta to node A via HTTP.
4. Assert node A accepts the delta (202).
5. Poll node B's HTTP endpoint until its versionId matches node A's.
6. Assert convergence within 20 seconds.

Implementation: tests/integration.rs::live_two_node (real iroh endpoints + HTTP)
Verifies: CON-005, NFR-001
```

```
TEST-016: Offline Reunion

Scenario:
1. Create DID D on nodes A and B.
2. Partition (disconnect peers).
3. Node A: apply 50 random deltas.
4. Node B: apply 30 random deltas (different fields).
5. Reconnect.
6. Wait for convergence.
7. Assert: both nodes have identical state.
8. Assert: state contains effects of all 80 deltas.

Verifies: NFR-002
```

```
TEST-017: Multi-Device Concurrent Group Update

Scenario:
1. Create DID D.
2. Device A: set documentData["members"] = ["alice"]
3. Device B: set documentData["endpoint"] = "https://example.com"
   (concurrent, no sync between steps 2 and 3)
4. Sync.
5. Assert: both devices have both "members" and "endpoint" in documentData.

Verifies: NFR-003
```

### Performance Tests

```
TEST-018: Resolution Latency Benchmark

Setup: Document with 100 verification methods, 1000 data fields.
Measure: Time for document.resolve() over 10,000 iterations.
Assert: p99 ≤ 1ms.

Verifies: NFR-004
```

```
TEST-019: Merge Throughput Benchmark

Setup: Document with 100 fields.
Measure: Time to merge 10,000 sequential deltas.
Assert: ≥ 10,000 deltas/second on single core.

Verifies: NFR-005
```

```
TEST-020: Binary Size Check

Setup: Compile with default features (pure core only), release mode,
  target aarch64-apple-darwin.
Measure: Size of libdid_crdt.a.
Assert: ≤ 2MB.

Verifies: NFR-006
```

```
TEST-021: No Unsafe in Pure Core

Setup: Run `cargo clippy` with `#[forbid(unsafe_code)]` on pure core module.
Assert: Zero violations.

Verifies: NFR-007
```

```
TEST-022: DHT Publication and Lookup (unit / integration)

Scenario:
1. Start a service node (features: service + sync) and create a DID via
   POST /dids.
2. Assert that DhtNode::publish() is called for the new DID (spy/mock on
   the pkarr client, or use a local pkarr relay for integration testing).
3. Call DhtNode::lookup(did) and assert it returns at least one NodeAddr
   containing the publishing node's iroh NodeId.
4. Verify the pkarr record's TXT value parses as "v=1;nid=<node_id>".

Verifies: REQ-013, CON-006 §publication
```

```
TEST-023: Cold-Start Convergence via DHT

Scenario:
1. Start node A with features: service + sync (no PEERS configured).
   Node A creates DID D and publishes to the in-process pkarr relay stub.
2. Start node B with features: service + sync (no PEERS configured,
   same in-process relay stub).  Node B has an empty DocStore.
3. Submit a GET /{D} to node B.
4. Assert: node B performs a DHT lookup, discovers node A, connects,
   requests the full delta history, and bootstraps the document.
5. Assert: the GET response on node B returns a valid DID document
   matching node A's resolved document (same versionId).
6. Assert: the round-trip completes within 15 seconds (NFR-008).

Implementation: uses an in-process pkarr relay stub (a thin in-memory
map from pub_key → SignedPacket, injected via the DhtNode constructor)
to avoid dependence on external infrastructure or network in CI.

Verifies: REQ-014, NFR-008, CON-006 §cold-start resolution, CON-006 §genesis bootstrap
```

```
TEST-024: Genesis Bootstrap Failure and Admission Cases (unit)

Covers the BootstrapFailed / PartialHistory paths and the admission-control
gate in CON-006.

Scenario A — PartialHistory (no genesis delta):
1. Construct a DELTAS batch for an unknown DID containing three deltas, none
   with an empty parents list (all reference prior deltas not in the batch).
2. Feed the batch to merge_inbound (DID admitted).
3. Assert: returns PartialHistory.  DocStore unchanged.

Scenario B — BootstrapFailed (multiple genesis-like deltas):
1. Construct a DELTAS batch containing two deltas both with parents == [].
2. Feed the batch to merge_inbound for an unknown, admitted DID.
3. Assert: returns BootstrapFailed.  DocStore unchanged.

Scenario C — BootstrapFailed (wrong key):
1. Create a legitimate DID D with key K.
2. Construct a DELTAS batch claiming DID D but replacing the genesis delta's
   key with an unrelated key K2.
3. Feed the batch to merge_inbound (DID admitted).
4. Assert: returns BootstrapFailed (check (a) fails — the DID re-derived
   from K2 cannot match D; a wrong key can never reach check (b)).
   DocStore unchanged.

Scenario D — BootstrapFailed (wrong genesis op type):
1. Construct a genesis delta (parents == []) whose op is not
   AddVerificationMethod.
2. Feed a DELTAS batch containing this delta for an unknown, admitted DID.
3. Assert: returns BootstrapFailed.  DocStore unchanged.

Scenario E — IgnoredUnsolicited (admission control):
1. Construct a perfectly VALID DELTAS batch (genuine genesis) for an
   unknown DID.
2. Feed it to merge_inbound with the default policy (no pending cold-start
   request, replicate-all off). Also feed the same batch with (a) the DID
   in the wanted set and (b) replicate-all on.
3. Assert: default policy → ignored, DocStore unchanged; wanted or
   replicate-all → bootstrapped, DID in DocStore.
   Also assert at the routing layer (GossipState::handle): an ANNOUNCE for
   an unknown DID produces a full-history REQUEST only when the DID is
   wanted or replicate-all is on; otherwise no outgoing message.

Scenario F — BootstrapFailed (tampered genesis metadata; check (b) proper):
1. Construct a genesis-like delta for DID D with the CORRECT key K but a
   tampered field that check (a) cannot see — e.g. a non-zero genesis
   timestamp.
2. Feed the batch to merge_inbound (DID admitted).
3. Assert: returns BootstrapFailed via check (b) — the content hash covers
   the full genesis tuple, catching tampering the key check passes.
   DocStore unchanged.

Implementation: all scenarios use in-process delta construction; no network
or DHT infrastructure required.

Verifies: CON-006 §genesis bootstrap (error paths), CON-006 §error model,
CON-006 §admission control
```

---

```
TEST-025: Reserved documentData Keys Refused at Admission (unit)

Regression cover for BUG-001, admission direction.

1. Create a document and, for EVERY name in the reserved DID Core property set,
   submit a signed SetDocumentData delta using that name as its key.
2. Assert: each is rejected as DeltaRejected, and none enters the delta log.

Iterating the whole reserved set rather than a sample is deliberate: a name
added to the set later without a matching guard would otherwise pass unnoticed.
```

```
TEST-026: State-Borne Reserved Key Cannot Shadow id (unit)

Regression cover for BUG-001, projection direction. Admission-time rejection is
not sufficient on its own, because state-based merge unions documentData
wholesale without passing through delta admission.

1. Create a document, then insert a documentData entry named `id` DIRECTLY into
   state, modelling what arrives from a peer running pre-fix code.
2. Resolve, serialise, and re-parse the document.
3. Assert: the parsed id is the document's real DID, and exactly one top-level
   id member was emitted.

The assertion is made after a serialise/parse round trip on purpose. The defect
does not exist in the struct -- it exists only once the document is written out,
and it is the consumer's parse that decides which member wins.
```

```
TEST-027: Injected verificationMethod Cannot Outlive Its Revoked Key (unit)

Regression cover for BUG-001's most serious consequence: authentication
material persisting past revocation of the key that introduced it.

1. Create a document with genesis key K0; add a second key K1.
2. K1 submits a SetDocumentData delta setting `verificationMethod` to an array
   containing an attacker-chosen method.
3. Assert: the delta is rejected.
4. Revoke K1, and assert the revocation took effect.
5. Resolve, serialise, re-parse.
6. Assert: verificationMethod contains exactly the genuine K0 entry, and no
   injected entry.

Step 3 is the fix; steps 4-6 assert the property the fix protects. Before the
fix, step 2 succeeded and step 6 saw ONLY the injected array.
```

```
TEST-028: alsoKnownAs Recogniser (unit)

Covers CON-007 in both directions.

Refusal — each of these is submitted as a single-entry set and MUST be
rejected, with the document's alias set left empty:
1. empty string
2. `hugo@chat.anuna.io` (a bare handle — no scheme)
3. `/relative/path` (relative reference)
4. `1nvalid:x` (scheme does not start with a letter)
5. `acct:` (empty body)
6. `acct:hugo chat` (space)
7. `acct:hugo<DEL>x` and `acct:hugo<LF>x` (non-printable)

Whole-delta refusal:
8. `["acct:ok@x.io", "no-scheme"]` — rejected entirely; the well-formed entry
   MUST NOT be admitted on its own.

Bounds:
9. A set of MAX_ALSO_KNOWN_AS + 1 entries is rejected.
10. A single entry longer than MAX_ALSO_KNOWN_AS_URI_LEN is rejected.

Acceptance — the forms the binding actually uses MUST pass, or the refusal
cases above prove only that everything is rejected:
11. `acct:hugo@chat.anuna.io`, `https://chat.anuna.io/u/hugo`, `did:crdt:...`
```

```
TEST-029: alsoKnownAs LWW Semantics (unit)

Covers the register behaviour REQ-015 requires, including the property that
motivated choosing a register over a 2P-Set.

Scenario A — withdrawal and reinstatement:
1. Set alias A at t=10; assert present.
2. Set the empty set at t=20; assert withdrawn.
3. Set alias A again at t=30; assert present.

Step 3 is the one a 2P-Set could not satisfy.

Scenario B — a stale write must not resurrect a withdrawal:
1. Set alias A at t=20, then the empty set at t=30.
2. Deliver a Set of [A] stamped t=10 (out-of-order arrival).
3. Assert: the alias set is still empty.

LWW is only safe here if a delta that merely arrived later, but is stamped
earlier, loses. A withdrawal that could be undone by out-of-order delivery
would make withdrawal unreliable, and withdrawal is the half of the binding
that carries the security weight.
```

```
TEST-030: alsoKnownAs Projection and Convergence (unit)

1. Typed projection: after setting one alias, the resolved document's
   alsoKnownAs equals it, the serialised JSON contains EXACTLY ONE alsoKnownAs
   member, and re-parsing yields the alias. (The single-member assertion is the
   regression guard against BUG-001's duplicate-member failure, which is how
   this property behaved before it was typed.)
2. Empty is absent: with no aliases set, the serialised document has no
   alsoKnownAs member at all, rather than an empty array.
3. Canonicalisation: two replicas that write the same aliases in different
   orders, one with a duplicate entry, reach an identical alias set AND an
   identical content_hash.
4. versionId moves: setting an alias changes the resolved
   didDocumentMetadata.versionId. Without this the alias set would be outside
   observable state and a consumer caching on versionId would never observe a
   withdrawal.
```

## 12. Purity Boundary Map

### Pure Core (no I/O, no shared state, deterministic)

- **`document.rs`**: `Document` struct — composite CRDT state, `new()`, `merge()`, `merge_state()`, `resolve()`, `content_hash()`, `to_bytes()`, `from_bytes()`
- **`crdt.rs`**: CRDT field wrappers — thin typed wrappers over `crdts::GSet`, `crdts::Orswot`, `crdts::LWWReg`, `crdts::Map`; enforce DID-specific invariants (e.g., deactivation latch, rotation seq check)
- **`delta.rs`**: `SignedDelta` construction and serialisation — deterministic canonical JSON, signature computation
- **`validate.rs`**: Delta validation — signature verification via `ssi`, authorisation rules (seq check, deactivation check)
- **`hlc.rs`**: Hybrid Logical Clock — advance, compare, serialise (wall-clock read is injected, not called)
- **`resolve.rs`**: CRDT state → W3C DID Document materialisation — pure transformation, no I/O
- **`did.rs`**: DID identifier type — `did:crdt:<blake3-hash>`, parsing, display

### Effectful Shell (orchestrates I/O, calls pure core)

- **`store.rs`** (feature: "sync"): Persist and retrieve `Document` state via iroh-blobs; pin content-addressed snapshots
- **`sync.rs`** (feature: "sync"): iroh-gossip integration; send/receive deltas and announcements; manage peer connections
- **`service.rs`** (feature: "service"): Axum HTTP server; DID resolution endpoint; delta submission endpoint; metrics endpoint
- **`anchor.rs`** (feature: "anchor"): Pluggable blockchain timestamping trait and implementations
- **`clock_source.rs`**: System clock provider injected into HLC (the only I/O dependency of the clock)

### Boundary Contracts

- `SignedDelta` → Pure Core (validation + merge)
- `Document` (serialised bytes) → Effectful Shell (storage + gossip)
- `Hlc` → crosses both (pure advancement logic, effectful time source injection)
- `DidDocument` (W3C JSON-LD) → Effectful Shell (HTTP response serialisation)

### Dependency Rule

Dependencies point inward: shell → core. Core MUST NOT import from shell. The pure core MUST NOT depend on `tokio`, `iroh`, `axum`, or any async runtime.

### Enforcement

- `#[forbid(unsafe_code)]` on the pure core module
- Feature gates at the Cargo.toml level ensure shell dependencies are not compiled unless opted in
- CI check: `cargo build --no-default-features` compiles the pure core in isolation
- Module visibility: pure core is `pub`, shell modules are `pub(crate)` or feature-gated `pub`

---

## 13. Verification Strategy

| Component | Technique | Rationale |
|---|---|---|
| CRDT merge functions | Property-based testing (proptest) | Algebraic properties (commutativity, associativity, idempotence) are natural proptest properties. Generator produces random delta sequences; property asserts convergence regardless of ordering. |
| Signature validation | Example-based testing + fuzzing (cargo-fuzz) | Known-good and known-bad signatures as examples. Fuzz the delta format to verify rejection of malformed inputs at the trust boundary. |
| HLC ordering | Property-based testing | Property: for all event pairs, if A causally precedes B then HLC(A) < HLC(B). Monotonicity under adversarial clock skew. |
| Key rotation tiebreaking | Property-based testing | Property: for all concurrent rotation pairs, tiebreak is deterministic and commutative. |
| Snapshot determinism | Property-based testing | Property: for all delta sets S, to_bytes(merge(S)) is identical regardless of merge order. |
| W3C compliance | Example-based testing | Resolve known document states and validate against DID Core JSON-LD schema. |
| HTTP API | Integration testing | Spin up service, exercise endpoints, verify response codes and bodies. |
| Gossip convergence | Integration testing | Multi-node cluster with simulated partitions and reconnection. |
| Performance | Benchmark testing (criterion) | Resolution latency, merge throughput, binary size. |
| Purity enforcement | Static analysis | `#[forbid(unsafe_code)]`, no-std compilation check, module import analysis. |

---

## 14. Observability

```
OBS-001: Convergence Latency

Metric: Histogram — time from delta creation to all-replica convergence.
Labels: delta_field (verificationMethods, documentData, activeKey, etc.)
Alert: p99 > 30s sustained for 5 minutes.
Dashboard: convergence latency distribution over time.
```

```
OBS-002: Resolution Latency

Metric: Histogram — time for resolve() call.
Labels: document_size_bucket (small < 10 fields, medium < 100, large < 1000).
Alert: p99 > 5ms.
Dashboard: resolution latency by document size.
```

```
OBS-003: Merge Throughput

Metric: Counter — deltas merged per second.
Labels: outcome (accepted, rejected, deduplicated).
Dashboard: merge rate and rejection ratio over time.
```

```
OBS-004: Delta Rejection Rate

Metric: Counter — rejected deltas by reason.
Labels: reason (invalid_signature, deactivated_did, stale_rotation, unknown_did).
Alert: invalid_signature rate > 10/minute (potential attack or misconfiguration).
```

```
OBS-005: Peer Count

Metric: Gauge — number of connected iroh-gossip peers.
Alert: peer_count == 0 sustained for 5 minutes (node is isolated).
Dashboard: peer connectivity over time.

Note (CON-006): once DHT discovery is implemented, peers are added
dynamically as DhtNode::lookup() resolves holders of known DIDs. The
alert threshold and isolation semantics remain valid, but the expected
steady-state peer count will increase from the number of manually
configured PEERS to the union of all DHT-discovered peer addresses.
OBS-005 label cardinality may also grow; consider adding a
discovery_source label (static | dht) when CON-006 is landed.
```

```
OBS-006: State Size

Metric: Gauge — serialised CRDT state size in bytes per DID.
Labels: did (truncated hash).
Alert: any single DID state > 10MB (possible abuse or compaction needed).
Dashboard: state size distribution.
```

---

## 15. Traceability Matrix

```
REQ-001 (DID Creation)         → TEST-001          → document.rs      → (no OBS — local only)
REQ-002 (CRDT Document Model)  → TEST-002, TEST-003 → crdt.rs          → OBS-003
REQ-003 (Signed Delta)         → TEST-004          → delta.rs, validate.rs → OBS-004
REQ-004 (CRDT Merge)           → TEST-002, TEST-003, TEST-005 → document.rs → OBS-003
REQ-005 (Key Rotation)         → TEST-006, TEST-007 → crdt.rs          → OBS-004 (stale_rotation)
REQ-006 (Revocation)           → TEST-008          → crdt.rs          → OBS-003
REQ-007 (Deactivation)         → TEST-009          → crdt.rs          → OBS-004 (deactivated_did)
REQ-008 (HLC)                  → TEST-010          → hlc.rs           → (no OBS — internal)
REQ-009 (W3C Resolution)       → TEST-011, TEST-025, TEST-026, TEST-027 → resolve.rs, document.rs → OBS-002, OBS-004
REQ-010 (Content-Addressed)    → TEST-012          → document.rs, store.rs → OBS-006
REQ-011 (Library API)          → TEST-013          → lib.rs           → (no OBS — compile-time)
REQ-012 (Service Mode)         → TEST-014          → service.rs       → OBS-002, OBS-005
REQ-013 (DHT Registration)     → TEST-022          → sync/dht.rs      → OBS-005
REQ-014 (Cold-Start Resolution)→ TEST-023          → sync/dht.rs, sync/live.rs → OBS-005
REQ-015 (alsoKnownAs)          → TEST-028, TEST-029, TEST-030 → crdt.rs, validate.rs, document.rs → OBS-004

NFR-001 (Convergence Latency)  → TEST-015          → sync.rs          → OBS-001
NFR-002 (Offline Tolerance)    → TEST-016          → document.rs      → OBS-001
NFR-003 (Multi-Device)         → TEST-017          → document.rs      → OBS-003
NFR-004 (Resolution Latency)   → TEST-018          → resolve.rs       → OBS-002
NFR-005 (Merge Throughput)     → TEST-019          → document.rs      → OBS-003
NFR-006 (Binary Size)          → TEST-020          → Cargo.toml       → (CI check)
NFR-007 (No Unsafe)            → TEST-021          → pure core module → (CI check)
NFR-008 (Cold-Start Latency)   → TEST-023          → sync/dht.rs, sync/live.rs → OBS-005

CON-001 (Core API)             → TEST-001–013
CON-002 (Delta Format)         → TEST-004, TEST-010
CON-003 (HTTP API)             → TEST-011, TEST-014
CON-004 (Sync Protocol)        → TEST-012, TEST-015
CON-005 (Service-Sync)         → TEST-015-live
CON-006 (DHT Discovery)        → TEST-022, TEST-023, TEST-024
```

---

## 16. Security Considerations

### Threat Model

| Threat | Mitigation | Verification |
|---|---|---|
| Forged delta (attacker signs with wrong key) | Signature verification against verificationMethods G-Set | TEST-004, OBS-004 |
| Key compromise (attacker obtains private key) | Rotate to new key at higher seq. Old key can still rotate (recovery path). Social recovery via multi-sig is a future extension. | TEST-006, TEST-007 |
| Replay attack (re-submit old delta) | CRDT idempotence — replaying a delta has no effect | TEST-005 |
| Sybil attack (flood with DID creations) | Admission control: nodes ignore unsolicited DELTAS for unknown DIDs (CON-006 §admission control), so a flood cannot force storage on nodes that never requested the DIDs. ADR-003's layers (genesis PoW, per-IP rate limits, invitation codes) are specified but NOT yet implemented; replicate-all nodes accept flood risk until they land. | TEST-024 scenario E, OBS-004, OBS-006 |
| DHT record overwrite (publicly-derivable pkarr key) | Redirection cannot forge a document (genesis verification + signature chain). Erasure/censorship of cold-start discovery is possible and only mitigable: static PEERS / gossip-mesh fallback now; signed pointer payloads and announce-set rendezvous as future work (OQ-14). | CON-006 §genesis bootstrap (security) |
| State bloat (attacker grows document unboundedly) | State size monitoring (OBS-006). Future: compaction policy, field count limits. | OBS-006 |
| Partition attack (isolate node, feed stale state) | CRDT merge is correct under arbitrary partitions. Peer count monitoring alerts on isolation. | TEST-016, OBS-005 |
| Clock manipulation (push HLC into far future) | HLC rejects physical timestamps > wall_clock + max_drift. Configurable drift threshold. | TEST-010 |
| Property shadowing via documentData (authorised key injects a duplicate DID Core member, so a last-wins parser reads the injected value) | Reserved DID Core property names refused at delta admission AND skipped at projection. Both are required: state-based merge unions documentData without passing admission. Note this defeated key revocation, since an injected verificationMethod does not live in the 2P-Set that revocation acts on. | BUG-001, TEST-025, TEST-026, TEST-027 |

### Cryptographic Requirements

- Supported signature suites: EcdsaSecp256k1Signature2019, Ed25519Signature2020
- Key derivation: BIP-39 mnemonic → BIP-32 HD key path (compatible with existing wallet infrastructure)
- Hash function: BLAKE3-256 for content addressing, not for signatures (signatures use suite-native hashing)
- No custom cryptography — delegate to `ssi` and established crate ecosystem

**Quantum-resistance posture (current):** Neither Ed25519 nor secp256k1 ECDSA is quantum-resistant
— both rely on discrete-log hardness over elliptic curves, which Shor's algorithm can attack.
BLAKE3-256 retains ~128-bit effective security under Grover's algorithm (acceptable for a hash
function). The pkarr-derived Ed25519 keypair introduced in ADR-006 (CON-006) is consistent with
this baseline — it introduces no new regression. Migrating to post-quantum signature schemes
(e.g. ML-DSA / Dilithium, or SPHINCS+) is deferred future work and would require new SuiteType
variants and a key-rotation migration path. See open question #12.

### AI Trust Boundary (per USDD protocol)

Cryptographic operations are a **Tier 1 no-go area**. The signature verification module (`validate.rs`) and key rotation logic MUST receive cross-model adversarial review + human domain expert review before implementation.

---

## 17. Crate Structure

```
did-crdt/
├── Cargo.toml
├── src/
│   ├── lib.rs                  — public API re-exports
│   │
│   ├── core/                   — PURE CORE (no I/O)
│   │   ├── mod.rs
│   │   ├── document.rs         — Document struct, merge, resolve
│   │   ├── crdt.rs             — typed CRDT field wrappers
│   │   ├── delta.rs            — SignedDelta construction
│   │   ├── validate.rs         — signature + authorisation checks
│   │   ├── hlc.rs              — Hybrid Logical Clock
│   │   ├── resolve.rs          — CRDT state → W3C DID Document
│   │   └── did.rs              — DID identifier type
│   │
│   ├── sync/                   — feature: "sync"
│   │   ├── mod.rs
│   │   ├── store.rs            — iroh-blobs persistence
│   │   ├── gossip.rs           — iroh-gossip delta propagation
│   │   ├── protocol.rs         — message types (ANNOUNCE, REQUEST, DELTAS)
│   │   └── dht.rs              — DHT peer discovery (DhtNode::publish, DhtNode::lookup)
│   │
│   ├── service/                — feature: "service"
│   │   ├── mod.rs
│   │   ├── server.rs           — axum HTTP server
│   │   ├── handlers.rs         — route handlers
│   │   └── metrics.rs          — prometheus metrics
│   │
│   └── anchor/                 — feature: "anchor"
│       ├── mod.rs
│       └── traits.rs           — pluggable anchoring trait
│
├── tests/
│   ├── properties.rs           — proptest: commutativity, associativity, idempotence
│   ├── rotation.rs             — key rotation scenarios
│   ├── convergence.rs          — multi-replica convergence
│   └── integration.rs          — HTTP API + gossip tests
│
├── benches/
│   ├── merge.rs                — merge throughput benchmark
│   └── resolve.rs              — resolution latency benchmark
│
├── fuzz/
│   └── fuzz_targets/
│       └── delta_parse.rs      — fuzz delta deserialisation
│
└── examples/
    ├── create_did.rs           — minimal DID creation
    ├── multi_device.rs         — two-device sync simulation
    └── service.rs              — standalone resolver service
```

---

## 18. Open Questions

The following questions have been resolved by Architecture Decision Records (ADRs)
in `docs/adr/`. The remaining questions are tracked for future work.

### 18.1 Resolved

1. **Compaction / garbage collection** — *Resolved by [ADR-001](../docs/adr/ADR-001-compaction-gc-strategy.md).*
   Decision: two-tier compaction model. Tier 1: periodic signed snapshots every
   128 deltas or 512 KiB (whichever comes first), with a 72-hour tombstone TTL
   before pruning. Tier 2: incremental delta pruning on read (replay only deltas
   since the last valid snapshot). Snapshots must be signed by the current
   controller and are optional — nodes that never compact remain correct but pay
   higher resolution cost.

2. **Key compromise recovery** — *Resolved by [ADR-002](../docs/adr/ADR-002-key-compromise-recovery.md).*
   Decision: recovery key with 48-hour time-lock challenge period. Controllers
   register cold-storage recovery keys (optionally M-of-N threshold) in a
   `recovery_method` field. A recovery delta carries a `not_before` timestamp at
   least 48 hours in the future; the current controller may cancel it during that
   window. After the window, nodes apply the recovery. Total key loss (both
   operational and recovery keys compromised) is treated as an unrecoverable
   situation and must be documented for operators.

5. **Sybil resistance** — *Resolved by [ADR-003](../docs/adr/ADR-003-sybil-resistance.md).*
   Decision: layered defence. Creation deltas require 20-bit proof-of-work on the
   genesis delta (≈ 0.5 s per DID). Gossip ingress enforces per-IP rate limits
   (5/min, 50/hr, 200/day by default). Enterprise operators may additionally
   enable invitation codes for closed namespaces. Update deltas carry no PoW
   cost.

8. **State size limits** — *Resolved by [ADR-004](../docs/adr/ADR-004-state-size-limits.md).*
   Decision: limits are enforced in the library (`validate.rs`), not pushed to
   the service layer. Defaults: 20 verification methods, 20 services, 4 KiB per
   field value, 256 KiB total document state. Hard maximums (100 VMs, 100
   services, 64 KiB per field, 1 MiB total) cannot be exceeded by any
   configuration. Per-delta limits: 64 KiB serialised size, 50 mutations. A new
   `crdt_delta_rejected_size_total` counter is added alongside `OBS-006`.

9. **DHT peer discovery and cold-start bootstrap** — *Resolved by
   [ADR-006](#adr-006-pkarr-derived-keypair-for-did-keyed-dht-discovery).*
   Decision: derive a deterministic Ed25519 keypair from each DID's BLAKE3
   hash and publish pkarr records advertising the node's iroh NodeId.
   Genesis bootstrap uses an empty-frontier DELTAS exchange rather than a
   STATE message.  Specified in CON-006, REQ-013, REQ-014.

10. **CON-004 errata** — *Resolved in this revision.* CON-004 has been
    updated to reflect the actual implementation: (a) REQUEST uses
    `frontier: Vec<DeltaHash>`, not `since: Option<Hlc>`; (b) the STATE
    message variant is intentionally absent — full CRDT state is a
    trusted-domain primitive and is not transmitted over untrusted
    connections (see SPEC-036 §11 for the rationale). CON-004 now
    documents both decisions inline.

### 18.2 Open (future work)

3. **DID method registration.** `did:crdt` needs registration in the W3C DID
   Method Registry. The W3C DID Method specification has been drafted
   (`specs/did-method-spec.md`); formal registration is pending implementation
   stabilisation.

4. **WASM target.** The pure core should compile to WASM for browser-based
   wallets. This needs validation against the `crdts`, `ssi`, and `blake3`
   crates' WASM compatibility. Tracked in Phase 4 of the implementation plan.

6. **Interop with existing DID methods.** Can a `did:crdt` document reference
   verification methods from `did:key` or `did:web` DIDs? Cross-method
   controller relationships need specification.

7. **Legal timestamping.** Some jurisdictions require proof-of-existence at a
   specific time. The `anchor` feature gate is a placeholder — the anchoring
   trait interface needs design.

11. **DHT holder privacy.** Publishing a DID→NodeId mapping to a public DHT
    reveals which node hosts a given DID. The opt-out flag
    (DISABLE_DHT_PUBLISH) in CON-006 is a first mitigation; a more
    principled privacy model (e.g. onion-routed DHT queries, private set
    intersection for discovery) is future work. Related: OQ-13.

12. **Post-quantum signatures.** The current signature suites (Ed25519, secp256k1) are
    not quantum-resistant. A future migration would add new SuiteType variants for
    ML-DSA (CRYSTALS-Dilithium) or SPHINCS+ and a versioned key-rotation path for
    existing documents. The pkarr-derived keypair (ADR-006) is scoped to DHT
    discovery and shares the same exposure. No regression is introduced by CON-006;
    the quantum-resistance gap predates it.

13. **DHT single-publisher availability.** Because all holders of a DID derive
    the same Ed25519 keypair, each DhtNode::publish() call overwrites the
    previous pkarr record — only the most recently publishing node's NodeId
    is in the DHT at any given time (CON-006 §lookup, ADR-006 §trade-offs).
    If that node goes offline before the next 60-minute refresh cycle, the
    DID becomes temporarily undiscoverable via DHT even if other nodes hold
    it. Possible mitigations: (a) extend the TXT record to carry multiple
    "nid=" attributes, with the publisher aggregating recent peer
    announcements before signing; (b) adopt Approach A from ADR-006
    (the `mainline` crate's native multi-value get_peers semantics). Related:
    OQ-11, OQ-14.

14. **DHT discovery censorship (record hijack).** The pkarr signing key is
    derivable from the public DID string, so any party that knows a DID can
    overwrite its discovery record. Redirection is harmless to integrity
    (CON-006 §genesis bootstrap rejects anything the controller did not
    author) but erasure suppresses cold-start discovery — a publish-rate
    race the defender cannot reliably win. Mitigation path: (a) sign the
    pointer payload (nid/relay/addrs + freshness timestamp) with the
    genesis key so resolvers discard unauthorised pointers — eliminates
    redirection, not erasure; (b) announce-set rendezvous over mainline
    get_peers/announce_peer keyed by the DID hash (ADR-006 Approach A) —
    honest announcers cannot be erased, degrading the attack to noise that
    costs the resolver extra connection attempts. The limitation is
    inherent to rendezvous keys publicly derivable from a hash-based
    identifier; the operational fallbacks are static PEERS and gossip-mesh
    membership. Related: OQ-13.

---

## 19. Implementation Plan

### Phase 1: Pure Core (target: proof of concept)

- [ ] Scaffold Rust crate with module structure
- [ ] Implement CRDT field wrappers over `crdts` crate
- [ ] Implement `Document` struct with `new()`, `merge()`, `resolve()`
- [ ] Implement `SignedDelta` with `ssi` signature integration
- [ ] Implement HLC
- [ ] Write proptest properties: commutativity, associativity, idempotence
- [ ] Write key rotation and deactivation scenario tests
- [ ] `#[forbid(unsafe_code)]` on core module
- [ ] Benchmark: merge throughput, resolution latency

**Quality gates:** All property tests pass. Merge throughput ≥ 10,000/sec. No unsafe.

### Phase 2: Sync Layer

- [x] Implement iroh-gossip delta propagation (CON-004, CON-005)
- [ ] Implement iroh-blobs snapshot storage (store.rs)
- [x] Define sync protocol messages (ANNOUNCE, REQUEST, DELTAS) — note: STATE omitted by design
- [x] Two-node convergence integration test (TEST-015-live)
- [ ] Offline reunion integration test (TEST-016)
- [ ] Convergence latency measurement (NFR-001)
- [x] Implement DHT peer registration: DhtNode::publish() using pkarr-derived keypair (CON-006, REQ-013)
- [x] Implement DHT peer lookup: DhtNode::lookup() (CON-006, REQ-014)
- [x] Extend merge_inbound for genesis bootstrap from empty-frontier DELTAS (CON-006 §genesis bootstrap)
- [x] Integrate DhtNode into LiveNode and Server::run() lifecycle
- [x] Implement periodic DHT refresh background task (60-min cadence)
- [x] DHT publication unit test with in-process pkarr relay stub (TEST-022)
- [x] Cold-start convergence integration test with in-process pkarr relay stub (TEST-023)
- [x] Genesis bootstrap failure-path and admission-control unit tests (TEST-024)
- [x] Admission control: solicited-only genesis bootstrap with wanted set + REPLICATE_ALL opt-in (CON-006 §admission control)
- [x] Self-contained addressing hints in pkarr TXT record (relay= / addrs=, ADR-006 amendment)
- [ ] Signed discovery pointer payloads (genesis-key-signed nid/relay/addrs, OQ-14 mitigation a)
- [ ] Announce-set rendezvous fallback via mainline get_peers (OQ-14 mitigation b, ADR-006 Approach A)

**Quality gates:** Two-node convergence < 30s p99. Offline reunion with zero data loss. Cold-start resolution < 15s p90 in CI with in-process relay stub (NFR-008).

### Phase 3: Service Layer

- [ ] Implement axum HTTP server with DID resolution endpoint
- [ ] Implement delta submission endpoint
- [ ] Add prometheus metrics (OBS-001 through OBS-006)
- [ ] Dockerise
- [ ] HTTP API integration tests

**Quality gates:** DID Resolution spec compliance. All OBS signals emitting.

### Phase 4: Hardening

- [ ] Fuzz delta deserialisation
- [ ] Security review of validate.rs (Tier 1 — cross-model + human)
- [ ] Implement ADR-003 sybil-resistance layers: 20-bit genesis PoW, gossip-ingress per-IP rate limits, optional invitation codes (currently specified only; CON-006 §admission control is the interim flood defence)
- [ ] WASM compilation test
- [ ] Write DID Method specification document
- [x] Address open questions (compaction, key recovery, sybil resistance, state size limits) — see ADR-001 through ADR-004 in docs/adr/

**Quality gates:** Zero fuzzing crashes. Security review passed. WASM compiles.


---

## 20. Defects

```
BUG-001: documentData Could Shadow Any DID Core Property

Severity: high -- document integrity, and it defeats key revocation.
Status:   fixed 2026-08-13. Never deployed; no live exposure.

SYMPTOM

A resolved DID document could contain two members of the same name. A
consumer's answer to "what is this document's id" or "which keys authenticate
it" then depended on which member its JSON parser kept.

MECHANISM

DidDocument.extra is serialised with serde's flatten, and the documentData
LWW-Map was projected into it unfiltered. serde does not deduplicate across a
flatten boundary, so a documentData entry whose key names a DID Core property
emits a SECOND member of that name beside the typed field. serde_json retains
the last, which is the injected one.

EVIDENCE

Setting documentData["id"] on an otherwise ordinary document produced:

  "id":"did:crdt:a9baa8e5...", ..., "id":"did:crdt:ATTACKER"
  re-parsed id -> "did:crdt:ATTACKER"

IMPACT

1. Revocation bypass. A key may write a shadow verificationMethod array into
   documentData and then be revoked. Revocation acts on the 2P-Set; the
   injected value does not live there, so it outlives the key that wrote it and
   a last-wins parser sees only the injected array. Ending what a key can
   assert is the entire purpose of revoking it.

2. Identifier restatement. A holder could make their own document claim to be a
   different DID -- the binding a verifier checks by recomputing the identifier
   from the genesis public key.

3. Every other DID Core property is equally shadowable, including
   authentication, assertionMethod, controller and service.

Submitting the delta requires an authorised key, so this is not reachable
anonymously. It remains a privilege-persistence defect rather than a cosmetic
one, for the reason in (1).

It violates REQ-009 on both of that requirement's explicit terms: the resolved
document's id no longer matched the DID, and an object carrying duplicate
members does not validate against the DID Core JSON-LD schema. It is
additionally a LangSec violation -- a trust-boundary projection emitting a
document whose meaning is settled by the recipient's parser rather than by its
producer.

ROOT CAUSE

An untyped escape hatch -- documentData accepts any JSON value under any key --
was projected into a typed namespace, the DID document, with no reserved-name
discipline at the join.

RESOLUTION

A reserved set of DID Core property names, enforced in BOTH directions:

- Document::merge refuses a SetDocumentData naming a reserved property, so it
  never enters the delta log.
- The projection skips reserved keys however they arrived.

Both are necessary. State-based merge unions documentData wholesale without
passing delta admission, so a peer on older code -- or a hostile one -- can
seat a reserved key directly into state; admission-time rejection alone leaves
that path open.

alsoKnownAs is reserved by this fix. It is a DID Core property and therefore
requires a typed field rather than an untyped passthrough -- delivered as
REQ-015 / CON-007, which is why the reservation does not remove a capability.

Trace:
- REQ-009
- TEST-025
- TEST-026
- TEST-027
```

---

**END OF SPECIFICATION**
