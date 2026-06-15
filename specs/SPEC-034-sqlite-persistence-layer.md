---
title: "SPEC-034: SQLite Persistence Layer for did-crdt"
id: SPEC-034
version: 0.1.0
status: draft
created: 2026-04-23
last_updated: 2026-04-23
authors: Anuna Research
reviewers: Engineering, Security
audience: engineers, operators, protocol designers
parent: SPEC-032
references:
  - "SPEC-032: did-crdt - Coordination-Free Decentralised Identifiers via Signed CRDTs"
  - "SPEC-033: did-crdt W3C DID Core Compliance Amendments"
  - "ADR-001: Compaction and Garbage Collection Strategy"
  - "ADR-004: State Size Limits"
  - "CON-002: SignedDelta - Delta Format"
  - "CON-003: HTTP Resolution API"
---

# SPEC-034: SQLite Persistence Layer for did-crdt

| Field | Value |
|---|---|
| Document ID | SPEC-034 |
| Title | SQLite Persistence Layer for did-crdt |
| Version | 0.1.0 |
| Status | Draft |
| Created | 2026-04-23 |
| Last Updated | 2026-04-23 |
| Authors | Anuna Research |
| Reviewers | Engineering, Security |
| Parent | SPEC-032 |

---

## 1. Executive Summary

The current `did-crdt` HTTP service is useful for protocol experiments, but its
state lives in an in-memory `HashMap`. A process restart loses every DID, and
memory grows roughly with the number of documents loaded. This prevents a small
resolver node from answering the operational question that matters for cheap
hosting: how many DIDs can a low-cost machine manage when durable state lives on
disk instead of in RAM?

This specification defines an SQLite-backed persistence layer for the service
feature. The design stores two complementary records for each DID:

1. An append-only log of accepted `SignedDelta` values, encoded as canonical
   JSON and indexed by DID, HLC timestamp, admission sequence, and BLAKE3 hash.
2. A materialized CRDT state snapshot, encoded as a versioned binary state
   envelope, used for fast resolution and future delta admission without
   replaying the full log on every request.

The delta log is the audit and rebuild source. The materialized state is the
fast path. Both are written in one SQLite transaction so `201 Created` and
`202 Accepted` mean the mutation is durable before the HTTP response is sent.

This is an effectful-shell feature. The pure CRDT core remains free of SQLite,
Tokio, Axum, filesystem, and environment dependencies.

---

## 2. Feature Overview

**Feature Name:** `sqlite-persistence`

**Purpose:** Provide durable, low-memory persistence for DID documents and
their accepted signed deltas in the standalone HTTP service.

**Primary user story:** As an operator running a cheap DID resolver node, I
want accepted DIDs and deltas persisted to disk so that restarts, redeploys, and
low-memory operation do not destroy or require preloading the node's state.

**Acceptance criteria:**

- [ ] A DID created through `POST /dids` survives process restart.
- [ ] A delta accepted through `POST /dids/{did}/deltas` survives process restart.
- [ ] Duplicate accepted deltas are idempotent and do not create additional rows.
- [ ] `GET /{did}` reads the requested DID from SQLite without loading every DID.
- [ ] A complete document can be rebuilt from persisted deltas in admission order.
- [ ] SQLite writes are atomic across the document row and delta row.
- [ ] The HTTP service can run in memory mode when no storage path is configured.
- [ ] The persistence feature does not add dependencies to the default pure core.

**Data classification:** Public protocol data. DID documents and signed deltas
are public by design, but operators may still treat the database as sensitive
because service endpoints and application-specific `document_data` can contain
correlating metadata.

**Privacy notes:** The persistence layer MUST NOT store private keys, API
tokens, request IP addresses, user agents, or authentication secrets. Rejected
delta bodies are not persisted by default.

---

## 3. Context and Constraints

### 3.1 Existing Service State

The service currently exposes the required HTTP surface:

- `POST /dids` creates a DID.
- `GET /{did}` resolves a DID.
- `POST /dids/{did}/deltas` submits a signed delta.
- `GET /metrics` exposes Prometheus metrics.

The runtime state is held in process memory. `STORAGE_PATH` is parsed at
startup but is not yet wired to durable storage. This specification turns that
configuration surface into an actual storage backend while preserving memory
mode for tests and demos.

### 3.2 Delta Admission Is Stateful

`Document::merge(delta)` checks the DID, deactivation latch, authorised signer,
revoked signer set, operation semantics, and delta size limit before applying
the CRDT mutation. A delta can be valid only after causally prior deltas have
been accepted. The persistence layer therefore MUST preserve accepted admission
order per DID, not only HLC ordering.

### 3.3 The Stored State Is Not the Resolved DID Document

The resolved DID document is a W3C projection. It omits CRDT causal context and
cannot safely accept future deltas on its own. SQLite MUST persist the full
merge-sufficient CRDT state, including internal OR-Set causal context, LWW
registers, revocation sets, active key state, deactivation state, and created
and updated timestamps.

### 3.4 Current JSON State Serialisation Is Not a Sufficient Storage Contract

The current `Document::to_bytes()` uses `serde_json` over the internal
`Document` struct. Some CRDT internals can contain non-string map keys. JSON
objects require string keys, which makes raw JSON unsuitable as the long-term
storage contract for internal CRDT state.

The SQLite store SHALL use a versioned binary state envelope for materialized
state. `SignedDelta` values remain stored as canonical JSON because canonical
JSON is the protocol signing format and is useful for audit/export.

---

## 4. User Profiles and Happy Paths

### 4.1 Operator: Cheap Public Test Node

**Role:** Runs a small `did-crdt-service` instance on a low-cost VM with a
single attached persistent volume.

**Goals:**

- Keep monthly cost close to the smallest viable node.
- Restart and redeploy without data loss.
- Estimate cost per DID from observed document and delta storage size.
- Avoid operating a separate database service.

**Happy path:**

1. Operator deploys `did-crdt-service` with `DID_CRDT_STORAGE=sqlite` and
   `STORAGE_PATH=/data/did-crdt.sqlite3`.
2. The service creates the database, applies migrations, enables WAL, and
   starts listening.
3. Clients create DIDs and submit deltas.
4. The operator restarts the process.
5. Previously created DIDs resolve successfully without loading all DIDs into
   memory at startup.
6. Metrics show document count, delta count, database size, read latency, and
   write latency.

### 4.2 Developer: Service Integrator

**Role:** Embeds the HTTP service or store abstraction in integration tests,
benchmarks, and deployments.

**Goals:**

- Use the same HTTP handlers with either memory or SQLite storage.
- Write deterministic tests around persistence and replay.
- Keep the pure core independent from SQLite.

**Happy path:**

1. Developer runs `cargo test --features service,storage-sqlite`.
2. Integration tests create a temporary SQLite database.
3. The test creates a DID, applies deltas, drops the service state, reopens the
   database, and resolves the DID.
4. The result matches the pre-restart resolution metadata and DID document.

### 4.3 Auditor: Delta Log Reviewer

**Role:** Reviews how a DID reached its current state.

**Goals:**

- Export accepted deltas for a specific DID.
- Recompute delta hashes and state hashes independently.
- Rebuild the materialized state from the delta log and detect divergence.

**Happy path:**

1. Auditor requests the accepted delta list for `did:crdt:<hash>`.
2. The store returns canonical delta bytes ordered by per-DID admission sequence.
3. The auditor replays the sequence against an empty document state.
4. The rebuilt state hash matches `documents.state_hash`.

---

## 5. Requirements

### REQ-035: SQLite Storage Mode

The system SHALL provide an SQLite-backed storage mode for the HTTP service
WHEN the `storage-sqlite` Cargo feature is enabled AND the operator configures
SQLite storage WITH `DID_CRDT_STORAGE=sqlite` or a non-empty `STORAGE_PATH`.

Trace:
- CON-005
- CON-008
- TEST-039
- OBS-007

### REQ-036: Durable DID Creation

The system SHALL persist a newly created DID document and its genesis delta in
a single SQLite transaction BEFORE returning `201 Created` from `POST /dids`
FOR service clients WITH no document row visible without its genesis delta.

Trace:
- CON-006
- CON-007
- TEST-039
- TEST-041
- OBS-009

### REQ-037: Durable Delta Admission

The system SHALL persist each accepted non-genesis `SignedDelta`, the updated
materialized CRDT state, and the updated document counters in a single SQLite
transaction BEFORE returning `202 Accepted` from `POST /dids/{did}/deltas`.

Trace:
- CON-006
- CON-007
- TEST-040
- TEST-041
- OBS-008
- OBS-009

### REQ-038: Delta Deduplication and Idempotence

The system SHALL identify duplicate accepted deltas by BLAKE3 hash of the
canonical full `SignedDelta` bytes and SHALL treat duplicate submission for the
same DID as an idempotent success WITH no additional delta row, no admission
sequence increment, and no state change.

Trace:
- CON-006
- CON-007
- TEST-042
- OBS-008

### REQ-039: Point Lookup Resolution

The system SHALL resolve `GET /{did}` by loading only the requested DID's
materialized state from SQLite, not by scanning or preloading all documents,
FOR any database containing at least one million DIDs WITH memory use bounded by
the configured cache.

Trace:
- CON-005
- CON-006
- TEST-047
- OBS-010

### REQ-040: Rebuild From Deltas

The system SHALL rebuild the materialized CRDT state for a DID from its accepted
delta log ordered by per-DID admission sequence WITH the rebuilt state hash
matching `documents.state_hash`.

Trace:
- CON-005
- CON-006
- TEST-043
- TEST-048
- OBS-013

### REQ-041: Snapshot and Compaction Compatibility

The system SHALL persist compaction snapshots separately from accepted deltas
and SHALL retain all accepted deltas by default until signed snapshot pruning is
implemented per ADR-001 WITH the genesis delta always retained.

Trace:
- CON-006
- CON-007
- TEST-044
- OBS-011

### REQ-042: Schema Migration

The system SHALL apply forward-only SQLite schema migrations at startup before
serving traffic WITH each migration recorded in `schema_migrations` and the
SQLite `user_version` updated atomically.

Trace:
- CON-006
- CON-008
- TEST-045
- OBS-012

### REQ-043: Storage Backend Abstraction

The system SHALL route HTTP handlers through a storage backend abstraction so
that memory mode and SQLite mode implement the same create, resolve, delta
admission, delta listing, health, and statistics contracts.

Trace:
- CON-005
- TEST-050

### REQ-044: Delta Listing for Sync and Audit

The system SHALL provide a store-level delta listing operation that returns
accepted canonical delta bytes for a DID ordered by admission sequence and
filtered by optional HLC lower bound and limit.

Trace:
- CON-005
- CON-006
- TEST-043
- TEST-049

### REQ-045: Backup and Restore

The system SHALL support online-consistent SQLite backup and restore procedures
that preserve documents, deltas, snapshots, migrations, and metadata WITH
post-restore integrity verification available through the rebuild operation.

Trace:
- CON-006
- CON-008
- TEST-049
- OBS-013

### REQ-046: Startup Failure Semantics

The system SHALL fail startup when SQLite storage is explicitly configured but
the database cannot be opened, migrated, or validated; it SHALL fall back to
memory storage only when SQLite was not explicitly configured.

Trace:
- CON-008
- TEST-051
- OBS-012

---

## 6. Non-Functional Requirements

### NFR-008: Durability

A successful create or accepted delta write SHALL survive process crash and
restart UNDER the configured SQLite synchronous mode WITH zero acknowledged
mutations missing after recovery.

Trace:
- TEST-041
- OBS-012

### NFR-009: Bounded Memory

The service SHALL keep resident memory independent of total DID count UNDER
point lookup and write workloads WITH no startup scan of all document rows and
with SQLite page cache bounded by configuration.

Trace:
- TEST-046
- TEST-047
- OBS-011

### NFR-010: Resolution Latency

SQLite-backed DID resolution SHALL complete in <= 25 ms at p95 UNDER a database
containing 100,000 small DID documents on a shared single-core development
machine WITH WAL mode enabled and a warm filesystem cache.

Trace:
- TEST-046
- TEST-047
- OBS-010

### NFR-011: Write Throughput

SQLite-backed DID creation SHALL sustain >= 200 creates per second and accepted
delta admission SHALL sustain >= 500 deltas per second UNDER a single writer
workload on a shared single-core development machine WITH `synchronous=NORMAL`.

Trace:
- TEST-046
- TEST-047
- OBS-009

### NFR-012: Storage Efficiency

Total SQLite file size SHALL be <= 4x the combined size of canonical delta bytes
and latest materialized state bytes UNDER 100,000 small DID documents after WAL
checkpoint WITH no indexes other than those specified in CON-006.

Trace:
- TEST-047
- OBS-011

### NFR-013: Startup Time

SQLite-backed service startup SHALL complete in <= 2 seconds UNDER a database
containing one million DIDs WITH no pending migrations and no integrity rebuild
requested.

Trace:
- TEST-051
- OBS-013

### NFR-014: Integrity Detection

The persistence layer SHALL detect mismatches between stored state bytes,
stored BLAKE3 state hash, and rebuilt state hash DURING explicit integrity
verification WITH corrupt documents reported and not silently resolved.

Trace:
- TEST-048
- OBS-013

---

## 7. Architecture Decision Records

### ADR-006: SQLite Over RocksDB, redb, and External Databases

#### Context

The target deployment is a minimal standalone resolver node. The operator wants
the lowest possible per-DID cost and does not want to run a separate database
service. The workload is simple: point lookups by DID, append accepted deltas,
update one materialized state row, list deltas for one DID, and read counters.

#### Decision

Use SQLite as the first durable persistence backend for the service feature.
Expose it behind a storage trait so another backend can be added later without
changing HTTP handler semantics.

#### Rationale

- SQLite is a single-file embedded database and maps directly to an attached
  persistent volume.
- The write path needs transactional updates across document state and delta
  rows. SQLite provides this without a separate service.
- Point lookups by primary key and ordered delta scans by `(did, sequence)` are
  exactly the access patterns SQLite handles well.
- Operational complexity matters more than peak write throughput for the cheap
  node goal.

#### Trade-offs

| Option | Advantages | Disadvantages |
|---|---|---|
| SQLite | Single file, transactional, easy backup, easy introspection, small operations surface | Single writer, blocking API in common Rust bindings |
| RocksDB | High write throughput, LSM compaction, mature KV engine | Larger dependency and image footprint, more compaction tuning, harder inspection |
| redb | Pure Rust, embedded, transactional KV | Less mature ecosystem, less SQL introspection |
| External Postgres | Excellent concurrency and operations tooling | Requires a second service, violates cheapest-node constraint |

#### Status

Proposed.

### ADR-007: Deltas as Source of Audit, Materialized State as Fast Path

#### Context

The CRDT state can be reconstructed from accepted deltas if they are replayed in
accepted causal order. Replaying on every resolution is too expensive, but
storing only materialized state loses auditability and makes state corruption
hard to repair.

#### Decision

Persist accepted deltas append-only and persist the latest materialized CRDT
state in the same transaction. Reads use the materialized state. Integrity
checks and repair use the delta log.

#### Rationale

- The delta log explains how the DID reached its current state.
- The document row makes normal resolution O(1) database lookups.
- Atomic writes prevent a delta without corresponding state or state without a
  corresponding delta.
- The design is compatible with future gossip because deltas are already
  addressable and ordered.

#### Trade-offs

| Choice | Benefit | Cost |
|---|---|---|
| Deltas only | Minimal derived state, simple audit | Slow resolution or rebuild cache required |
| State only | Fast reads and fewer rows | No local audit trail, poor repair story |
| Deltas plus state | Fast reads and rebuildable audit | Extra disk use and transaction complexity |

#### Status

Proposed.

### ADR-008: Canonical JSON for Deltas, Versioned Binary Envelope for State

#### Context

`SignedDelta` signing input is canonical JSON. Operators and auditors should be
able to export and inspect accepted deltas. Internal CRDT state, however, can
include data structures that are not naturally representable as JSON objects,
including maps keyed by non-string actor identifiers.

#### Decision

Store each accepted `SignedDelta` as canonical JSON bytes and hash those bytes
with BLAKE3 for deduplication. Store materialized CRDT state as
`did-crdt.document-state.cbor.v1`, a versioned binary envelope that can encode
internal CRDT maps without JSON key restrictions.

#### Rationale

- Delta bytes remain close to the protocol and audit surface.
- State bytes preserve merge-sufficient internals without relying on a resolved
  DID document projection.
- A codec label in the database gives future migrations a precise branch point.

#### Trade-offs

| Choice | Benefit | Cost |
|---|---|---|
| JSON for both deltas and state | Human-readable, one codec | Internal CRDT state cannot be represented reliably |
| Binary for both deltas and state | Compact, simple storage code | Delta audit/export no longer matches protocol JSON |
| Canonical JSON deltas plus binary state | Protocol-aligned deltas and robust state | Two codecs to test and document |

#### Status

Proposed.

### ADR-009: Blocking SQLite Behind Async Service Boundary

#### Context

The HTTP service is async. Common Rust SQLite bindings are synchronous. Running
blocking database work directly on async runtime workers can starve unrelated
HTTP requests.

#### Decision

SQLite store operations SHALL execute through a blocking boundary, either
`tokio::task::spawn_blocking` or a dedicated store worker thread. HTTP handlers
MUST NOT hold an async `RwLock<HashMap<...>>` while performing SQLite I/O.

#### Rationale

- The pure core remains synchronous and deterministic.
- The service avoids blocking runtime worker threads.
- The design leaves room for read connections and a write connection later.

#### Trade-offs

| Option | Advantages | Disadvantages |
|---|---|---|
| `spawn_blocking` per operation | Simple first implementation | Needs care with connection ownership |
| Dedicated store worker | Serializes writes naturally, predictable | More plumbing and queue backpressure |
| Async SQLite wrapper | Cleaner handler signatures | Additional dependency and still backed by blocking SQLite work |

#### Status

Proposed.

---

## 8. Contract Specifications

### CON-005: DocumentStore Interface

Endpoint/Interface: Rust service storage abstraction.

```rust
pub enum StoreHealth {
    Ready,
    Degraded { reason: String },
}

pub enum DeltaAdmissionOutcome {
    Accepted {
        did: Did,
        delta_hash: [u8; 32],
        sequence: u64,
        state_hash_after: [u8; 32],
    },
    Duplicate {
        did: Did,
        delta_hash: [u8; 32],
        sequence: u64,
    },
}

pub struct DeltaListOptions {
    pub since_hlc: Option<HlcTimestamp>,
    pub after_sequence: Option<u64>,
    pub limit: u32,
}

pub struct StoredDelta {
    pub did: Did,
    pub delta_hash: [u8; 32],
    pub sequence: u64,
    pub timestamp: HlcTimestamp,
    pub canonical_json: Vec<u8>,
}

pub struct StoreStats {
    pub document_count: u64,
    pub delta_count: u64,
    pub snapshot_count: u64,
    pub database_bytes: Option<u64>,
    pub wal_bytes: Option<u64>,
}

pub trait DocumentStore: Send + Sync + 'static {
    fn create_document(
        &self,
        document: &Document,
        genesis_delta: &SignedDelta,
    ) -> Result<DeltaAdmissionOutcome>;

    fn get_document(&self, did: &Did) -> Result<Option<Document>>;

    fn admit_delta(
        &self,
        did: &Did,
        delta: &SignedDelta,
    ) -> Result<DeltaAdmissionOutcome>;

    fn list_deltas(
        &self,
        did: &Did,
        options: DeltaListOptions,
    ) -> Result<Vec<StoredDelta>>;

    fn rebuild_document(&self, did: &Did) -> Result<Option<Document>>;

    fn health(&self) -> StoreHealth;

    fn stats(&self) -> Result<StoreStats>;
}
```

Pre-conditions:

- `create_document` receives a document that already contains the genesis
  delta's effect.
- `admit_delta` receives a delta whose `did` field matches the path DID.
- SQLite-backed implementations are called from a blocking boundary, not
  directly on an async runtime worker.

Post-conditions:

- `create_document` writes exactly one document row and one genesis delta row.
- `get_document` returns merge-sufficient CRDT state, not only resolved JSON.
- `admit_delta` either persists an accepted delta and new state atomically,
  returns a duplicate outcome, or persists nothing.
- `list_deltas` returns canonical delta bytes ordered by admission sequence.
- `rebuild_document` returns the same resolved state as `get_document` unless
  corruption is detected.

Error model:

- `UnknownDid`: delta admission targets a DID absent from the store.
- `DuplicateDid`: creation attempts to insert an existing DID.
- `DeltaRejected`: pure core rejected the delta.
- `CodecError`: stored bytes could not be decoded.
- `IntegrityError`: stored hash does not match stored or rebuilt bytes.
- `StorageUnavailable`: database cannot be read or written.

Implements:
- REQ-035
- REQ-039
- REQ-040
- REQ-043
- REQ-044

Verified by:
- TEST-039
- TEST-040
- TEST-043
- TEST-047
- TEST-050

### CON-006: SQLite Schema

Endpoint/Interface: SQLite database file at `STORAGE_PATH`.

Initial schema version: `1`.

```sql
PRAGMA foreign_keys = ON;

CREATE TABLE schema_migrations (
  version INTEGER PRIMARY KEY CHECK (version > 0),
  applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms >= 0),
  description TEXT NOT NULL
);

CREATE TABLE store_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE documents (
  did TEXT PRIMARY KEY,
  state_codec TEXT NOT NULL,
  state_version INTEGER NOT NULL CHECK (state_version > 0),
  state_bytes BLOB NOT NULL,
  state_hash BLOB NOT NULL CHECK (length(state_hash) = 32),
  version_id TEXT NOT NULL,
  created_ms INTEGER NOT NULL CHECK (created_ms >= 0),
  updated_ms INTEGER NOT NULL CHECK (updated_ms >= 0),
  delta_count INTEGER NOT NULL CHECK (delta_count >= 1),
  latest_delta_hash BLOB CHECK (latest_delta_hash IS NULL OR length(latest_delta_hash) = 32),
  compacted_delta_count INTEGER NOT NULL DEFAULT 0 CHECK (compacted_delta_count >= 0),
  deactivated INTEGER NOT NULL DEFAULT 0 CHECK (deactivated IN (0, 1)),
  inserted_at_ms INTEGER NOT NULL CHECK (inserted_at_ms >= 0),
  stored_at_ms INTEGER NOT NULL CHECK (stored_at_ms >= 0)
);

CREATE TABLE deltas (
  did TEXT NOT NULL,
  sequence INTEGER NOT NULL CHECK (sequence >= 0),
  delta_hash BLOB NOT NULL CHECK (length(delta_hash) = 32),
  delta_codec TEXT NOT NULL,
  delta_bytes BLOB NOT NULL,
  wall_ms INTEGER NOT NULL CHECK (wall_ms >= 0),
  logical INTEGER NOT NULL CHECK (logical >= 0),
  node_id INTEGER NOT NULL,
  op_type TEXT NOT NULL,
  signer TEXT NOT NULL,
  proof_suite TEXT NOT NULL,
  proof_value TEXT NOT NULL,
  is_genesis INTEGER NOT NULL DEFAULT 0 CHECK (is_genesis IN (0, 1)),
  state_hash_after BLOB NOT NULL CHECK (length(state_hash_after) = 32),
  accepted_at_ms INTEGER NOT NULL CHECK (accepted_at_ms >= 0),
  PRIMARY KEY (did, delta_hash),
  UNIQUE (did, sequence),
  FOREIGN KEY (did) REFERENCES documents(did) ON DELETE CASCADE
);

CREATE UNIQUE INDEX deltas_hash_global
  ON deltas(delta_hash);

CREATE INDEX deltas_by_did_sequence
  ON deltas(did, sequence);

CREATE INDEX deltas_by_did_hlc
  ON deltas(did, wall_ms, logical, node_id);

CREATE INDEX deltas_by_did_op_type
  ON deltas(did, op_type);

CREATE TABLE snapshots (
  did TEXT NOT NULL,
  snapshot_hash BLOB NOT NULL CHECK (length(snapshot_hash) = 32),
  state_codec TEXT NOT NULL,
  state_version INTEGER NOT NULL CHECK (state_version > 0),
  state_bytes BLOB NOT NULL,
  created_ms INTEGER NOT NULL CHECK (created_ms >= 0),
  compacted_delta_count INTEGER NOT NULL CHECK (compacted_delta_count >= 0),
  base_sequence INTEGER NOT NULL CHECK (base_sequence >= 0),
  base_delta_hash BLOB CHECK (base_delta_hash IS NULL OR length(base_delta_hash) = 32),
  retained_genesis_hash BLOB NOT NULL CHECK (length(retained_genesis_hash) = 32),
  inserted_at_ms INTEGER NOT NULL CHECK (inserted_at_ms >= 0),
  PRIMARY KEY (did, snapshot_hash),
  FOREIGN KEY (did) REFERENCES documents(did) ON DELETE CASCADE
);

CREATE INDEX snapshots_by_did_base_sequence
  ON snapshots(did, base_sequence);
```

Required metadata keys:

| Key | Value |
|---|---|
| `store.kind` | `sqlite` |
| `store.schema_version` | `1` |
| `store.created_by` | crate name and semantic version |
| `store.created_at_ms` | Unix millisecond timestamp |
| `store.state_codec.default` | `did-crdt.document-state.cbor.v1` |
| `store.delta_codec.default` | `did-crdt.signed-delta.canonical-json.v1` |

Pre-conditions:

- `PRAGMA foreign_keys = ON` is set for every SQLite connection.
- `PRAGMA journal_mode = WAL` is set during database initialisation.
- `PRAGMA busy_timeout` is set from configuration before serving traffic.

Post-conditions:

- Every document has at least one delta row.
- Every delta row belongs to an existing document.
- Delta admission order is recoverable from `(did, sequence)`.
- The latest document row identifies the latest accepted delta hash.

Error model:

- Schema migration failure prevents service startup.
- Constraint violation during create or delta admission rolls back the full
  transaction.
- Hash length violations indicate programmer error and are fatal in tests.

Implements:
- REQ-036
- REQ-037
- REQ-038
- REQ-040
- REQ-041
- REQ-042
- REQ-044
- REQ-045

Verified by:
- TEST-039
- TEST-040
- TEST-041
- TEST-042
- TEST-043
- TEST-044
- TEST-045
- TEST-049

### CON-007: SQLite Write Transaction Protocol

Endpoint/Interface: Store-internal create and delta-admission transactions.

Create transaction:

```text
BEGIN IMMEDIATE;
  assert documents.did does not exist;
  encode genesis SignedDelta as canonical JSON;
  delta_hash = BLAKE3(delta_bytes);
  encode materialized Document state as did-crdt.document-state.cbor.v1;
  state_hash = BLAKE3(state_bytes);
  INSERT documents(... delta_count = 1, latest_delta_hash = delta_hash ...);
  INSERT deltas(... sequence = 0, is_genesis = 1, state_hash_after = state_hash ...);
COMMIT;
```

Delta admission transaction:

```text
BEGIN IMMEDIATE;
  encode incoming SignedDelta as canonical JSON;
  delta_hash = BLAKE3(delta_bytes);
  if deltas(did, delta_hash) exists:
      return Duplicate after COMMIT or ROLLBACK with no mutation;
  SELECT state_bytes, delta_count FROM documents WHERE did = ?;
  if no document:
      ROLLBACK and return UnknownDid;
  decode materialized Document state;
  call Document::merge(delta) in the pure core;
  if merge rejects:
      ROLLBACK and return DeltaRejected;
  next_sequence = documents.delta_count;
  encode updated Document state;
  state_hash = BLAKE3(state_bytes);
  INSERT deltas(... sequence = next_sequence, state_hash_after = state_hash ...);
  UPDATE documents SET state_bytes = ?, state_hash = ?, delta_count = delta_count + 1,
      latest_delta_hash = delta_hash, updated_ms = ?, version_id = ?, deactivated = ?,
      stored_at_ms = ? WHERE did = ?;
COMMIT;
```

Pre-conditions:

- Incoming delta size has passed ADR-004 limits before or during merge.
- The transaction is opened with `BEGIN IMMEDIATE` to obtain the write lock
  before decoding and merging state.

Post-conditions:

- A successful HTTP acknowledgement always corresponds to a committed SQLite
  transaction.
- Rejected deltas leave no document, delta, or snapshot mutation.
- Duplicate deltas leave no document, delta, or snapshot mutation.
- `documents.delta_count` equals the number of rows in `deltas` for that DID.

Error model:

- SQLite busy timeout returns `StorageUnavailable`.
- Decode failure returns `CodecError` and increments storage error metrics.
- Hash mismatch returns `IntegrityError`; the DID is not resolved until repaired
  or rebuilt.

Implements:
- REQ-036
- REQ-037
- REQ-038
- REQ-041

Verified by:
- TEST-040
- TEST-041
- TEST-042
- TEST-048

### CON-008: Configuration Contract

Endpoint/Interface: Environment variables and service startup configuration.

| Variable | Values | Default | Meaning |
|---|---|---|---|
| `DID_CRDT_STORAGE` | `memory`, `sqlite` | `memory` unless `STORAGE_PATH` is set | Selects backend |
| `STORAGE_PATH` | filesystem path | unset | SQLite file path when SQLite storage is enabled |
| `SQLITE_SYNCHRONOUS` | `normal`, `full` | `normal` | Durability/performance trade-off |
| `SQLITE_BUSY_TIMEOUT_MS` | integer | `5000` | Wait time for write lock |
| `SQLITE_CACHE_SIZE_KIB` | integer | `8192` | SQLite page cache budget |
| `SQLITE_AUTO_MIGRATE` | `true`, `false` | `true` | Whether startup applies migrations |
| `SQLITE_INTEGRITY_CHECK_ON_START` | `false`, `quick`, `full` | `false` | Optional startup validation depth |

Required SQLite pragmas:

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL; -- or FULL when SQLITE_SYNCHRONOUS=full
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = <SQLITE_BUSY_TIMEOUT_MS>;
PRAGMA temp_store = MEMORY;
PRAGMA cache_size = -<SQLITE_CACHE_SIZE_KIB>;
```

Pre-conditions:

- `DID_CRDT_STORAGE=sqlite` requires `STORAGE_PATH`.
- Parent directory for `STORAGE_PATH` must exist and be writable by the service
  user.

Post-conditions:

- Explicit SQLite configuration never silently falls back to memory mode.
- Memory mode remains available for demos and tests.
- Startup logs identify backend, path, schema version, synchronous mode, and
  migration result.

Error model:

- Missing path with explicit SQLite returns startup configuration error.
- Open, migration, pragma, or integrity-check failure returns startup failure.

Implements:
- REQ-035
- REQ-042
- REQ-045
- REQ-046

Verified by:
- TEST-045
- TEST-049
- TEST-051

### CON-009: State and Delta Codecs

Endpoint/Interface: Store-internal byte formats.

Delta codec:

```text
name: did-crdt.signed-delta.canonical-json.v1
input: SignedDelta
bytes: canonical JSON of the full SignedDelta, including proof
hash: BLAKE3(bytes)
purpose: audit, deduplication, sync export, replay input
```

State codec:

```rust
pub struct DocumentStateV1 {
    pub did: Did,
    pub verification_methods: VerificationMethods,
    pub service_endpoints: ServiceEndpoints,
    pub document_data: DocumentData,
    pub active_key: ActiveKey,
    pub revocations: Revocations,
    pub revoked_verification_methods: RevokedVerificationMethods,
    pub deactivated: Deactivated,
    pub created_ms: Option<u64>,
    pub updated_ms: Option<u64>,
}
```

```text
name: did-crdt.document-state.cbor.v1
input: DocumentStateV1
bytes: deterministic CBOR encoding of DocumentStateV1
hash: BLAKE3(bytes)
purpose: fast point lookup and future delta admission
excluded: per-replica in-memory delta_log, runtime caches, HTTP metadata
```

Pre-conditions:

- `DocumentStateV1` must contain enough information to continue accepting
  future deltas without replaying historical deltas.
- Codec implementation belongs outside the pure core if it depends on optional
  storage dependencies; pure conversion functions may live in a feature-gated
  module.

Post-conditions:

- Encoding then decoding a `DocumentStateV1` produces a document that resolves
  identically and accepts the same valid future delta as the original document.
- Canonical delta bytes can be deserialised into `SignedDelta` and re-hashed to
  the stored `delta_hash`.

Error model:

- Unknown codec label returns `CodecError`.
- Decode failure returns `CodecError`.
- Hash mismatch returns `IntegrityError`.

Implements:
- REQ-037
- REQ-040
- REQ-041

Verified by:
- TEST-043
- TEST-048
- TEST-052

### CON-010: HTTP Behaviour With Persistent Storage

Endpoint/Interface: Existing HTTP service routes.

`POST /dids`

- Builds the document and genesis delta using the pure core.
- Calls `DocumentStore::create_document`.
- Returns `201 Created` only after commit.
- Returns `409 Conflict` if the DID already exists.

`GET /{did}`

- Calls `DocumentStore::get_document`.
- Returns the same DID Resolution envelope as CON-003.
- Returns `404 Not Found` if the DID is absent.
- Returns a storage error response if bytes fail integrity validation.

`POST /dids/{did}/deltas`

- Parses `SignedDelta`.
- Calls `DocumentStore::admit_delta`.
- Returns `202 Accepted` after commit.
- Returns `202 Accepted` with duplicate metadata for an already accepted delta.
- Returns `404 Not Found` for an unknown target DID.
- Returns `400`, `403`, or `409` for invalid, unauthorised, or rejected deltas
  as defined by the existing service contract.

`GET /metrics`

- Includes storage metrics from OBS-007 through OBS-013 when SQLite is active.

Pre-conditions:

- HTTP handlers do not directly know whether the backend is memory or SQLite.

Post-conditions:

- Existing API clients do not need to change to benefit from persistence.
- Response acknowledgement means the storage backend has completed its write
  contract.

Error model:

- Storage backend errors map to `503 Service Unavailable` unless they indicate
  local corruption, which maps to `500 Internal Server Error` and increments
  integrity metrics.

Implements:
- REQ-035
- REQ-036
- REQ-037
- REQ-039
- REQ-043

Verified by:
- TEST-039
- TEST-040
- TEST-050

---

## 9. Purity Boundary Map

### Pure Core (no I/O, no shared state, deterministic)

- `src/core/document.rs`: creates, merges, resolves, and hashes DID document
  CRDT state.
- `src/core/delta.rs`: defines `SignedDelta`, signing input, HLC-bearing
  operations, and canonical JSON logic.
- `src/core/crdt.rs`: defines merge-sufficient CRDT field wrappers.
- `DocumentStateV1` conversion functions, if implemented without SQLite or
  filesystem dependencies.

### Effectful Shell (orchestrates I/O, calls pure core)

- `src/service/store/mod.rs`: backend trait, errors, stats, health contracts.
- `src/service/store/memory.rs`: in-memory implementation for tests and demos.
- `src/service/store/sqlite.rs`: SQLite connection management, transactions,
  migrations, pragmas, and backup hooks.
- `src/service/handlers.rs`: HTTP parsing and response mapping.
- `src/service/metrics.rs`: Prometheus counters, gauges, and histograms.

### Boundary Contracts

- `SignedDelta` crosses from HTTP body into pure validation and merge.
- `Document` crosses from pure core into store encoding.
- `DocumentStateV1` crosses between pure state and SQLite BLOB storage.
- `StoredDelta` crosses from SQLite rows into sync, audit, and rebuild paths.
- `StoreStats` crosses from store into metrics.

### Dependency Rule

Dependencies point inward: service/store -> core. Core MUST NOT import
`rusqlite`, `tokio`, `axum`, filesystem APIs, environment APIs, or SQLite
types.

### Enforcement

- `storage-sqlite` is an optional Cargo feature.
- `cargo build --no-default-features` compiles the pure core without SQLite.
- `cargo build --features service` compiles memory-backed HTTP service.
- `cargo build --features service,storage-sqlite` compiles persistent service.
- Code review rejects imports from `src/core` to `src/service` or SQLite crates.

---

## 10. Verification Strategy

| Component | Technique | Rationale |
|---|---|---|
| Codec roundtrip | Property-based testing | Stored state must survive arbitrary valid CRDT internals, including service OR-Sets with actor-keyed context. |
| Delta deduplication | Example-based integration testing | Exact duplicate behaviour is contractual and maps to SQL uniqueness. |
| Create and delta transactions | Integration testing with real SQLite | Atomicity must be verified against the real database engine, not mocks. |
| Rebuild from deltas | Property-based testing plus integration testing | For any accepted delta sequence, replay should reproduce stored state. |
| Migration | Example-based migration tests | Schema version transitions are finite and explicit. |
| Corruption detection | Fault-injection tests | Hash mismatches and truncated bytes must fail closed. |
| Performance and saturation | Benchmarks | Cheap-node capacity depends on measured memory, disk bytes, and latency. |
| HTTP compatibility | Integration tests | Persistence must not break CON-003 response semantics. |

---

## 11. Test Specifications

### TEST-039: DID Creation Survives Restart

Scenario:

1. Open a temporary SQLite database.
2. Start the service with SQLite storage.
3. `POST /dids` with a valid public key.
4. Capture the returned DID and resolution result.
5. Drop service state and close all connections.
6. Reopen the same SQLite database.
7. `GET /{did}`.
8. Assert the DID resolves and resolution metadata matches the pre-restart
   document version.

Verifies:
- REQ-035
- REQ-036

### TEST-040: Accepted Delta Survives Restart

Scenario:

1. Create a DID in SQLite mode.
2. Submit a valid signed `AddServiceEndpoint` or `SetDocumentData` delta.
3. Assert `POST /dids/{did}/deltas` returns `202 Accepted`.
4. Restart the service.
5. Resolve the DID.
6. Assert the resolved document includes the delta effect.
7. Assert one non-genesis row exists in `deltas`.

Verifies:
- REQ-037

### TEST-041: Create and Delta Writes Are Atomic

Scenario:

1. Run create and delta-admission paths against a test SQLite store that can
   inject an error between document update and delta insert.
2. Force failure after each internal write step.
3. Reopen the database after each forced failure.
4. Assert there is no document row without genesis delta and no accepted delta
   row whose `state_hash_after` is not reflected by the document row.

Verifies:
- REQ-036
- REQ-037
- NFR-008

### TEST-042: Duplicate Delta Is Idempotent

Scenario:

1. Create a DID.
2. Submit a valid delta.
3. Submit the exact same canonical delta bytes again.
4. Assert the second submission returns duplicate/accepted semantics.
5. Assert `deltas` row count and `documents.delta_count` did not change.
6. Assert state hash did not change.

Verifies:
- REQ-038

### TEST-043: Rebuild From Accepted Deltas

Property:

For all valid accepted delta sequences for one DID, replaying persisted deltas
ordered by `(did, sequence)` produces a document whose state hash and resolved
document match the materialized `documents` row.

Generator:

- DID with genesis delta.
- 1 to 200 valid deltas over verification methods, service endpoints,
  document data, key rotation, revocation, and deactivation where causally
  prior signing keys are available.

Assertion:

- `rebuild_document(did).resolve() == get_document(did).resolve()`.
- Re-encoded rebuild state hash equals `documents.state_hash`.

Verifies:
- REQ-040
- REQ-044

### TEST-044: Snapshot Persistence and Genesis Retention

Scenario:

1. Create a DID.
2. Apply more deltas than the compaction threshold.
3. Trigger compaction.
4. Assert a snapshot row exists.
5. Assert the genesis delta remains in `deltas`.
6. Assert accepted deltas are not pruned by default.
7. Assert resolution after restart matches resolution before restart.

Verifies:
- REQ-041

### TEST-045: Schema Migration Is Forward-Only

Scenario:

1. Create a version 0 or empty database fixture.
2. Start the SQLite store with auto-migration enabled.
3. Assert all version 1 tables, indexes, metadata, and `user_version` exist.
4. Restart with auto-migration disabled.
5. Assert startup succeeds when schema is current.
6. Start with an intentionally future `user_version`.
7. Assert startup fails safely.

Verifies:
- REQ-042

### TEST-046: Concurrent Readers and Single Writer

Scenario:

1. Create a database with 10,000 DIDs.
2. Run concurrent resolution requests while one writer admits deltas.
3. Assert read requests either see the old committed state or new committed
   state, never a partial transaction.
4. Assert no request blocks beyond configured busy timeout except the writer
   that owns the SQLite write lock.

Verifies:
- NFR-009
- NFR-010
- NFR-011

### TEST-047: SQLite Saturation and Cost Benchmark

Scenario:

1. Create 100,000 small DIDs in SQLite mode.
2. Record create throughput, p95 write latency, database bytes, WAL bytes, and
   resident memory.
3. Resolve 10,000 randomly sampled DIDs.
4. Record p95 read latency and resident memory.
5. Checkpoint WAL.
6. Calculate bytes per DID and bytes per accepted delta.

Assertions:

- Memory remains bounded by configured page cache and does not scale linearly
  with document count.
- NFR-010, NFR-011, and NFR-012 thresholds hold on the benchmark machine.

Verifies:
- REQ-039
- NFR-009
- NFR-010
- NFR-011
- NFR-012

### TEST-048: Corruption Detection Fails Closed

Scenario:

1. Create a DID and accepted delta.
2. Stop the service.
3. Modify one byte in `documents.state_bytes` without updating `state_hash`.
4. Restart the service.
5. Attempt to resolve the DID.
6. Assert the store returns `IntegrityError` and does not serve corrupted state.
7. Run rebuild from deltas.
8. Assert rebuild can repair or report the mismatch explicitly.

Verifies:
- REQ-040
- NFR-014

### TEST-049: Backup and Restore Integrity

Scenario:

1. Create a database with documents, deltas, and snapshots.
2. Run the documented online backup procedure.
3. Restore into a new database path.
4. Open the restored database.
5. Run rebuild integrity verification for a sample and full count verification
   for all rows.
6. Assert document count, delta count, snapshot count, and sampled state hashes
   match the source database.

Verifies:
- REQ-045

### TEST-050: HTTP API Compatibility

Scenario:

1. Run the existing CON-003 HTTP integration tests against memory storage.
2. Run the same tests against SQLite storage.
3. Assert response status codes, JSON shape, and resolution metadata semantics
   are identical except for persistence across restart.

Verifies:
- REQ-043

### TEST-051: Startup Configuration Failures

Scenario:

1. Start with `DID_CRDT_STORAGE=sqlite` and no `STORAGE_PATH`.
2. Assert startup fails.
3. Start with `STORAGE_PATH` pointing to an unwritable directory.
4. Assert startup fails.
5. Start with neither `DID_CRDT_STORAGE` nor `STORAGE_PATH`.
6. Assert memory mode starts.

Verifies:
- REQ-046
- NFR-013

### TEST-052: State Codec Handles OR-Set Internals

Property:

For all documents containing service endpoint add/remove history from multiple
actors, encoding and decoding `DocumentStateV1` with
`did-crdt.document-state.cbor.v1` preserves future merge behaviour.

Generator:

- One DID.
- 2 to 10 actor node IDs.
- 1 to 100 service endpoint add/remove deltas and document data deltas.

Assertion:

- Decoded document resolves identically to the original.
- A valid future delta accepted by the original is accepted by the decoded
  document and produces the same resolved state.

Verifies:
- CON-009

---

## 12. Observability

### OBS-007: Stored Document Count

Metric: Gauge `did_crdt_store_documents_total`.

Labels: `backend`.

Meaning: Number of rows in `documents`.

Alert: Unexpected drop below previous durable count after restart.

Trace:
- REQ-035

### OBS-008: Stored Delta Count

Metric: Gauge `did_crdt_store_deltas_total`.

Labels: `backend`.

Meaning: Number of accepted delta rows.

Alert: Delta count decreases without an explicit pruning operation.

Trace:
- REQ-037
- REQ-038

### OBS-009: Storage Write Latency

Metric: Histogram `did_crdt_store_write_seconds`.

Labels: `backend`, `operation`, `outcome`.

Operations: `create_document`, `admit_delta`, `snapshot`, `migration`.

Alert: p95 write latency > 100 ms for 5 minutes.

Trace:
- REQ-036
- REQ-037
- NFR-011

### OBS-010: Storage Read Latency

Metric: Histogram `did_crdt_store_read_seconds`.

Labels: `backend`, `operation`, `outcome`.

Operations: `get_document`, `list_deltas`, `stats`, `health`.

Alert: p95 `get_document` latency > 25 ms for 5 minutes.

Trace:
- REQ-039
- NFR-010

### OBS-011: SQLite Disk and Cache Size

Metric: Gauges:

- `did_crdt_store_database_bytes`
- `did_crdt_store_wal_bytes`
- `did_crdt_store_page_cache_bytes`

Labels: `backend`.

Alert: Database plus WAL exceeds configured storage budget.

Trace:
- REQ-041
- NFR-009
- NFR-012

### OBS-012: Storage Error Count

Metric: Counter `did_crdt_store_errors_total`.

Labels: `backend`, `operation`, `reason`.

Reasons: `busy_timeout`, `constraint`, `codec`, `integrity`, `migration`,
`open`, `permission`, `unavailable`.

Alert: Any `integrity` error or sustained `busy_timeout` errors.

Trace:
- REQ-042
- REQ-046
- NFR-008

### OBS-013: Rebuild and Integrity Verification

Metrics:

- Histogram `did_crdt_store_rebuild_seconds`.
- Counter `did_crdt_store_integrity_checks_total`.
- Counter `did_crdt_store_integrity_failures_total`.

Labels: `backend`, `scope`, `outcome`.

Alert: Any integrity failure.

Trace:
- REQ-040
- REQ-045
- NFR-013
- NFR-014

---

## 13. Security, Privacy, and Failure Modes

| Failure mode | Mitigation | Trace |
|---|---|---|
| Acknowledged delta lost on crash | Commit SQLite transaction before `202 Accepted`; test crash windows | REQ-037, TEST-041 |
| Delta row without matching state | Single transaction and foreign keys | CON-006, CON-007 |
| State row corrupted on disk | BLAKE3 `state_hash`; fail closed; rebuild from deltas | REQ-040, TEST-048 |
| Duplicate delta inflates cost | Unique `(did, delta_hash)` and duplicate outcome | REQ-038, TEST-042 |
| HTTP runtime starvation | Blocking SQLite boundary | ADR-009 |
| Unbounded memory from preload | Point lookup by primary key; no startup full scan | REQ-039, NFR-009 |
| Rejected malicious payloads fill disk | Do not persist rejected deltas by default | Privacy notes |
| Backup captures partial write | Use SQLite online backup or checkpointed copy procedure | REQ-045 |
| Future codec cannot read old rows | Store codec labels and schema migrations | CON-006, CON-009 |
| Operator thinks memory fallback is durable | Explicit SQLite failures abort startup | REQ-046 |

---

## 14. Traceability Matrix

| Artifact | Contracts | Tests | Observability |
|---|---|---|---|
| REQ-035 SQLite Storage Mode | CON-005, CON-008, CON-010 | TEST-039 | OBS-007 |
| REQ-036 Durable DID Creation | CON-006, CON-007, CON-010 | TEST-039, TEST-041 | OBS-009 |
| REQ-037 Durable Delta Admission | CON-006, CON-007, CON-009, CON-010 | TEST-040, TEST-041 | OBS-008, OBS-009 |
| REQ-038 Delta Deduplication | CON-006, CON-007 | TEST-042 | OBS-008 |
| REQ-039 Point Lookup Resolution | CON-005, CON-006, CON-010 | TEST-047 | OBS-010 |
| REQ-040 Rebuild From Deltas | CON-005, CON-006, CON-009 | TEST-043, TEST-048 | OBS-013 |
| REQ-041 Snapshot Compatibility | CON-006, CON-007, CON-009 | TEST-044 | OBS-011 |
| REQ-042 Schema Migration | CON-006, CON-008 | TEST-045 | OBS-012 |
| REQ-043 Storage Backend Abstraction | CON-005, CON-010 | TEST-050 | Existing HTTP metrics |
| REQ-044 Delta Listing | CON-005, CON-006 | TEST-043, TEST-049 | OBS-010 |
| REQ-045 Backup and Restore | CON-006, CON-008 | TEST-049 | OBS-013 |
| REQ-046 Startup Failure Semantics | CON-008 | TEST-051 | OBS-012 |
| NFR-008 Durability | CON-007, CON-008 | TEST-041 | OBS-012 |
| NFR-009 Bounded Memory | CON-005, CON-006 | TEST-046, TEST-047 | OBS-011 |
| NFR-010 Resolution Latency | CON-005, CON-006 | TEST-046, TEST-047 | OBS-010 |
| NFR-011 Write Throughput | CON-007 | TEST-046, TEST-047 | OBS-009 |
| NFR-012 Storage Efficiency | CON-006 | TEST-047 | OBS-011 |
| NFR-013 Startup Time | CON-008 | TEST-051 | OBS-013 |
| NFR-014 Integrity Detection | CON-009 | TEST-048 | OBS-013 |

---

## 15. Implementation Plan

### Phase 1: Store Abstraction and Memory Parity

1. Introduce `src/service/store/mod.rs` with `DocumentStore`, store errors,
   stats, and health types.
2. Move the current `Arc<RwLock<HashMap<String, Document>>>` behaviour behind
   `MemoryStore`.
3. Update HTTP handlers to depend on `Arc<dyn DocumentStore>`.
4. Run existing service tests against `MemoryStore`.

Quality gate:

- Existing HTTP tests pass with no SQLite feature enabled.

### Phase 2: Codecs and SQLite Schema

1. Add `storage-sqlite` feature and SQLite dependencies.
2. Implement canonical full-delta encoding and BLAKE3 delta hashing.
3. Implement `DocumentStateV1` conversion and CBOR encoding.
4. Add migrations for CON-006 schema.
5. Add SQLite open, pragma, health, stats, and migration code.

Quality gate:

- TEST-052 proves state codec roundtrip for OR-Set internals.
- TEST-045 proves migration behaviour.

### Phase 3: Durable Create, Resolve, and Delta Admission

1. Implement `SqliteStore::create_document`.
2. Implement `SqliteStore::get_document`.
3. Implement `SqliteStore::admit_delta`.
4. Wire startup configuration and explicit failure semantics.
5. Add persistence integration tests.

Quality gate:

- TEST-039 through TEST-042 pass.
- Existing CON-003 HTTP tests pass against both stores.

### Phase 4: Delta Listing, Rebuild, Integrity, and Backup

1. Implement `list_deltas`.
2. Implement `rebuild_document`.
3. Add state hash verification before resolution.
4. Document SQLite backup and restore procedure.
5. Add integrity and backup tests.

Quality gate:

- TEST-043, TEST-048, and TEST-049 pass.

### Phase 5: Saturation and Operational Metrics

1. Add storage metrics OBS-007 through OBS-013.
2. Extend the existing saturation harness to support SQLite mode.
3. Measure creates, updates, random resolves, memory, and disk bytes.
4. Publish bytes-per-DID and bytes-per-delta results in the README or operator
   documentation.

Quality gate:

- TEST-047 produces repeatable capacity numbers for cheap-node planning.

---

## 16. Open Questions

1. **State codec crate:** This spec names deterministic CBOR as the required
   state envelope shape. Implementation must choose the exact Rust crate and
   deterministic encoding configuration before coding.
2. **Rejected delta quarantine:** Rejected deltas are not persisted by default.
   A later operator-facing forensics feature may add a bounded quarantine table
   with explicit disk limits.
3. **Signed snapshot pruning:** ADR-001 describes signed snapshots, but current
   code compacts into an internal `DocumentSnapshot`, not a signed snapshot
   delta. Until signed snapshot deltas exist, SQLite retains all accepted
   deltas by default.
4. **State-based sync ingestion:** This spec optimizes the HTTP delta path.
   Accepting full state from peers should remain separate because state blobs
   have weaker auditability than signed deltas.
5. **Read connection pool:** The first implementation may use one connection
   behind a blocking boundary. A later optimisation can add dedicated read
   connections if TEST-047 shows point lookups are bottlenecked.

---

## 17. Review Checklist

- [ ] All requirements are atomic and testable.
- [ ] Deltas are persisted and indexed independently from materialized state.
- [ ] `201` and `202` responses are defined as post-commit acknowledgements.
- [ ] SQLite mode cannot silently fall back to volatile memory.
- [ ] Pure core remains independent from SQLite and async runtime dependencies.
- [ ] JSON state serialization is not used as the durable internal-state
      contract.
- [ ] Rebuild and integrity paths are specified before implementation.
- [ ] Saturation testing measures disk-backed capacity, not only in-memory
      capacity.
