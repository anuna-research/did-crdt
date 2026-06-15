# ADR-001: Compaction and Garbage Collection Strategy

**Status:** Accepted
**Date:** 2026-03-10
**Deciders:** did:crdt core team

---

## Context

The `did:crdt` document model is built on a delta-CRDT where every mutation is
appended as a signed delta. Because CRDTs require monotonic growth (no
information may be silently discarded without breaking convergence), state grows
without bound over a document's lifetime. For long-lived DIDs — particularly
ones that rotate keys frequently or accumulate many service endpoints — this
creates two concrete problems:

1. **Resolution cost.** Replaying an unbounded delta log to reconstruct the
   current state is O(n) in the number of deltas, and network transfer of the
   full log grows proportionally.
2. **Storage cost.** Gossip-layer nodes (iroh-blobs) must store the full history
   of every document they replicate.

The core CRDT data structures in use are:
- **LWW-Register** for `controller`, `also_known_as`, and each service/VM field.
- **OR-Set** for `service` and `verification_method` collections.

OR-Sets accumulate tombstones when elements are removed; LWW-Registers
accumulate superseded values.

---

## Decision

We adopt a **two-tier compaction model**:

### Tier 1 — Snapshot compaction (periodic)

At configurable intervals (default: every 128 deltas *or* when state exceeds
512 KiB, whichever comes first), a node MAY produce a **compacted snapshot**:

- The snapshot is the fully merged CRDT state at that point, serialised as a
  single signed delta with `delta_type = Snapshot`.
- All deltas with `seq ≤ snapshot_seq` MAY be discarded by any node that holds
  the snapshot.
- The snapshot MUST be signed by the current controller key(s) to be valid.
- Nodes that receive only the snapshot can reconstruct the current state without
  the prior delta chain.

**Tombstone retention rule:** Tombstones in the OR-Set MUST be retained in the
snapshot for a minimum of 72 hours (configurable via `tombstone_ttl`) after the
item was removed. This prevents removed elements from re-appearing if an older
delta propagates late. After the TTL expires the tombstone entry MAY be dropped
from future snapshots.

### Tier 2 — Incremental delta pruning (on read)

When resolving a document, the resolver SHOULD reconstruct from the most recent
valid snapshot plus only the deltas with `seq > snapshot_seq`. This bounds
resolution time to O(deltas since last snapshot) rather than O(all deltas).

### Snapshot validity

A snapshot is valid if and only if:
1. Its `signature` verifies against a key that was the controller at `snapshot_seq`.
2. Its `seq` is strictly greater than any previously accepted snapshot seq for
   the same DID.
3. The resulting merged state is semantically valid per `validate.rs`.

Nodes MUST reject snapshots that fail any of the above checks.

---

## Consequences

**Positive:**
- Resolution time is bounded to O(128) delta replays in the common case.
- Storage is bounded to ~512 KiB per DID in steady state (plus the rolling
  window of recent deltas).
- Compaction is optional: nodes that never compact remain fully correct; they
  simply pay higher resolution cost.

**Negative / trade-offs:**
- A compromised key can produce a fraudulent snapshot. Mitigated by the
  signature requirement and the key-rotation recovery path (see ADR-002).
- The 72-hour tombstone TTL is a heuristic; networks with extreme clock skew or
  very slow gossip propagation could still see re-insertion of removed elements.
  Operators MUST tune `tombstone_ttl` to exceed their worst-case gossip latency.
- Snapshot production and verification are not free; large documents may incur
  noticeable CPU cost at compaction time.

---

## Alternatives Considered

| Alternative | Reason rejected |
|---|---|
| No compaction (pure append-only) | State grows without bound; unacceptable for long-lived DIDs |
| Centralised checkpoint authority | Reintroduces trust assumptions we are trying to eliminate |
| Content-addressed DAG (like IPLD) | Significantly higher implementation complexity; deferred to Phase 3+ |
| Epoch-based full re-genesis | Breaks continuity of the DID identifier; violates DID Core spec |
