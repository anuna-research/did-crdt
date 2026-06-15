# ADR-004: State Size Limits

**Status:** Accepted
**Date:** 2026-03-10
**Deciders:** did:crdt core team

---

## Context

A `did:crdt` document can accumulate state indefinitely:
- OR-Set collections (`service`, `verification_method`) can grow without a
  natural ceiling.
- LWW-Register values can be replaced with arbitrarily large payloads.
- Even after compaction (see ADR-001), the *current* merged state may be very
  large if a document contains thousands of fields.

Without limits, a single misbehaving (or compromised) controller can create a
document that:
1. Exhausts memory during resolution.
2. Causes downstream parsers to allocate unbounded buffers.
3. Degrades gossip performance for all peers.

The question is whether limits belong in the library (`validate.rs`) or are a
policy decision for the service layer.

---

## Decision

**Limits are enforced in the library**, not pushed entirely to the service layer.
The library provides safe defaults that protect any embedding application, while
allowing operators to tighten (but not loosen beyond a hard cap) the limits via
configuration.

### Field-level limits (per document, enforced in `validate.rs`)

| Field | Default limit | Hard maximum |
|---|---|---|
| `verification_method` count | 20 | 100 |
| `service` count | 20 | 100 |
| `also_known_as` count | 10 | 50 |
| `controller` list length | 5 | 20 |
| Any single field value (bytes) | 4 KiB | 64 KiB |
| Total serialised document state | 256 KiB | 1 MiB |

**Definitions:**
- *Default limit*: enforced unless the operator overrides via `SizeLimits`
  config. Overrides must be ≤ the hard maximum.
- *Hard maximum*: absolute ceiling enforced unconditionally in the library.
  No configuration can exceed it.

### Delta-level limits (per incoming delta)

| Property | Limit |
|---|---|
| Maximum serialised delta size | 64 KiB |
| Maximum number of field mutations in one delta | 50 |

Deltas that exceed these limits are rejected at ingress before deserialization
completes (to prevent zip-bomb-style attacks).

### Enforcement point

Limits are checked in two places:

1. **`validate_delta()`** — checks per-delta limits before the delta is merged.
2. **`validate_document()`** — checks post-merge document limits after applying
   a delta. If applying a valid-looking delta would push the document past a
   limit, the delta is rejected.

Both functions return `ValidationError::SizeLimitExceeded` with a human-readable
description of which limit was violated.

### Observability

The existing `OBS-006` metric (`crdt_state_size_bytes`) is the primary signal.
A new counter `crdt_delta_rejected_size_total` is added to track how often
size-limit rejections occur in production.

---

## Consequences

**Positive:**
- Every application embedding the library is protected by default; no
  service-layer boilerplate required.
- The hard maximum prevents a misconfigured or malicious service layer from
  opening the library to DoS.
- Limits are explicit and auditable in one place (`validate.rs`).

**Negative / trade-offs:**
- The limits are somewhat arbitrary; real-world usage may hit them for legitimate
  documents (e.g., an IoT fleet DID with 50+ service endpoints). Operators for
  such use cases must explicitly raise the configuration limits.
- Enforcing limits post-merge means the library must complete the merge before
  deciding to reject; this is O(1) extra work but not zero.
- Hard maxima are baked into the library ABI. Raising a hard maximum requires a
  library version bump — this is intentional (it forces a deliberate decision)
  but may cause friction.

---

## Alternatives Considered

| Alternative | Reason rejected |
|---|---|
| No library limits (policy only) | Any embedding application that omits policy limits is vulnerable; unsafe default |
| Soft limits only (advisory, not enforced) | Too easy to ignore; provides no actual protection |
| Per-byte metering (gas model) | Over-engineered for this use case; adds significant complexity |
| Single global document size limit only | Per-field limits give finer-grained rejection messages and are more useful for debugging |
