# ADR-003: Sybil Resistance

**Status:** Accepted
**Date:** 2026-03-10
**Deciders:** did:crdt core team

---

## Context

`did:crdt` has no blockchain or central registry. Any peer can broadcast a
creation delta that mints a new DID. Without a cost-of-creation mechanism,
adversaries can flood the gossip network with millions of spurious DIDs at near
zero cost, causing:

1. **Storage exhaustion** on honest nodes.
2. **Bandwidth exhaustion** as garbage deltas are gossiped.
3. **Pollution of discovery indices** (if any are built on top).

This is the classic **Sybil attack**: one entity masquerades as many peers to
gain disproportionate influence or to degrade the network.

We must choose a mechanism that imposes a meaningful creation cost without
reintroducing a centralised authority.

---

## Decision

We adopt a **layered defence** strategy that combines creation proof-of-work
with gossip-layer rate limiting. Neither alone is sufficient; together they
provide defence-in-depth.

### Layer 1 — Creation PoW

Every creation delta (the first delta for a DID, `seq = 0`) MUST include a
`pow_nonce` field such that:

```
SHA-256(genesis_delta_bytes || pow_nonce) has leading_zero_bits >= POW_DIFFICULTY
```

The `POW_DIFFICULTY` constant is set to **20 bits** in the initial
implementation (expected ~1 million hash iterations; ≈ 0.5 s on a modern
laptop).

**Rationale for PoW over PoS / fees:**
- No token or stake is required, keeping the system self-contained.
- 20-bit difficulty is negligible for human-scale DID creation but multiplies
  cost of batch-Sybil attacks by 2²⁰ ≈ 10⁶ per DID.
- Difficulty can be adjusted via a protocol constant without changing the
  schema.

**PoW does not apply to update deltas** (`seq > 0`). Only the creation event
carries the cost.

### Layer 2 — Gossip-layer rate limiting

Nodes MUST enforce per-IP creation rate limits:

| Window | Maximum new DID creations accepted |
|---|---|
| 1 minute | 5 |
| 1 hour | 50 |
| 24 hours | 200 |

These limits are enforced at the gossip ingress point. Nodes that exceed the
limit have their creation deltas silently dropped (not forwarded). The limits
are configurable via the node configuration file; the values above are the
recommended defaults.

**Note:** Rate limiting is a best-effort defence at the application layer and
can be bypassed by distributed botnets. It is a complement to PoW, not a
replacement.

### Layer 3 — Invitation codes (optional, operator-controlled)

For closed or semi-closed deployments (e.g., an enterprise identity namespace),
operators MAY enable an **invitation code** requirement. When enabled:
- A creation delta MUST include an `invitation_token` field.
- The token is a signed capability issued by a node the operator has designated
  as an inviter.
- Nodes in the namespace reject creation deltas without a valid token.

Invitation codes are off by default (open network mode). Operators who enable
them take responsibility for the invitation issuance flow.

---

## Consequences

**Positive:**
- PoW imposes a real but modest cost on legitimate DID creation (sub-second)
  while making bulk Sybil attacks expensive.
- Rate limiting prevents fast-path flooding even before PoW verification.
- Invitation codes give enterprise operators a hard gate when they need it,
  without affecting the default open-network use case.

**Negative / trade-offs:**
- 20-bit PoW is not a strong barrier for a well-resourced adversary with GPU
  farms; it delays rather than prevents nation-state-scale attacks.
- PoW adds a non-trivial latency to DID creation (≈ 0.5 s). Applications that
  create DIDs in bulk (e.g., automated device provisioning) will feel this cost.
  For such use cases, operators should consider pre-computing PoW or using
  invitation codes.
- Rate limits create friction for legitimate nodes on shared IP ranges (NAT,
  cloud VMs). Operators should whitelist known infrastructure IPs if needed.
- PoW verification adds CPU cost to gossip ingress; nodes processing high-volume
  creation floods will see elevated CPU usage.

---

## Alternatives Considered

| Alternative | Reason rejected |
|---|---|
| No Sybil resistance | Unacceptable: trivially exploitable |
| Blockchain-based registration fee | External dependency; contradicts self-contained design |
| Stake-based admission | Requires a token economy; out of scope |
| Pure rate limiting (no PoW) | Bypassable with distributed source IPs; insufficient alone |
| Invitation-only (no PoW) | Unacceptable for the default open-network case |
| High difficulty PoW (28+ bits) | Legitimate creation latency becomes user-visible (> 30 s) |
