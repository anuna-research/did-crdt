# ADR-002: Key Compromise Recovery

**Status:** Accepted
**Date:** 2026-03-10
**Deciders:** did:crdt core team

---

## Context

`did:crdt` uses a sequence-number-based Last-Write-Wins (LWW) register for the
`controller` field: the delta with the highest `seq` wins a conflict. This
design works well under normal operation but creates an attack surface when a
private key is stolen:

> An attacker who compromises the controller key can issue a rotation delta with
> `seq = current_seq + 1`, replacing the legitimate holder's key with their own.
> The legitimate holder cannot simply re-issue a rotation at a higher seq — the
> attacker can always respond with `seq + 2`.

This is sometimes called the **seq-race attack**. A recovery mechanism must
break the cycle without reintroducing a trusted authority.

---

## Decision

We adopt a **recovery key with time-lock** model.

### Recovery key

When a DID is created (or at any point thereafter), the controller MAY register
one or more **recovery keys** in a special `recovery_method` field:

```json
"recovery_method": [
  {
    "id": "#recovery-1",
    "type": "Ed25519VerificationKey2020",
    "publicKeyMultibase": "z..."
  }
]
```

Recovery keys are:
- Stored in the CRDT document but are **not** listed in `verificationMethod`
  (they confer no ordinary signing authority).
- Ideally kept in cold storage, separate from operational keys.
- Optionally M-of-N threshold (see below).

### Recovery delta

A **recovery delta** is a special delta with `delta_type = Recovery`. It:
1. Contains a new controller key (the replacement).
2. Is signed by a registered recovery key.
3. Carries a `not_before` timestamp that is at least `recovery_delay` seconds in
   the future (default: **48 hours**).

### Time-lock (challenge period)

Nodes that receive a recovery delta enter a **challenge period** equal to the
`recovery_delay`. During this window:
- The recovery delta is gossiped but not yet applied to the resolved state.
- The *current* controller can issue a **recovery cancel** delta (signed by the
  current controller key) that permanently invalidates the pending recovery for
  that `recovery_seq`.
- If no cancel arrives before `not_before`, nodes apply the recovery delta,
  replacing the controller key.

This gives a legitimate holder who has not been displaced a window to cancel a
fraudulent recovery. An attacker who has stolen *only* the operational key (but
not the recovery key) cannot initiate recovery; an attacker who has stolen
*both* is a total compromise and out of scope.

### M-of-N recovery (optional)

The `recovery_method` field MAY contain multiple keys with a `threshold`
annotation:

```json
"recovery_method": {
  "threshold": 2,
  "keys": ["#recovery-1", "#recovery-2", "#recovery-3"]
}
```

A recovery delta with threshold > 1 MUST carry `threshold` independent
signatures. This enables social recovery (trusted contacts each hold one shard)
without a central recovery service.

### Validator changes

`validate.rs` MUST enforce:
1. Only a registered recovery key (or M-of-N threshold) may sign a recovery
   delta.
2. `not_before > received_at + MIN_RECOVERY_DELAY` (MIN_RECOVERY_DELAY = 48h,
   configurable).
3. A cancel delta must be signed by the key that was controller at the time the
   recovery delta was received.
4. At most one pending recovery per DID at any time (simplifies conflict
   resolution).

---

## Consequences

**Positive:**
- An attacker who steals only the operational key cannot permanently hijack the
  DID as long as the recovery key is uncompromised.
- The 48-hour challenge window is visible in the gossip network; monitoring can
  alert the legitimate owner.
- M-of-N threshold recovery eliminates single-point-of-failure for recovery
  keys.

**Negative / trade-offs:**
- Recovery adds implementation complexity to `validate.rs` and the gossip
  protocol.
- The 48-hour window is a UX penalty in legitimate "lost device" scenarios;
  users must wait before the new key is accepted.
- If both the operational key and the recovery key are compromised simultaneously
  the DID is unrecoverable (total key loss). Operators should document this
  clearly and encourage hardware security keys for recovery.
- Nodes must maintain a pending-recovery store; this is additional state to
  manage and back up.

---

## Alternatives Considered

| Alternative | Reason rejected |
|---|---|
| No recovery (immutable controller after first set) | Unacceptable UX: lost device = permanently inaccessible DID |
| Social recovery without time-lock | Collusion between recovery parties can immediately hijack a DID without the owner noticing |
| Blockchain-anchored revocation | Reintroduces dependency on external consensus; contradicts the design goal of a self-contained CRDT |
| Revocation authority / CA model | Centralised trust; eliminated from the design from the start |
| Seq-cap (controller can never go above a seq limit) | Stops re-registration but doesn't help once an attacker has a key |
