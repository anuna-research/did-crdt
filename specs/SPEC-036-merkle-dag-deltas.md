---
title: "SPEC-036: Merkle-DAG Deltas for did:crdt"
id: SPEC-036
version: 0.1.0
status: draft
created: 2026-06-04
last_updated: 2026-06-04
authors: Anuna Research
reviewers: Engineering, Security
audience: protocol designers, engineers
parent: SPEC-032
references:
  - "SPEC-032: did-crdt - Coordination-Free Decentralised Identifiers via Signed CRDTs"
  - "SPEC-035: Causal Commitment Levels and Three-Valued Delta Admission"
  - "CON-002: SignedDelta - Delta Format"
  - "cbcl-rs SPEC-003: Verification Lattice - Algebraic Foundations for Causal Protocol Checking"
  - "Sanjuan, Poyhtari, Teixeira, Psaras 2020: Merkle-CRDTs - Merkle-DAGs meet CRDTs"
  - "Kleppmann 2022: Making CRDTs Byzantine Fault Tolerant"
---

# SPEC-036: Merkle-DAG Deltas for did:crdt

| Field | Value |
|---|---|
| Document ID | SPEC-036 |
| Title | Merkle-DAG Deltas for did:crdt |
| Version | 0.1.0 |
| Status | Draft |
| Created | 2026-06-04 |
| Last Updated | 2026-06-04 |
| Authors | Anuna Research |
| Reviewers | Engineering, Security |
| Parent | SPEC-032 |

---

## 1. Executive Summary

This specification makes every `SignedDelta` commit to its causal predecessors
by content hash, turning a DID's delta history into a **Merkle DAG**. This single
structural change closes three gaps that SPEC-032 and SPEC-035 leave open:

1. **Revocation-ordering monotonicity (SPEC-035 §2.2 residual).** Whether a
   delta was authorised relative to a *later* revocation of its key becomes a
   query over the delta's content-fixed causal past `↓D`, not over mutable
   current state. This makes the `Revoked` case of `core::admission`
   (SPEC-035) monotone, completing the three-valued admission lattice.
2. **State-sync Byzantine fault tolerance (SPEC-032 §V future-work item 2).**
   `merge_state` can carry Merkle-inclusion proofs over the delta DAG, so a
   receiver verifies that injected state derives from a valid signed-delta chain.
   This closes the unauthenticated-`merge_state` hole SPEC-032 §IV flags.
3. **Reconciliation and cold-start discovery (reviewer-flagged networking gap).**
   Frontier exchange plus causal-closure transfer gives efficient anti-entropy
   and late-joiner sync, the "delta discovery" SPEC-032 §V describes as designed
   but unbuilt.

The Merkle DAG is a **native did-crdt construct and introduces no dependency on
cbcl-rs.** cbcl SPEC-003 is cited as prior art: did-crdt has already
re-implemented its lattice algebra natively (`core::admission`, SPEC-035), and
its Lean proofs MAY be *adapted* where that is cheaper than re-deriving them.
Convergence with cbcl on a shared substrate is opportunistic — pursued only where
it is advantageous, never required.

> **Not on the paper's critical path.** This is a research-program milestone, not
> part of the DAPPS 2026 revision (SPEC-035 §6). The paper's coordination-free
> claim stands on SPEC-035 Level 0 alone.

> **Tier-1 boundary.** The delta format, signature coverage, and causal-validity
> decision are Tier-1 (SPEC-032 §16): cross-model adversarial review and human
> sign-off before merge.

---

## 1a. Implementation Status (2026-06-04)

**Phase 1 is implemented** as four green increments (234 tests passing), with one
deliberate deviation:

| REQ | Status | Where |
|---|---|---|
| 360 Delta identity = content hash | ✅ implemented | `core::delta::{DeltaHash, SignedDelta::content_hash}` |
| 361 Parent commitment (sorted/deduped) | ✅ implemented | `SignedDelta::parents`, `new_with_parents` |
| 362 Causal closure | ✅ implemented | `core::dag::DeltaDag::closure_find` |
| 363 Causal authorisation | ⚠️ `verify_causal` used for the out-of-order `DeltaPending` signal only; **authorisation itself is current-state** (safety floor, see §1b) | `core::causal::verify_causal` |
| 364 Frontier | ✅ implemented | `DeltaDag` frontier tracking |
| 369 Signature covers parents | ✅ implemented | `SignedDelta::signing_input` |

**Deviation from D2.** DID derivation is left **unchanged**. The genesis delta
commits to `parents == []`, but an empty set carries no information, so adding it
to the DID seed would only churn the identifier for no security gain.

**Admission is current-state authoritative (§1b), not pure-causal.** A brief
attempt to make `verify_causal` authoritative was reverted: it is unsafe under
compaction and `merge_state`, and pure-causal admits a revoked key's
*back-parented* delta (the documented "containment, not recovery" limit). So
`Document::merge` authorises against current materialised state and uses
`verify_causal` only for the out-of-order `Unknown` → `Error::DeltaPending`
signal. Order-independence lives on `merge_state`; the delta path requires causal
order (`convergence::delta_path_requires_causal_order_and_resolves_on_delivery`).

A real Tier-1 hole was caught and closed: `verify_causal`'s genesis branch
requires an **empty DAG**, else a rootless self-signed `AddVerificationMethod`
could graft a key, bypassing "an existing authorised key must introduce new keys."

**Still open / deferred:** the **Tier-1 adversarial review** before any future
pure-causal flip; a **frontier/version endpoint** so clients can author grounded
deltas (tests reconstruct the deterministic genesis hash as a stopgap);
`merge_state` does not carry/verify the DAG (Phase 4); and **compaction +
checkpointing are deferred** (§10) — the DAG is kept complete, so the §1b floor's
compaction justification no longer applies on the hot path.

## 1b. Admission: causal-authoritative with a state-import floor

With compaction removed (§10) the full delta log is always retained, so
`verify_causal` is **exact and authoritative**: its verdict is a function of the
delta's own causal past `↓D`, hence order-independent. The only facts it cannot
see are those `merge_state` imports *without* their originating deltas. So
`Document::merge` authorises causally, with a narrow current-state floor for
state-imported facts only:

1. reject non-canonical `parents` (REQ-361);
2. if `verify_causal` is `Unknown`, return `DeltaPending` (out-of-order hold);
3. **causal verdict** (authoritative): `Valid` ⇒ the signer is added in `↓D` and
   neither revoked nor deactivated *in `↓D`* — admit. `Invalid` ⇒ reject, with one
   exception: `SignerNotAuthorised` for a signer with **no `AddVerificationMethod`
   delta in the DAG** (`has_authorising_delta`) can only have arrived via a trusted
   state-merge import, which is undecidable causally, so it falls through to the
   floor. A **parentless** delta on a non-empty DAG (genesis impersonation) and a
   signer whose AddVM **is** a held delta but was excluded from `↓D` (deliberate
   *back-parenting*) are rejected;
4. **state-import floor** — enforce ONLY facts present in current state but **not
   backed by a delta** in the DAG: deactivation with no `Deactivate` delta
   (`has_deactivate_delta`), a signer absent from current state, or revocation with
   no `RevokeVerificationMethod` delta (`has_revoking_delta`). A fact *backed* by a
   delta is already decided causally and MUST NOT be re-checked against current
   state — otherwise a delta concurrent with a revocation/deactivation *delta*
   would be wrongly rejected, breaking convergence and bundle sync;
5. RotateKey: no staleness gate — all rotations admitted; the ActiveKey
   Max-Register resolves them (higher seq wins, hash tiebreak at equal seq).

This gives genuine **"containment, not recovery"**: a delta concurrent with a
revocation/deactivation is *retained* (the revocation governs only its own causal
future), and the same delta is admitted regardless of delivery order, so replicas
and verified-bundle receivers converge. The earlier current-state-authoritative
floor — needed only because compaction could truncate `↓D` — is gone with
compaction.

## 2. Design Decisions Taken

No deployed DIDs exist, so the format is unconstrained by compatibility. The
following are **decided** (not open):

- **D1 — `parents` is mandatory.** Every delta carries a sorted, deduplicated set
  of parent delta hashes (its observed frontier). The genesis delta has an empty
  parent set.
- **D2 — identifier derivation may change.** The genesis payload now includes the
  (empty) parent set; `did = BLAKE3-256(canonical genesis incl. parents)`. No
  version flag is required.
- **D3 — native encoding and algebra; no cbcl dependency.** did-crdt keeps its
  canonical-JSON + BLAKE3-256 delta format and adds `parents`. The admission
  lattice is already native (`core::admission`, SPEC-035). cbcl SPEC-003 is prior
  art only: its Lean proofs MAY be adapted as a convenience, but did-crdt takes
  no dependency on cbcl's crate or its S-expression message store.
- **D4 — signatures cover parents.** `parents` is part of `signing_input`, so a
  delta cannot be re-parented without invalidating its signature.
- **D5 — HLC is retained but demoted.** HLC continues to order `LWW-Map` metadata
  (wall-clock semantics). It is **no longer load-bearing for authorisation
  ordering**; causal authorisation order comes from the DAG.

Remaining open questions are in §7.

---

## 3. Requirements

### REQ-360: Delta Identity is its Content Hash

A delta's identity SHALL be `BLAKE3-256` over its canonical serialisation,
including `parents`. The hash commits to the delta's entire causal closure `↓D`
recursively (cf. cbcl SPEC-003 REQ-306: "the hash *is* the position"). Two
replicas holding the same delta hash necessarily agree on its full causal
history.

### REQ-361: Parent Commitment

Each `SignedDelta` SHALL carry `parents: Vec<DeltaHash>`, the set of frontier
delta hashes (REQ-364) the signer had observed at creation, sorted byte-wise
ascending and deduplicated (so the set is canonical and order-independent). The
genesis delta SHALL have `parents == []`.

### REQ-362: Causal Closure

The causal closure `↓D` SHALL be the set of deltas reachable by following
`parents` from `D` to the genesis. Because every hash commits to its parents
recursively (REQ-360), `↓D` is **content-fixed at creation** and tamper-evident.

### REQ-363: Causal Authorisation (the revocation-ordering fix)

A delta `D` signed by key `K` SHALL be admitted per `core::admission`
(SPEC-035) using `↓D`, not current state:

- `AddVerificationMethod(K) ∉ ↓D` and not otherwise resolvable → **`Unknown`**
  (closure incomplete or key never introduced in this past).
- `AddVerificationMethod(K) ∈ ↓D` and `RevokeVerificationMethod(K) ∉ ↓D` →
  **`Valid`**.
- `RevokeVerificationMethod(K) ∈ ↓D` → **`Invalid(Revoked)`**.

Because `↓D` is fixed, this decision is **monotone**: completing the store moves
`Unknown` upward and never reverses a resolved result. A revocation *not* in `↓D`
(concurrent or later) never affects `D`, which is exactly SPEC-032's
"containment, not recovery." This promotes `RejectReason::Revoked` from the
SPEC-035 §2.2 residual to a monotone decision.

### REQ-364: Frontier

For each DID, the implementation SHALL track the **frontier**: the set of delta
hashes not referenced as a parent by any held delta. New deltas take the current
frontier as their `parents`. The frontier is the anti-entropy handle (REQ-366).

### REQ-365: Causal-Closure Bundle

The system SHALL support transferring a minimal self-verifying subset of history:
all deltas in `↓target`, topologically sorted, such that every `parents` hash
resolves within the bundle. Mirrors cbcl SPEC-003 REQ-311. Use cases: late
joiner, out-of-band transfer (SPEC-032 §V mode 3), third-party audit. The bundle
is tamper-evident by content addressing; it does not prove it is the *only*
history (an adversary may omit concurrent branches — completeness is verifiable
within the bundle, not across the DID).

### REQ-366: Reconciliation (Anti-Entropy)

Two replicas of a DID SHALL reconcile by exchanging frontiers and transferring
causal-closure bundles (REQ-365) for hashes the other lacks. Cost is proportional
to the difference, not the history (agreement on a hash implies agreement on its
sub-DAG). Mirrors cbcl SPEC-003 REQ-312. This is the "delta discovery" path
SPEC-032 §V leaves unbuilt. Merge is set union over the delta DAG: commutative,
associative, idempotent.

### REQ-367: DAG-Aware Compaction

Compaction SHALL be redefined as a **checkpoint** over a DAG cut (an antichain),
replacing SPEC-032's linear 128-delta snapshot. Deltas strictly below an accepted
checkpoint MAY be pruned; the checkpoint retains a digest commitment to the
pruned region and the genesis delta is always retained (genesis re-derivation).
Pruning is a non-monotone retraction and therefore requires explicit, bounded
coordination at the checkpoint (cf. cbcl SPEC-003 ADR-304) — the one deliberate
coordination point in the protocol.

### REQ-368: Authenticated State Proofs

`merge_state` SHALL accept state only with a proof that it derives from a valid
delta chain: Merkle inclusion of the claimed CRDT state against a frontier whose
deltas causally verify (REQ-363). A receiver rejects injected state lacking a
valid proof. This closes the SPEC-032 §IV state-sync caveat: BFT no longer
depends on the operational policy "only accept signed deltas," because state-sync
is now itself authenticated.

### REQ-369: Signature Coverage Over Parents (Tier-1)

`signing_input` SHALL include the canonical `parents` set. A delta whose parents
are altered SHALL fail signature verification. This prevents an adversary from
re-parenting a valid delta to forge a different causal past (e.g., to place a
revocation outside `↓D`).

---

## 4. Security Analysis (delta)

- **Revocation ordering** is now monotone and tamper-evident (REQ-363, 369): an
  adversary cannot make a post-revocation delta appear pre-revocation, because
  `↓D` is signed and content-fixed.
- **State-sync BFT** is enforced, not assumed (REQ-368): the
  unauthenticated-`merge_state` hole (SPEC-032 §IV) is closed.
- **Re-parenting / causal forgery** is prevented by REQ-369.
- **DoS via deep or wide DAGs** is bounded by the existing 64 KiB per-delta limit
  plus checkpoint compaction (REQ-367); closure verification cost is bounded by
  the post-checkpoint history depth.
- **Key-compromise recovery** is unchanged: the DAG makes containment *precise
  and convergent*, but a compromised key's pre-revocation deltas remain in `↓`
  of their successors (containment, not recovery). M-of-N authorisation
  (SPEC-032 future work 1) is still the orthogonal mitigation.

---

## 5. Implementation Phasing

| Phase | Scope | REQs | Tier-1 |
|---|---|---|:--:|
| 1 | `parents` field, frontier tracking, content-closure causal verify; fold into `core::admission` | 360–364, 369 | ✅ |
| 2 | Causal-closure bundles + frontier-exchange reconciliation | 365, 366 | partial |
| 3 | DAG-aware checkpoint compaction | 367 | partial |
| 4 | Authenticated state proofs for `merge_state` | 368 | ✅ |

**Fold-back:** Phase 1 promotes `RejectReason::Revoked` (SPEC-035) from residual
to a monotone causal-closure decision, completing the Level 0 → Level 2
trajectory of SPEC-035.

**Phase 4 implementation status (2026-06-05) — verified-replay, REVIEW-PENDING.**
Implemented as the "signed checkpoint + verified replay" form of REQ-368 (OQ-4),
minus the checkpoint (Phase 3 deferred, §10): `Document::merge_verified_bundle`
re-derives authenticated state from a `ClosureBundle` of signed deltas by
replaying each through `validate::verify_signature` **and** `Document::merge`
(authorisation), in topological order, atomically on a working copy.
`Document::export_bundle` produces the bundle. `merge_state` is retained for
trusted/intra-domain peers and now documents its no-authentication contract.
Crucially, `merge` does **not** verify signatures (deferred to `validate`), so
the replay calls `verify_signature` explicitly — that is what makes the path
authenticated. Adversarial tests cover forged signatures, tampered ops, dangling
parents, parent cycles, order-independence, idempotence, and atomic rollback.
**This is a Tier-1 change (§5) and is NOT yet adversarially reviewed or signed
off; it must not be relied on for BFT, nor the paper's state-sync caveat
relaxed, until that review lands.** The compact per-field Merkle-accumulator
variant of REQ-368 remains future work and is only worthwhile once Phase 3
signed checkpoints exist.

---

## 6. Relationship to SPEC-035 and the Admission Lattice

SPEC-035 (`core::admission`) provides the three-valued result lattice and proves
the **presence** component monotone. SPEC-036 supplies the missing input — a
content-fixed causal past — that makes the **ordering** component (`Revoked`)
monotone too. After Phase 1, `verify(delta, ↓D)` is a total monotone homomorphism
into `AdmissionResult`, and the paper's "monotone admission" claim holds for the
whole decision, not just presence.

---

## 7. Open Questions

- **OQ-1 — verification depth on the hot path.** Full `↓D` re-verification is
  O(history). Adopt cbcl's tiered verification (REQ-212: local / partial / full
  audit) so the hot path checks only the relevant sub-closure?
- **OQ-2 — checkpoint authority.** Who signs a REQ-367 checkpoint? Controller-only
  (SPEC-032 future work 1) or M-of-N? This is the only coordination point, so its
  trust model matters.
- **OQ-3 — HLC retention.** Keep HLC solely for `LWW-Map` wall-clock metadata
  ordering (D5), or replace metadata ordering with DAG position + a deterministic
  tiebreak and drop HLC entirely?
- **OQ-4 — state-proof format.** REQ-368 inclusion proof: Merkle path over a
  per-field accumulator, or a signed frontier the receiver replays? Trade proof
  size against verification cost.

---

## 8. Recommendation

Pin §2 decisions, resolve OQ-1 and OQ-4 (they shape the Tier-1 surface), then
implement Phase 1 behind security review. Phases 2–4 can land independently once
Phase 1 establishes the `parents`/closure substrate.

---

## 9. Phase 3 Detailed Design — Checkpointing for Safe Pure-Causal Admission

**Goal.** Let `verify_causal` be *authoritative* again — restoring pure-causal
"containment, not recovery" semantics — without the current safety regression
(§1b), by preserving the causal facts that compaction otherwise destroys.

**Problem recap.** Today `compact()` prunes the delta log (to genesis), and
`from_bytes` rebuilds the DAG from what remains, so a delta parented on the
post-compaction frontier has a closure that no longer contains pre-cut
revocations / deactivation / key additions. A purely causal check then
*underreports* and would admit forbidden mutations — which is why §1b falls back
to current-state authorisation. The fix is a **checkpoint** that summarises the
pruned prefix and that `verify_causal` consults at the cut.

### REQ-370: Checkpoint summary

`compact()` SHALL produce a `Checkpoint` over the cut (the antichain of head
hashes it subsumes — normally the current frontier) recording the
authorisation-relevant facts **as of the cut**: the set of added verification-
method ids, the set of revoked ids, the deactivation flag, and the maximum
rotation sequence. It SHALL also retain a digest over the pruned region
(integrity) and the genesis delta (DID re-derivation). These facts are exactly
the inputs `verify_causal` needs; they are monotone, so a checkpoint never
"forgets" a revocation.

### REQ-371: Checkpoint-aware closure evaluation

`verify_causal` SHALL treat the checkpoint as the floor of the closure. When a
traversal from `D`'s parents reaches a hash at or below the cut, it SHALL stop
there (not report it `Unknown`/missing) and fold in the checkpoint facts:

- *signer added in `↓D`* ⟺ an `AddVerificationMethod` for it is in the retained
  closure **or** the signer is in `checkpoint.added`;
- *signer revoked in `↓D`* ⟺ a `RevokeVerificationMethod` for it is in the
  retained closure **or** the signer is in `checkpoint.revoked`;
- *deactivated in `↓D`* ⟺ a `Deactivate` is in the retained closure **or**
  `checkpoint.deactivated`.

This is causally sound: the cut is an antichain, so everything it summarises is
causally *before* every retained head, hence before any `D` parented on the
post-cut frontier. Concurrency is therefore never ambiguous — a revocation
*concurrent* with `D` is neither in the retained closure nor below `D`'s cut, so
`D` is correctly admitted (containment, not recovery), while a revocation in
`D`'s causal past is caught by the checkpoint. Once REQ-370/371 hold, the §1b
current-state floor is removed and `verify_causal` becomes authoritative again.

### REQ-372: Checkpoint authentication (resolves OQ-2)

A `Checkpoint` asserts facts a peer cannot independently re-derive once the
prefix is pruned, so it MUST be authenticated: signed over `(cut, added,
revoked, deactivated, max_seq, digest)` by an authorised controller key (or
M-of-N per SPEC-032 future work 1). An unsigned checkpoint is a trust hole (a
peer could forge "key X not revoked"); receivers SHALL reject checkpoints
lacking a valid signature from a key authorised at the cut.

### REQ-373: Checkpoint reconciliation

Two replicas that compact at different cuts hold different checkpoints. Because
the facts are monotone, checkpoints merge deterministically: `added`/`revoked`
by set union, `deactivated` by OR, `max_seq` by max, retaining the deeper cut.
Reconciliation (REQ-366) SHALL exchange and merge checkpoints alongside deltas;
a replica MAY always fall back to the un-compacted delta history if it retains
it.

### Phase 3 → Phase 4 link

The signed `Checkpoint` (REQ-372) is precisely the authenticated state proof
REQ-368 needs: a `merge_state` recipient can verify the checkpoint signature and
replay the bounded post-cut deltas, rather than trusting raw injected state. So
Phase 3 largely subsumes Phase 4's proof format (OQ-4 → "signed checkpoint +
verified replay").

### Effort / sequencing

1. ✅ **Implemented (step 1).** `Checkpoint` type + `compact()` emits it (cut =
   frontier; added/revoked keys, deactivation, max seq, digest), serialized so it
   survives reload, exposed via `Document::checkpoint()`. Additive and non-Tier-1
   — **not yet consumed by admission**, so behaviour is unchanged.
2. Checkpoint-aware `verify_causal` (REQ-371) + remove the §1b current-state
   floor. **Tier-1** — adversarial review.
3. Checkpoint signing/verification (REQ-372). Tier-1.
4. Checkpoint reconciliation (REQ-373) + fold into `merge_state` to close Phase 4.

Steps 1 is safe to land immediately; step 2 is the one that flips admission back
to pure-causal and must not merge before review. Until then, §1b stands.

---

## 10. Compaction removed (2026-06-05)

**Update (later same day).** Compaction is now **removed from the codebase
entirely**, not merely deferred. `compact()`, `Checkpoint`, `DocumentSnapshot`,
the DAG `boundary`/checkpoint machinery, and `COMPACTION_THRESHOLD` are all gone.
Rationale: `compact()` had **zero non-test callers**, yet its dormant
boundary/checkpoint code was the sole source of repeated admission and
verified-sync correctness defects at the compaction boundary (two review rounds).
With it removed the delta log is always complete, so causal admission is exact
(`verify_causal` is never truncated) and the boundary special-cases in admission,
`export_bundle`, `merge_verified_bundle`, and `rebuild_dag` all dissolve. The
back-parenting / state-merge-import admission fix (§1b step 2a) stands on its own,
independent of compaction. Compaction returns as proper Phase 3 (checkpoint-aware,
REQ-370–373) once the admission model is settled — re-introduced as a designed
feature, not carried as dead code. The original deferral note follows.

**Decision (earlier).** Automatic compaction is removed from the admission hot
path (`Document::merge` no longer compacts at a threshold). `compact()` remains an
explicit, opt-in call; the full delta log is retained by default.

**Why.** Compaction prunes the delta log, which destroys the causal facts the
DAG needs for admission. Recovering them requires the entire checkpoint
mechanism (§9) and was the root cause of a cluster of liveness/persistence
defects (frontier lost after compaction+reload, rebuild from a pruned log, half
the justification for the §1b safety floor). Compaction is a *memory/cost*
optimisation for scale; entangling it with the not-yet-settled admission model
was premature — an optimisation driving the design of the thing it should merely
shrink. With a complete log the DAG is always complete and admission is correct
without checkpoints.

**Consequences.**
- The checkpoint machinery (§9, Phase 3) and the DAG `boundary` are now dormant —
  exercised only by an explicit `compact()` — and Phase 3 is deferred with
  compaction. It is revisited *together with* compaction once the admission
  semantics are pinned.
- The §1b current-state floor remains the admission default, now justified
  primarily by `merge_state` (state-sync still drops the DAG — Phase 4) and by
  the back-parenting key-compromise limit (see below), not by compaction.
- What deferring compaction does **not** fix: pure-causal admission still admits
  a revoked key's *back-parented* delta (one whose `parents` sit below its own
  revocation, so the revocation is not in `↓D`). That is intrinsic to causal
  revocation — the paper's documented "containment, not recovery" limit — and is
  independent of compaction. It is the reason §1b (immediate current-state
  revocation) remains the safer default; the orthogonal mitigation is M-of-N
  authorisation for sensitive operations.

## 11. Unauthenticated state wire-message removed; op-replay remove-context gap (2026-06-06)

**Change.** The `SyncMessage::State` variant — the wire message that shipped a
whole materialised `Document` to a peer — is **removed**. Every cross-peer
payload now travels as authenticated `SignedDelta`s (`DELTAS`). The gossip
responder already only ever emitted `DELTAS` (frontier-exchange reconciliation,
REQ-366), so `State` was attack surface with no legitimate producer: it let an
untrusted peer hand a replica a fabricated document for unconditional
`merge_state`. Removing it makes `Document::merge_state` **unreachable from the
network**; it remains as a *local/trusted-domain* primitive only.

**Why `merge_state` is kept (and is not redundant).** `merge_state` is a true
semilattice join over the typed CRDT fields — provably commutative, associative
and idempotent (TEST-002/003/005) — and is the **convergence ground truth** for
strong eventual consistency. In particular it is the only path that correctly
reconciles *concurrent observed-removes*: e.g. replica A adds service `svc-x`
while replica B concurrently removes `svc-x` (having never observed the add).

**Op-replay remove-context gap (future work).** Op-replay (`merge`, and hence
`merge_verified_bundle`) is **not yet a complete CvRDT** for that case. A
`RemoveServiceEndpoint { id }` delta does not carry the ORSWOT *dots* it
observed; `apply_op` re-derives the remove context from the *receiving* replica's
current state (`ServiceEndpoints::remove_by_id`). Replaying a remove therefore
removes whatever the receiver currently holds rather than exactly what the author
observed, so concurrent add/remove of the same id is order-dependent under pure
op-replay. State-merge (`merge_state`) sidesteps this by joining the actual
stored dots. The principled fix is to make removes carry their observed dots
(a δ-state CRDT) — or reconstruct them from the always-retained DAG (the adds of
`id` in the remove delta's causal past) — after which op-replay becomes a
complete CvRDT and `merge_state` can be retired. Tracked as future work; not on
the camera-ready critical path.
