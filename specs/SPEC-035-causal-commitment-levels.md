---
title: "SPEC-035: Causal Commitment Levels and Three-Valued Delta Admission"
id: SPEC-035
version: 0.1.0
status: stub
created: 2026-06-04
last_updated: 2026-06-04
authors: Anuna Research
reviewers: Engineering, Security
audience: protocol designers, engineers
parent: SPEC-032
references:
  - "SPEC-032: did-crdt - Coordination-Free Decentralised Identifiers via Signed CRDTs"
  - "SPEC-034: SQLite Persistence Layer for did-crdt"
  - "CON-002: SignedDelta - Delta Format"
  - "cbcl-rs SPEC-003: Verification Lattice - Algebraic Foundations for Causal Protocol Checking"
  - "Sanjuan, Poyhtari, Teixeira, Psaras 2020: Merkle-CRDTs - Merkle-DAGs meet CRDTs"
  - "Conway et al. 2012: Logic and Lattices for Distributed Programming (BloomL)"
  - "Kuper 2015: Lattice-Based Data Structures (LVars, threshold reads)"
---

# SPEC-035: Causal Commitment Levels and Three-Valued Delta Admission

| Field | Value |
|---|---|
| Document ID | SPEC-035 |
| Title | Causal Commitment Levels and Three-Valued Delta Admission |
| Version | 0.1.0 |
| Status | **Stub** (problem framing + decision menu; requirements not yet detailed) |
| Created | 2026-06-04 |
| Last Updated | 2026-06-04 |
| Authors | Anuna Research |
| Reviewers | Engineering, Security |
| Parent | SPEC-032 |

---

## 0. Status and Scope of This Stub

This is a **design stub**, not an implementation specification. It frames a
decision — *how much causal information a `SignedDelta` must commit to* — and lays
out a menu of three levels with explicit cost/benefit. It does **not** yet
contain detailed `REQ-`/`CON-` clauses; those are deferred until a level is
chosen.

> **Tier-1 boundary.** Any change to `src/core/validate.rs` (signature and
> authorisation checks) is a Tier-1 no-go area per SPEC-032 §16: cross-model
> adversarial review and human domain-expert sign-off are required before merge.
> This stub deliberately stops short of prescribing changes to that path. The
> lattice **type** (Level 0 below) can land without touching the trust boundary;
> the **semantic reclassification** cannot.

This work is **not required** for the coordination-free claim defended in
SPEC-032 / the DAPPS 2026 paper. See §6.

---

## 1. Motivation

SPEC-032 admits two paths with different guarantees: a fully order-independent
state-merge path (`merge_state`), and a signed-delta path that the paper
describes as requiring *causal delivery* and as *order-sensitive* — "a delta
signed by a newly added key is rejected if it arrives before the
`AddVerificationMethod` that introduces that key."

That order-sensitivity is, in part, an artefact of **two-valued admission**.
`merge()` (`src/core/document.rs`) and `check_authorisation()`
(`src/core/validate.rs`) return `Result<(), Error>`, collapsing two distinct
situations into one `Err`:

1. **"Predecessor not seen yet"** — the authorising key's `AddVerificationMethod`
   has not arrived. *Undecidable*, not invalid.
2. **"Genuinely forbidden"** — DID mismatch, deactivated document, stale
   rotation, signer revoked-in-causal-past.

cbcl-rs SPEC-003 separates these with a three-valued result lattice
(`Unknown` / `Valid` / `Violation`) and proves verification a **monotone lattice
homomorphism** — so "predecessor not seen" becomes `Unknown` (⊥) that resolves
*upward* as the store grows, never a retraction. Lifting that distinction makes
the delta-admission decision monotone in the correct (knowledge) lattice, which
in turn lets did-crdt state the stronger claim: the transport needs only
*eventual delivery* (a liveness assumption), not *causal delivery* (a transport
ordering property) — i.e. coordination-free in the full CALM sense, not merely
consensus-free.

The catch: not every admission question is answerable from grow-only set
membership. Some depend on **causal order**, and that is the subject of this
stub.

---

## 2. Two Kinds of Dependency

Delta admission asks questions of the current store. They fall into two classes,
with very different requirements.

### 2.1 Presence dependencies — no causal commitment required

- "Is the signing key in the add-G-Set?"
- "Is the document deactivated?" / "Does the DID match?"

These are **set-membership queries against grow-only structures**. The answer is
monotone for free: absent → `Unknown`, present → resolves up, never regresses.
This is the load-bearing case behind the coordination-free reframe, and did-crdt
**already supports it** with HLC timestamps + the existing G-Sets. No Merkle DAG,
no parent pointers.

### 2.2 Ordering dependencies — require a content-fixed causal cut

- "Was there a revocation of key `K` *causally before* this delta?"
- "Is this `RotateKey` stale relative to the rotation that authorised it?"

Here validity is a function of causal *order* between two mutually-relevant
operations. This is the family that breaks monotonicity under the naive rule
"revoked-in-current-state → reject": the same delta can read `Valid` before a
revocation propagates and `Violation` after — a `Valid → Violation` flip, which
is **not** ≤ in the flat lattice.

**Why HLC is insufficient for §2.2.** HLC is causally *consistent* but not
causally *committing*:

1. It is **forgeable by an authorised-but-Byzantine signer** (the same timestamp
   inflation SPEC-032 already concedes for LWW metadata). A compromised key can
   backdate a delta to claim it preceded its own revocation.
2. Even with honest clocks, timestamp comparison **linearises concurrent
   events** — it cannot distinguish "R was genuinely in this delta's causal past"
   from "R is concurrent with a smaller timestamp."

A content-addressed causal commitment fixes both: it makes a delta's causal past
`↓D` **immutable at creation** (the hash *is* the causal position, cf. cbcl-rs
SPEC-003 REQ-306). Then "is there a revocation of `K` in `↓D`?" has a fixed
answer once `↓D` is complete — `Unknown` while incomplete, then `Valid`/
`Violation` and stable. A revocation *not* in `↓D` (concurrent or later) never
affects this delta's validity, which is exactly SPEC-032's "containment, not
recovery — does not roll back already-authorised operations." **HLC orders; a
commitment proves. Monotone BFT validity needs the proof.**

---

## 3. Commitment Levels (the decision menu)

The choice is not binary. Three levels, from cheapest to most capable:

### Level 0 — Three-valued admission, no new causal metadata

Lift the `Unknown`/`Valid`/`Violation` lattice **type** (and its Lean proofs)
from cbcl-rs SPEC-003 verbatim — it is payload-generic except the `Violation`
arm. Reclassify the **presence** rejections (§2.1): "signer key absent" becomes
`Unknown` rather than `Err`. Ordering cases (§2.2) remain as today.

- **Buys:** the coordination-free reframe (presence monotone), the formal
  "admission is a monotone homomorphism" statement, mechanised in Lean.
- **Leaves open:** revocation/rotation ordering stays non-monotone — but note the
  practical blast radius is limited, since a G-Set effect that already merged is
  not undone by a later rejection; only admission of *not-yet-applied* deltas is
  affected.
- **Cost:** pure-core addition (new `core::admission` module); the lattice type
  is no-behaviour-change and does **not** touch the Tier-1 path. Reclassifying
  "signer absent" → `Unknown` **does** touch admission semantics → Tier-1 review.

### Level 1 — Per-key causal anchor (lightweight)

Each delta commits to **one** predecessor hash: the `AddVerificationMethod` that
introduced its signing key (optionally plus the head it observed). A single
back-pointer, not multi-parent fan-in.

- **Buys:** makes "key added before this delta, not revoked in its causal past" a
  content-fixed, **monotone** predicate — the minimum that fixes §2.2 revocation
  ordering.
- **Cost:** `SignedDelta` (CON-002) gains a `caused_by` field; signing input and
  canonical JSON change → wire-format and signature-coverage change → Tier-1.

### Level 2 — Full delta Merkle DAG (cbcl-style)

Every delta commits to its full sorted set of causal predecessors; `↓D` fully
fixed. Mirrors cbcl-rs SPEC-003 REQ-301/306/311/312 (Merkle-CRDT).

- **Buys, in one structural move, three gaps SPEC-032 already concedes:**
  1. **Revocation/rotation causal ordering** → monotone (this stub's §2.2).
  2. **State-sync BFT gap** → closed. SPEC-032 §V already names the mechanism:
     *"Authenticated state proofs (e.g., Merkle inclusion over the delta DAG)."*
     That mechanism *is* this DAG (cbcl REQ-306/311).
  3. **Reconciliation / cold-start discovery** → cbcl frontier-exchange
     anti-entropy (REQ-312) is a drop-in for the unbuilt "delta discovery" the
     paper reviewers flagged.
- **Unification:** *deltas-as-Merkle-DAG = cbcl's message store.* The genesis
  delta is already content-addressed (the DID *is* its hash), so this is the
  natural Merkle-CRDT extension (Sanjuan/Psaras 2020).
- **Cost:** largest. Frontier tracking, DAG-aware compaction (cbcl REQ-313
  checkpoint), causal-closure bundles, reconciliation protocol. Substantial, and
  Tier-1 for the admission portions.

---

## 4. Level → Gap Matrix

| Capability | L0 | L1 | L2 |
|---|:--:|:--:|:--:|
| Presence monotone (`Unknown` for key-absent) | ✅ | ✅ | ✅ |
| Coordination-free claim (eventual ≫ causal delivery) | ✅ | ✅ | ✅ |
| Lean-mechanised admission monotonicity | ✅ | ✅ | ✅ |
| Revocation/rotation ordering monotone | ❌ | ✅ | ✅ |
| State-sync BFT (authenticated state proofs) | ❌ | ❌ | ✅ |
| Frontier reconciliation / cold-start discovery | ❌ | ❌ | ✅ |
| Touches Tier-1 (`validate.rs`) | partial¹ | ✅ | ✅ |
| Wire-format / signature-coverage change | ❌ | ✅ | ✅ |

¹ The lattice *type* is no-behaviour-change; reclassifying "signer absent" →
`Unknown` is the part that touches admission semantics.

---

## 5. Open Questions

- **OQ-1.** For Level 0, what is the policy on `Unknown` — Reject (zero state,
  rely on retransmission) or bounded Buffer (cbcl REQ-305: `max_pending` + `ttl`)?
  A buffer is new mutable state and a DoS surface; Reject preserves the current
  zero-pending-state design.
- **OQ-2.** Is the small Level-0 non-monotonicity in the revocation case
  acceptable in practice (given already-merged effects persist regardless), or is
  Level 1 a hard requirement for a clean convergence proof?
- **OQ-3.** If Level 2, does did-crdt adopt cbcl's S-expression message store
  directly, or a did-crdt-native binary DAG encoding sharing the same algebra?
- **OQ-4.** Backwards compatibility: can L1/L2 `caused_by` be an *optional*
  field so existing genesis-hash DIDs remain valid, or does it force a new
  identifier-derivation version?

---

## 6. Relationship to the Paper / Review Response

**This SPEC is not on the critical path for the DAPPS 2026 revision.** The
coordination-free defense rests entirely on the **presence** case (§2.1), which
HLC + G-Sets already support; Level 0's lattice reframe is sufficient to state it
formally. For the revision, revocation-ordering should be handled by *stating the
semantics* ("revocation prevents future admission; containment, not recovery")
and *naming* Merkle inclusion over the delta DAG as the route to making ordering
itself monotone — which is already consistent with SPEC-032 §V's future-work
text. No `validate.rs` change is needed mid-revision.

The Merkle DAG (Level 2) is the right **research-program** end state: the single
change that retires revocation-ordering, state-sync BFT, and reconciliation
together, and the point at which did-crdt and cbcl-rs converge on one Merkle-CRDT
substrate. It should be scoped as its own full specification (mirroring cbcl
SPEC-003 REQ-301/306/311/312), not as a rider on the paper.

---

## 7. Recommendation

1. **Now:** lift the Level-0 lattice **type** + `Result.lean` proofs into a pure
   `core::admission` module (no behaviour change, no Tier-1 trigger). This makes
   the "monotone admission" claim concrete and citable.
2. **Behind Tier-1 review:** reclassify "signer absent" → `Unknown` and decide
   OQ-1 (Reject vs Buffer).
3. **Defer:** Level 1 vs Level 2 until OQ-2/OQ-4 are resolved; promote this stub
   to a full SPEC at that point.
