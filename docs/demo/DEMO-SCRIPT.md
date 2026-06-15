# did:crdt Demo Script

**Duration:** ~4 minutes
**Navigate:** arrow keys or click steps

---

## Act 1 — The Idea *(~30s)*

> Every DID method today compromises. Blockchains charge fees and require connectivity. Peer methods are free but static.
>
> did:crdt maps each document field to a CRDT whose merge is monotone. State-based merge converges without coordination by the CALM theorem. The delta path requires causal delivery — but the end state is always the same.
>
> **[Point out]** The comparison table. Six CRDT fields on the left. Resolved W3C document on the right.

**→ advance**

## Act 2 — Resolution *(~30s)*

> Resolution is a pure local projection — under 1ms. Three discovery modes: owner-presented (like did:peer but updatable), gossip/DHT for third-party verification, or out-of-band. The resolver doesn't care how deltas arrived.
>
> **[Point out]** The caveat: first-contact DHT resolution adds 1-2s. If no peer is online, resolution blocks. The <1ms figure is local projection only. We're honest about that.

**→ advance**

## Act 3 — The Proof *(~60s)*

### Partition

> Two devices, same DID, different networks. Node A adds a blog, sets location, revokes a credential. Node B adds a social link, sets a bio, rotates the controller.
>
> **[Point out]** Version IDs diverge. Documents differ.

**→ advance**

### Merge

> Both replicas merge. Each CRDT field merges independently. Five specific conflict scenarios, each with a deterministic resolution — see the table.
>
> **[Point out]** Green borders. Version IDs match. Documents identical.

**→ advance**

## Act 4 — Trade-offs *(~45s)*

### Compromised key

> Alice rotated from key-0 to key-1. But key-0 is still in the G-Set — append-only. An attacker with the old key signs a rogue service endpoint. It succeeds.
>
> This is the cost of monotonicity. Removing keys would break order-independence. Future work: controller-key-only auth with a rotation-depth window, or M-of-N threshold for sensitive operations.
>
> **[Point out]** The rogue `#svc-rogue` endpoint in the CRDT state and resolved document. It's there. We don't hide it.

**→ advance**

### LWW silent loss

> Two devices write to the same metadata key concurrently. Only the higher HLC survives. The other is silently discarded — no error, no trace.
>
> This is inherent to LWW. Guidance: use distinct keys, or use the OR-Set for data where both values should survive.
>
> **[Point out]** Only one displayName value in the resolved document.

**→ advance**

## Act 5 — Why It Matters *(~30s)*

> **Cost:** Even at weekly rotation for 10K devices, blockchain gas is $2.6M-$26M/year. did:crdt: $20/month.
>
> **Security:** Deterministic validity check. Any number of Byzantine nodes tolerated. But honest about the G-Set trade-off — compromised keys remain authorised.
>
> **Real:** 2,600 lines of Rust, zero unsafe, WASM, seven property-based proofs.

---

## If Asked

**"Why not just restrict to the current controller key?"** — Creates order-dependent failures. A delta from the new key gets rejected if it arrives before the rotation delta. Requires causal delivery, which is coordination. Rotation-depth window is the proposed solution.

**"Can an attacker deactivate the DID?"** — Yes. Any G-Set key can set the boolean latch. Irreversible. M-of-N threshold for Deactivate is future work.

**"What about multi-node network testing?"** — Current evaluation is microbenchmarks and property tests. Multi-node convergence over real networks is an evaluation gap we acknowledge.
