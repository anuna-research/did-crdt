//! Memory footprint measurement for DID documents at various sizes.
//!
//! Measures both the shallow `size_of_val` and a deep estimate that accounts
//! for heap-allocated contents (Strings, Vecs, BTreeSet/BTreeMap entries, the
//! dotted-ORSWOT live map and version-vector context, delta log, etc.).
//!
//! Run with: cargo test --test memory_footprint -- --nocapture

use did_crdt::{
    core::{
        delta::{default_relationships, DeltaOp, SignedDelta, SuiteType},
        hlc::HlcTimestamp,
    },
    Document,
};

/// Build a `Document` pre-populated with `vm_count` verification methods and
/// `svc_count` service endpoints (same pattern as benches/).
fn build_doc(vm_count: usize, svc_count: usize) -> Document {
    let (mut doc, _) = Document::new("zBenchGenesisKey").expect("Document::new must succeed");
    let signer = format!("{}#key-0", doc.did);

    for i in 1..vm_count {
        let ts = HlcTimestamp {
            wall_ms: i as u64 * 10,
            logical: 0,
            node_id: 1,
        };
        let op = DeltaOp::AddVerificationMethod {
            id: format!("{}#key-{}", doc.did, i),
            public_key_multibase: format!("zBenchKey{}", i),
            suite_type: SuiteType::default(),
            relationships: default_relationships(),
        };
        let mut d = SignedDelta::unsigned(doc.did.clone(), op, ts, signer.clone());
        d.parents = doc.frontier();
        doc.merge(d).expect("merge VM must succeed");
    }

    for i in 0..svc_count {
        let ts = HlcTimestamp {
            wall_ms: 10_000 + i as u64 * 10,
            logical: 0,
            node_id: 1,
        };
        let op = DeltaOp::AddServiceEndpoint {
            id: format!("{}#svc-{}", doc.did, i),
            service_type: "LinkedDomains".to_owned(),
            endpoint: format!("https://bench-{}.example.com", i),
        };
        let mut d = SignedDelta::unsigned(doc.did.clone(), op, ts, signer.clone());
        d.parents = doc.frontier();
        doc.merge(d).expect("merge service must succeed");
    }

    doc
}

/// Deep heap size estimate via manual accounting of known data structures.
///
/// We compute the heap footprint by walking the resolved DID document
/// (which surfaces all live entries) and accounting for the known Rust
/// allocation patterns of each CRDT wrapper.
fn estimate_deep_heap(doc: &Document, vm_count: usize, svc_count: usize) -> HeapEstimate {
    let did_str = doc.did.to_string();

    // ── Did string ──
    // String = 24 bytes stack + heap allocation of len bytes
    let did_heap = did_str.len();

    // ── VerificationMethods (GSet<VerificationMethodEntry>) ──
    // GSet is backed by BTreeSet. Each entry:
    //   - BTreeSet node overhead: ~64 bytes (two pointers + metadata)
    //   - VerificationMethodEntry (stack in node): size_of = ~104 bytes
    //     but the Strings inside are heap-allocated:
    //       id: ~70 chars (did:crdt:<64-char-hash>#key-N)
    //       public_key_multibase: ~12-20 chars
    //       relationships: Vec<enum> = 24 stack + 1*4 = 28 bytes typically
    let vm_id_len = did_str.len() + 6; // "#key-N" suffix
    let vm_pubkey_len = 15; // "zBenchKeyNN" average
    let vm_rel_heap = 8; // Vec of 1 enum (8 bytes capacity)
    let vm_node_overhead = 64; // BTreeSet per-node
    let vm_entry_heap = vm_id_len + vm_pubkey_len + vm_rel_heap + vm_node_overhead;
    let vm_heap = vm_count * vm_entry_heap;

    // ── ServiceEndpoints (dotted ORSWOT) ──
    // Implemented as a BTreeMap<Dot, ServiceEntry> (live map) keyed by
    // Dot = HlcTimestamp (24 bytes), plus a BTreeMap<u64, Dot> version-vector
    // context (one entry per node).
    // Each ServiceEntry:
    //   - id: ~70 chars
    //   - service_type: ~13 chars ("LinkedDomains")
    //   - endpoint: ~35 chars ("https://bench-NN.example.com")
    // Per-entry overhead: Dot key (~24 bytes) + BTree node (~64 bytes)
    let svc_id_len = did_str.len() + 6;
    let svc_type_len = 13;
    let svc_endpoint_len = 35;
    let svc_orswot_overhead = 24 + 64;
    let svc_entry_heap = svc_id_len + svc_type_len + svc_endpoint_len + svc_orswot_overhead;
    let svc_heap = svc_count * svc_entry_heap;
    // Version-vector context: one BTreeMap entry per node_id (~24 bytes).
    // In our test we have 1 actor.
    let vclock_heap = 24;

    // ── DocumentData (BTreeMap<String, LWWReg<Value, HlcTimestamp>>) ──
    // Empty in our test fixture
    let data_heap = 0;

    // ── ActiveKey (LWWReg<Option<String>, ActiveKeyMarker>) ──
    // Contains one Option<String>; after genesis rotation it holds the key ref.
    let active_key_heap = vm_id_len; // the key-0 reference string

    // ── Revocations + RevokedVerificationMethods ──
    // Empty in our test fixture
    let revocations_heap = 0;

    // ── delta_log (Vec<SignedDelta>) ──
    // Each SignedDelta contains:
    //   - did: Did (String ~70 bytes)
    //   - op: DeltaOp enum, heap depends on variant:
    //     AddVM: 2 Strings (~85 bytes heap) + Vec (~28)
    //     AddService: 3 Strings (~120 bytes heap)
    //   - timestamp: HlcTimestamp (24 bytes, stack)
    //   - proof: DeltaProof with verification_method String (~70) + proof_value String (~0 for unsigned)
    //   Total per delta: ~250-350 bytes heap
    let delta_count = 1 + vm_count.saturating_sub(1) + svc_count;
    let delta_avg_heap = 300;
    let delta_log_heap = delta_count * delta_avg_heap;
    // Vec itself: capacity * size_of::<SignedDelta>() for the spine
    let signed_delta_stack = 200; // approximate size_of::<SignedDelta>()
    let delta_log_spine = delta_count * signed_delta_stack;

    let total_heap = did_heap
        + vm_heap
        + svc_heap
        + vclock_heap
        + data_heap
        + active_key_heap
        + revocations_heap
        + delta_log_heap
        + delta_log_spine;

    HeapEstimate {
        did_heap,
        vm_heap,
        vm_count,
        svc_heap,
        svc_count,
        vclock_heap,
        data_heap,
        active_key_heap,
        revocations_heap,
        delta_count,
        delta_log_heap: delta_log_heap + delta_log_spine,
        total_heap,
    }
}

struct HeapEstimate {
    did_heap: usize,
    vm_heap: usize,
    vm_count: usize,
    svc_heap: usize,
    svc_count: usize,
    vclock_heap: usize,
    data_heap: usize,
    active_key_heap: usize,
    revocations_heap: usize,
    delta_count: usize,
    delta_log_heap: usize,
    total_heap: usize,
}

#[test]
fn measure_memory_footprint() {
    let sizes: &[(&str, usize, usize)] =
        &[("small", 1, 1), ("medium", 10, 10), ("large", 100, 100)];

    let struct_size = std::mem::size_of::<Document>();

    println!("\n{:=<80}", "");
    println!("DID Document In-Memory Footprint Measurement");
    println!("{:=<80}", "");
    println!(
        "  size_of::<Document>() = {} bytes (stack frame)",
        struct_size
    );

    for &(label, vm_count, svc_count) in sizes {
        let doc = build_doc(vm_count, svc_count);

        let shallow = std::mem::size_of_val(&doc);
        let est = estimate_deep_heap(&doc, vm_count, svc_count);

        // Measure serialised size (full document with delta log)
        let ser_bytes = doc.to_bytes().unwrap();
        let ser_len = ser_bytes.len();

        println!(
            "\n--- {} ({} VMs, {} services) ---",
            label, vm_count, svc_count
        );
        println!(
            "  Stack (size_of_val)                = {:>8} bytes",
            shallow
        );
        println!(
            "  Serialised (to_bytes)              = {:>8} bytes ({:.1} KiB)",
            ser_len,
            ser_len as f64 / 1024.0
        );
        println!();
        println!("  Heap breakdown (estimated):");
        println!(
            "    DID string                       = {:>8} bytes",
            est.did_heap
        );
        println!(
            "    Verification methods ({:>3})       = {:>8} bytes",
            est.vm_count, est.vm_heap
        );
        println!(
            "    Service endpoints ({:>3})          = {:>8} bytes",
            est.svc_count, est.svc_heap
        );
        println!(
            "    Version-vector context           = {:>8} bytes",
            est.vclock_heap
        );
        println!(
            "    Document data                    = {:>8} bytes",
            est.data_heap
        );
        println!(
            "    Active key                       = {:>8} bytes",
            est.active_key_heap
        );
        println!(
            "    Revocations                      = {:>8} bytes",
            est.revocations_heap
        );
        println!(
            "    Delta log ({:>3} deltas)           = {:>8} bytes ({:.1} KiB)",
            est.delta_count,
            est.delta_log_heap,
            est.delta_log_heap as f64 / 1024.0
        );
        println!("    ────────────────────────────────────────────");
        println!(
            "    Total estimated heap              = {:>8} bytes ({:.1} KiB)",
            est.total_heap,
            est.total_heap as f64 / 1024.0
        );
        println!();

        let total = shallow + est.total_heap;
        println!(
            "  TOTAL (stack + heap estimate)      = {:>8} bytes ({:.1} KiB)",
            total,
            total as f64 / 1024.0
        );

        let gb = 1024.0 * 1024.0 * 1024.0;
        println!(
            "  DIDs per 1 GiB RAM                 ~ {:>12.0}",
            gb / total as f64
        );
        println!(
            "  DIDs per 8 GiB RAM                 ~ {:>12.0}",
            8.0 * gb / total as f64
        );
    }

    // Now measure without delta log: in production, after compaction the delta
    // log is truncated. The CRDT state without delta log is the steady-state
    // footprint.
    println!("\n{:=<80}", "");
    println!("Steady-state estimate (CRDT state only, no delta log)");
    println!("{:=<80}", "");

    for &(label, vm_count, svc_count) in sizes {
        let doc = build_doc(vm_count, svc_count);
        let est = estimate_deep_heap(&doc, vm_count, svc_count);
        let shallow = std::mem::size_of_val(&doc);

        let crdt_only = est.total_heap - est.delta_log_heap;
        let total = shallow + crdt_only;
        let gb = 1024.0 * 1024.0 * 1024.0;

        println!("  {:>6}: CRDT state = {:>6} bytes ({:.1} KiB) | total = {:>6} bytes ({:.1} KiB) | {:.0} DIDs/GiB",
            label, crdt_only, crdt_only as f64 / 1024.0,
            total, total as f64 / 1024.0,
            gb / total as f64);
    }

    // ── Serialised size (disk footprint) ──────────────────────────────────
    println!("\n{:=<80}", "");
    println!("Serialised Size (Disk Footprint via to_bytes())");
    println!("{:=<80}", "");

    let disk_20gb: f64 = 20.0 * 1024.0 * 1024.0 * 1024.0;

    println!("\n  With delta log (full document):");
    for &(label, vm_count, svc_count) in sizes {
        let doc = build_doc(vm_count, svc_count);
        let ser_len = doc.to_bytes().unwrap().len();
        println!("    {:>6} ({:>3} VMs, {:>3} svcs): {:>8} bytes ({:.1} KiB) | {:.0} DIDs per 20 GB disk",
            label, vm_count, svc_count,
            ser_len, ser_len as f64 / 1024.0,
            disk_20gb / ser_len as f64);
    }

    // ── Combined summary table ────────────────────────────────────────────
    println!("\n{:=<80}", "");
    println!("Summary Table");
    println!("{:=<80}", "");
    println!(
        "  {:>6} | {:>10} {:>10} | {:>10} | {:>12}",
        "Size", "RAM(full)", "RAM(state)", "Disk(full)", "DIDs/GiB(state)"
    );
    println!(
        "  {:->6}-+-{:->10}-{:->10}-+-{:->10}-+-{:->12}",
        "", "", "", "", ""
    );

    let gb = 1024.0 * 1024.0 * 1024.0;

    for &(label, vm_count, svc_count) in sizes {
        let doc = build_doc(vm_count, svc_count);
        let shallow = std::mem::size_of_val(&doc);
        let est = estimate_deep_heap(&doc, vm_count, svc_count);
        let ram_full = shallow + est.total_heap;

        // Steady-state RAM = CRDT state without the retained delta log.
        let crdt_only = est.total_heap - est.delta_log_heap;
        let ram_state = shallow + crdt_only;

        let ser_full = doc.to_bytes().unwrap().len();

        println!(
            "  {:>6} | {:>8} B {:>8} B | {:>8} B | {:>12.0}",
            label,
            ram_full,
            ram_state,
            ser_full,
            gb / ram_state as f64
        );
    }

    println!("\n{:=<80}", "");
    println!("Notes:");
    println!(
        "  - 'Total' = stack frame ({} B) + estimated heap allocations",
        struct_size
    );
    println!("  - The full delta log is always retained (compaction is deferred — SPEC-036 §10)");
    println!("  - Delta log dominates for documents with many operations");
    println!("  - RAM(state) = materialised CRDT state with the delta log excluded");
    println!("  - Service endpoints (dotted ORSWOT) carry Dot + version-vector overhead per entry");
    println!("  - Estimates use conservative per-entry overhead (BTree nodes ~64 B)");
    println!("{:=<80}\n", "");
}
