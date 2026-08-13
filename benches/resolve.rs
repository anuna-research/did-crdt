//! Resolution latency benchmark (TEST-018).
//!
//! Measures the wall time for `Document::resolve()` across three document size
//! buckets (OBS-002).  Target: p99 < 1 ms for all buckets (NFR-004).
//!
//! | Bucket | Verification methods | Service endpoints |
//! |--------|---------------------|-------------------|
//! | small  |  1                  |  1                |
//! | medium | 10                  | 10                |
//! | large  | 100                 | 100               |
//!
//! `resolve()` is a pure read operation, so no per-iteration clone is needed.
//! The document fixture is built once in the setup phase and borrowed for the
//! entire benchmark run.
//!
//! See SPEC-032 §13 (Performance) and NFR-004.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use did_crdt::{
    core::{
        delta::{default_relationships, DeltaOp, SignedDelta, SuiteType},
        hlc::HlcTimestamp,
    },
    Document,
};

// ── size buckets ──────────────────────────────────────────────────────────────

/// (label, vm_count, svc_count) — matching OBS-002 bucket definitions.
const SIZES: &[(&str, usize, usize)] = &[("small", 1, 1), ("medium", 10, 10), ("large", 100, 100)];

// ── fixture builder ───────────────────────────────────────────────────────────

/// Build a `Document` pre-populated with `vm_count` verification methods and
/// `svc_count` service endpoints, ready for resolution benchmarking.
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
        doc.merge(d)
            .expect("merge VM must succeed during fixture build");
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
        doc.merge(d)
            .expect("merge service must succeed during fixture build");
    }

    doc
}

// ── resolve benchmark ─────────────────────────────────────────────────────────

fn bench_resolve(c: &mut Criterion) {
    let mut group = c.benchmark_group("resolve");

    for &(label, vm_count, svc_count) in SIZES {
        let doc = build_doc(vm_count, svc_count);

        group.bench_with_input(BenchmarkId::new("size", label), &doc, |b, doc| {
            b.iter(|| doc.resolve().expect("resolve must succeed"));
        });
    }

    group.finish();
}

// ── criterion registration ────────────────────────────────────────────────────

criterion_group!(benches, bench_resolve);
criterion_main!(benches);
