//! Merge throughput benchmark (TEST-019).
//!
//! Measures wall time for `Document::merge(delta)` across all `DeltaOp`
//! variants and three document size buckets (OBS-002):
//!
//! | Bucket | Verification methods | Service endpoints |
//! |--------|---------------------|-------------------|
//! | small  |  1                  |  1                |
//! | medium | 10                  | 10                |
//! | large  | 100                 | 100               |
//!
//! Each bench uses `iter_batched` so that per-iteration clone cost is
//! measured in setup, not in the timed section.  `Throughput::Elements(1)`
//! lets Criterion report deltas-per-second in addition to latency.
//!
//! See SPEC-032 §13 (Performance) and NFR-001.

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
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
/// `svc_count` service endpoints.
///
/// Returns `(doc, signer_key_id)` where `signer_key_id` is the full DID-URL
/// of the genesis key (`<did>#key-0`), usable as `proof.verification_method`
/// for subsequent unsigned deltas.
fn build_doc(vm_count: usize, svc_count: usize) -> (Document, String) {
    let (mut doc, _) = Document::new("zBenchGenesisKey").expect("Document::new must succeed");
    // Genesis always creates `<did>#key-0`; this is the only authorised signer.
    let signer = format!("{}#key-0", doc.did);

    // Add extra verification methods (VM 1 … vm_count-1).
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

    // Add service endpoints (svc-0 … svc-(svc_count-1)).
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

    (doc, signer)
}

/// A timestamp far beyond any fixture timestamp, ensuring it is causally later.
const BENCH_TS: HlcTimestamp = HlcTimestamp {
    wall_ms: 1_000_000,
    logical: 0,
    node_id: 99,
};

// ── merge benchmarks ──────────────────────────────────────────────────────────

fn bench_merge_add_verification_method(c: &mut Criterion) {
    let mut group = c.benchmark_group("merge/add_verification_method");
    group.throughput(Throughput::Elements(1));

    for &(label, vm_count, svc_count) in SIZES {
        let (doc, signer) = build_doc(vm_count, svc_count);
        // Add the next key index (not yet present in the fixture).
        let op = DeltaOp::AddVerificationMethod {
            id: format!("{}#key-{}", doc.did, vm_count),
            public_key_multibase: format!("zBenchNewKey{}", vm_count),
            suite_type: SuiteType::default(),
            relationships: default_relationships(),
        };
        let mut delta = SignedDelta::unsigned(doc.did.clone(), op, BENCH_TS, signer);
        delta.parents = doc.frontier();

        group.bench_with_input(
            BenchmarkId::new("size", label),
            &(doc, delta),
            |b, (d, delta)| {
                b.iter_batched(
                    || (d.clone(), delta.clone()),
                    |(mut doc, delta)| doc.merge(delta).expect("merge must succeed"),
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_merge_add_service_endpoint(c: &mut Criterion) {
    let mut group = c.benchmark_group("merge/add_service_endpoint");
    group.throughput(Throughput::Elements(1));

    for &(label, vm_count, svc_count) in SIZES {
        let (doc, signer) = build_doc(vm_count, svc_count);
        let op = DeltaOp::AddServiceEndpoint {
            id: format!("{}#svc-new", doc.did),
            service_type: "DIDCommMessaging".to_owned(),
            endpoint: "https://bench-new.example.com/didcomm".to_owned(),
        };
        let mut delta = SignedDelta::unsigned(doc.did.clone(), op, BENCH_TS, signer);
        delta.parents = doc.frontier();

        group.bench_with_input(
            BenchmarkId::new("size", label),
            &(doc, delta),
            |b, (d, delta)| {
                b.iter_batched(
                    || (d.clone(), delta.clone()),
                    |(mut doc, delta)| doc.merge(delta).expect("merge must succeed"),
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_merge_remove_service_endpoint(c: &mut Criterion) {
    let mut group = c.benchmark_group("merge/remove_service_endpoint");
    group.throughput(Throughput::Elements(1));

    for &(label, vm_count, svc_count) in SIZES {
        let (doc, signer) = build_doc(vm_count, svc_count);
        // Remove the first service (always present for svc_count >= 1).
        let op = DeltaOp::RemoveServiceEndpoint {
            id: format!("{}#svc-0", doc.did),
        };
        let mut delta = SignedDelta::unsigned(doc.did.clone(), op, BENCH_TS, signer);
        delta.parents = doc.frontier();

        group.bench_with_input(
            BenchmarkId::new("size", label),
            &(doc, delta),
            |b, (d, delta)| {
                b.iter_batched(
                    || (d.clone(), delta.clone()),
                    |(mut doc, delta)| doc.merge(delta).expect("merge must succeed"),
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_merge_set_document_data(c: &mut Criterion) {
    let mut group = c.benchmark_group("merge/set_document_data");
    group.throughput(Throughput::Elements(1));

    for &(label, vm_count, svc_count) in SIZES {
        let (doc, signer) = build_doc(vm_count, svc_count);
        let op = DeltaOp::SetDocumentData {
            key: "alsoKnownAs".to_owned(),
            value: serde_json::json!("https://bench.example.com/profile"),
        };
        let mut delta = SignedDelta::unsigned(doc.did.clone(), op, BENCH_TS, signer);
        delta.parents = doc.frontier();

        group.bench_with_input(
            BenchmarkId::new("size", label),
            &(doc, delta),
            |b, (d, delta)| {
                b.iter_batched(
                    || (d.clone(), delta.clone()),
                    |(mut doc, delta)| doc.merge(delta).expect("merge must succeed"),
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_merge_rotate_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("merge/rotate_key");
    group.throughput(Throughput::Elements(1));

    for &(label, vm_count, svc_count) in SIZES {
        let (doc, signer) = build_doc(vm_count, svc_count);
        let op = DeltaOp::RotateKey {
            seq: 1,
            key_ref: format!("{}#key-0", doc.did),
        };
        let mut delta = SignedDelta::unsigned(doc.did.clone(), op, BENCH_TS, signer);
        delta.parents = doc.frontier();

        group.bench_with_input(
            BenchmarkId::new("size", label),
            &(doc, delta),
            |b, (d, delta)| {
                b.iter_batched(
                    || (d.clone(), delta.clone()),
                    |(mut doc, delta)| doc.merge(delta).expect("merge must succeed"),
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_merge_revoke_credential(c: &mut Criterion) {
    let mut group = c.benchmark_group("merge/revoke_credential");
    group.throughput(Throughput::Elements(1));

    for &(label, vm_count, svc_count) in SIZES {
        let (doc, signer) = build_doc(vm_count, svc_count);
        let op = DeltaOp::RevokeCredential {
            credential_id: "urn:uuid:bench-0000-0000-0000-000000000001".to_owned(),
        };
        let mut delta = SignedDelta::unsigned(doc.did.clone(), op, BENCH_TS, signer);
        delta.parents = doc.frontier();

        group.bench_with_input(
            BenchmarkId::new("size", label),
            &(doc, delta),
            |b, (d, delta)| {
                b.iter_batched(
                    || (d.clone(), delta.clone()),
                    |(mut doc, delta)| doc.merge(delta).expect("merge must succeed"),
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_merge_revoke_verification_method(c: &mut Criterion) {
    let mut group = c.benchmark_group("merge/revoke_verification_method");
    group.throughput(Throughput::Elements(1));

    for &(label, vm_count, svc_count) in SIZES {
        let (doc, signer) = build_doc(vm_count, svc_count);
        // Revoke the first extra key (key-1 if vm_count > 1, otherwise key-0).
        let target_key = if vm_count > 1 {
            format!("{}#key-1", doc.did)
        } else {
            format!("{}#key-0", doc.did)
        };
        let op = DeltaOp::RevokeVerificationMethod { key_id: target_key };
        let mut delta = SignedDelta::unsigned(doc.did.clone(), op, BENCH_TS, signer);
        delta.parents = doc.frontier();

        group.bench_with_input(
            BenchmarkId::new("size", label),
            &(doc, delta),
            |b, (d, delta)| {
                b.iter_batched(
                    || (d.clone(), delta.clone()),
                    |(mut doc, delta)| doc.merge(delta).expect("merge must succeed"),
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

// ── criterion registration ────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_merge_add_verification_method,
    bench_merge_add_service_endpoint,
    bench_merge_remove_service_endpoint,
    bench_merge_set_document_data,
    bench_merge_rotate_key,
    bench_merge_revoke_credential,
    bench_merge_revoke_verification_method,
);
criterion_main!(benches);
