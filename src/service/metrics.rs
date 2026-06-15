//! Prometheus metrics for the did-crdt service.
//!
//! Metrics defined here (see SPEC-032 §14 OBS-001 – OBS-006):
//!
//! - `did_crdt_convergence_latency_seconds` — histogram, by delta_field
//! - `did_crdt_resolution_latency_seconds`  — histogram, by document_size_bucket
//! - `did_crdt_deltas_merged_total`         — counter, by outcome
//! - `did_crdt_delta_rejections_total`      — counter, by reason
//! - `did_crdt_peer_count`                  — gauge
//! - `did_crdt_state_size_bytes`            — gauge, by did

use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
    TextEncoder,
};

/// All prometheus metrics exposed by the did-crdt service.
///
/// Constructed once at server startup and shared via [`AppState`].
pub struct Metrics {
    /// OBS-001 — Histogram of time from delta creation to all-replica convergence.
    ///
    /// Labels: `delta_field` (e.g. "verificationMethods", "documentData", …)
    pub convergence_latency: HistogramVec,

    /// OBS-002 — Histogram of time for a `resolve()` call.
    ///
    /// Labels: `document_size_bucket` ("small", "medium", "large")
    pub resolution_latency: HistogramVec,

    /// OBS-003 — Counter of deltas merged, by outcome.
    ///
    /// Labels: `outcome` ("accepted", "rejected", "deduplicated")
    pub deltas_merged: IntCounterVec,

    /// OBS-004 — Counter of rejected deltas, by rejection reason.
    ///
    /// Labels: `reason` ("invalid_signature", "deactivated_did",
    ///   "stale_rotation", "unknown_did", "invalid_format")
    pub delta_rejections: IntCounterVec,

    /// OBS-005 — Gauge of connected iroh-gossip peers.
    pub peer_count: IntGauge,

    /// OBS-006 — Gauge of serialised CRDT state size in bytes, per DID.
    ///
    /// Labels: `did` (truncated hash)
    pub state_size: IntGaugeVec,

    registry: Registry,
}

impl Metrics {
    /// Create and register all metrics with a fresh, isolated registry.
    pub fn new() -> Self {
        let registry = Registry::new();

        // OBS-001 convergence latency
        let convergence_latency = HistogramVec::new(
            HistogramOpts::new(
                "did_crdt_convergence_latency_seconds",
                "Time from delta creation to all-replica convergence",
            )
            .buckets(vec![0.001, 0.01, 0.1, 1.0, 5.0, 10.0, 30.0]),
            &["delta_field"],
        )
        .expect("convergence_latency metric must be valid");
        registry.register(Box::new(convergence_latency.clone())).expect("register");

        // OBS-002 resolution latency
        let resolution_latency = HistogramVec::new(
            HistogramOpts::new(
                "did_crdt_resolution_latency_seconds",
                "Time for a resolve() call",
            )
            .buckets(vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1]),
            &["document_size_bucket"],
        )
        .expect("resolution_latency metric must be valid");
        registry.register(Box::new(resolution_latency.clone())).expect("register");

        // OBS-003 deltas merged total
        let deltas_merged = IntCounterVec::new(
            Opts::new("did_crdt_deltas_merged_total", "Total deltas merged, by outcome"),
            &["outcome"],
        )
        .expect("deltas_merged metric must be valid");
        registry.register(Box::new(deltas_merged.clone())).expect("register");

        // OBS-004 delta rejections total
        let delta_rejections = IntCounterVec::new(
            Opts::new("did_crdt_delta_rejections_total", "Total deltas rejected, by reason"),
            &["reason"],
        )
        .expect("delta_rejections metric must be valid");
        registry.register(Box::new(delta_rejections.clone())).expect("register");

        // OBS-005 peer count
        let peer_count =
            IntGauge::new("did_crdt_peer_count", "Number of connected iroh-gossip peers")
                .expect("peer_count metric must be valid");
        registry.register(Box::new(peer_count.clone())).expect("register");

        // OBS-006 state size bytes
        let state_size = IntGaugeVec::new(
            Opts::new(
                "did_crdt_state_size_bytes",
                "Serialised CRDT state size in bytes",
            ),
            &["did"],
        )
        .expect("state_size metric must be valid");
        registry.register(Box::new(state_size.clone())).expect("register");

        Self {
            convergence_latency,
            resolution_latency,
            deltas_merged,
            delta_rejections,
            peer_count,
            state_size,
            registry,
        }
    }

    /// Encode all metrics to the Prometheus text exposition format.
    pub fn encode(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buf = Vec::new();
        encoder.encode(&metric_families, &mut buf).unwrap_or_default();
        String::from_utf8(buf).unwrap_or_default()
    }

    /// Record a single resolution, timing it against the current instant.
    ///
    /// `field_count` is used to choose the `document_size_bucket` label:
    /// - < 10 fields → "small"
    /// - < 100 fields → "medium"
    /// - ≥ 100 fields → "large"
    pub fn observe_resolution(&self, elapsed_secs: f64, field_count: usize) {
        let bucket = match field_count {
            n if n < 10 => "small",
            n if n < 100 => "medium",
            _ => "large",
        };
        self.resolution_latency
            .with_label_values(&[bucket])
            .observe(elapsed_secs);
    }

    /// Increment the accepted-delta counter and update the state-size gauge.
    pub fn record_delta_accepted(&self, did_truncated: &str, state_bytes: i64) {
        self.deltas_merged.with_label_values(&["accepted"]).inc();
        self.state_size.with_label_values(&[did_truncated]).set(state_bytes);
    }

    /// Increment the rejected-delta counter for the given reason.
    pub fn record_delta_rejected(&self, reason: &str) {
        self.deltas_merged.with_label_values(&["rejected"]).inc();
        self.delta_rejections.with_label_values(&[reason]).inc();
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obs_001_convergence_latency_records_observation() {
        let m = Metrics::new();
        m.convergence_latency
            .with_label_values(&["verificationMethods"])
            .observe(0.05);
        let output = m.encode();
        assert!(output.contains("did_crdt_convergence_latency_seconds"));
        assert!(output.contains("verificationMethods"));
    }

    #[test]
    fn obs_002_resolution_latency_observe_resolution() {
        let m = Metrics::new();
        m.observe_resolution(0.001, 5);   // small
        m.observe_resolution(0.002, 50);  // medium
        m.observe_resolution(0.003, 200); // large
        let output = m.encode();
        assert!(output.contains("did_crdt_resolution_latency_seconds"));
        assert!(output.contains("small"));
        assert!(output.contains("medium"));
        assert!(output.contains("large"));
    }

    #[test]
    fn obs_003_deltas_merged_accepted_increments() {
        let m = Metrics::new();
        m.record_delta_accepted("abc123456789abcd", 512);
        let output = m.encode();
        assert!(output.contains("did_crdt_deltas_merged_total"));
        assert!(output.contains(r#"outcome="accepted""#));
    }

    #[test]
    fn obs_004_delta_rejections_by_reason() {
        let m = Metrics::new();
        m.record_delta_rejected("invalid_signature");
        m.record_delta_rejected("deactivated_did");
        m.record_delta_rejected("stale_rotation");
        m.record_delta_rejected("unknown_did");
        m.record_delta_rejected("invalid_format");
        let output = m.encode();
        assert!(output.contains("did_crdt_delta_rejections_total"));
        assert!(output.contains("invalid_signature"));
        assert!(output.contains("deactivated_did"));
        assert!(output.contains("stale_rotation"));
        assert!(output.contains("unknown_did"));
        assert!(output.contains("invalid_format"));
    }

    #[test]
    fn obs_005_peer_count_gauge_set_and_encode() {
        let m = Metrics::new();
        m.peer_count.set(7);
        let output = m.encode();
        assert!(output.contains("did_crdt_peer_count 7"));
    }

    #[test]
    fn obs_006_state_size_gauge_per_did() {
        let m = Metrics::new();
        m.record_delta_accepted("deadbeef12345678", 1024);
        let output = m.encode();
        assert!(output.contains("did_crdt_state_size_bytes"));
        assert!(output.contains("deadbeef12345678"));
    }

    #[test]
    fn encode_returns_valid_utf8_text() {
        let m = Metrics::new();
        let output = m.encode();
        // Text format always ends with a newline or is empty.
        assert!(output.is_empty() || output.ends_with('\n'));
    }

    #[test]
    fn default_constructs_fresh_metrics() {
        let m = Metrics::default();
        // Fresh registry — encode should produce valid (empty or header-only) text.
        let _ = m.encode();
    }
}
