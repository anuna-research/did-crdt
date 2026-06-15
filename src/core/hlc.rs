//! Hybrid Logical Clock (HLC).
//!
//! Provides causally-consistent timestamps that advance monotonically even
//! under concurrent updates and bounded clock skew.  The pure-core clock
//! is driven by an injected [`ClockSource`] so that the core remains
//! free of any I/O dependency and trivially testable.
//!
//! # Semantics
//!
//! * **Advance-on-send** ([`Hlc::send`]) — called before emitting an event;
//!   advances the clock to be strictly greater than the previous timestamp.
//! * **Advance-on-receive** ([`Hlc::recv`]) — called on receipt of a remote
//!   timestamp; merges the remote and local clocks, then advances.
//!
//! Reference: Kulkarni et al., "Logical Physical Clocks and Consistent
//! Snapshots in Globally Distributed Databases", 2014.

use serde::{Deserialize, Serialize};

// ── ClockSource ───────────────────────────────────────────────────────────────

/// Injectable source of wall-clock time in milliseconds since the Unix epoch.
///
/// The trait is the sole point of contact between the pure HLC core and
/// real-world time, making the clock fully testable without mocking or
/// platform-specific APIs.
pub trait ClockSource {
    fn wall_ms(&self) -> u64;
}

/// A real wall-clock backed by [`std::time::SystemTime`].
pub struct SystemClock;

impl ClockSource for SystemClock {
    fn wall_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

// ── HlcTimestamp ─────────────────────────────────────────────────────────────

/// An HLC timestamp: `(wall_ms, logical, node_id)`.
///
/// The derived `Ord` uses lexicographic order, so timestamps are first
/// compared by wall time, then by logical counter, then by node identifier.
/// This satisfies the HLC requirement that every generated timestamp is
/// strictly greater than its predecessor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HlcTimestamp {
    /// Wall-clock component in milliseconds since the Unix epoch.
    pub wall_ms: u64,
    /// Logical counter — incremented when two events share the same wall tick.
    pub logical: u32,
    /// Node identifier for tiebreaking (lower bits of a node UUID or key hash).
    pub node_id: u64,
}

// ── Hlc ──────────────────────────────────────────────────────────────────────

/// Mutable HLC state tracked per replica.
///
/// `node_id` is injected at construction and embedded into every timestamp
/// this clock produces.  Wall-clock reads are injected at each call via a
/// [`ClockSource`].
#[derive(Debug)]
pub struct Hlc {
    last: HlcTimestamp,
}

impl Hlc {
    /// Create a new HLC seeded with the given wall time and node identifier.
    ///
    /// Typically called once per process with `clock.wall_ms()` and a stable
    /// per-node id derived from a public key hash or UUID.
    pub fn new(now_ms: u64, node_id: u64) -> Self {
        Self {
            last: HlcTimestamp { wall_ms: now_ms, logical: 0, node_id },
        }
    }

    /// **Advance-on-send**: generate the next timestamp for a locally-produced
    /// event.
    ///
    /// The returned timestamp is strictly greater than the last timestamp
    /// issued by this clock.
    pub fn send(&mut self, clock: &impl ClockSource) -> HlcTimestamp {
        self.advance_send(clock.wall_ms())
    }

    /// **Advance-on-receive**: advance the clock on receipt of a remote
    /// timestamp.
    ///
    /// The returned timestamp is strictly greater than both the local clock
    /// and the remote timestamp, preserving causality.
    pub fn recv(&mut self, remote: HlcTimestamp, clock: &impl ClockSource) -> HlcTimestamp {
        self.advance_recv(remote, clock.wall_ms())
    }

    // ── internal helpers ─────────────────────────────────────────────────────

    fn advance_send(&mut self, now_ms: u64) -> HlcTimestamp {
        let wall = now_ms.max(self.last.wall_ms);
        let logical = if wall == self.last.wall_ms { self.last.logical + 1 } else { 0 };
        self.last = HlcTimestamp { wall_ms: wall, logical, node_id: self.last.node_id };
        self.last
    }

    fn advance_recv(&mut self, remote: HlcTimestamp, now_ms: u64) -> HlcTimestamp {
        let wall = now_ms.max(self.last.wall_ms).max(remote.wall_ms);
        let logical = if wall == self.last.wall_ms && wall == remote.wall_ms {
            self.last.logical.max(remote.logical) + 1
        } else if wall == self.last.wall_ms {
            self.last.logical + 1
        } else if wall == remote.wall_ms {
            remote.logical + 1
        } else {
            0
        };
        self.last = HlcTimestamp { wall_ms: wall, logical, node_id: self.last.node_id };
        self.last
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// A deterministic clock for tests: returns whatever value is currently
    /// stored in an interior-mutable cell.
    struct ManualClock(Cell<u64>);

    impl ManualClock {
        fn new(ms: u64) -> Self {
            Self(Cell::new(ms))
        }
        fn set(&self, ms: u64) {
            self.0.set(ms);
        }
    }

    impl ClockSource for ManualClock {
        fn wall_ms(&self) -> u64 {
            self.0.get()
        }
    }

    // ── construction ─────────────────────────────────────────────────────────

    #[test]
    fn new_seeds_wall_and_node_id() {
        let clock = ManualClock::new(1_000);
        let mut hlc = Hlc::new(clock.wall_ms(), 42);
        let ts = hlc.send(&clock);
        assert_eq!(ts.node_id, 42);
        assert_eq!(ts.wall_ms, 1_000);
    }

    // ── advance-on-send ───────────────────────────────────────────────────────

    #[test]
    fn send_advances_logical_when_wall_unchanged() {
        let clock = ManualClock::new(1_000);
        let mut hlc = Hlc::new(1_000, 1);

        let t1 = hlc.send(&clock);
        let t2 = hlc.send(&clock);
        let t3 = hlc.send(&clock);

        assert_eq!(t1.wall_ms, 1_000);
        assert_eq!(t2.wall_ms, 1_000);
        assert_eq!(t3.wall_ms, 1_000);

        assert!(t1 < t2, "t1 must be strictly less than t2");
        assert!(t2 < t3, "t2 must be strictly less than t3");
        assert_eq!(t1.logical + 1, t2.logical);
        assert_eq!(t2.logical + 1, t3.logical);
    }

    #[test]
    fn send_resets_logical_when_wall_advances() {
        let clock = ManualClock::new(1_000);
        let mut hlc = Hlc::new(1_000, 1);
        let t1 = hlc.send(&clock);

        clock.set(2_000);
        let t2 = hlc.send(&clock);

        assert_eq!(t2.wall_ms, 2_000);
        assert_eq!(t2.logical, 0, "logical resets when wall advances");
        assert!(t1 < t2);
    }

    #[test]
    fn send_does_not_regress_when_wall_goes_backwards() {
        let clock = ManualClock::new(5_000);
        let mut hlc = Hlc::new(5_000, 1);
        hlc.send(&clock); // wall_ms = 5_000, logical = 1

        clock.set(3_000); // simulated clock skew
        let t = hlc.send(&clock);

        assert_eq!(t.wall_ms, 5_000, "wall must not regress");
        assert!(t.logical > 0, "logical must be positive when wall is clamped");
    }

    #[test]
    fn send_preserves_node_id() {
        let clock = ManualClock::new(1_000);
        let mut hlc = Hlc::new(1_000, 0xDEAD_BEEF);
        let ts = hlc.send(&clock);
        assert_eq!(ts.node_id, 0xDEAD_BEEF);
    }

    // ── advance-on-receive ────────────────────────────────────────────────────

    #[test]
    fn recv_picks_max_wall() {
        let clock = ManualClock::new(1_000);
        let mut hlc = Hlc::new(1_000, 1);

        let remote =
            HlcTimestamp { wall_ms: 9_000, logical: 0, node_id: 2 };
        let ts = hlc.recv(remote, &clock);

        assert_eq!(ts.wall_ms, 9_000);
        assert_eq!(ts.logical, 1, "increments above remote logical");
    }

    #[test]
    fn recv_increments_logical_when_all_walls_equal() {
        let clock = ManualClock::new(5_000);
        let mut hlc = Hlc::new(5_000, 1);
        hlc.send(&clock); // logical = 1

        let remote = HlcTimestamp { wall_ms: 5_000, logical: 3, node_id: 2 };
        let ts = hlc.recv(remote, &clock);

        assert_eq!(ts.wall_ms, 5_000);
        // must be > max(local.logical, remote.logical) = max(1, 3) = 3
        assert_eq!(ts.logical, 4);
    }

    #[test]
    fn recv_uses_local_logical_when_local_wall_wins() {
        // local is ahead; remote.wall < local.wall
        let clock = ManualClock::new(8_000);
        let mut hlc = Hlc::new(8_000, 1);
        hlc.send(&clock); // logical = 1

        let remote = HlcTimestamp { wall_ms: 5_000, logical: 99, node_id: 2 };
        let ts = hlc.recv(remote, &clock);

        assert_eq!(ts.wall_ms, 8_000);
        assert_eq!(ts.logical, 2, "local.logical + 1");
    }

    #[test]
    fn recv_result_greater_than_both_inputs() {
        let clock = ManualClock::new(3_000);
        let mut hlc = Hlc::new(3_000, 1);
        let local_before = hlc.send(&clock);

        let remote = HlcTimestamp { wall_ms: 3_000, logical: 5, node_id: 2 };
        let merged = hlc.recv(remote, &clock);

        assert!(merged > local_before, "merged must exceed local");
        assert!(merged > remote, "merged must exceed remote");
    }

    #[test]
    fn recv_preserves_node_id() {
        let clock = ManualClock::new(1_000);
        let mut hlc = Hlc::new(1_000, 77);
        let remote = HlcTimestamp { wall_ms: 2_000, logical: 0, node_id: 99 };
        let ts = hlc.recv(remote, &clock);
        assert_eq!(ts.node_id, 77, "node_id must come from local clock");
    }

    // ── ordering ─────────────────────────────────────────────────────────────

    #[test]
    fn timestamps_ordered_by_wall_then_logical_then_node() {
        let a = HlcTimestamp { wall_ms: 1, logical: 0, node_id: 0 };
        let b = HlcTimestamp { wall_ms: 2, logical: 0, node_id: 0 };
        let c = HlcTimestamp { wall_ms: 2, logical: 1, node_id: 0 };
        let d = HlcTimestamp { wall_ms: 2, logical: 1, node_id: 1 };

        assert!(a < b);
        assert!(b < c);
        assert!(c < d);
    }

    // ── two-replica scenario ──────────────────────────────────────────────────

    #[test]
    fn two_replicas_converge_causally() {
        let clock_a = ManualClock::new(1_000);
        let clock_b = ManualClock::new(1_000);

        let mut a = Hlc::new(1_000, 1);
        let mut b = Hlc::new(1_000, 2);

        // A sends
        let ts_a = a.send(&clock_a);

        // B receives from A, then sends
        let ts_b_after_recv = b.recv(ts_a, &clock_b);
        let ts_b_send = b.send(&clock_b);

        // Every event on B after receiving from A must be > ts_a
        assert!(ts_b_after_recv > ts_a);
        assert!(ts_b_send > ts_a);
    }
}
