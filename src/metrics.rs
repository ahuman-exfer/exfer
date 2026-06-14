//! Node operational metrics.
//!
//! A flat set of monotonic [`AtomicU64`] counters held in an `Arc<NodeMetrics>`
//! on the [`crate::network::sync::Node`]. Each counter is incremented at an
//! existing event site (where the corresponding log line is already emitted)
//! with `Ordering::Relaxed` — these are telemetry only and never gate a
//! consensus decision, validation outcome, or relay action. The
//! `get_node_info` JSON-RPC method reads a [`MetricsSnapshot`] of them.
//!
//! The counter subset here is the cheaply-countable part of the orphan-rate
//! roadmap's "Measurement first" section: monotonic events that already have a
//! discrete code site. Per-stage latency histograms (receive -> PoW-verified
//! -> connected -> relayed, and self-mined mine -> broadcast) are intentionally
//! DEFERRED — they need timing plumbing threaded through the block pipeline,
//! not a single atomic increment, and adding that plumbing would touch the hot
//! validation path. See the module-level note in the roadmap.

use std::sync::atomic::{AtomicU64, Ordering};

/// Shared, monotonic node metrics. Cloned via `Arc` onto the node.
#[derive(Debug, Default)]
pub struct NodeMetrics {
    /// Blocks that advanced the canonical chain (tip-extend or reorg winner) —
    /// the `Accepted` outcome of `process_block`.
    pub blocks_accepted: AtomicU64,
    /// Blocks demoted from the canonical chain to fork storage during a reorg.
    /// This is the orphan/stale proxy: a block that was once on our best chain
    /// and is now disconnected.
    pub blocks_orphaned: AtomicU64,
    /// Reorgs applied (fork won fork-choice and replaced the tip in place).
    pub reorgs_applied: AtomicU64,
    /// Cumulative count of old-chain blocks undone across all reorgs
    /// (sum of reorg depth). Pairs with `reorgs_applied` to give mean depth.
    pub total_blocks_undone: AtomicU64,
    /// Reorg-trigger retries: a reorg that was blocked on a missing ancestor is
    /// re-attempted after the ancestor arrives. A persistently climbing value
    /// is the deep-fork re-admission live-lock canary.
    pub retrying_reorg_trigger: AtomicU64,
    /// Recoverable (non-fatal) errors surfaced while retrying a reorg trigger.
    pub reorg_recoverable_errors: AtomicU64,
    /// Fatal consensus errors surfaced while retrying a reorg trigger
    /// (initiates graceful shutdown). Should stay 0 on a healthy node.
    pub reorg_fatal_errors: AtomicU64,
    /// Peers disconnected for exceeding the duplicate-block replay quota
    /// (`TrafficQuotaExceeded` on the NewBlock path).
    pub rate_cap_disconnects: AtomicU64,
    /// Novel NewBlock messages soft-dropped for exceeding the per-peer
    /// `MAX_BLOCKS_PER_MIN` cap (no disconnect, no strike).
    pub rate_cap_softdrops: AtomicU64,
    /// Blocks dropped by the global cross-peer block-rate cap
    /// (`MAX_GLOBAL_BLOCKS_PER_MIN` exhausted). Previously silent; now also
    /// logged at WARN at the drop site.
    pub global_block_drops: AtomicU64,
    /// `try_send` failures on the peer-event channel (NewBlock / TipResponse
    /// dropped because the bus was saturated). A fresh-tip drop here inflates
    /// the effective orphan rate; recovery is a re-request / the GetTip poll.
    pub channel_send_drops: AtomicU64,
}

impl NodeMetrics {
    /// Construct an all-zero metrics set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment a counter by one (relaxed; telemetry only).
    #[inline]
    pub fn incr(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Add `n` to a counter (relaxed; telemetry only).
    #[inline]
    pub fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    /// Take a consistent-enough point-in-time snapshot for the RPC response.
    /// Counters are read independently (no global lock); skew between counters
    /// is at most one in-flight event and is acceptable for telemetry.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            blocks_accepted: self.blocks_accepted.load(Ordering::Relaxed),
            blocks_orphaned: self.blocks_orphaned.load(Ordering::Relaxed),
            reorgs_applied: self.reorgs_applied.load(Ordering::Relaxed),
            total_blocks_undone: self.total_blocks_undone.load(Ordering::Relaxed),
            retrying_reorg_trigger: self.retrying_reorg_trigger.load(Ordering::Relaxed),
            reorg_recoverable_errors: self.reorg_recoverable_errors.load(Ordering::Relaxed),
            reorg_fatal_errors: self.reorg_fatal_errors.load(Ordering::Relaxed),
            rate_cap_disconnects: self.rate_cap_disconnects.load(Ordering::Relaxed),
            rate_cap_softdrops: self.rate_cap_softdrops.load(Ordering::Relaxed),
            global_block_drops: self.global_block_drops.load(Ordering::Relaxed),
            channel_send_drops: self.channel_send_drops.load(Ordering::Relaxed),
        }
    }
}

/// Plain-value snapshot of [`NodeMetrics`], serialized into `get_node_info`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MetricsSnapshot {
    pub blocks_accepted: u64,
    pub blocks_orphaned: u64,
    pub reorgs_applied: u64,
    pub total_blocks_undone: u64,
    pub retrying_reorg_trigger: u64,
    pub reorg_recoverable_errors: u64,
    pub reorg_fatal_errors: u64,
    pub rate_cap_disconnects: u64,
    pub rate_cap_softdrops: u64,
    pub global_block_drops: u64,
    pub channel_send_drops: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_all_zero() {
        let m = NodeMetrics::new();
        let s = m.snapshot();
        assert_eq!(
            s,
            MetricsSnapshot {
                blocks_accepted: 0,
                blocks_orphaned: 0,
                reorgs_applied: 0,
                total_blocks_undone: 0,
                retrying_reorg_trigger: 0,
                reorg_recoverable_errors: 0,
                reorg_fatal_errors: 0,
                rate_cap_disconnects: 0,
                rate_cap_softdrops: 0,
                global_block_drops: 0,
                channel_send_drops: 0,
            }
        );
    }

    #[test]
    fn incr_and_add_accumulate() {
        let m = NodeMetrics::new();
        NodeMetrics::incr(&m.blocks_accepted);
        NodeMetrics::incr(&m.blocks_accepted);
        NodeMetrics::incr(&m.reorgs_applied);
        NodeMetrics::add(&m.total_blocks_undone, 3);
        NodeMetrics::add(&m.blocks_orphaned, 3);

        let s = m.snapshot();
        assert_eq!(s.blocks_accepted, 2);
        assert_eq!(s.reorgs_applied, 1);
        assert_eq!(s.total_blocks_undone, 3);
        assert_eq!(s.blocks_orphaned, 3);
        // untouched counters stay zero
        assert_eq!(s.channel_send_drops, 0);
        assert_eq!(s.global_block_drops, 0);
    }

    #[test]
    fn snapshot_is_independent_of_later_mutation() {
        let m = NodeMetrics::new();
        NodeMetrics::incr(&m.rate_cap_disconnects);
        let s1 = m.snapshot();
        NodeMetrics::incr(&m.rate_cap_disconnects);
        let s2 = m.snapshot();
        assert_eq!(s1.rate_cap_disconnects, 1);
        assert_eq!(s2.rate_cap_disconnects, 2);
    }
}
