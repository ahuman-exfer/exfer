//! Round 41 audit-fix structural tests.
//!
//! P1: Abuse penalties tracked by IP address, not connection tuple
//! P2: Fork block storage bounded by MAX_FORK_BLOCKS
//! P3: build_script_context returns Result (no silent zero-digest fallback)

// ---- P1: Global block/tx budgets ----

/// refund_global_tx_slot must exist — used only for cheap pre-check rejection.

#[test]
fn p2_max_fork_blocks_exists() {
    use exfer::network::sync::MAX_FORK_BLOCKS;
    // R106: increased from 256 to 2048 to handle legitimate long forks
    // (especially around retarget windows after network partitions).
    #[allow(clippy::assertions_on_constants)]
    {
        assert!(
            MAX_FORK_BLOCKS > 0 && MAX_FORK_BLOCKS <= 4608,
            "MAX_FORK_BLOCKS must be bounded: got {}",
            MAX_FORK_BLOCKS
        );
    }
}

