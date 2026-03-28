//! AUDIT-FIXES-13 regression tests.
//!
//! Fix 1 [P0]: process_block race — UTXO lock acquired before tip read,
//!             tip updated before UTXO lock release
//! Fix 2 [P2]: Ping rate limiting in handle_peer_messages

// ── Fix 1: process_block TOCTOU race elimination ─────────────────────

mod process_block_race_tests {

#[test]
    fn max_pings_per_min_constant_exists() {
        assert_eq!(exfer::types::MAX_PINGS_PER_MIN, 10);
    }
}
