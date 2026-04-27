pub mod amount;
pub mod block;
pub mod hash;
pub mod transaction;

// Re-exports
#[allow(unused_imports)]
pub use amount::Amount;
#[allow(unused_imports)]
pub use block::{Block, BlockHeader};
#[allow(unused_imports)]
pub use hash::Hash256;
#[allow(unused_imports)]
pub use transaction::{Transaction, TxInput, TxOutput, TxWitness};

// ── Consensus constants ──

pub const VERSION: u32 = 1;
pub const PROTOCOL_VERSION: u32 = 5;
pub const TARGET_BLOCK_TIME_SECS: u64 = 10;
pub const RETARGET_WINDOW: u64 = 4_320;
pub const MAX_RETARGET_FACTOR: u64 = 4;
pub const COINBASE_MATURITY: u64 = 360;
pub const MAX_BLOCK_SIZE: usize = 4_194_304; // 4 MiB
pub const MAX_TX_SIZE: usize = 1_048_576; // 1 MiB
pub const MTP_WINDOW: usize = 11;
pub const MAX_TIMESTAMP_DRIFT: u64 = 120; // policy
pub const MAX_TIMESTAMP_GAP: u64 = 604_800; // consensus (~7 days)
#[allow(dead_code)]
pub const BLOCK_HEADER_SIZE: usize = 156;

// ── Assume-valid checkpoint ──

/// Height at which the assume-valid checkpoint is verified.
/// Blocks at or below this height skip Argon2id PoW during IBD/replay.
pub const ASSUME_VALID_HEIGHT: u64 = 302_400;
/// Block hash at ASSUME_VALID_HEIGHT. Verified exactly once during sync.
pub const ASSUME_VALID_HASH: [u8; 32] = [
    0x67, 0x3c, 0x2a, 0x1e, 0x9a, 0x94, 0x8e, 0xd5,
    0x19, 0x15, 0x98, 0x08, 0xee, 0xb0, 0xbd, 0x94,
    0x37, 0x3e, 0xc8, 0x3e, 0xe8, 0x57, 0x3b, 0xef,
    0x20, 0xb5, 0x24, 0x5f, 0x5e, 0x6c, 0x32, 0x17,
];
/// Cumulative work at ASSUME_VALID_HEIGHT on the canonical chain. Used by v1.5.0
/// Fix 2 cold-bootstrap subpath 2b to derive `verified_cumulative_work` without
/// walking storage below the checkpoint anchor. Big-endian 256-bit integer.
///
/// Value generated 2026-04-19 from the canonical chain by walking retarget
/// boundaries via RPC against TWO independent canonical nodes (S2 at
/// 82.221.100.201 and S3 at 89.127.232.155), requiring byte-exact agreement
/// on each of the 71 retarget-boundary targets, then summing
/// `work_from_target(difficulty_target) × window_blocks` across heights
/// 0..=ASSUME_VALID_HEIGHT inclusive. Decimal: 3,839,137,688.
///
/// **Release procedure:** regenerate alongside `ASSUME_VALID_HEIGHT` and
/// `ASSUME_VALID_HASH` if any of them are changed. Multi-source verification
/// (≥2 independent canonical nodes) is **required** per the v1.7.0 spec —
/// single-source ceremonies are insufficient for a value that becomes a trusted
/// release anchor. The retarget-boundary fixture in
/// `tests/assume_valid_cumulative_work_guard.rs` must be regenerated alongside.
/// The build-time consistency test `assume_valid_cumulative_work_guard.rs`
/// asserts the value is not the zero placeholder AND that it matches the
/// cumulative work recomputed from the regenerated fixture. A runtime guard in
/// `process_block` (`src/network/sync.rs`) also compares this constant against
/// the computed cumulative work when the node reaches the checkpoint via normal
/// block-by-block validation, and flips `assume_valid_cumulative_work_trusted`
/// to `false` on mismatch so cold-bootstrap tip validation falls through to
/// `--verify-all`-equivalent.
pub const ASSUME_VALID_CUMULATIVE_WORK: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xe4, 0xd9, 0xf5, 0x98,
];

// ── v1.5.0 Fix 2 — tip-validation constants ──

/// Maximum concurrent tip-validation attempts in the steady-state regime
/// (our local tip > ASSUME_VALID_HEIGHT). The bootstrap regime uses 1.
pub const MAX_CONCURRENT_TIP_VALIDATIONS: usize = 4;
/// Bootstrap-regime concurrency: up to 4 simultaneous bootstrap coordinator
/// instances, each validating a **distinct** `TargetTip`. Lifted from 1 in
/// v1.7.0 (Change 3). Same-TargetTip peers join an existing coordinator's pool
/// rather than spawning redundant coordinators (dedup rule); a 5th distinct
/// target is silently dropped and re-considered on the next TipResponse
/// re-advertisement. Rate limiter is shared across coordinators — total
/// Argon2/sec throughput is unchanged, peer diversity + stall tolerance
/// improve. See docs/v1.7.0-brief.md.
pub const MAX_CONCURRENT_TIP_VALIDATIONS_BOOTSTRAP: usize = 4;

/// v1.7.0 Change 4: bootstrap-regime coordinator wall-clock ceiling. Used as
/// the deadline floor in `compute_deadline()`'s bootstrap branch in place of
/// the generic `TIP_VALIDATION_DEADLINE_FLOOR_SECS = 7200`, which is far too
/// lax now that the post-Change-1 forward span is <10K headers. Caps malicious
/// slot-squatting to ~5 min per target instead of 2 h. Honest 5–10K-header
/// bootstrap completes in ~1.5 min on a typical 8-core laptop, giving a >3×
/// safety margin. See docs/v1.7.0-brief.md Change 4.
pub const BOOTSTRAP_COORDINATOR_DEADLINE_SECS: u64 = 300;

/// v1.7.0 Change 4: progress-based abort. A bootstrap coordinator aborts with
/// `BootstrapStalled` if `validated_forward.len()` has not increased within
/// this window, regardless of per-batch timeouts. Catches peers that reply
/// "on time" (under `TIP_VALIDATION_BATCH_TIMEOUT_SECS`) with prefix-failing
/// or empty batches that never advance the accumulated prefix. Coordinator
/// abort is **coordinator-scope-only** — the active peer is removed from this
/// coordinator's pool but receives NO identity/IP strike (matches the narrow
/// `should_strike()` policy that only strikes on `DeliveredInvalidHeader`).
pub const BOOTSTRAP_COORDINATOR_STALL_SECS: u64 = 90;
/// Steady-state validation rate cap: 20 Argon2 evaluations per wall-clock second
/// across all concurrent tip-validations. ~2 cores at ~100 ms/eval. Kept low so
/// an adversarial flood of fake tips cannot starve normal mining / block validation.
pub const MAX_VALIDATION_ARGON2_PER_SEC: u32 = 20;
/// Bootstrap multiplier: during cold bootstrap the rate cap is scaled per-core so
/// the one active validation can use available CPU (safe because concurrency=1
/// by construction, see MAX_CONCURRENT_TIP_VALIDATIONS_BOOTSTRAP).
///
/// Effective bootstrap rate = num_cpus × this constant.
pub const VALIDATION_ARGON2_PER_CORE_BOOTSTRAP: u32 = 10;
/// Wall-clock timeout for the next batch of headers in a single tip-validation
/// attempt. Matches the inline `Duration::from_secs(120)` used by the existing
/// IBD path; named here for clarity and to allow future tuning.
pub const TIP_VALIDATION_BATCH_TIMEOUT_SECS: u64 = 120;
/// Floor on per-attempt wall-clock deadline (seconds). Actual deadline is
/// `max(TIP_VALIDATION_DEADLINE_FLOOR_SECS, ceil(expected_argon2_seconds × 1.5))`.
pub const TIP_VALIDATION_DEADLINE_FLOOR_SECS: u64 = 7200;
/// Deadline-scaling multiplier over expected Argon2 time (1.5×). Provides
/// ~50 % margin for RTT variance and scheduling jitter without letting an
/// attacker pin us indefinitely.
pub const TIP_VALIDATION_DEADLINE_SCALE_PCT: u64 = 150;

// ── Emission constants ──

pub const BASE_REWARD: u64 = 100_000_000; // 1.0 EXFER
pub const DECAY_COMPONENT: u64 = 9_900_000_000; // 99.0 EXFER
pub const HALF_LIFE: u64 = 6_307_200; // ~2 years at 10s blocks
#[allow(dead_code)]
pub const EXFER_UNIT: u64 = 100_000_000; // 1 EXFER = 10^8 exfers

// ── Proof of Work constants ──

pub const ARGON2_MEMORY_KIB: u32 = 65_536; // 64 MiB
pub const ARGON2_ITERATIONS: u32 = 2;
pub const ARGON2_PARALLELISM: u32 = 1;
pub const ARGON2_OUTPUT_LEN: usize = 32;

// ── Fee / Cost constants ──

pub const UTXO_LOOKUP_COST: u64 = 100;
pub const UTXO_CREATE_COST: u64 = 100;
pub const SMT_DELETE_COST: u64 = 500;
pub const SMT_INSERT_COST: u64 = 500;
#[allow(dead_code)]
pub const STANDARD_SPEND_COST: u64 = 20_000;
pub const MIN_FEE_DIVISOR: u64 = 100;
pub const DUST_THRESHOLD: u64 = 200; // ceil_div(20000, 100)
pub const PHASE1_SCRIPT_EVAL_COST: u64 = 5_000;
/// Cost charged per output for script deserialization + typecheck.
/// Phase 1 (32-byte pubkey hash) scripts skip this, but Phase 2+ scripts
/// require deserialization, type inference, strict edge checks, and jet scans.
/// Priced per output to prevent cheap validation-DoS via many complex scripts.
pub const OUTPUT_TYPECHECK_COST: u64 = 1_000;

// ── Limits ──

pub const MAX_WITNESS_SIZE: usize = 65_535; // u16 VarBytes wire limit
pub const MAX_DATUM_SIZE: usize = 4_096;
pub const MAX_REDEEMER_SIZE: usize = 16_384;
#[allow(dead_code)]
pub const MAX_SCRIPT_MEMORY: usize = 16_777_216; // 16 MiB
pub const MAX_SCRIPT_STEPS: u64 = 4_000_000; // 4M steps per-input cap
pub const MAX_TX_SCRIPT_BUDGET: u128 = 20_000_000; // 20M steps per-transaction cap
pub const MAX_SCRIPT_NODES: usize = 65_535; // must fit u16 count prefix
pub const MAX_LIST_LENGTH: usize = 65_536;
pub const MAX_VALUE_DEPTH: usize = 128;
pub const MIN_TX_SIZE: usize = 50; // Minimum possible serialized tx
pub const MAX_SPENT_UTXOS_SIZE: usize = 16_777_216; // 16 MiB cap on serialized undo metadata per block

// ── Network constants ──

pub const MAX_MESSAGE_SIZE: usize = 8_388_608; // 8 MiB
pub const MAX_OUTBOUND_PEERS: usize = 8;
pub const MAX_INBOUND_PEERS: usize = 256;
pub const MAX_INBOUND_PER_IP: usize = 1;
/// Eviction overcommit: TCP accept allows up to MAX_INBOUND_PEERS + this many mid-handshake
/// sockets before rejecting, giving post-handshake eviction room to land without dropping
/// legitimate reconnect bursts. See v1.5.0 Fix 1.
pub const EVICTION_PENDING_HEADROOM: usize = 32;
/// v1.6.0 Fix 1 redesign: handshake + initial-exchange settle window. Peers
/// younger than this are unconditionally protected from eviction selection.
/// Shorter than v1.5.0's EVICTION_MIN_AGE_SECS=60 because eviction is now
/// utility-based, not age-gated; this window only ensures GetTip/GetAddr
/// exchanges can complete before the peer is scored.
pub const POST_HANDSHAKE_GRACE_SECS: u64 = 15;

/// Number of inbound peers protected by most-recent useful-message timestamp.
pub const PROTECT_USEFUL_N: usize = 8;

/// Number of inbound peers protected by session age (oldest first).
pub const PROTECT_OLDEST_N: usize = 8;

/// Number of unique network-groups whose oldest member is protected.
/// Deterministic selection: groups ranked by age of their oldest member
/// (oldest first), ties by NetworkGroup byte-order. If the pool has fewer
/// than N groups, all groups' oldest members are protected.
pub const PROTECT_GROUPS_N: usize = 16;

/// Useful-message freshness window: a peer that sent a useful message within
/// the last N seconds is eligible for the useful-protection top-N.
pub const USEFUL_PROTECTION_SECS: u64 = 600;
pub const PING_INTERVAL_SECS: u64 = 60;
/// Time the supervisor will wait for a Pong reply after firing a keepalive
/// Ping before tearing down the peer with `PeerError::PongTimeout`.
///
/// Must EXCEED the peer's 60-s `MAX_RESPONSE_BYTES_PER_MIN` tumbling-reset
/// window. v1.8.0 introduced per-peer paced transport: when a peer hits its
/// 16 MiB/min response-byte budget mid-cycle, it goes silent for up to 60 s
/// while waiting for the window to roll over. With the previous 15-s value,
/// the supervisor's 60-s ping interval + 15-s deadline tore down healthy
/// peers at the 75-s mark — exactly when budget-paced peers were structurally
/// quiet. Empirical observation: ~7 such drops per 44-min Stage B IBD on a
/// residential link, costing ~7-14 min of cold-boot wall-clock. v1.8.2 raises
/// to 90 s = 1.5× the 60-s budget window, with margin for mid-frame writer
/// head-of-line blocking on slow links (a ~4 MiB BlockResponse can take
/// 20-30 s to drain before a queued Pong reaches the wire). Aligns with the
/// v1.8.0 paced-transport timeout family (`STAGE_A_PROGRESS_TIMEOUT = 120`,
/// `TIP_VALIDATION_BATCH_TIMEOUT_SECS = 120`). PongTimeout does not strike
/// (per v1.7.2 round-2 fix), so the cost of a longer deadline is bounded:
/// a truly-dead-but-app-alive peer lingers ~75 s longer before reconnect.
pub const PONG_DEADLINE_SECS: u64 = 90;
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 5;
pub const CONNECT_TIMEOUT_SECS: u64 = 5;
#[allow(dead_code)]
pub const MAX_INV_ITEMS: usize = 64;
pub const MAX_GETBLOCKS_ITEMS: usize = 64;
pub const MEMPOOL_CAPACITY: usize = 8_192;
pub const MAX_BLOCKS_PER_MIN: u32 = 12;
pub const MAX_GLOBAL_BLOCKS_PER_MIN: u32 = 24;
pub const MAX_TXS_PER_MIN: u32 = 60;
pub const MAX_GLOBAL_TXS_PER_MIN: u32 = 200;
pub const MAX_PINGS_PER_MIN: u32 = 10;
pub const MAX_REQUESTS_PER_MIN: u32 = 30;
pub const MAX_UNSOLICITED_PER_MIN: u32 = 10;
pub const MAX_GETBLOCKS_RESPONSE: usize = 8;
pub const MAX_RESPONSE_BYTES_PER_MIN: usize = 16_777_216; // 16 MiB per peer
/// Global aggregate egress cap across all peers, per minute.
/// With 64 inbound + 8 outbound peers each at 16 MiB, theoretical max is
/// ~1.1 GiB/min. This global cap keeps aggregate egress bounded regardless
/// of peer count. Set to 128 MiB/min (8 peers at full rate).
pub const MAX_GLOBAL_RESPONSE_BYTES_PER_MIN: usize = 134_217_728; // 128 MiB
/// Addresses seen from fewer than this many independent sources are
/// deprioritized during peer selection to resist Sybil addr poisoning.
pub const MIN_ADDR_SOURCES_FOR_CONNECT: u32 = 2;
pub const MAX_ORPHAN_BLOCKS: usize = 16;
pub const MAX_ORPHAN_BLOCK_SIZE: usize = MAX_BLOCK_SIZE; // must match MAX_BLOCK_SIZE — valid blocks can be up to 4 MiB
pub const MAX_ORPHAN_CACHE_BYTES: usize = 67_108_864; // 64 MiB total orphan cache (MAX_ORPHAN_BLOCKS * MAX_BLOCK_SIZE)
#[allow(dead_code)]
pub const MAX_PENDING_BLOCK_REQUESTS: usize = 64; // per-peer cap on outstanding GetBlocks requests
pub const MAX_FORK_BLOCK_SIZE: usize = MAX_BLOCK_SIZE; // must match MAX_BLOCK_SIZE (bounds disk: 128 * 4 MiB = 512 MiB worst case)

// ── Peer discovery constants ──

pub const MAX_ADDR_ITEMS: usize = 64;
pub const MAX_ADDR_BOOK_SIZE: usize = 1024;
pub const MAX_ADDR_PER_MSG_ACCEPT: usize = 16;
pub const MAX_GETADDR_PER_CONN: u32 = 2;
pub const MAX_UNSOLICITED_ADDR_PER_MIN: u32 = 3;
pub const ADDR_FLUSH_INTERVAL_SECS: u64 = 300;
/// Accept Addr messages only within this window after sending GetAddr.
pub const ADDR_RESPONSE_WINDOW_SECS: u64 = 30;
/// Max addresses from a single /16 subnet prefix in the address book.
pub const MAX_ADDR_BOOK_PER_SUBNET16: usize = 32;
/// A single peer may contribute at most 25% of the address book.
pub const MAX_ADDR_BOOK_PEER_FRACTION_NUM: usize = 1;
pub const MAX_ADDR_BOOK_PEER_FRACTION_DEN: usize = 4;

// ── Cryptographic helpers ──

/// Returns true if the given 32-byte Ed25519 public key is a small-order
/// (weak) point. Small-order keys have order dividing 8 on the Ed25519
/// curve and can validate signatures across unrelated messages, breaking
/// transaction-message binding. Must be rejected in all verification paths.
pub fn is_weak_ed25519_key(pubkey_bytes: &[u8; 32]) -> bool {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    let compressed = CompressedEdwardsY(*pubkey_bytes);
    match compressed.decompress() {
        Some(point) => point.is_small_order(),
        None => true, // cannot decompress — reject
    }
}

// ── Domain separators ──

pub const DS_SIG: &[u8] = b"EXFER-SIG";
pub const DS_TX: &[u8] = b"EXFER-TX";
pub const DS_TXROOT: &[u8] = b"EXFER-TXROOT";
pub const DS_STATE: &[u8] = b"EXFER-STATE";
pub const DS_ADDR: &[u8] = b"EXFER-ADDR";
#[allow(dead_code)]
pub const DS_AGENT: &[u8] = b"EXFER-AGENT";
#[allow(dead_code)]
pub const DS_SCRIPT: &[u8] = b"EXFER-SCRIPT";
#[allow(dead_code)]
pub const DS_MERKLE: &[u8] = b"EXFER-MERKLE";
pub const DS_POW_P: &[u8] = b"EXFER-POW-P";
pub const DS_POW_S: &[u8] = b"EXFER-POW-S";
pub const DS_WTXID: &[u8] = b"EXFER-WTXID";
pub const DS_AUTH: &[u8] = b"EXFER-AUTH";
pub const DS_SESSION: &[u8] = b"EXFER-SESSION";
/// MAC key separator: initiator → responder direction.
/// Uses raw SHA-256 (no length prefix), not domain_hash.
pub const DS_MAC_IR: &[u8] = b"EXFER-MAC-IR";
/// MAC key separator: responder → initiator direction.
/// Uses raw SHA-256 (no length prefix), not domain_hash.
pub const DS_MAC_RI: &[u8] = b"EXFER-MAC-RI";

// ── Peer penalty constants ──

/// Maximum invalid blocks (failed validation after pre-checks) a peer
/// may send per rate-limit window before being disconnected.
pub const MAX_INVALID_BLOCKS_PER_PEER: u32 = 3;

/// Maximum invalid transactions a peer may send per rate-limit window
/// before being disconnected. Higher than blocks since tx rejection is
/// cheaper (no PoW), but still bounded to prevent validator abuse.
pub const MAX_INVALID_TXS_PER_PEER: u32 = 16;

/// Maximum interleaved non-response messages tolerated per recv call
/// during IBD sync before treating peer as misbehaving. Raised from 10
/// to 50: the overall Instant-based deadline (120s) is the primary DoS
/// bound; this counter only prevents extreme per-request spam.
#[allow(dead_code)]
pub const MAX_CONTROL_MSGS_DURING_IBD: u32 = 50;

/// Maximum retained non-canonical (fork) headers after eviction.
/// `evict_fork_block()` keeps header + work for difficulty ancestry walks;
/// this cap bounds unbounded growth from sustained fork traffic.
pub const MAX_RETAINED_FORK_HEADERS: u32 = 10_000;
