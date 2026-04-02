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
pub const ASSUME_VALID_HEIGHT: u64 = 130_000;
/// Block hash at ASSUME_VALID_HEIGHT. Verified exactly once during sync.
pub const ASSUME_VALID_HASH: [u8; 32] = [
    0xe8, 0xb1, 0x06, 0xba, 0xaf, 0xf1, 0x42, 0x9b,
    0x0d, 0x4b, 0x47, 0xfe, 0xcc, 0x6a, 0x1e, 0x2b,
    0x1f, 0x7e, 0x4b, 0xee, 0x8d, 0x6e, 0xe2, 0x18,
    0x64, 0x5c, 0x45, 0x03, 0xe5, 0x45, 0xa1, 0x7f,
];

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
pub const PING_INTERVAL_SECS: u64 = 60;
pub const PONG_DEADLINE_SECS: u64 = 15;
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
