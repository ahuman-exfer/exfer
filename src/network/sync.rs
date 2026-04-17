use crate::chain::fork_choice::{is_better_chain, ChainTip};
use crate::chain::state::{UtxoEntry, UtxoSet};
use crate::chain::storage::ChainStorage;
use crate::consensus::difficulty::expected_difficulty;
use crate::consensus::validation::{
    compute_tx_root, undo_block_transactions, validate_and_apply_block_transactions_atomic,
    validate_block_header, validate_block_header_skip_pow, validate_block_structure,
    ValidationError,
};
use crate::mempool::{Mempool, MempoolError};
use crate::network::peer::{
    reader_recv, writer_task, Peer, PeerError, PeerMetadata, PeerSharedState, ReaderState,
    WriterControl,
};
use crate::network::protocol::{
    is_routable, AddrEntry, GetHeadersMsg, HelloMsg, Message, TipResponseMsg,
};
use crate::types::block::{Block, BlockHeader};
use crate::types::hash::Hash256;
use crate::types::transaction::{OutPoint, Transaction};
use crate::types::*;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::{Duration, Instant};
use tracing::{error, info, warn};

pub type PeerId = [u8; 32];

pub struct PeerSession {
    pub session_id: u64,
    pub socket_addr: SocketAddr,
    pub is_outbound: bool,
    pub tx: mpsc::Sender<Message>,
    pub shutdown: Arc<AtomicBool>,
    pub established_at: Instant,
}

pub struct RetryState {
    pub backoff_secs: u64,
    pub next_attempt_at: std::time::Instant,
}

pub struct LogicalPeer {
    #[allow(dead_code)]
    pub identity: PeerId,
    pub session: Option<PeerSession>,
    pub known_addrs: HashSet<SocketAddr>,
    pub preferred_dial_addr: Option<SocketAddr>,
    pub desired_outbound: bool,
    pub retry: RetryState,
    pub tip: Option<PeerTip>,
    pub ibd_cooldown_until: Option<std::time::Instant>,
}

pub struct PeerRegistry {
    pub by_identity: HashMap<PeerId, LogicalPeer>,
    pub connected_socket_to_identity: HashMap<SocketAddr, PeerId>,
    pub known_dial_addr_to_identity: HashMap<SocketAddr, PeerId>,
    pub pending_inbound_sockets: HashSet<SocketAddr>,
    pub pending_outbound_addrs: HashSet<SocketAddr>,
}

pub struct OutboundBootstrap {
    pub retry: RetryState,
    pub desired_outbound: bool,
}

pub enum SessionAttachResult {
    NewLogicalConnect,
    ReplacedExistingSession { old_shutdown: Arc<AtomicBool> },
    RejectedDuplicate,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self {
            by_identity: HashMap::new(),
            connected_socket_to_identity: HashMap::new(),
            known_dial_addr_to_identity: HashMap::new(),
            pending_inbound_sockets: HashSet::new(),
            pending_outbound_addrs: HashSet::new(),
        }
    }

    #[allow(dead_code)]
    pub fn has_identity(&self, identity: &PeerId) -> bool {
        self.by_identity.contains_key(identity)
    }

    pub fn get_by_identity(&self, identity: &PeerId) -> Option<&LogicalPeer> {
        self.by_identity.get(identity)
    }

    pub fn get_mut_by_identity(&mut self, identity: &PeerId) -> Option<&mut LogicalPeer> {
        self.by_identity.get_mut(identity)
    }

    #[allow(dead_code)]
    pub fn is_connected_socket(&self, addr: &SocketAddr) -> bool {
        self.connected_socket_to_identity.contains_key(addr)
    }

    pub fn reserve_inbound_socket(&mut self, addr: SocketAddr) -> bool {
        if self.connected_socket_to_identity.contains_key(&addr)
            || self.pending_inbound_sockets.contains(&addr)
            || self.pending_outbound_addrs.contains(&addr)
        {
            return false;
        }
        self.pending_inbound_sockets.insert(addr);
        true
    }

    pub fn release_inbound_socket(&mut self, addr: &SocketAddr) {
        self.pending_inbound_sockets.remove(addr);
    }

    pub fn reserve_outbound_addr(&mut self, addr: SocketAddr) -> bool {
        if self.connected_socket_to_identity.contains_key(&addr)
            || self.pending_outbound_addrs.contains(&addr)
            || self.pending_inbound_sockets.contains(&addr)
        {
            return false;
        }
        self.pending_outbound_addrs.insert(addr);
        true
    }

    pub fn release_outbound_addr(&mut self, addr: &SocketAddr) {
        self.pending_outbound_addrs.remove(addr);
    }

    pub fn inbound_count(&self) -> usize {
        self.by_identity
            .values()
            .filter(|p| p.session.as_ref().is_some_and(|s| !s.is_outbound))
            .count()
    }

    pub fn outbound_count(&self) -> usize {
        self.by_identity
            .values()
            .filter(|p| p.session.as_ref().is_some_and(|s| s.is_outbound))
            .count()
    }

    pub fn inbound_count_for_ip(&self, ip: std::net::IpAddr) -> usize {
        self.by_identity
            .values()
            .filter(|p| {
                p.session
                    .as_ref()
                    .is_some_and(|s| !s.is_outbound && s.socket_addr.ip() == ip)
            })
            .count()
    }

    pub fn bind_dial_addr(&mut self, identity: PeerId, addr: SocketAddr) {
        if let Some(lp) = self.by_identity.get_mut(&identity) {
            lp.known_addrs.insert(addr);
            lp.preferred_dial_addr = Some(addr);
        }
        self.known_dial_addr_to_identity.insert(addr, identity);
    }

    pub fn attach_session(
        &mut self,
        identity: PeerId,
        session: PeerSession,
        handshake_tip: PeerTip,
        dial_addr_hint: Option<SocketAddr>,
        desired_outbound: bool,
        our_pubkey: PeerId,
        active_ibd_peer: Option<(PeerId, u64)>,
        catching_up: bool,
    ) -> SessionAttachResult {
        let socket_addr = session.socket_addr;

        // Remove from pending sets
        self.pending_inbound_sockets.remove(&socket_addr);
        self.pending_outbound_addrs.remove(&socket_addr);

        let lp = self.by_identity.entry(identity).or_insert_with(|| LogicalPeer {
            identity,
            session: None,
            known_addrs: HashSet::new(),
            preferred_dial_addr: None,
            desired_outbound: false,
            retry: RetryState {
                backoff_secs: 5,
                next_attempt_at: std::time::Instant::now(),
            },
            tip: None,
            ibd_cooldown_until: None,
        });

        // Apply dial_addr_hint
        if let Some(addr) = dial_addr_hint {
            lp.known_addrs.insert(addr);
            lp.preferred_dial_addr = Some(addr);
            self.known_dial_addr_to_identity.insert(addr, identity);
        }

        // Track desired_outbound
        if desired_outbound {
            lp.desired_outbound = true;
        }

        // Write tip with confirmed = false
        let mut tip = handshake_tip;
        tip.confirmed = false;
        lp.tip = Some(tip);

        if lp.session.is_none() {
            // No existing session — new logical connect
            self.connected_socket_to_identity.insert(socket_addr, identity);
            lp.session = Some(session);
            SessionAttachResult::NewLogicalConnect
        } else {
            // Existing session — apply duplicate-identity rule
            let existing_session_id = lp.session.as_ref().unwrap().session_id;

            // Rule 1: If active IBD peer, reject newcomer to protect IBD session
            if let Some((ibd_id, ibd_sid)) = active_ibd_peer {
                if ibd_id == identity && ibd_sid == existing_session_id {
                    return SessionAttachResult::RejectedDuplicate;
                }
            }

            // Rule 1b: During CatchingUp, never evict existing sessions.
            // The remote peer may be serving our IBD — tiebreaker eviction
            // on the remote side kills the session the IBD loop is using.
            if catching_up {
                return SessionAttachResult::RejectedDuplicate;
            }

            // Rule 2: Don't replace a session that was recently established.
            // This prevents the outbound manager from racing with a fresh
            // inbound (e.g. an IBD peer just connected) and evicting it
            // before it can finish syncing.
            let existing_session = lp.session.as_ref().unwrap();
            if existing_session.established_at.elapsed() < Duration::from_secs(120) {
                return SessionAttachResult::RejectedDuplicate;
            }

            // Rule 3: Deterministic tiebreak
            let prefer_outbound = our_pubkey > identity;
            if session.is_outbound == prefer_outbound {
                // Replace existing session
                let old_session = lp.session.take().unwrap();
                let old_shutdown = old_session.shutdown;
                self.connected_socket_to_identity.remove(&old_session.socket_addr);
                self.connected_socket_to_identity.insert(socket_addr, identity);
                lp.session = Some(session);
                SessionAttachResult::ReplacedExistingSession { old_shutdown }
            } else {
                // Reject newcomer
                SessionAttachResult::RejectedDuplicate
            }
        }
    }

    pub fn detach_session_if_current(&mut self, identity: PeerId, session_id: u64) -> bool {
        if let Some(lp) = self.by_identity.get_mut(&identity) {
            if let Some(ref sess) = lp.session {
                if sess.session_id == session_id {
                    let socket_addr = sess.socket_addr;
                    lp.session = None;
                    self.connected_socket_to_identity.remove(&socket_addr);
                    return true;
                }
            }
        }
        false
    }
}

/// Error from `process_block`. Distinguished into recoverable (invalid block,
/// peer misbehavior) and fatal (UTXO state corruption that requires node restart).
#[derive(Debug)]
pub enum ProcessBlockError {
    /// Block was invalid or processing failed, but UTXO state is consistent.
    /// Safe to continue — disconnect/penalize the peer and move on.
    Recoverable(String),
    /// UTXO state is corrupted — the node MUST halt. Continuing would build
    /// on an invalid state, producing or accepting wrong blocks.
    Fatal(String),
    /// Reorg ancestry walk found a missing block. The caller should request
    /// this block from a peer and retry. This is NOT an invalid-block error —
    /// do not penalize the sender.
    MissingReorgAncestor(Hash256),
}

impl std::fmt::Display for ProcessBlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessBlockError::Recoverable(msg) => write!(f, "{}", msg),
            ProcessBlockError::Fatal(msg) => write!(f, "FATAL: {}", msg),
            ProcessBlockError::MissingReorgAncestor(h) => {
                write!(f, "missing reorg ancestor: {}", h)
            }
        }
    }
}

impl ProcessBlockError {
    /// Is this a fatal (UTXO-corrupted) error that requires node shutdown?
    pub fn is_fatal(&self) -> bool {
        matches!(self, ProcessBlockError::Fatal(_))
    }

    /// Is this a header-only rejection (bad timestamp, difficulty, PoW)?
    /// Self-mined blocks rejected for header-only reasons should not purge
    /// mempool transactions, since the transactions themselves are valid.
    pub fn is_header_only(&self) -> bool {
        match self {
            ProcessBlockError::Recoverable(msg) => {
                msg.starts_with("block header validation failed")
            }
            _ => false,
        }
    }

}

impl From<String> for ProcessBlockError {
    fn from(s: String) -> Self {
        ProcessBlockError::Recoverable(s)
    }
}

impl From<&str> for ProcessBlockError {
    fn from(s: &str) -> Self {
        ProcessBlockError::Recoverable(s.to_string())
    }
}

/// Outcome of successfully processing a block (no error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessBlockOutcome {
    /// Block accepted as new tip (or reorg winner). Chain state advanced.
    Accepted,
    /// Block stored as fork, already known, or otherwise persisted but not
    /// as the new tip. Children waiting on this parent can proceed.
    Stored,
    /// Block buffered for future processing (timestamp too far ahead).
    /// Orphan children should NOT be drained — the block is not yet stored.
    BufferedFuture,
}

/// Events forwarded from peer tasks to the central sync manager.
pub enum PeerEvent {
    Connected {
        identity: PeerId,
        #[allow(dead_code)]
        session_id: u64,
    },
    Disconnected {
        identity: PeerId,
        session_id: u64,
    },
    NewBlock {
        from: SocketAddr,
        from_identity: PeerId,
        #[allow(dead_code)]
        session_id: u64,
        block: Block,
        pre_validated: bool,
    },
    BlockResponse {
        from: SocketAddr,
        from_identity: PeerId,
        session_id: u64,
        block: Block,
        pre_validated: bool,
    },
    HeadersResponse {
        from_identity: PeerId,
        session_id: u64,
        headers: Vec<BlockHeader>,
    },
    TipResponse {
        from_identity: PeerId,
        session_id: u64,
        height: u64,
        block_id: Hash256,
        cumulative_work: [u8; 32],
    },
}

/// Sync state exposed to peer tasks and the mining loop.
///
/// Three-state model with hysteresis:
/// - **CatchingUp**: large gap, needs IBD (GetHeaders/GetBlocks).
/// - **Live**: on canonical chain, consuming relay blocks. May be a few
///   blocks behind due to processing latency.
///
/// Mining is gated separately: only mine when Live AND our validated tip
/// is within 1 block of the best confirmed peer's tip (MiningReady).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncState {
    CatchingUp = 0,
    /// On the canonical chain. Replaces the old "Synced" state.
    Live = 1,
}

/// "Recent tip progress" = tip advanced within this many seconds.
const RECENT_PROGRESS_SECS: u64 = 60;

/// Per-peer tip info tracked by the sync manager, keyed by identity.
#[derive(Clone, Copy)]
pub struct PeerTip {
    pub height: u64,
    pub cumulative_work: [u8; 32],
    pub block_id: Hash256,
    /// True once this peer's tip has been confirmed via a TipResponse.
    pub confirmed: bool,
}

/// Duration (seconds) before an IP abuse entry decays (no new strikes → entry removed).
const BAN_DECAY_SECS: u64 = 300;

/// Number of cumulative strikes (across all connections) before an IP is banned.
const IP_BAN_STRIKE_THRESHOLD: u32 = 10;

/// Duration (seconds) an IP is banned after reaching the strike threshold.
const IP_BAN_DURATION_SECS: u64 = 600;

/// Maximum entries in the difficulty target cache. Bounded to prevent
/// unbounded growth from blocks at many different heights/forks.
const MAX_DIFFICULTY_CACHE_ENTRIES: usize = 256;

/// During IBD, enforce wall-clock future-drift checks for blocks within
/// this many blocks of the peer's reported tip height. Prevents an
/// eclipsing peer from pinning us to a far-future chain tip.
const IBD_DRIFT_WINDOW: u64 = 20;

/// Hard cap on ip_abuse map entries. When exceeded, a full sweep removes
/// all decayed entries. If still over cap after sweep, oldest entries are
/// evicted to prevent unbounded memory growth from distributed one-shot abuse.
const MAX_IP_ABUSE_ENTRIES: usize = 4_096;

/// Hard cap on identity_bans map entries. When exceeded, expired entries
/// are swept. If still over cap, oldest bans are evicted.
const MAX_IDENTITY_BAN_ENTRIES: usize = 4_096;

/// Maximum number of future-timestamp blocks buffered for retry.
const MAX_FUTURE_BLOCKS: usize = 16;

/// Maximum age (seconds) before a future-timestamp block is evicted from the buffer.
const FUTURE_BLOCK_MAX_AGE_SECS: u64 = 300;

// Maximum concurrent Argon2id PoW verifications: 2 (via pow_semaphore).
// Each Argon2id allocates 64 MiB; bounding concurrency prevents memory spikes.

/// Maximum number of non-winning fork blocks stored on disk. Prevents
/// disk-pressure DoS from PoW-valid but semantically unvalidated fork blocks.
/// 128 blocks × 4 MiB (MAX_FORK_BLOCK_SIZE) = 512 MiB worst-case disk.
/// Covers ~21 minutes of block production at 10s intervals — sufficient
/// for any realistic reorg. Deeper forks are handled on demand via
/// MissingReorgAncestor recovery (re-fetches evicted blocks from peers).
pub const MAX_FORK_BLOCKS: u32 = 128;

/// Per-IP abuse tracking entry.
#[derive(Clone, Debug)]
pub struct IpAbuseEntry {
    /// Cumulative strike count across all connections from this IP.
    pub strikes: u32,
    /// When the current ban expires (None = not banned, just accumulating strikes).
    pub banned_until: Option<std::time::Instant>,
    /// Last time a strike was recorded (for decay).
    pub last_strike: std::time::Instant,
}

/// Per-address metadata for intelligent peer selection (P1b).
#[derive(Clone, Debug)]
pub struct AddrInfo {
    pub entry: AddrEntry,
    pub last_attempt: Option<std::time::Instant>,
    pub last_success: Option<std::time::Instant>,
    pub fail_count: u32,
    /// Set of peer identities (Ed25519 pubkeys) that announced this address.
    /// source_count = sources.len(). Duplicate announcements from the same
    /// peer are ignored, preventing Sybil inflation of source counts.
    pub sources: std::collections::HashSet<[u8; 32]>,
    /// IP of the peer that first contributed this address.
    pub contributed_by: Option<std::net::IpAddr>,
}

/// Maximum trigger blocks per missing ancestor.
pub const MAX_TRIGGERS_PER_ANCESTOR: usize = 16;
/// Maximum total trigger blocks across all ancestors.
pub const MAX_GLOBAL_TRIGGERS: usize = 64;

/// Node-level state for pending reorg triggers.
/// When a block's reorg is blocked by a missing ancestor, the trigger block
/// is saved here. When ANY peer later delivers the missing ancestor, all
/// saved trigger blocks are retried — regardless of which peer originally
/// triggered the save.
#[derive(Default)]
pub struct ReorgTriggerState {
    /// Map from missing ancestor block_id → trigger blocks waiting for it.
    pub triggers: HashMap<Hash256, Vec<Block>>,
    /// Insertion-order queue for global cap eviction. Each entry is the
    /// ancestor_id under which a trigger was queued.
    pub order: std::collections::VecDeque<Hash256>,
}

impl ReorgTriggerState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a trigger block for a missing ancestor, enforcing both the
    /// per-ancestor cap and global cap (evicting oldest if needed).
    /// Returns true if inserted, false if dropped.
    pub fn insert(&mut self, ancestor_id: Hash256, trigger_block: Block) -> bool {
        // Enforce global cap before inserting
        while self.order.len() >= MAX_GLOBAL_TRIGGERS {
            if let Some(evict_ancestor) = self.order.pop_front() {
                if let Some(evict_vec) = self.triggers.get_mut(&evict_ancestor) {
                    if !evict_vec.is_empty() {
                        let evicted = evict_vec.remove(0);
                        warn!(
                            "Global trigger cap: evicting oldest trigger block {} for ancestor {}",
                            evicted.header.block_id(),
                            evict_ancestor
                        );
                    }
                    if evict_vec.is_empty() {
                        self.triggers.remove(&evict_ancestor);
                    }
                }
            } else {
                break;
            }
        }
        let triggers = self.triggers.entry(ancestor_id).or_default();
        if triggers.len() < MAX_TRIGGERS_PER_ANCESTOR {
            triggers.push(trigger_block);
            self.order.push_back(ancestor_id);
            true
        } else {
            false
        }
    }

    /// Take all trigger blocks for a given ancestor (removing them).
    pub fn take(&mut self, ancestor_id: &Hash256) -> Option<Vec<Block>> {
        self.triggers.remove(ancestor_id)
    }
}

/// The main node state shared across tasks.
pub struct Node {
    pub storage: Arc<ChainStorage>,
    pub utxo_set: Arc<RwLock<UtxoSet>>,
    pub mempool: Arc<Mutex<Mempool>>,
    pub tip: Arc<RwLock<ChainTip>>,
    pub genesis_id: Hash256,
    /// Registry of logical peers, keyed by identity (Ed25519 pubkey).
    pub peers: Arc<Mutex<PeerRegistry>>,
    /// Address-only bootstrap entries for outbound dials (identity not yet known).
    pub outbound_bootstraps: std::sync::Mutex<HashMap<SocketAddr, OutboundBootstrap>>,
    /// Monotonically increasing session counter. Starts at 1.
    pub next_session_id: std::sync::atomic::AtomicU64,
    /// Identity + session_id of the peer currently serving IBD.
    pub active_ibd_peer: std::sync::Mutex<Option<(PeerId, u64)>>,
    /// Global (cross-peer) block rate limiter: (window_start, count).
    /// Caps aggregate PoW verifications to MAX_GLOBAL_BLOCKS_PER_MIN regardless
    /// of how many peers send NewBlock messages concurrently.
    pub global_block_limiter: std::sync::Mutex<(std::time::Instant, u32)>,
    /// Global (cross-peer) transaction validation limiter: (window_start, count).
    /// Caps aggregate tx validations to MAX_GLOBAL_TXS_PER_MIN regardless
    /// of how many peers send NewTx messages concurrently.
    pub global_tx_limiter: std::sync::Mutex<(std::time::Instant, u32)>,
    /// IP-based abuse tracker: maps IP address to (ban_until, cumulative_strikes).
    /// Keyed by IP (not IP:port) so reconnecting from a new port doesn't reset
    /// penalties. Entries decay after BAN_DECAY_SECS with no new strikes.
    pub ip_abuse: std::sync::Mutex<HashMap<std::net::IpAddr, IpAbuseEntry>>,
    /// Tracked fork blocks: (block_id, cumulative_work).
    /// Bounded by MAX_FORK_BLOCKS. When full, lowest-work block is evicted
    /// to make room for higher-work forks (prevents attacker-filling).
    pub fork_blocks: std::sync::Mutex<Vec<(Hash256, [u8; 32])>>,
    /// Orphan blocks: blocks received before their parent.
    /// Bounded by MAX_ORPHAN_BLOCKS count and MAX_ORPHAN_CACHE_BYTES total.
    /// Individual entries capped at MAX_ORPHAN_BLOCK_SIZE.
    /// Entries are (parent_hash, block, serialized_byte_size).
    /// When a parent arrives and is processed, matching orphans are
    /// drained and processed to prevent liveness failures from
    /// out-of-order block delivery.
    pub orphan_blocks: std::sync::Mutex<Vec<(Hash256, Block, usize)>>,
    /// Future-timestamp blocks: PoW-valid blocks whose timestamp exceeds
    /// wall clock + MAX_TIMESTAMP_DRIFT. SPEC policy: buffer and retry,
    /// do not reject permanently. Entries are (block, receive_time).
    /// Bounded by MAX_FUTURE_BLOCKS to prevent memory pinning.
    pub future_blocks: std::sync::Mutex<Vec<(Block, std::time::Instant)>>,
    /// Cache of expected difficulty targets by (prev_block_id, height).
    /// Avoids repeating the 4319-ancestor DB walk at retarget boundaries
    /// when multiple peers send blocks at the same height. Bounded by
    /// MAX_DIFFICULTY_CACHE_ENTRIES to prevent unbounded memory growth.
    pub difficulty_cache: std::sync::Mutex<HashMap<(Hash256, u64), Hash256>>,
    /// Graceful shutdown flag. Set on fatal consensus errors instead of
    /// hard-exiting. The main loop and listener check this flag and
    /// wind down cleanly, allowing log flush and DB close.
    pub shutdown: Arc<AtomicBool>,
    /// Address book for peer discovery (P1b). Maps SocketAddr → AddrInfo.
    pub addr_book: std::sync::Mutex<HashMap<SocketAddr, AddrInfo>>,
    /// Bounded semaphore for concurrent Argon2id PoW verifications.
    /// Prevents bursty block traffic from monopolizing all Tokio blocking
    /// threads. Permits = number of concurrent PoW hashes allowed.
    pub pow_semaphore: tokio::sync::Semaphore,
    /// Node's persistent Ed25519 identity key for mutual handshake authentication.
    pub identity_key: ed25519_dalek::SigningKey,
    /// Identity-based ban map: pubkey → banned_until Instant.
    pub identity_bans: std::sync::Mutex<HashMap<[u8; 32], std::time::Instant>>,
    /// Global (cross-peer) outbound response bandwidth limiter: (window_start, bytes_sent).
    /// Caps aggregate egress to MAX_GLOBAL_RESPONSE_BYTES_PER_MIN regardless of
    /// how many peers send GetBlocks/GetHeaders concurrently.
    pub global_response_limiter: std::sync::Mutex<(std::time::Instant, usize)>,
    /// Node-level pending reorg triggers. When a block's reorg is blocked by
    /// a missing ancestor, the trigger block is saved here. When ANY peer
    /// later delivers the missing ancestor, all saved triggers are retried.
    pub reorg_triggers: std::sync::Mutex<ReorgTriggerState>,
    /// Channel for peer tasks to send events to the sync manager.
    pub peer_events_tx: mpsc::Sender<PeerEvent>,
    /// Current sync state (0 = CatchingUp, 1 = Live).
    pub sync_state: std::sync::atomic::AtomicU8,
    /// Best confirmed peer cumulative work. Updated by the sync manager.
    /// The mining loop uses this for the MiningReady check:
    /// only mine when Live AND our tip's work is close to the best peer's.
    /// All-zeros means no confirmed peers (bootstrap — mining allowed).
    pub best_peer_work: std::sync::Mutex<[u8; 32]>,
    /// Set by the sync manager when transitioning to CatchingUp.
    /// The mining tip-watcher checks this to cancel in-flight mining
    /// immediately instead of waiting for a tip change.
    pub mining_cancel: AtomicBool,
    /// When true, assume-valid optimization is enabled.
    /// Disabled by --no-assume-valid or --verify-all.
    pub assume_valid: bool,
    /// True once the checkpoint block (ASSUME_VALID_HEIGHT) has been verified
    /// to match ASSUME_VALID_HASH. Set on startup if storage already has the
    /// checkpoint, or during IBD when block 130,000 arrives and matches.
    pub assume_valid_verified: AtomicBool,
    /// v1.4.2 Fix 3: node-wide in-flight pre-verification frame-buffer budget.
    /// Every peer's reader task takes an `Arc<PeerBudget>` derived from this
    /// before allocating a payload buffer. Caps actual peak memory at
    /// 128 MiB total and 16 MiB per peer under honest accounting (the
    /// reader holds both a payload buffer and a full-frame reconstruction
    /// buffer concurrently at HMAC verification time — see
    /// `crate::network::peer::peak_prever_bytes`). This prevents a pool of
    /// 256 peers × 4 MiB blocks from consuming ~1 GiB of unverified RAM.
    pub frame_budget: Arc<crate::network::frame_budget::FrameBudget>,
}

impl Node {
    /// Atomically check and consume one global block-processing slot.
    /// Look up expected difficulty target with caching. Returns `(target, was_cache_miss)`.
    /// At retarget boundaries this avoids repeating the ~4319-ancestor DB walk
    /// when multiple peers send blocks referencing the same parent.
    /// The caller uses `was_cache_miss` to enforce per-peer DB-walk limits.
    fn cached_expected_difficulty(
        &self,
        prev_block_id: &Hash256,
        height: u64,
    ) -> Result<(Hash256, bool), crate::consensus::difficulty::DifficultyError> {
        let key = (*prev_block_id, height);

        // Check cache first (fast path)
        {
            let cache = self
                .difficulty_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(target) = cache.get(&key) {
                return Ok((*target, false));
            }
        }

        // Cache miss — compute (potentially expensive DB walk)
        let target = crate::consensus::difficulty::expected_difficulty(
            &self.storage,
            prev_block_id,
            height,
        )?;

        // Store in cache, evict single entry if over cap
        {
            let mut cache = self
                .difficulty_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if cache.len() >= MAX_DIFFICULTY_CACHE_ENTRIES {
                // Evict one entry (lowest height) instead of clearing the
                // entire cache. clear() would let an attacker force repeated
                // DB walks by filling the cache then triggering a miss.
                if let Some(&evict_key) = cache.keys().min_by_key(|k| k.1) {
                    cache.remove(&evict_key);
                }
            }
            cache.insert(key, target);
        }

        Ok((target, true))
    }

    ///
    /// Returns `true` if a slot was available (and is now consumed), `false` if
    /// the per-minute budget is exhausted. Check and increment happen under a
    /// single mutex acquisition so concurrent peers cannot overshoot the limit.
    fn try_consume_global_block_slot(&self) -> bool {
        let mut limiter = self
            .global_block_limiter
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        if now.duration_since(limiter.0) >= std::time::Duration::from_secs(60) {
            limiter.0 = now;
            limiter.1 = 0;
        }
        if limiter.1 < MAX_GLOBAL_BLOCKS_PER_MIN {
            limiter.1 += 1;
            true
        } else {
            false
        }
    }

    /// Atomically check and consume one global tx-validation slot.
    ///
    /// Same pattern as try_consume_global_block_slot but for transactions.
    fn try_consume_global_tx_slot(&self) -> bool {
        let mut limiter = self
            .global_tx_limiter
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        if now.duration_since(limiter.0) >= std::time::Duration::from_secs(60) {
            limiter.0 = now;
            limiter.1 = 0;
        }
        if limiter.1 < MAX_GLOBAL_TXS_PER_MIN {
            limiter.1 += 1;
            true
        } else {
            false
        }
    }

    /// Refund a global tx slot after cheap pre-check rejection (before
    /// expensive validation). Only used for pre_check failures where no
    /// costly signature/script verification has occurred.
    fn refund_global_tx_slot(&self) {
        let mut limiter = self
            .global_tx_limiter
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        limiter.1 = limiter.1.saturating_sub(1);
    }

    /// Check and consume global outbound response bandwidth.
    /// Returns `true` if `bytes` fit within the per-minute global budget.
    fn try_consume_global_response_bytes(&self, bytes: usize) -> bool {
        let mut limiter = self
            .global_response_limiter
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        if now.duration_since(limiter.0) >= std::time::Duration::from_secs(60) {
            limiter.0 = now;
            limiter.1 = 0;
        }
        if limiter.1.saturating_add(bytes) <= MAX_GLOBAL_RESPONSE_BYTES_PER_MIN {
            limiter.1 = limiter.1.saturating_add(bytes);
            true
        } else {
            false
        }
    }

    /// Record a strike against an IP address. Returns true if the IP is now banned.
    /// Keyed by IP (not IP:port) so port rotation doesn't reset penalties.
    /// When an identity is provided and the IP gets banned, the identity is also banned.
    ///
    /// Post-handshake frames are HMAC-authenticated, so message-level violations
    /// are attributable to the authenticated identity. Pass `Some(identity)` for
    /// all post-handshake strikes so that abusive peers accumulate identity bans,
    /// not just IP bans. Only pass `None` for pre-handshake failures where the
    /// peer's identity has not yet been cryptographically verified.
    fn record_ip_strike(&self, ip: std::net::IpAddr, identity: Option<[u8; 32]>) -> bool {
        let mut abuse = self.ip_abuse.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        let decay = std::time::Duration::from_secs(BAN_DECAY_SECS);

        // Periodic sweep: when the map exceeds MAX_IP_ABUSE_ENTRIES,
        // remove all entries whose last strike has decayed and whose
        // ban (if any) has expired. Prevents unbounded growth from
        // distributed one-shot abusive IP patterns.
        if abuse.len() >= MAX_IP_ABUSE_ENTRIES {
            abuse.retain(|_, e| {
                let decayed = now.duration_since(e.last_strike) >= decay;
                let ban_active = e.banned_until.is_some_and(|until| now < until);
                !decayed || ban_active
            });
            // If still over cap after sweep, evict oldest non-banned entries.
            // Never evict actively-banned IPs — that would let an attacker
            // flush bans via churn from many disposable source IPs.
            while abuse.len() >= MAX_IP_ABUSE_ENTRIES {
                let oldest_ip = abuse
                    .iter()
                    .filter(|(_, e)| e.banned_until.is_none_or(|until| now >= until))
                    .min_by_key(|(_, e)| e.last_strike)
                    .map(|(ip, _)| *ip);
                if let Some(ip) = oldest_ip {
                    abuse.remove(&ip);
                } else {
                    break; // all remaining entries are actively banned
                }
            }
        }

        // If table is still at capacity after eviction (all entries are
        // actively banned), evict the oldest entry regardless of ban status
        // to make room for the new offender (LRU eviction).
        if abuse.len() >= MAX_IP_ABUSE_ENTRIES && !abuse.contains_key(&ip) {
            let oldest_ip = abuse
                .iter()
                .min_by_key(|(_, e)| e.last_strike)
                .map(|(ip, _)| *ip);
            if let Some(evict_ip) = oldest_ip {
                abuse.remove(&evict_ip);
            }
        }

        let entry = abuse.entry(ip).or_insert(IpAbuseEntry {
            strikes: 0,
            banned_until: None,
            last_strike: now,
        });

        // Decay old entries: if last strike was long ago, reset
        if now.duration_since(entry.last_strike) >= decay {
            entry.strikes = 0;
            entry.banned_until = None;
        }

        entry.strikes += 1;
        entry.last_strike = now;

        if entry.strikes >= IP_BAN_STRIKE_THRESHOLD {
            let ban_end = now + std::time::Duration::from_secs(IP_BAN_DURATION_SECS);
            entry.banned_until = Some(ban_end);
            // Persist ban to storage (P2a). Non-fatal on error.
            let ban_end_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() + IP_BAN_DURATION_SECS)
                .unwrap_or(0);
            if let Err(e) = self.storage.put_ip_ban(ip, ban_end_unix) {
                warn!("Failed to persist IP ban for {}: {}", ip, e);
            }
            // Also ban the peer's identity if known
            if let Some(pk) = identity {
                self.ban_identity(pk);
            }
            true
        } else {
            false
        }
    }

    /// Check if an IP address is currently banned. Also cleans up expired bans.
    fn is_ip_banned(&self, ip: std::net::IpAddr) -> bool {
        let mut abuse = self.ip_abuse.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = abuse.get_mut(&ip) {
            let now = std::time::Instant::now();
            if let Some(until) = entry.banned_until {
                if now >= until {
                    // Ban expired — decay the entry entirely
                    abuse.remove(&ip);
                    // Remove from persistent storage (P2a). Non-fatal on error.
                    if let Err(e) = self.storage.remove_ip_ban(ip) {
                        warn!("Failed to remove expired IP ban for {}: {}", ip, e);
                    }
                    return false;
                }
                return true;
            }
            // Not banned but has strikes — check decay
            if now.duration_since(entry.last_strike)
                >= std::time::Duration::from_secs(BAN_DECAY_SECS)
            {
                abuse.remove(&ip);
            }
        }
        false
    }

    // ── Identity ban helpers ──

    /// Check if a peer identity (pubkey) is currently banned.
    fn is_identity_banned(&self, pubkey: &[u8; 32]) -> bool {
        let mut bans = self.identity_bans.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(until) = bans.get(pubkey) {
            if std::time::Instant::now() >= *until {
                let pk = *pubkey;
                bans.remove(&pk);
                if let Err(e) = self.storage.remove_identity_ban(&pk) {
                    warn!("Failed to remove expired identity ban: {}", e);
                }
                return false;
            }
            return true;
        }
        false
    }

    /// Ban a peer identity for IP_BAN_DURATION_SECS.
    /// Sweeps expired bans when the map exceeds MAX_IDENTITY_BAN_ENTRIES.
    fn ban_identity(&self, pubkey: [u8; 32]) {
        if pubkey == [0u8; 32] {
            return;
        }
        let now = std::time::Instant::now();
        let until = now + std::time::Duration::from_secs(IP_BAN_DURATION_SECS);
        let mut bans = self.identity_bans.lock().unwrap_or_else(|e| e.into_inner());

        // Periodic sweep: remove expired bans when map exceeds cap
        if bans.len() >= MAX_IDENTITY_BAN_ENTRIES {
            let expired: Vec<[u8; 32]> = bans
                .iter()
                .filter(|(_, exp)| now >= **exp)
                .map(|(pk, _)| *pk)
                .collect();
            for pk in &expired {
                bans.remove(pk);
                if let Err(e) = self.storage.remove_identity_ban(pk) {
                    warn!("Failed to remove expired identity ban: {}", e);
                }
            }
            // If still over cap, evict oldest (soonest-expiring) bans
            while bans.len() >= MAX_IDENTITY_BAN_ENTRIES {
                let oldest = bans.iter().min_by_key(|(_, exp)| **exp).map(|(pk, _)| *pk);
                if let Some(pk) = oldest {
                    bans.remove(&pk);
                    if let Err(e) = self.storage.remove_identity_ban(&pk) {
                        warn!("Failed to evict identity ban: {}", e);
                    }
                } else {
                    break;
                }
            }
        }

        bans.insert(pubkey, until);
        let until_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() + IP_BAN_DURATION_SECS)
            .unwrap_or(0);
        if let Err(e) = self.storage.put_identity_ban(&pubkey, until_unix) {
            warn!("Failed to persist identity ban: {}", e);
        }
    }

    // ── Addr book helpers (P1b) ──

    /// Sample up to `n` random routable entries from the addr book for relay.
    /// Non-routable addresses are filtered out before sampling to prevent
    /// relaying private/loopback addresses to peers.
    pub fn addr_book_sample(&self, n: usize) -> Vec<AddrEntry> {
        let book = self.addr_book.lock().unwrap_or_else(|e| e.into_inner());
        let mut entries: Vec<AddrEntry> = book
            .values()
            .filter(|info| is_routable(&info.entry.addr))
            .map(|info| info.entry.clone())
            .collect();
        // Shuffle using Fisher-Yates
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let len = entries.len();
        for i in (1..len).rev() {
            let j = rng.gen_range(0..=i);
            entries.swap(i, j);
        }
        entries.truncate(n);
        entries
    }

    /// Select the best candidate address for outbound connection.
    /// Respects exponential backoff on failed addresses.
    /// Deprioritizes single-source addresses to resist Sybil addr poisoning:
    /// addresses confirmed by multiple independent peers are preferred. If no
    /// multi-source candidate is available, single-source addresses are used
    /// as fallback so bootstrap from a single seed still works.
    /// Returns None if no suitable candidate is available.
    pub fn addr_book_select_for_connect(&self) -> Option<SocketAddr> {
        let book = self.addr_book.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();

        // Collect connected peers to exclude
        // (peers lock is async Mutex — can't hold both. Snapshot connected addrs via a separate call.)
        // Instead, we'll let the caller check. For simplicity, filter by backoff only here.

        let mut best: Option<(SocketAddr, &AddrInfo)> = None;
        let mut best_fallback: Option<(SocketAddr, &AddrInfo)> = None;
        for (addr, info) in book.iter() {
            // Check backoff: next_attempt = last_attempt + min(5 * 2^fail_count, 3600)
            if let Some(last_attempt) = info.last_attempt {
                let backoff_secs =
                    std::cmp::min(5u64.saturating_mul(1u64 << info.fail_count.min(20)), 3600);
                let next_attempt = last_attempt + std::time::Duration::from_secs(backoff_secs);
                if now < next_attempt {
                    continue; // still in backoff
                }
            }

            // Prefer: recent last_success, multiple sources, low fail_count
            let is_better = |cur_best: &AddrInfo| -> bool {
                // Prefer addresses that have succeeded before
                let our_success = info.last_success.is_some();
                let their_success = cur_best.last_success.is_some();
                if our_success != their_success {
                    our_success
                } else {
                    // Then prefer more sources and lower fail count
                    (info.sources.len() as u32, u32::MAX - info.fail_count)
                        > (
                            cur_best.sources.len() as u32,
                            u32::MAX - cur_best.fail_count,
                        )
                }
            };

            // Multi-source addresses go into the preferred pool;
            // single-source into fallback only.
            if info.sources.len() as u32 >= MIN_ADDR_SOURCES_FOR_CONNECT
                || info.last_success.is_some()
            {
                let dominated = match &best {
                    None => true,
                    Some((_, cur)) => is_better(cur),
                };
                if dominated {
                    best = Some((*addr, info));
                }
            } else {
                let dominated = match &best_fallback {
                    None => true,
                    Some((_, cur)) => is_better(cur),
                };
                if dominated {
                    best_fallback = Some((*addr, info));
                }
            }
        }

        best.or(best_fallback).map(|(addr, _)| addr)
    }

    /// Merge validated addr entries into the addr book.
    /// Accepts up to MAX_ADDR_PER_MSG_ACCEPT entries, rejects unroutable and
    /// suspicious timestamps. Evicts oldest-last_seen when full.
    ///
    /// Enforces:
    /// - Per-/16 subnet diversity cap (MAX_ADDR_BOOK_PER_SUBNET16)
    /// - Per-peer contribution cap (25% of MAX_ADDR_BOOK_SIZE)
    fn merge_addr_entries(
        &self,
        entries: &[AddrEntry],
        peer_ip: std::net::IpAddr,
        peer_identity: &[u8; 32],
    ) {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut book = self.addr_book.lock().unwrap_or_else(|e| e.into_inner());
        let mut accepted = 0usize;

        // Pre-compute per-peer contribution count for cap enforcement
        let peer_contribution_cap =
            MAX_ADDR_BOOK_SIZE * MAX_ADDR_BOOK_PEER_FRACTION_NUM / MAX_ADDR_BOOK_PEER_FRACTION_DEN;
        let peer_contributions = book
            .values()
            .filter(|info| info.contributed_by == Some(peer_ip))
            .count();
        let mut new_contributions = 0usize;

        for entry in entries {
            if accepted >= MAX_ADDR_PER_MSG_ACCEPT {
                break;
            }

            // Reject unroutable
            if !is_routable(&entry.addr) {
                continue;
            }

            // Reject suspicious timestamps
            if entry.last_seen > now_unix + 600 {
                continue; // too far in the future
            }
            if now_unix > entry.last_seen && now_unix - entry.last_seen > 86400 {
                continue; // more than 1 day old
            }

            // Dedup: update timestamp, record announcing peer identity
            if let Some(existing) = book.get_mut(&entry.addr) {
                if entry.last_seen > existing.entry.last_seen {
                    existing.entry.last_seen = entry.last_seen;
                }
                existing.sources.insert(*peer_identity);
                accepted += 1;
                continue;
            }

            // Per-peer contribution cap: a single peer may not fill more
            // than 25% of the address book.
            if peer_contributions + new_contributions >= peer_contribution_cap {
                break;
            }

            // Subnet diversity: cap entries per /16 prefix
            let subnet16 = Self::subnet16(&entry.addr.ip());
            let subnet_count = book
                .keys()
                .filter(|a| Self::subnet16(&a.ip()) == subnet16)
                .count();
            if subnet_count >= MAX_ADDR_BOOK_PER_SUBNET16 {
                continue;
            }

            // Evict oldest when full
            if book.len() >= MAX_ADDR_BOOK_SIZE {
                let oldest = book
                    .iter()
                    .min_by_key(|(_, info)| info.entry.last_seen)
                    .map(|(addr, _)| *addr);
                if let Some(oldest_addr) = oldest {
                    book.remove(&oldest_addr);
                }
            }

            let mut sources = std::collections::HashSet::new();
            sources.insert(*peer_identity);
            book.insert(
                entry.addr,
                AddrInfo {
                    entry: entry.clone(),
                    last_attempt: None,
                    last_success: None,
                    fail_count: 0,
                    sources,
                    contributed_by: Some(peer_ip),
                },
            );
            new_contributions += 1;
            accepted += 1;
        }
    }

    /// Extract /16 subnet prefix as a 2-byte key.
    /// IPv4: first two octets. IPv6: first two bytes of the address.
    fn subnet16(ip: &std::net::IpAddr) -> [u8; 2] {
        match ip {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                [o[0], o[1]]
            }
            std::net::IpAddr::V6(v6) => {
                let o = v6.octets();
                [o[0], o[1]]
            }
        }
    }

    /// Record a successful connection to an address.
    /// Non-routable addresses (loopback, private, link-local) are silently
    /// skipped — same check applied to gossipped Addr entries.
    pub fn addr_book_record_success(&self, addr: SocketAddr) {
        if !is_routable(&addr) {
            return;
        }

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut book = self.addr_book.lock().unwrap_or_else(|e| e.into_inner());

        // If already tracked, just update metadata — no cap check needed
        if let Some(info) = book.get_mut(&addr) {
            info.fail_count = 0;
            info.last_success = Some(std::time::Instant::now());
            info.entry.last_seen = now_unix;
            return;
        }

        // New address: enforce cap with eviction before inserting
        if book.len() >= MAX_ADDR_BOOK_SIZE {
            let oldest = book
                .iter()
                .min_by_key(|(_, info)| info.entry.last_seen)
                .map(|(a, _)| *a);
            if let Some(oldest_addr) = oldest {
                book.remove(&oldest_addr);
            }
        }

        book.insert(
            addr,
            AddrInfo {
                entry: AddrEntry {
                    addr,
                    last_seen: now_unix,
                },
                last_attempt: None,
                last_success: Some(std::time::Instant::now()),
                fail_count: 0,
                sources: std::collections::HashSet::new(), // direct connection, no announcing peer
                contributed_by: None,
            },
        );
    }

    /// Record a failed connection attempt to an address.
    pub fn addr_book_record_failure(&self, addr: SocketAddr) {
        let mut book = self.addr_book.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(info) = book.get_mut(&addr) {
            info.fail_count = info.fail_count.saturating_add(1);
            info.last_attempt = Some(std::time::Instant::now());
        }
    }

    /// Flush the addr book to persistent storage.
    pub fn flush_addr_book(&self) {
        let book = self.addr_book.lock().unwrap_or_else(|e| e.into_inner());
        let addrs: Vec<(SocketAddr, u64)> = book
            .values()
            .map(|info| (info.entry.addr, info.entry.last_seen))
            .collect();
        drop(book);
        if let Err(e) = self.storage.put_known_addrs(&addrs) {
            warn!("Failed to flush addr book to storage: {}", e);
        }
    }

    /// Buffer a PoW-valid block whose timestamp is too far ahead.
    /// Bounded by MAX_FUTURE_BLOCKS; oldest entries are evicted first.
    /// Expired entries (older than FUTURE_BLOCK_MAX_AGE_SECS) are pruned on insert.
    fn buffer_future_block(&self, block: Block) {
        let mut buf = self.future_blocks.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();

        // Prune expired entries
        buf.retain(|(_, t)| now.duration_since(*t).as_secs() < FUTURE_BLOCK_MAX_AGE_SECS);

        // Deduplicate
        let block_id = block.header.block_id();
        if buf.iter().any(|(b, _)| b.header.block_id() == block_id) {
            return;
        }

        // Evict oldest if at capacity
        if buf.len() >= MAX_FUTURE_BLOCKS {
            buf.remove(0);
        }

        buf.push((block, now));
    }

    /// Drain future-timestamp blocks and retry processing.
    /// Called periodically from the sync manager.
    ///
    /// Preserves original insertion timestamps for blocks that are still
    /// future — prevents age-reset bypass that would let an attacker keep
    /// slots occupied indefinitely.
    pub async fn retry_future_blocks(&self) {
        let candidates: Vec<(Block, std::time::Instant)> = {
            let mut buf = self.future_blocks.lock().unwrap_or_else(|e| e.into_inner());
            let now = std::time::Instant::now();
            // Prune expired entries
            buf.retain(|(_, t)| now.duration_since(*t).as_secs() < FUTURE_BLOCK_MAX_AGE_SECS);
            // Take all current candidates WITH their original timestamps
            buf.drain(..).collect()
        };

        for (future_blk, original_ts) in candidates {
            let wall_clock = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs());
            let blk_id = future_blk.header.block_id();
            // Use pre-validated path: PoW was already verified before buffering.
            match self
                .process_block_pre_validated(future_blk.clone(), wall_clock)
                .await
            {
                Ok(ProcessBlockOutcome::Accepted) => {
                    info!("Accepted previously-future block {}", blk_id);
                    self.broadcast(&Message::NewBlock(future_blk), None).await;
                    self.try_process_orphans(&blk_id).await;
                }
                Ok(ProcessBlockOutcome::Stored) => {
                    self.try_process_orphans(&blk_id).await;
                }
                Ok(ProcessBlockOutcome::BufferedFuture) => {
                    let mut buf = self.future_blocks.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(entry) = buf.iter_mut().find(|(b, _)| b.header.block_id() == blk_id)
                    {
                        entry.1 = original_ts;
                    }
                }
                Err(ProcessBlockError::MissingReorgAncestor(missing_id)) => {
                    info!(
                        "Future block {} needs missing ancestor {}; queuing recovery",
                        blk_id, missing_id
                    );
                    {
                        let mut rt = self
                            .reorg_triggers
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        if !rt.insert(missing_id, future_blk) {
                            warn!("Dropping future trigger block {}: too many triggers for ancestor {}", blk_id, missing_id);
                        }
                    }
                    // Request missing ancestor from any connected peer
                    let identities: Vec<PeerId> = {
                        let p = self.peers.lock().await;
                        p.by_identity
                            .iter()
                            .filter(|(_, lp)| lp.session.is_some())
                            .map(|(id, _)| *id)
                            .collect()
                    };
                    for id in identities {
                        if self
                            .send_to_peer(&id, Message::GetBlocks(vec![missing_id]))
                            .await
                        {
                            break;
                        }
                    }
                }
                Err(e) if e.is_fatal() => {
                    tracing::error!(
                        fatal = true,
                        error = %e,
                        "FATAL: consensus state corrupted retrying future block, initiating graceful shutdown"
                    );
                    self.shutdown.store(true, Ordering::SeqCst);
                    return;
                }
                Err(e) => {
                    warn!(
                        "Future block {} hit recoverable error, re-buffering: {}",
                        blk_id, e
                    );
                    let mut buf = self.future_blocks.lock().unwrap_or_else(|e| e.into_inner());
                    if buf.len() < MAX_FUTURE_BLOCKS {
                        buf.push((future_blk, original_ts));
                    }
                }
            }
        }
    }

    /// Allocate a new unique session id.
    fn next_session_id(&self) -> u64 {
        self.next_session_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Reset retry state to initial backoff.
    fn reset_retry(logical_peer: &mut LogicalPeer) {
        logical_peer.retry.backoff_secs = 5;
        logical_peer.retry.next_attempt_at = std::time::Instant::now();
    }

    /// Bump retry state with exponential backoff.
    fn bump_retry(logical_peer: &mut LogicalPeer) {
        logical_peer.retry.backoff_secs =
            std::cmp::min(logical_peer.retry.backoff_secs * 2, 300);
        logical_peer.retry.next_attempt_at = std::time::Instant::now()
            + std::time::Duration::from_secs(logical_peer.retry.backoff_secs);
    }

    /// Reset bootstrap retry state to initial backoff.
    fn reset_bootstrap_retry(bootstrap: &mut OutboundBootstrap) {
        bootstrap.retry.backoff_secs = 5;
        bootstrap.retry.next_attempt_at = std::time::Instant::now();
    }

    /// Bump bootstrap retry state with exponential backoff.
    fn bump_bootstrap_retry(bootstrap: &mut OutboundBootstrap) {
        bootstrap.retry.backoff_secs =
            std::cmp::min(bootstrap.retry.backoff_secs * 2, 300);
        bootstrap.retry.next_attempt_at = std::time::Instant::now()
            + std::time::Duration::from_secs(bootstrap.retry.backoff_secs);
    }

    /// Send a message to a specific session (identity + session_id must match).
    /// Returns true if sent successfully, false otherwise.
    pub async fn send_to_session(&self, identity: PeerId, session_id: u64, msg: Message) -> bool {
        let tx = {
            let peers = self.peers.lock().await;
            match peers.get_by_identity(&identity) {
                Some(lp) => match &lp.session {
                    Some(s) if s.session_id == session_id => Some(s.tx.clone()),
                    _ => None,
                },
                None => None,
            }
        };
        if let Some(tx) = tx {
            match tokio::time::timeout(std::time::Duration::from_millis(50), tx.send(msg)).await {
                Ok(Ok(())) => true,
                _ => false,
            }
        } else {
            false
        }
    }

    /// Send a message to a specific peer via its outbound channel, keyed by identity.
    /// Returns true if sent successfully, false if peer not found or channel full.
    pub async fn send_to_peer(&self, identity: &PeerId, msg: Message) -> bool {
        let tx = {
            let peers = self.peers.lock().await;
            peers
                .get_by_identity(identity)
                .and_then(|p| p.session.as_ref().map(|s| s.tx.clone()))
        };
        if let Some(tx) = tx {
            match tokio::time::timeout(std::time::Duration::from_millis(50), tx.send(msg)).await {
                Ok(Ok(())) => true,
                _ => false,
            }
        } else {
            false
        }
    }

    /// Broadcast a message to all connected peers, optionally excluding one by identity.
    pub async fn broadcast(&self, msg: &Message, exclude: Option<PeerId>) {
        let targets: Vec<(SocketAddr, mpsc::Sender<Message>)> = {
            let peers = self.peers.lock().await;
            peers
                .by_identity
                .iter()
                .filter(|(id, _)| exclude.as_ref() != Some(*id))
                .filter_map(|(_, peer)| {
                    peer.session
                        .as_ref()
                        .map(|s| (s.socket_addr, s.tx.clone()))
                })
                .collect()
        };
        for (addr, tx) in targets {
            match tokio::time::timeout(std::time::Duration::from_millis(50), tx.send(msg.clone()))
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {}
                Err(_) => {
                    warn!("Broadcast to {} timed out (channel full)", addr);
                }
            }
        }
    }

    /// Drain orphan blocks whose parent matches `parent_id` and process them.
    /// Returns the list of successfully processed block IDs (for recursive
    /// orphan resolution).
    async fn try_process_orphans(&self, parent_id: &Hash256) -> Vec<Hash256> {
        let children: Vec<Block> = {
            let mut orphans = self.orphan_blocks.lock().unwrap_or_else(|e| e.into_inner());
            let mut matched = Vec::new();
            let mut i = 0;
            while i < orphans.len() {
                if orphans[i].0 == *parent_id {
                    let (_parent, block, _size) = orphans.swap_remove(i);
                    matched.push(block);
                } else {
                    i += 1;
                }
            }
            matched
        };

        let mut processed_ids = Vec::new();
        for child in children {
            let child_id = child.header.block_id();
            let wall_clock = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs());
            match self.process_block(child, wall_clock).await {
                Ok(ProcessBlockOutcome::Accepted) => {
                    info!("Accepted orphan block {}", child_id);
                    processed_ids.push(child_id);
                }
                Ok(ProcessBlockOutcome::Stored) => {
                    // Block stored as fork or already known — still recurse
                    // so children waiting on this parent can be attempted.
                    info!(
                        "Orphan block {} stored (fork/known), recursing children",
                        child_id
                    );
                    processed_ids.push(child_id);
                }
                Ok(ProcessBlockOutcome::BufferedFuture) => {
                    // Block buffered for future processing — do NOT recurse.
                    // Children remain in the orphan cache until this block
                    // is actually stored by retry_future_blocks.
                    info!(
                        "Orphan block {} buffered as future, skipping children",
                        child_id
                    );
                }
                Err(e) if e.is_fatal() => {
                    tracing::error!(
                        fatal = true,
                        error = %e,
                        "FATAL: consensus state corrupted processing orphan, initiating graceful shutdown"
                    );
                    self.shutdown.store(true, Ordering::SeqCst);
                    return processed_ids;
                }
                Err(e) => {
                    warn!("Rejected orphan block {}: {}", child_id, e);
                }
            }
        }
        // Recursive: process grandchildren of any newly accepted/stored blocks
        for id in processed_ids.clone() {
            let grandchildren = Box::pin(self.try_process_orphans(&id)).await;
            processed_ids.extend(grandchildren);
        }
        processed_ids
    }

    /// Retry all saved trigger blocks for a given ancestor that just arrived.
    /// Takes trigger blocks from the shared node-level reorg trigger state
    /// (not per-peer), so triggers saved by peer A can be retried when peer B
    /// delivers the missing ancestor. If a trigger still has a deeper missing
    /// ancestor, it is re-queued under the deeper ancestor and requested from
    /// `request_peer` (or any connected peer).
    pub async fn retry_reorg_triggers(
        &self,
        ancestor_id: &Hash256,
        wall_clock: Option<u64>,
        request_peer: Option<PeerId>,
    ) {
        let trigger_blocks = {
            let mut rt = self
                .reorg_triggers
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            rt.take(ancestor_id)
        };
        if let Some(trigger_blocks) = trigger_blocks {
            for trigger_block in trigger_blocks {
                let trigger_id = trigger_block.header.block_id();
                info!(
                    "Retrying reorg trigger block {} after ancestor {} arrived",
                    trigger_id, ancestor_id
                );
                match self.process_block(trigger_block.clone(), wall_clock).await {
                    Ok(ProcessBlockOutcome::Accepted) => {
                        info!("Reorg trigger block {} accepted", trigger_id);
                        self.try_process_orphans(&trigger_id).await;
                    }
                    Ok(ProcessBlockOutcome::Stored) => {
                        self.try_process_orphans(&trigger_id).await;
                    }
                    Ok(ProcessBlockOutcome::BufferedFuture) => {
                        info!("Reorg trigger block {} buffered as future", trigger_id);
                    }
                    Err(ProcessBlockError::MissingReorgAncestor(deeper_id)) => {
                        info!(
                            "Reorg trigger {} still missing deeper ancestor {}; re-queuing",
                            trigger_id, deeper_id
                        );
                        {
                            let mut rt = self
                                .reorg_triggers
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            rt.insert(deeper_id, trigger_block);
                        }
                        // Request deeper ancestor from preferred peer or any peer
                        if let Some(id) = request_peer {
                            self.send_to_peer(&id, Message::GetBlocks(vec![deeper_id]))
                                .await;
                        } else {
                            let identities: Vec<PeerId> = {
                                let p = self.peers.lock().await;
                                p.by_identity
                                    .iter()
                                    .filter(|(_, lp)| lp.session.is_some())
                                    .map(|(id, _)| *id)
                                    .collect()
                            };
                            for id in identities {
                                if self
                                    .send_to_peer(&id, Message::GetBlocks(vec![deeper_id]))
                                    .await
                                {
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) if e.is_fatal() => {
                        tracing::error!(
                            fatal = true,
                            error = %e,
                            "FATAL: consensus state corrupted processing reorg trigger, initiating graceful shutdown"
                        );
                        self.shutdown.store(true, Ordering::SeqCst);
                        return;
                    }
                    Err(e) => {
                        warn!(
                            "Reorg trigger block {} failed after ancestor recovery: {}",
                            trigger_id, e
                        );
                    }
                }
            }
        }
    }

    /// Store a fork block with work-based eviction.
    ///
    /// When the fork pool is full, evicts the lowest-cumulative-work block
    /// to make room — unless the new block has even lower work, in which
    /// case it is dropped. This prevents an attacker from filling the pool
    /// with low-work junk while still bounding total disk usage.
    ///
    /// Returns Ok(true) if stored, Ok(false) if dropped (lower work than
    /// all existing fork blocks).
    fn try_store_fork_block(
        &self,
        block: &Block,
        cumulative_work: &[u8; 32],
    ) -> Result<bool, ProcessBlockError> {
        let block_id = block.header.block_id();

        // Recheck: a concurrent winner may have committed this block while
        // we were doing header validation / fork-choice. Without this guard
        // the same block ends up in both canonical storage and fork tracking.
        if self
            .storage
            .has_block(&block_id)
            .map_err(|e| ProcessBlockError::Recoverable(e.to_string()))?
        {
            return Ok(false);
        }

        // Per-entry size cap: bounds worst-case disk to MAX_FORK_BLOCKS * MAX_FORK_BLOCK_SIZE.
        let block_size = block.serialize().map(|b| b.len()).unwrap_or(usize::MAX);
        if block_size > MAX_FORK_BLOCK_SIZE {
            return Ok(false);
        }

        // --- Decision phase: acquire lock, determine action, release lock.
        //     No blocking I/O while holding the mutex — prevents async
        //     runtime starvation under fork-pressure traffic.
        let evict_id: Option<Hash256>;
        {
            let fork_blocks = self.fork_blocks.lock().unwrap_or_else(|e| e.into_inner());

            if fork_blocks.iter().any(|(id, _)| *id == block_id) {
                return Ok(false);
            }

            if fork_blocks.len() as u32 >= MAX_FORK_BLOCKS {
                // Min-work eviction: evict only if incoming block has more
                // work than the weakest entry. This prevents low-work spam
                // from churning out better fork candidates. Deep-fork reorg
                // safety is handled by on-demand MissingReorgAncestor recovery.
                if let Some((min_idx, _)) = fork_blocks
                    .iter()
                    .enumerate()
                    .min_by(|a, b| a.1 .1.cmp(&b.1 .1))
                {
                    if *cumulative_work > fork_blocks[min_idx].1 {
                        evict_id = Some(fork_blocks[min_idx].0);
                    } else {
                        // Incoming block is weaker — don't evict, don't store
                        return Ok(false);
                    }
                } else {
                    evict_id = None;
                }
            } else {
                evict_id = None;
            }
        } // lock dropped

        // --- I/O phase: blocking DB operations outside the lock.
        // Evict: remove fork tracking + block body (bulk data), but keep
        // header + work on disk for retarget ancestry and fork-choice.
        // Block bodies can be re-fetched via MissingReorgAncestor if needed.
        if let Some(eid) = evict_id {
            self.storage
                .evict_fork_block(&eid)
                .map_err(|e| ProcessBlockError::Recoverable(e.to_string()))?;
        }

        self.storage
            .store_fork_block_atomic(block, cumulative_work)
            .map_err(|e| ProcessBlockError::Recoverable(e.to_string()))?;

        // Re-check: a concurrent commit_block_atomic / commit_reorg_atomic
        // may have promoted this block to canonical between our has_block
        // guard and the store above. If so, the concurrent commit removed
        // the FORK_BLOCKS_TABLE entry — skip the in-memory push to avoid
        // a canonical block occupying a fork slot.
        if !self
            .storage
            .is_fork_block(&block_id)
            .map_err(|e| ProcessBlockError::Recoverable(e.to_string()))?
        {
            return Ok(false);
        }

        // --- Commit phase: re-acquire lock, update in-memory state.
        //     Collect IDs trimmed by cap enforcement for disk cleanup after
        //     the lock is released (no blocking I/O under mutex).
        let trimmed_ids: Vec<Hash256>;
        {
            let mut fork_blocks = self.fork_blocks.lock().unwrap_or_else(|e| e.into_inner());

            // Remove evicted entry (may already be gone if concurrent handler acted)
            if let Some(eid) = evict_id {
                fork_blocks.retain(|(id, _)| *id != eid);
            }

            // Dedupe: another handler may have stored same block concurrently
            if !fork_blocks.iter().any(|(id, _)| *id == block_id) {
                fork_blocks.push((block_id, *cumulative_work));
            }

            // Re-enforce cap: concurrent callers may have all passed the
            // decision-phase cap check before any reached commit. Trim
            // lowest-work entries so the vec never exceeds the hard cap.
            let mut removed = Vec::new();
            while fork_blocks.len() as u32 > MAX_FORK_BLOCKS {
                if let Some((min_idx, _)) = fork_blocks
                    .iter()
                    .enumerate()
                    .min_by(|a, b| a.1 .1.cmp(&b.1 .1))
                {
                    let (rid, _) = fork_blocks.swap_remove(min_idx);
                    removed.push(rid);
                } else {
                    break;
                }
            }
            trimmed_ids = removed;
        }

        // --- Disk cleanup phase: evict trimmed entries outside the lock.
        // Removes fork tracking + block body; keeps header + work for
        // retarget ancestry and fork-choice comparisons.
        for tid in &trimmed_ids {
            self.storage
                .evict_fork_block(tid)
                .map_err(|e| ProcessBlockError::Recoverable(e.to_string()))?;
        }

        Ok(true)
    }

    /// Remove promoted blocks from fork_blocks after a successful reorg.
    /// Prevents zombie entries from consuming slots after their blocks
    /// become canonical.
    fn cleanup_promoted_fork_blocks(&self, promoted_ids: &[Hash256]) {
        let mut fork_blocks = self.fork_blocks.lock().unwrap_or_else(|e| e.into_inner());
        fork_blocks.retain(|(id, _)| !promoted_ids.contains(id));
    }

    /// Process a newly received block.
    ///
    /// Flow:
    /// 1. Header-only validation (PoW, difficulty, timestamps) — no UTXO needed
    /// 2. Store block
    /// 3. Fork-choice
    /// 4. If winning: full tx validation against correct UTXO state
    ///    - Extends tip: validate against current UTXO
    ///    - Reorg: undo old chain, validate+apply new chain against rolled-back state
    pub async fn process_block(
        &self,
        block: Block,
        wall_clock: Option<u64>,
    ) -> Result<ProcessBlockOutcome, ProcessBlockError> {
        self.process_block_inner(block, wall_clock, false).await
    }

    /// Process a block whose difficulty and PoW have already been verified
    /// by the caller (NewBlock/BlockResponse pre-checks). Skips redundant
    /// Argon2id PoW verification in validate_block_header (R110 P2 fix).
    pub async fn process_block_pre_validated(
        &self,
        block: Block,
        wall_clock: Option<u64>,
    ) -> Result<ProcessBlockOutcome, ProcessBlockError> {
        self.process_block_inner(block, wall_clock, true).await
    }

    async fn process_block_inner(
        &self,
        block: Block,
        wall_clock: Option<u64>,
        skip_pow: bool,
    ) -> Result<ProcessBlockOutcome, ProcessBlockError> {
        let block_id = block.header.block_id();

        // Check if we already have this block
        if self
            .storage
            .has_block(&block_id)
            .map_err(|e| e.to_string())?
        {
            return Ok(ProcessBlockOutcome::Stored);
        }

        // Reject height-0 blocks — genesis is stored at startup, never via process_block
        if block.header.height == 0 {
            return Err("height-0 blocks are not accepted via process_block".into());
        }

        // 1. Header-only validation (no UTXO state needed)
        let parent_header = self
            .storage
            .get_header(&block.header.prev_block_id)
            .map_err(|e| e.to_string())?
            .ok_or("parent block not found")?;
        let parent = Some(parent_header);

        let ancestor_timestamps = self
            .storage
            .get_ancestor_timestamps(&block.header.prev_block_id, MTP_WINDOW)
            .map_err(|e| e.to_string())?;

        // Compute expected difficulty via cache (cheap hit if caller already
        // computed via cached_expected_difficulty in NewBlock/BlockResponse
        // pre-checks — avoids redundant ~4319-ancestor DB walks at retarget
        // boundaries, R110 P2 fix).
        // "Not found" means a retarget ancestor header was evicted — route to
        // MissingReorgAncestor so the recovery machinery fetches it.
        let (expected_target, _) = match self
            .cached_expected_difficulty(&block.header.prev_block_id, block.header.height)
        {
            Ok(v) => v,
            Err(crate::consensus::difficulty::DifficultyError::AncestorNotFound(missing_id)) => {
                return Err(ProcessBlockError::MissingReorgAncestor(missing_id));
            }
            Err(e) => return Err(ProcessBlockError::Recoverable(e.to_string())),
        };

        // When skip_pow is true, caller already verified difficulty + PoW
        // (NewBlock/BlockResponse pre-checks or IBD assume-valid). Use the
        // skip variant to avoid redundant Argon2id computation.
        let header_result = if skip_pow {
            validate_block_header_skip_pow(
                &block,
                parent.as_ref(),
                &ancestor_timestamps,
                &expected_target,
                wall_clock,
            )
        } else {
            validate_block_header(
                &block,
                parent.as_ref(),
                &ancestor_timestamps,
                &expected_target,
                wall_clock,
            )
        };
        if let Err(e) = header_result {
            if matches!(e, ValidationError::TimestampTooFarAhead { .. }) {
                // POLICY: buffer and retry, do not reject permanently (SPEC.md:408).
                self.buffer_future_block(block);
                return Ok(ProcessBlockOutcome::BufferedFuture);
            }
            return Err(format!("block header validation failed: {:?}", e).into());
        }

        // Assume-valid checkpoint: when block at checkpoint height arrives,
        // verify hash matches. On match, mark checkpoint as proven. On
        // mismatch, reject — caller (IBD) must wipe unproven blocks.
        if self.assume_valid && block.header.height == ASSUME_VALID_HEIGHT {
            let expected = Hash256(ASSUME_VALID_HASH);
            if block_id == expected {
                self.assume_valid_verified.store(true, Ordering::SeqCst);
                info!("Assume-valid checkpoint verified at height {}", ASSUME_VALID_HEIGHT);
            } else {
                return Err(ProcessBlockError::Recoverable(format!(
                    "assume-valid checkpoint FAILED at height {}: expected {}, got {}",
                    ASSUME_VALID_HEIGHT, expected, block_id
                )));
            }
        }

        // 2. Compute cumulative work in memory for fork-choice (defer storage).
        //    Under full eviction (all-or-nothing), if a parent exists its
        //    work always exists too. Missing work = data corruption → error.
        let parent_work = self
            .storage
            .get_cumulative_work(&block.header.prev_block_id)
            .map_err(|e| e.to_string())?
            .ok_or("parent cumulative work not found")?;

        let new_tip = ChainTip::new(
            block_id,
            block.header.height,
            &block.header.difficulty_target,
            &parent_work,
        );

        // 3. Fork choice BEFORE state application
        //    Initial check is optimistic; we re-check under UTXO write lock
        //    to avoid races with concurrent peer tasks.
        {
            let current_tip = self.tip.read().await.clone();
            if !is_better_chain(&new_tip, &current_tip) {
                // Validate tx_root before storing (cheap, no UTXO state needed).
                // Rejects blocks with tampered transactions.
                let computed_tx_root = compute_tx_root(&block.transactions)
                    .map_err(|e| format!("fork block tx_root computation failed: {}", e))?;
                if block.header.tx_root != computed_tx_root {
                    return Err("fork block tx_root mismatch".into());
                }
                // Lightweight structural pre-validation: catches format/size/dust
                // errors before disk storage, avoiding expensive reorg undo/redo
                // for blocks that would inevitably fail semantic validation.
                validate_block_structure(&block)
                    .map_err(|e| format!("fork block structure invalid: {}", e))?;
                // Store block + work atomically for future fork-choice
                // Bounded: drops silently if fork pool is full.
                self.try_store_fork_block(&block, &new_tip.cumulative_work)?;
                return Ok(ProcessBlockOutcome::Stored);
            }
        }

        // Acquire UTXO write lock FIRST, then re-read tip.
        // Holding utxo_set.write() serialises all state mutations —
        // no concurrent process_block can change tip or UTXO state.
        let mut utxo_set = self.utxo_set.write().await;
        {
            let mut all_confirmed_txs: Vec<Transaction> = Vec::new();
            let mut orphaned_txs: Vec<Transaction> = Vec::new();

            // Read tip UNDER the UTXO write lock — prevents TOCTOU race
            let current_tip = self.tip.read().await.clone();

            if !is_better_chain(&new_tip, &current_tip) {
                // Tip changed while we waited — this block is no longer best chain
                drop(utxo_set);
                let computed_tx_root = compute_tx_root(&block.transactions)
                    .map_err(|e| format!("fork block tx_root computation failed: {}", e))?;
                if block.header.tx_root != computed_tx_root {
                    return Err("fork block tx_root mismatch".into());
                }
                validate_block_structure(&block)
                    .map_err(|e| format!("fork block structure invalid: {}", e))?;
                // Bounded: drops silently if fork pool is full.
                self.try_store_fork_block(&block, &new_tip.cumulative_work)?;
                return Ok(ProcessBlockOutcome::Stored);
            }

            if block.header.prev_block_id == current_tip.block_id {
                // Extends current tip — validate and apply in-place (no clone).
                // On failure the atomic function rolls back automatically.
                // Spent UTXOs are collected incrementally during apply (captures
                // intra-block dependency spends that don't exist pre-block).
                let (_total_fees, spent_utxos) =
                    validate_and_apply_block_transactions_atomic(&block, &mut utxo_set).map_err(
                        |e| match e {
                            ValidationError::StateCorrupted(msg) => ProcessBlockError::Fatal(
                                format!("block tx apply corrupted state: {}", msg),
                            ),
                            other => ProcessBlockError::Recoverable(format!(
                                "block tx validation failed: {:?}",
                                other
                            )),
                        },
                    )?;

                // State root check (O(1) with incremental SMT)
                let computed_state_root = utxo_set.state_root();
                if block.header.state_root != computed_state_root {
                    // Undo the entire block and restore pre-block state
                    if let Err(undo_err) =
                        undo_block_transactions(&block, &mut utxo_set, &spent_utxos)
                    {
                        return Err(ProcessBlockError::Fatal(format!(
                            "state root mismatch rollback failed: {}",
                            undo_err
                        )));
                    }
                    return Err("state root mismatch".into());
                }

                // Validation passed — atomic persist (single redb transaction)
                if let Err(e) =
                    self.storage
                        .commit_block_atomic(&block, &new_tip.cumulative_work, &spent_utxos)
                {
                    // Storage failed — undo in-memory mutations to stay consistent with disk
                    if let Err(undo_err) =
                        undo_block_transactions(&block, &mut utxo_set, &spent_utxos)
                    {
                        return Err(ProcessBlockError::Fatal(format!(
                            "storage failed: {}: rollback also failed: {}",
                            e, undo_err
                        )));
                    }
                    return Err(e.to_string().into());
                }

                // utxo_set already reflects the applied block — no swap needed

                all_confirmed_txs = block.transactions.clone();
            } else {
                // Fork wins but doesn't extend tip — perform reorg in-place.
                // The triggering block is NOT stored to disk before the walk —
                // it lives in memory. commit_reorg_atomic stores it atomically
                // with all other reorg metadata, closing the crash-consistency gap.
                //
                // On any failure after UTXO mutations begin, we undo applied
                // new-chain blocks then redo old-chain blocks to restore the
                // pre-reorg state, keeping memory consistent with disk.

                // 1. Find common ancestor
                // Start with the triggering block already in new_chain (from memory),
                // then walk backwards from its parent.
                let mut old_chain = Vec::new();
                let mut new_chain = vec![block.clone()];
                let mut old_id = current_tip.block_id;
                let mut new_id = block.header.prev_block_id;
                let mut old_height = current_tip.height;
                let mut new_height = block.header.height - 1;

                while old_height > new_height {
                    let blk = self
                        .storage
                        .get_block(&old_id)
                        .map_err(|e| e.to_string())?
                        .ok_or_else(|| {
                            ProcessBlockError::Fatal(format!(
                                "canonical block {} missing during reorg (old chain)",
                                old_id
                            ))
                        })?;
                    old_id = blk.header.prev_block_id;
                    old_chain.push(blk);
                    old_height -= 1;
                }
                while new_height > old_height {
                    let blk = match self.storage.get_block(&new_id).map_err(|e| e.to_string())? {
                        Some(b) => b,
                        None => return Err(ProcessBlockError::MissingReorgAncestor(new_id)),
                    };
                    new_id = blk.header.prev_block_id;
                    new_chain.push(blk);
                    new_height -= 1;
                }
                while old_id != new_id {
                    let old_blk = self
                        .storage
                        .get_block(&old_id)
                        .map_err(|e| e.to_string())?
                        .ok_or_else(|| {
                            ProcessBlockError::Fatal(format!(
                                "canonical block {} missing during reorg (old walk)",
                                old_id
                            ))
                        })?;
                    old_id = old_blk.header.prev_block_id;
                    old_chain.push(old_blk);

                    let new_blk =
                        match self.storage.get_block(&new_id).map_err(|e| e.to_string())? {
                            Some(b) => b,
                            None => return Err(ProcessBlockError::MissingReorgAncestor(new_id)),
                        };
                    new_id = new_blk.header.prev_block_id;
                    new_chain.push(new_blk);
                }

                info!(
                    "Reorg: undoing {} blocks, applying {} blocks",
                    old_chain.len(),
                    new_chain.len()
                );

                // 2. Undo old chain in-place (most recent first — already in order)
                //    Track how many blocks we've undone so we can redo them on failure.
                let mut old_undone = 0;
                let mut undo_err: Option<String> = None;
                for blk in &old_chain {
                    let blk_id = blk.header.block_id();
                    let spent = match self.storage.get_spent_utxos(&blk_id) {
                        Ok(Some(s)) => s,
                        Ok(None) => {
                            undo_err = Some(format!(
                                "missing spent-UTXO metadata for block {} at height {} during reorg undo",
                                blk_id, blk.header.height
                            ));
                            break;
                        }
                        Err(e) => {
                            undo_err = Some(e.to_string());
                            break;
                        }
                    };
                    for tx in blk.transactions.iter().rev() {
                        let tx_spent: Vec<_> = spent
                            .iter()
                            .filter(|(op, _)| {
                                tx.inputs.iter().any(|i| {
                                    i.prev_tx_id == op.tx_id && i.output_index == op.output_index
                                })
                            })
                            .cloned()
                            .collect();
                        if let Err(e) = utxo_set.undo_transaction(tx, &tx_spent) {
                            // Fail closed: undo failed mid-reorg, state is inconsistent.
                            // Attempt to redo what was undone, but propagate either way.
                            let _ = redo_old_chain_blocks(&mut utxo_set, &old_chain[..old_undone]);
                            return Err(ProcessBlockError::Fatal(format!(
                                "reorg undo_transaction failed: {}",
                                e
                            )));
                        }
                    }
                    old_undone += 1;
                }
                if let Some(e) = undo_err {
                    // Redo the blocks we already undid to restore pre-reorg state
                    if let Err(redo_err) =
                        redo_old_chain_blocks(&mut utxo_set, &old_chain[..old_undone])
                    {
                        return Err(ProcessBlockError::Fatal(format!(
                            "{}: redo also failed: {}",
                            e, redo_err
                        )));
                    }
                    // Missing spent-UTXO metadata means the node cannot
                    // execute this or future reorgs — fatal, not recoverable.
                    return Err(ProcessBlockError::Fatal(e));
                }

                // 3. Apply new chain with full tx validation (oldest first)
                new_chain.reverse();
                let mut all_spent: Vec<(Hash256, Vec<(OutPoint, UtxoEntry)>)> = Vec::new();
                let mut new_applied = 0; // count of fully-applied new-chain blocks

                let apply_err: Option<ProcessBlockError> = 'apply: {
                    for blk in &new_chain {
                        // Defense-in-depth: re-validate headers for stored fork
                        // blocks to catch local DB corruption/tampering.
                        {
                            let blk_parent = self
                                .storage
                                .get_header(&blk.header.prev_block_id)
                                .map_err(|e| e.to_string());
                            let blk_parent = match blk_parent {
                                Ok(Some(h)) => h,
                                Ok(None) => {
                                    break 'apply Some(ProcessBlockError::Fatal(format!(
                                        "reorg: parent header missing for block at height {}",
                                        blk.header.height
                                    )));
                                }
                                Err(e) => {
                                    break 'apply Some(ProcessBlockError::Fatal(format!(
                                        "reorg: storage error reading parent header: {}",
                                        e
                                    )));
                                }
                            };
                            let anc_ts = match self
                                .storage
                                .get_ancestor_timestamps(&blk.header.prev_block_id, MTP_WINDOW)
                            {
                                Ok(ts) => ts,
                                Err(e) => {
                                    break 'apply Some(ProcessBlockError::Fatal(format!(
                                        "reorg: ancestor timestamps error: {}",
                                        e
                                    )));
                                }
                            };
                            let exp_target = match expected_difficulty(
                                &self.storage,
                                &blk.header.prev_block_id,
                                blk.header.height,
                            ) {
                                Ok(t) => t,
                                Err(
                                    crate::consensus::difficulty::DifficultyError::AncestorNotFound(
                                        missing_id,
                                    ),
                                ) => {
                                    break 'apply Some(ProcessBlockError::MissingReorgAncestor(
                                        missing_id,
                                    ));
                                }
                                Err(e) => {
                                    break 'apply Some(ProcessBlockError::Fatal(format!(
                                        "reorg: difficulty computation error: {}",
                                        e
                                    )));
                                }
                            };
                            if let Err(e) = validate_block_header(
                                blk,
                                Some(&blk_parent),
                                &anc_ts,
                                &exp_target,
                                None, // no wall_clock for stored blocks
                            ) {
                                break 'apply Some(ProcessBlockError::Recoverable(format!(
                                    "reorg: header re-validation failed at height {}: {:?}",
                                    blk.header.height, e
                                )));
                            }
                        }

                        // Validate and apply — spent UTXOs are collected
                        // incrementally inside (captures intra-block spends).
                        let spent_utxos = match validate_and_apply_block_transactions_atomic(
                            blk,
                            &mut utxo_set,
                        ) {
                            Ok((_fees, spent)) => spent,
                            Err(ValidationError::StateCorrupted(msg)) => {
                                // Atomic apply hit state corruption — fatal
                                break 'apply Some(ProcessBlockError::Fatal(format!(
                                    "reorg block apply corrupted state: {}",
                                    msg
                                )));
                            }
                            Err(e) => {
                                // Block rolled back by atomic function — recoverable
                                break 'apply Some(ProcessBlockError::Recoverable(format!(
                                    "reorg block tx validation failed: {:?}",
                                    e
                                )));
                            }
                        };

                        // Verify state_root for every block during reorg
                        if blk.header.state_root != utxo_set.state_root() {
                            // Undo this successfully-applied block first
                            if let Err(undo_err) =
                                undo_block_transactions(blk, &mut utxo_set, &spent_utxos)
                            {
                                break 'apply Some(ProcessBlockError::Fatal(format!(
                                    "state root mismatch at height {}: rollback failed: {}",
                                    blk.header.height, undo_err
                                )));
                            }
                            break 'apply Some(ProcessBlockError::Recoverable(format!(
                                "state root mismatch during reorg at height {}",
                                blk.header.height
                            )));
                        }

                        all_spent.push((blk.header.block_id(), spent_utxos));
                        new_applied += 1;
                    }
                    None
                };
                if let Some(e) = apply_err {
                    // Undo whatever new-chain blocks succeeded, then redo old chain
                    if let Err(undo_err) =
                        undo_applied_new_chain(&mut utxo_set, &new_chain[..new_applied], &all_spent)
                    {
                        return Err(ProcessBlockError::Fatal(format!(
                            "{}: new-chain undo failed: {}",
                            e, undo_err
                        )));
                    }
                    if let Err(redo_err) = redo_old_chain_blocks(&mut utxo_set, &old_chain) {
                        return Err(ProcessBlockError::Fatal(format!(
                            "{}: old-chain redo failed: {}",
                            e, redo_err
                        )));
                    }
                    return Err(e);
                }

                // Collect canonical height entries for new chain
                let new_chain_heights: Vec<(u64, Hash256)> = new_chain
                    .iter()
                    .map(|blk| (blk.header.height, blk.header.block_id()))
                    .collect();

                // Compute cumulative work for each promoted ancestor.
                // new_chain is oldest-first; chain from fork point's work.
                // old_id == new_id == fork point after the walk above.
                let fork_point_work = self
                    .storage
                    .get_cumulative_work(&old_id)
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| {
                        ProcessBlockError::Fatal(format!(
                            "fork point {} cumulative work missing during reorg",
                            old_id
                        ))
                    })?;
                let mut new_chain_work: Vec<(Hash256, [u8; 32])> = Vec::new();
                {
                    use crate::consensus::difficulty::{add_work, work_from_target};
                    let mut prev_work = fork_point_work;
                    for blk in &new_chain {
                        let blk_work = work_from_target(&blk.header.difficulty_target);
                        let cum_work = add_work(&prev_work, &blk_work);
                        new_chain_work.push((blk.header.block_id(), cum_work));
                        prev_work = cum_work;
                    }
                }

                // Stale heights to delete (if old tip was higher)
                let (stale_start, stale_end) = if current_tip.height > block.header.height {
                    (Some(block.header.height + 1), Some(current_tip.height))
                } else {
                    (None, None)
                };

                // Validation passed — atomic persist (single redb transaction).
                // commit_reorg_atomic stores all new-chain blocks (trigger +
                // promoted ancestors), their work, spent UTXOs, height index,
                // and tip atomically. Re-inserting all promoted blocks prevents
                // a race where fork eviction deletes ancestor data between the
                // reorg walk and this commit.
                if let Err(e) = self.storage.commit_reorg_atomic(
                    &block,
                    &new_tip.cumulative_work,
                    &all_spent,
                    &new_chain_heights,
                    &new_chain,
                    &new_chain_work,
                    stale_start,
                    stale_end,
                    &block_id,
                ) {
                    // Storage failed — undo new chain, redo old chain
                    if let Err(undo_err) =
                        undo_applied_new_chain(&mut utxo_set, &new_chain[..new_applied], &all_spent)
                    {
                        return Err(ProcessBlockError::Fatal(format!(
                            "storage failed: {}: new-chain undo failed: {}",
                            e, undo_err
                        )));
                    }
                    if let Err(redo_err) = redo_old_chain_blocks(&mut utxo_set, &old_chain) {
                        return Err(ProcessBlockError::Fatal(format!(
                            "storage failed: {}: old-chain redo failed: {}",
                            e, redo_err
                        )));
                    }
                    return Err(e.to_string().into());
                }

                // utxo_set already reflects the new chain — no swap needed

                // Collect ALL newly-canonical transactions for mempool cleanup
                for blk in &new_chain {
                    all_confirmed_txs.extend(blk.transactions.clone());
                }

                // Collect orphaned txs from disconnected blocks for mempool
                // re-introduction. Non-coinbase txs that were in the old chain
                // but NOT in the new chain may still be valid and should be
                // re-added to mempool rather than silently dropped.
                {
                    let new_tx_ids: std::collections::HashSet<Hash256> = all_confirmed_txs
                        .iter()
                        .filter_map(|tx| tx.tx_id().ok())
                        .collect();
                    for blk in &old_chain {
                        for tx in &blk.transactions {
                            if tx.is_coinbase() {
                                continue;
                            }
                            if let Ok(tx_id) = tx.tx_id() {
                                if !new_tx_ids.contains(&tx_id) {
                                    orphaned_txs.push(tx.clone());
                                }
                            }
                        }
                    }
                }

                // Demote disconnected old-chain blocks to fork storage so
                // they can be reused if a subsequent reorg reverses this one,
                // without re-downloading from peers.
                //
                // Split into I/O → commit → cleanup phases so the fork_blocks
                // mutex is never held across blocking DB operations.
                {
                    // --- I/O phase: DB reads + writes, no lock held.
                    let mut stored: Vec<(Hash256, [u8; 32])> = Vec::new();
                    for blk in &old_chain {
                        let blk_id = blk.header.block_id();
                        let work = match self.storage.get_cumulative_work(&blk_id) {
                            Ok(Some(w)) => w,
                            _ => continue, // work missing — skip demotion
                        };
                        if let Err(e) = self.storage.store_fork_block_atomic(blk, &work) {
                            warn!(
                                "Failed to demote old-chain block {} to fork storage: {}",
                                blk_id, e
                            );
                            continue;
                        }
                        stored.push((blk_id, work));
                    }

                    // --- Commit phase: acquire lock, update in-memory state only.
                    let trimmed = {
                        let mut fork_blocks =
                            self.fork_blocks.lock().unwrap_or_else(|e| e.into_inner());
                        for (blk_id, work) in &stored {
                            if !fork_blocks.iter().any(|(id, _)| id == blk_id) {
                                fork_blocks.push((*blk_id, *work));
                            }
                        }
                        // Enforce cap: collect lowest-work entries to evict.
                        let mut removed = Vec::new();
                        while fork_blocks.len() as u32 > MAX_FORK_BLOCKS {
                            if let Some((min_idx, _)) = fork_blocks
                                .iter()
                                .enumerate()
                                .min_by(|a, b| a.1 .1.cmp(&b.1 .1))
                            {
                                let (rid, _) = fork_blocks.swap_remove(min_idx);
                                removed.push(rid);
                            } else {
                                break;
                            }
                        }
                        removed
                    }; // lock released

                    // --- Cleanup phase: evict trimmed entries, no lock held.
                    for tid in &trimmed {
                        let _ = self.storage.evict_fork_block(tid);
                    }
                }

                // Clean up fork_blocks: remove promoted blocks so they don't
                // consume cap slots as zombies.
                let promoted_ids: Vec<Hash256> =
                    new_chain.iter().map(|blk| blk.header.block_id()).collect();
                self.cleanup_promoted_fork_blocks(&promoted_ids);
            }

            // Update in-memory tip WHILE still holding UTXO write lock.
            // Storage tip was already persisted atomically in the commit above.
            {
                let mut tip = self.tip.write().await;
                *tip = new_tip;
            }

            // UTXO state and tip are now atomically consistent — release UTXO lock
            drop(utxo_set);

            // Remove confirmed transactions from mempool and collect
            // outpoints for revalidation. Release the lock before
            // acquiring tip/UTXO locks to avoid holding mempool across .await.
            let outpoints = {
                let mut mempool = self.mempool.lock().await;
                mempool.remove_confirmed(&all_confirmed_txs);
                mempool.referenced_outpoints()
            }; // mempool lock released

            // Revalidate remaining mempool entries against post-block UTXO set.
            // Use tip.height + 1 (next block height) since that's the height
            // at which these transactions would actually be mined.
            // Snapshot tip height and UTXO state outside the mempool lock
            // so we never hold mempool across an .await point.
            let new_height = self.tip.read().await.height.saturating_add(1);
            let utxo_snapshot = {
                let utxo_read = self.utxo_set.read().await;
                utxo_read.snapshot_for_outpoints(&outpoints)
            };

            // Re-acquire mempool to revalidate against the snapshot.
            {
                let mut mempool = self.mempool.lock().await;
                mempool.revalidate(&utxo_snapshot, new_height);
            }
            // Release mempool lock before expensive orphan validation.
            // Snapshot UTXO data under a brief read lock, validate outside
            // all locks, then re-acquire mempool to add validated txs.

            if !orphaned_txs.is_empty() {
                let reintro_height = new_height;

                // Snapshot phase: brief UTXO read lock to snapshot all
                // outpoints, then release before expensive validation.
                let tx_snapshots: Vec<_>;
                {
                    let utxo_read = self.utxo_set.read().await;
                    tx_snapshots = orphaned_txs
                        .iter()
                        .map(|tx| {
                            let input_outpoints: Vec<_> = tx
                                .inputs
                                .iter()
                                .map(|i| OutPoint::new(i.prev_tx_id, i.output_index))
                                .collect();
                            utxo_read.snapshot_for_outpoints(&input_outpoints)
                        })
                        .collect();
                } // utxo read lock released before validation

                // Validate each orphaned tx against its snapshot (no lock held).
                let mut validated_orphans: Vec<(Transaction, u64, u128, u128)> = Vec::new();
                for (tx, snap) in orphaned_txs.iter().zip(tx_snapshots.iter()) {
                    match crate::consensus::validation::validate_transaction(
                        tx,
                        snap,
                        reintro_height,
                    ) {
                        Ok((fee, script_cost, script_validation_cost)) => {
                            validated_orphans.push((
                                tx.clone(),
                                fee,
                                script_cost,
                                script_validation_cost,
                            ));
                        }
                        Err(_) => {
                            // Tx no longer valid post-reorg — drop silently
                        }
                    }
                }

                // Re-acquire mempool lock only to insert validated txs
                if !validated_orphans.is_empty() {
                    let mut mempool = self.mempool.lock().await;
                    let mut reintroduced = 0u32;
                    for (tx, fee, script_cost, script_validation_cost) in validated_orphans {
                        let _ = mempool.add_validated(
                            tx,
                            fee,
                            script_cost,
                            script_validation_cost,
                            reintro_height,
                        );
                        reintroduced += 1;
                    }
                    drop(mempool);
                    info!(
                        "Reintroduced {} orphaned txs to mempool after reorg",
                        reintroduced
                    );
                }
            }

            info!("New tip: height={}, id={}", block.header.height, block_id);
        }

        Ok(ProcessBlockOutcome::Accepted)
    }

    /// Run the peer listener (accepts inbound connections).
    pub async fn listen(self: Arc<Self>, bind_addr: SocketAddr) -> Result<(), std::io::Error> {
        let listener = TcpListener::bind(bind_addr).await?;
        info!("Listening on {}", bind_addr);

        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                info!("Shutdown flag set, stopping listener");
                return Ok(());
            }

            let (stream, addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!("Accept error (transient, retrying): {}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            };
            let node = self.clone();

            if self.is_ip_banned(addr.ip()) {
                warn!("Rejecting connection from banned IP {}", addr.ip());
                drop(stream);
                continue;
            }

            {
                let mut peers = self.peers.lock().await;
                let inbound_count = peers.inbound_count() + peers.pending_inbound_sockets.len();
                if inbound_count >= MAX_INBOUND_PEERS {
                    warn!("Max inbound peers reached, rejecting {}", addr);
                    continue;
                }
                let ip = addr.ip();
                let ip_inbound = peers.inbound_count_for_ip(ip);
                if ip_inbound >= MAX_INBOUND_PER_IP {
                    warn!("Max inbound per IP reached for {}, rejecting {}", ip, addr);
                    continue;
                }
                if !peers.reserve_inbound_socket(addr) {
                    warn!("Already connected to {}, rejecting duplicate", addr);
                    continue;
                }
            }

            tokio::spawn(async move {
                if let Err(e) = node.handle_inbound(stream, addr).await {
                    warn!("Peer {} error: {}", addr, e);
                }
            });
        }
    }

    /// Handle an inbound peer connection.
    async fn handle_inbound(
        self: Arc<Self>,
        stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<(), PeerError> {
        let tip = self.tip.read().await;
        let our_hello = HelloMsg {
            version: PROTOCOL_VERSION,
            genesis_block_id: self.genesis_id,
            best_height: tip.height,
            best_block_id: tip.block_id,
            cumulative_work: tip.cumulative_work,
            nonce: [0u8; 32],
            echo: [0u8; 32],
            pubkey: [0u8; 32],
            sig: [0u8; 64],
        };
        drop(tip);

        let mut handshake_identity: Option<[u8; 32]> = None;
        let peer_result = Peer::handshake(
            stream,
            addr,
            our_hello,
            true,
            &self.identity_key,
            &mut handshake_identity,
        )
        .await;
        let mut peer = match peer_result {
            Ok(p) => p,
            Err(e) => {
                self.peers.lock().await.release_inbound_socket(&addr);
                return Err(e);
            }
        };

        if self.is_identity_banned(&peer.identity) {
            self.peers.lock().await.release_inbound_socket(&addr);
            warn!("Rejecting {} — identity banned", addr);
            return Err(PeerError::Io("identity banned".into()));
        }

        let session_id = self.next_session_id();
        let (otx, orx) = mpsc::channel::<Message>(256);
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let peer_session = PeerSession {
            session_id,
            socket_addr: addr,
            is_outbound: false,
            tx: otx,
            shutdown: shutdown_flag.clone(),
            established_at: Instant::now(),
        };
        let handshake_tip = PeerTip {
            height: peer.best_height,
            cumulative_work: peer.cumulative_work,
            block_id: Hash256::ZERO,
            confirmed: false,
        };
        let our_pubkey = self.identity_key.verifying_key().to_bytes();
        let active_ibd = {
            let g = self.active_ibd_peer.lock().unwrap_or_else(|e| e.into_inner());
            *g
        };

        let emit_connected;
        {
            let mut peers = self.peers.lock().await;
            let catching_up = self.sync_state.load(std::sync::atomic::Ordering::Relaxed)
                == SyncState::CatchingUp as u8;
            match peers.attach_session(
                peer.identity,
                peer_session,
                handshake_tip,
                None,
                false,
                our_pubkey,
                active_ibd,
                catching_up,
            ) {
                SessionAttachResult::NewLogicalConnect => {
                    emit_connected = true;
                    Node::reset_retry(peers.get_mut_by_identity(&peer.identity).unwrap());
                }
                SessionAttachResult::ReplacedExistingSession { old_shutdown } => {
                    old_shutdown.store(true, Ordering::Relaxed);
                    emit_connected = false;
                    Node::reset_retry(peers.get_mut_by_identity(&peer.identity).unwrap());
                }
                SessionAttachResult::RejectedDuplicate => {
                    peers.release_inbound_socket(&addr);
                    warn!("Rejecting inbound {} — duplicate identity", addr);
                    return Err(PeerError::DuplicateIdentity(peer.identity));
                }
            }
        }

        // Don't record inbound ephemeral ports as dial targets —
        // the remote address is a random OS port, not a listening address.

        if emit_connected {
            let _ = self
                .peer_events_tx
                .send(PeerEvent::Connected {
                    identity: peer.identity,
                    session_id,
                })
                .await;
        }

        let getaddr_sent_at = match peer.send(&Message::GetAddr).await {
            Ok(()) => Some(Instant::now()),
            Err(_) => None,
        };

        let peer_identity = peer.identity;

        let result = self
            .clone()
            .run_peer_supervisor(peer, orx, getaddr_sent_at, session_id)
            .await;

        // Post-supervisor cleanup
        {
            // Authenticated-session abuse — record IP strike. Strikes accumulate across
            // reconnections; persistent abusers hit the ban threshold.
            match &result {
                Err(PeerError::HmacFailure)
                | Err(PeerError::RateLimitExceeded)
                | Err(PeerError::SlowPeer(_)) => {
                    warn!(
                        "Authenticated peer {} disconnected ({}) — recording IP strike",
                        addr,
                        result.as_ref().unwrap_err()
                    );
                    self.record_ip_strike(addr.ip(), Some(peer_identity));
                }
                _ => {}
            }

            // Handle IBD cooldown + active_ibd_peer clearing
            let was_ibd_peer = {
                let mut ibd_guard = self.active_ibd_peer.lock().unwrap_or_else(|e| e.into_inner());
                if *ibd_guard == Some((peer_identity, session_id)) {
                    *ibd_guard = None;
                    true
                } else {
                    false
                }
            };
            if was_ibd_peer {
                let mut peers = self.peers.lock().await;
                if let Some(lp) = peers.get_mut_by_identity(&peer_identity) {
                    lp.ibd_cooldown_until =
                        Some(std::time::Instant::now() + std::time::Duration::from_secs(60));
                }
            }

            let detached = self
                .peers
                .lock()
                .await
                .detach_session_if_current(peer_identity, session_id);

            if detached {
                let _ = self
                    .peer_events_tx
                    .send(PeerEvent::Disconnected {
                        identity: peer_identity,
                        session_id,
                    })
                    .await;
            }
        }

        result
    }

    /// Connect to an outbound peer.
    /// Returns the authenticated peer identity on success (or long-lived session error).
    pub async fn connect(self: Arc<Self>, addr: SocketAddr) -> Result<[u8; 32], PeerError> {
        // reserve_outbound_addr is done by caller (run_outbound_manager).
        // If called directly, caller must have reserved.

        let stream = match tokio::time::timeout(
            std::time::Duration::from_secs(CONNECT_TIMEOUT_SECS),
            TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                self.peers.lock().await.release_outbound_addr(&addr);
                return Err(PeerError::Io(e.to_string()));
            }
            Err(_) => {
                self.peers.lock().await.release_outbound_addr(&addr);
                return Err(PeerError::Io(format!(
                    "connect timeout after {}s",
                    CONNECT_TIMEOUT_SECS
                )));
            }
        };

        let tip = self.tip.read().await;
        let our_hello = HelloMsg {
            version: PROTOCOL_VERSION,
            genesis_block_id: self.genesis_id,
            best_height: tip.height,
            best_block_id: tip.block_id,
            cumulative_work: tip.cumulative_work,
            nonce: [0u8; 32],
            echo: [0u8; 32],
            pubkey: [0u8; 32],
            sig: [0u8; 64],
        };
        drop(tip);

        let mut handshake_identity: Option<[u8; 32]> = None;
        let mut peer = match Peer::handshake(
            stream,
            addr,
            our_hello,
            false,
            &self.identity_key,
            &mut handshake_identity,
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                self.peers.lock().await.release_outbound_addr(&addr);
                return Err(e);
            }
        };

        if self.is_identity_banned(&peer.identity) {
            self.peers.lock().await.release_outbound_addr(&addr);
            warn!("Rejecting {} — identity banned", addr);
            return Err(PeerError::Io("identity banned".into()));
        }

        let session_id = self.next_session_id();
        let (otx, orx) = mpsc::channel::<Message>(256);
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let peer_session = PeerSession {
            session_id,
            socket_addr: addr,
            is_outbound: true,
            tx: otx,
            shutdown: shutdown_flag.clone(),
            established_at: Instant::now(),
        };
        let handshake_tip = PeerTip {
            height: peer.best_height,
            cumulative_work: peer.cumulative_work,
            block_id: Hash256::ZERO,
            confirmed: false,
        };
        let our_pubkey = self.identity_key.verifying_key().to_bytes();
        let active_ibd = {
            let g = self.active_ibd_peer.lock().unwrap_or_else(|e| e.into_inner());
            *g
        };

        let emit_connected;
        {
            let mut peers = self.peers.lock().await;
            let catching_up = self.sync_state.load(std::sync::atomic::Ordering::Relaxed)
                == SyncState::CatchingUp as u8;
            match peers.attach_session(
                peer.identity,
                peer_session,
                handshake_tip,
                Some(addr),
                false,
                our_pubkey,
                active_ibd,
                catching_up,
            ) {
                SessionAttachResult::NewLogicalConnect => {
                    emit_connected = true;
                    Node::reset_retry(peers.get_mut_by_identity(&peer.identity).unwrap());
                }
                SessionAttachResult::ReplacedExistingSession { old_shutdown } => {
                    old_shutdown.store(true, Ordering::Relaxed);
                    emit_connected = false;
                    Node::reset_retry(peers.get_mut_by_identity(&peer.identity).unwrap());
                }
                SessionAttachResult::RejectedDuplicate => {
                    peers.release_outbound_addr(&addr);
                    warn!("Rejecting outbound {} — duplicate identity", addr);
                    return Err(PeerError::DuplicateIdentity(peer.identity));
                }
            }
        }

        self.addr_book_record_success(addr);

        if emit_connected {
            let _ = self
                .peer_events_tx
                .send(PeerEvent::Connected {
                    identity: peer.identity,
                    session_id,
                })
                .await;
        }

        let getaddr_sent_at = match peer.send(&Message::GetAddr).await {
            Ok(()) => Some(Instant::now()),
            Err(_) => None,
        };

        let peer_identity = peer.identity;

        let result = self
            .clone()
            .run_peer_supervisor(peer, orx, getaddr_sent_at, session_id)
            .await;

        // Post-supervisor cleanup
        {
            // Authenticated-session abuse — record IP strike. Strikes accumulate across
            // reconnections; persistent abusers hit the ban threshold.
            match &result {
                Err(PeerError::HmacFailure)
                | Err(PeerError::RateLimitExceeded)
                | Err(PeerError::SlowPeer(_)) => {
                    warn!(
                        "Authenticated peer {} disconnected ({}) — recording IP strike",
                        addr,
                        result.as_ref().unwrap_err()
                    );
                    self.record_ip_strike(addr.ip(), Some(peer_identity));
                }
                _ => {}
            }

            // Handle IBD cooldown + active_ibd_peer clearing
            let was_ibd_peer = {
                let mut ibd_guard = self.active_ibd_peer.lock().unwrap_or_else(|e| e.into_inner());
                if *ibd_guard == Some((peer_identity, session_id)) {
                    *ibd_guard = None;
                    true
                } else {
                    false
                }
            };
            if was_ibd_peer {
                let mut peers = self.peers.lock().await;
                if let Some(lp) = peers.get_mut_by_identity(&peer_identity) {
                    lp.ibd_cooldown_until =
                        Some(std::time::Instant::now() + std::time::Duration::from_secs(60));
                }
            }

            let detached = self
                .peers
                .lock()
                .await
                .detach_session_if_current(peer_identity, session_id);

            if detached {
                let _ = self
                    .peer_events_tx
                    .send(PeerEvent::Disconnected {
                        identity: peer_identity,
                        session_id,
                    })
                    .await;
            }
        }

        result.map(|()| peer_identity)
    }

    /// Reader task: reads messages from the peer and dispatches them.
    ///
    /// - Sync manager messages (NewBlock, BlockResponse, Headers, TipResponse):
    ///   forwarded to `peer_events_tx`.
    /// - Request messages (GetBlocks, GetHeaders, GetTip, GetAddr, Ping):
    ///   responses queued to `normal_tx` or `ctrl_tx` (never writes to socket).
    /// - Pong: notifies supervisor via shared atomic.
    async fn reader_task(
        self: Arc<Self>,
        mut state: ReaderState,
        shared: Arc<PeerSharedState>,
        ctrl_tx: mpsc::Sender<WriterControl>,
        normal_tx: mpsc::Sender<Message>,
        meta: Arc<PeerMetadata>,
        mut getaddr_sent_at: Option<Instant>,
        session_id: u64,
    ) -> Result<(), PeerError> {
        // Rate limiting: rolling window counts
        let mut block_count: u32 = 0;
        let mut tx_count: u32 = 0;
        let mut ping_count: u32 = 0;
        let mut request_count: u32 = 0;
        let mut unsolicited_count: u32 = 0;
        let mut response_bytes: usize = 0;
        let mut invalid_block_count: u32 = 0;
        let mut invalid_tx_count: u32 = 0;
        let mut getaddr_count: u32 = 0;
        let mut unsolicited_addr_count: u32 = 0;
        let mut window_start = Instant::now();

        loop {
            if shared.shutdown.load(Ordering::Relaxed) {
                return Ok(());
            }
            if self.shutdown.load(Ordering::SeqCst) {
                return Err(PeerError::Io("node shutting down".into()));
            }

            // Reset rate limit window every 60 seconds
            let now = Instant::now();
            if now.duration_since(window_start) >= Duration::from_secs(60) {
                block_count = 0;
                tx_count = 0;
                ping_count = 0;
                request_count = 0;
                unsolicited_count = 0;
                response_bytes = 0;
                invalid_block_count = 0;
                invalid_tx_count = 0;
                unsolicited_addr_count = 0;
                window_start = now;
            }

            // Check IP ban
            if self.is_ip_banned(meta.addr.ip()) {
                warn!("Disconnecting banned IP {}", meta.addr.ip());
                return Err(PeerError::RateLimitExceeded);
            }

            // Check identity ban
            if self.is_identity_banned(&meta.identity) {
                warn!("Disconnecting banned identity from {}", meta.addr);
                return Err(PeerError::RateLimitExceeded);
            }

            // Read one message (1s poll timeout built into reader_recv)
            let msg = match reader_recv(&mut state, &shared).await? {
                Some(m) => m,
                None => continue, // timeout, loop back
            };

            match msg {
                Message::Ping => {
                    ping_count += 1;
                    if ping_count > MAX_PINGS_PER_MIN {
                        return Err(PeerError::RateLimitExceeded);
                    }
                    let _ = ctrl_tx.try_send(WriterControl::SendPong);
                }
                Message::Pong => {
                    if shared.awaiting_pong.load(Ordering::Relaxed) {
                        shared.pong_received.store(true, Ordering::Relaxed);
                    } else {
                        unsolicited_count += 1;
                        if unsolicited_count > MAX_UNSOLICITED_PER_MIN {
                            return Err(PeerError::RateLimitExceeded);
                        }
                    }
                }
                Message::NewBlock(block) => {
                    // During IBD (CatchingUp), exempt from per-peer block rate
                    // limit — the sync peer legitimately sends many blocks.
                    let catching_up = self.sync_state.load(
                        std::sync::atomic::Ordering::Relaxed,
                    ) == SyncState::CatchingUp as u8;
                    if !catching_up {
                        block_count += 1;
                        if block_count > MAX_BLOCKS_PER_MIN {
                            return Err(PeerError::RateLimitExceeded);
                        }
                    }
                    if self.is_ip_banned(meta.addr.ip()) {
                        continue;
                    }
                    let block_id = block.header.block_id();
                    let already_known = self
                        .storage
                        .has_block(&block_id)
                        .map_err(|e| PeerError::Io(format!("storage read failed: {}", e)))?;
                    if already_known {
                        continue;
                    }
                    if block.header.height == 0 || block.header.version != VERSION {
                        warn!("Rejected trivially invalid block from {}", meta.addr);
                        invalid_block_count += 1;
                        if self.record_ip_strike(meta.addr.ip(), Some(meta.identity)) {
                            return Err(PeerError::RateLimitExceeded);
                        }
                        if invalid_block_count > MAX_INVALID_BLOCKS_PER_PEER {
                            return Err(PeerError::RateLimitExceeded);
                        }
                        continue;
                    }
                    // Global block slot consumed in process_block_event after
                    // parent lookup — orphans don't count toward the cap.
                    let _ = self.peer_events_tx.try_send(PeerEvent::NewBlock {
                        from: meta.addr,
                        from_identity: meta.identity,
                        session_id,
                        block,
                        pre_validated: false,
                    });
                }
                Message::NewTx(tx) => {
                    tx_count += 1;
                    if tx_count > MAX_TXS_PER_MIN {
                        return Err(PeerError::RateLimitExceeded);
                    }
                    if self.is_ip_banned(meta.addr.ip()) {
                        warn!("Dropping tx from banned IP {}", meta.addr.ip());
                        continue;
                    }
                    if !self.try_consume_global_tx_slot() {
                        warn!(
                            "Global tx rate limit exceeded, dropping tx from {}",
                            meta.addr
                        );
                        continue;
                    }

                    {
                        let mempool = self.mempool.lock().await;
                        if let Err(e) = mempool.pre_check(&tx) {
                            tracing::debug!(
                                "Mempool pre-check rejected tx from {}: {}",
                                meta.addr,
                                e
                            );
                            if matches!(e, MempoolError::DoubleSpend(_)) {
                                invalid_tx_count += 1;
                                if invalid_tx_count > MAX_INVALID_TXS_PER_PEER {
                                    return Err(PeerError::RateLimitExceeded);
                                }
                            }
                            self.refund_global_tx_slot();
                            continue;
                        }
                    }

                    let tip_snapshot;
                    let utxo_snapshot;
                    {
                        let utxo_set = self.utxo_set.read().await;
                        tip_snapshot = self.tip.read().await.clone();
                        let outpoints: Vec<_> = tx
                            .inputs
                            .iter()
                            .map(|i| {
                                crate::types::transaction::OutPoint::new(
                                    i.prev_tx_id,
                                    i.output_index,
                                )
                            })
                            .collect();
                        utxo_snapshot = utxo_set.snapshot_for_outpoints(&outpoints);
                    }
                    let height = tip_snapshot.height.saturating_add(1);
                    let validation_result = crate::consensus::validation::validate_transaction(
                        &tx,
                        &utxo_snapshot,
                        height,
                    );

                    match validation_result {
                        Ok((fee, script_cost, script_validation_cost)) => {
                            let current_tip = self.tip.read().await.block_id;
                            let mut mempool = self.mempool.lock().await;
                            if current_tip != tip_snapshot.block_id {
                                tracing::debug!(
                                    "Discarding tx from {}: tip changed during validation",
                                    meta.addr
                                );
                                self.refund_global_tx_slot();
                                continue;
                            }
                            let tx_for_relay = tx.clone();
                            match mempool.add_validated(
                                tx,
                                fee,
                                script_cost,
                                script_validation_cost,
                                height,
                            ) {
                                Ok(tx_id) => {
                                    tracing::debug!("Added tx {} from {}", tx_id, meta.addr);
                                    drop(mempool);
                                    self.broadcast(&Message::NewTx(tx_for_relay), Some(meta.identity))
                                        .await;
                                }
                                Err(e) => {
                                    tracing::debug!(
                                        "Mempool rejected tx from {}: {}",
                                        meta.addr,
                                        e
                                    );
                                    self.refund_global_tx_slot();
                                    if matches!(e, MempoolError::DoubleSpend(_)) {
                                        invalid_tx_count += 1;
                                        if invalid_tx_count > MAX_INVALID_TXS_PER_PEER {
                                            return Err(PeerError::RateLimitExceeded);
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!("Rejected tx from {}: {:?}", meta.addr, e);
                            self.refund_global_tx_slot();
                            invalid_tx_count += 1;
                            self.record_ip_strike(meta.addr.ip(), Some(meta.identity));
                            if invalid_tx_count > MAX_INVALID_TXS_PER_PEER {
                                return Err(PeerError::RateLimitExceeded);
                            }
                        }
                    }
                }
                Message::GetTip => {
                    request_count += 1;
                    if request_count > MAX_REQUESTS_PER_MIN {
                        return Err(PeerError::RateLimitExceeded);
                    }
                    let (tip_height, tip_block_id, tip_work) = {
                        let tip = self.tip.read().await;
                        (tip.height, tip.block_id, tip.cumulative_work)
                    };
                    let _ = normal_tx.try_send(Message::TipResponse(TipResponseMsg {
                        height: tip_height,
                        block_id: tip_block_id,
                        cumulative_work: tip_work,
                    }));
                }
                Message::GetBlocks(hashes) => {
                    let catching_up = self.sync_state.load(std::sync::atomic::Ordering::Relaxed)
                        == SyncState::CatchingUp as u8;
                    for hash in hashes.iter().take(MAX_GETBLOCKS_RESPONSE) {
                        if let Ok(Some(block)) = self.storage.get_block(hash) {
                            let msg = Message::BlockResponse(block);
                            let msg_len = msg.serialize().map(|b| b.len()).unwrap_or(0);
                            if !catching_up {
                                if response_bytes > 0
                                    && response_bytes.saturating_add(msg_len)
                                        > MAX_RESPONSE_BYTES_PER_MIN
                                {
                                    break;
                                }
                                if !self.try_consume_global_response_bytes(msg_len) {
                                    break;
                                }
                            }
                            response_bytes = response_bytes.saturating_add(msg_len);
                            match tokio::time::timeout(Duration::from_secs(5), normal_tx.send(msg)).await {
                                Ok(Ok(())) => {}
                                Ok(Err(_)) => {
                                    warn!("GetBlocks: writer channel closed while sending BlockResponse");
                                    break;
                                }
                                Err(_) => {
                                    warn!("GetBlocks: timed out sending BlockResponse to writer (channel full)");
                                    break;
                                }
                            }
                        }
                    }
                }
                Message::GetHeaders(req) => {
                    let catching_up = self.sync_state.load(std::sync::atomic::Ordering::Relaxed)
                        == SyncState::CatchingUp as u8;
                    let mut headers = Vec::new();
                    let clamped_count =
                        std::cmp::min(req.max_count as u64, MAX_GETBLOCKS_ITEMS as u64);
                    let tip_height = self.tip.read().await.height;
                    let end_height = std::cmp::min(
                        req.start_height.saturating_add(clamped_count),
                        tip_height.saturating_add(1),
                    );
                    for h in req.start_height..end_height {
                        if let Ok(Some(block_id)) = self.storage.get_block_id_by_height(h) {
                            if let Ok(Some(header)) = self.storage.get_header(&block_id) {
                                headers.push(header);
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                    let msg = Message::Headers(headers);
                    let msg_len = msg.serialize().map(|b| b.len()).unwrap_or(0);
                    if !catching_up {
                        let per_peer_over = response_bytes > 0
                            && response_bytes.saturating_add(msg_len) > MAX_RESPONSE_BYTES_PER_MIN;
                        if per_peer_over || !self.try_consume_global_response_bytes(msg_len) {
                            // Budget exceeded — send empty headers
                            let _ = tokio::time::timeout(Duration::from_secs(5), normal_tx.send(Message::Headers(Vec::new()))).await;
                        } else {
                            response_bytes = response_bytes.saturating_add(msg_len);
                            match tokio::time::timeout(Duration::from_secs(5), normal_tx.send(msg)).await {
                                Ok(Ok(())) => {}
                                Ok(Err(_)) => warn!("GetHeaders: writer channel closed while sending Headers"),
                                Err(_) => warn!("GetHeaders: timed out sending Headers to writer (channel full)"),
                            }
                        }
                    } else {
                        response_bytes = response_bytes.saturating_add(msg_len);
                        match tokio::time::timeout(Duration::from_secs(5), normal_tx.send(msg)).await {
                            Ok(Ok(())) => {}
                            Ok(Err(_)) => warn!("GetHeaders: writer channel closed while sending Headers"),
                            Err(_) => warn!("GetHeaders: timed out sending Headers to writer (channel full)"),
                        }
                    }
                }
                Message::BlockResponse(block) => {
                    // Only exempt the active IBD peer from block rate limits.
                    // All other peers are rate-limited even during CatchingUp.
                    let is_ibd_peer = {
                        let guard = self.active_ibd_peer.lock().unwrap_or_else(|e| e.into_inner());
                        guard.map_or(false, |(id, _)| id == meta.identity)
                    };
                    if !is_ibd_peer {
                        block_count += 1;
                        if block_count > MAX_BLOCKS_PER_MIN {
                            return Err(PeerError::RateLimitExceeded);
                        }
                    }
                    if self.is_ip_banned(meta.addr.ip()) {
                        continue;
                    }
                    let block_id = block.header.block_id();
                    let already_known = self
                        .storage
                        .has_block(&block_id)
                        .map_err(|e| PeerError::Io(format!("storage: {}", e)))?;
                    if already_known {
                        continue;
                    }
                    if block.header.height == 0 || block.header.version != VERSION {
                        warn!(
                            "Rejected trivially invalid BlockResponse from {}",
                            meta.addr
                        );
                        invalid_block_count += 1;
                        if self.record_ip_strike(meta.addr.ip(), Some(meta.identity)) {
                            return Err(PeerError::RateLimitExceeded);
                        }
                        continue;
                    }
                    // Global block slot consumed in process_block_event after
                    // parent lookup — orphans don't count toward the cap.
                    let _ = self.peer_events_tx.send(PeerEvent::BlockResponse {
                        from: meta.addr,
                        from_identity: meta.identity,
                        session_id,
                        block,
                        pre_validated: false,
                    }).await;
                }
                Message::Headers(headers) => {
                    let _ = self.peer_events_tx.send(PeerEvent::HeadersResponse {
                        from_identity: meta.identity,
                        session_id,
                        headers,
                    }).await;
                }
                Message::Inv(_) => {
                    tracing::debug!("Ignoring Inv from {}", meta.addr);
                }
                Message::GetAddr => {
                    getaddr_count += 1;
                    if getaddr_count > MAX_GETADDR_PER_CONN {
                        unsolicited_count += 1;
                        if unsolicited_count > MAX_UNSOLICITED_PER_MIN {
                            return Err(PeerError::RateLimitExceeded);
                        }
                        continue;
                    }
                    let sample = self.addr_book_sample(MAX_ADDR_ITEMS);
                    if !sample.is_empty() {
                        let _ = normal_tx.try_send(Message::Addr(sample));
                    }
                }
                Message::Addr(entries) => {
                    let in_window = getaddr_sent_at.is_some_and(|t| {
                        now.duration_since(t) < Duration::from_secs(ADDR_RESPONSE_WINDOW_SECS)
                    });
                    if !in_window {
                        unsolicited_addr_count += 1;
                        if unsolicited_addr_count > MAX_UNSOLICITED_ADDR_PER_MIN {
                            unsolicited_count += 1;
                            if unsolicited_count > MAX_UNSOLICITED_PER_MIN {
                                return Err(PeerError::RateLimitExceeded);
                            }
                        }
                        continue;
                    }
                    self.merge_addr_entries(&entries, meta.addr.ip(), &meta.identity);
                    getaddr_sent_at = None;
                }
                Message::TipResponse(tip_msg) => {
                    let _ = self.peer_events_tx.try_send(PeerEvent::TipResponse {
                        from_identity: meta.identity,
                        session_id,
                        height: tip_msg.height,
                        block_id: tip_msg.block_id,
                        cumulative_work: tip_msg.cumulative_work,
                    });
                }
                _ => {
                    unsolicited_count += 1;
                    if unsolicited_count > MAX_UNSOLICITED_PER_MIN {
                        return Err(PeerError::RateLimitExceeded);
                    }
                }
            }
        }
    }

    /// Supervisor task: manages reader and writer tasks for a peer connection.
    ///
    /// Replaces `handle_peer_messages` — spawns separate reader and writer
    /// tasks on split TCP halves so that socket writes (large BlockResponse,
    /// Headers) never block inbound reads (preventing pong timeouts).
    async fn run_peer_supervisor(
        self: Arc<Self>,
        peer: Peer,
        normal_rx: mpsc::Receiver<Message>,
        getaddr_sent_at: Option<Instant>,
        session_id: u64,
    ) -> Result<(), PeerError> {
        let peer_addr = peer.addr;
        let peer_identity = peer.identity;

        let (reader_state, writer_state, metadata) = peer.into_split();
        let meta = Arc::new(metadata);
        // v1.4.2 Fix 3: attach this peer to the node-wide frame-buffer
        // budget. The PeerBudget is dropped when `shared` is dropped at
        // task exit, which releases any outstanding in-flight bytes (the
        // FrameReservation RAII guard held inside the reader loop releases
        // synchronously).
        let peer_budget = crate::network::frame_budget::PeerBudget::new(self.frame_budget.clone());
        let shared = Arc::new(PeerSharedState::with_frame_budget(peer_budget));

        // Read the shutdown flag from LogicalPeer.session (set by attach_session)
        let external_shutdown = {
            let peers = self.peers.lock().await;
            peers
                .get_by_identity(&peer_identity)
                .and_then(|lp| {
                    lp.session
                        .as_ref()
                        .filter(|s| s.session_id == session_id)
                        .map(|s| s.shutdown.clone())
                })
                .unwrap_or_else(|| Arc::new(AtomicBool::new(false)))
        };

        // Control channel: Pong, Ping, disconnect — always dequeued first
        let (ctrl_tx, ctrl_rx) = mpsc::channel::<WriterControl>(8);

        // The reader needs a sender to enqueue responses (GetBlocks replies, etc.)
        // into the writer's normal channel. We create a second sender by creating
        // a new channel pair — the writer reads from normal_rx (relay from PeerInfo.tx)
        // AND from reader_normal_rx (reader's responses). We merge them with a
        // forwarder approach: the normal_rx feeds into a merged channel.
        //
        // Simpler approach: create ONE channel, give the sender to PeerInfo.tx
        // and clone it for the reader. The receiver goes to the writer.
        // But PeerInfo.tx was already created by the caller with its own channel.
        // So we need to forward from the caller's normal_rx into our merged channel.
        let (merged_tx, merged_rx) = mpsc::channel::<Message>(4096);
        let reader_tx = merged_tx.clone();

        // Forward from the caller's outbound_rx (PeerInfo.tx) into merged channel
        let fwd_shared = shared.clone();
        let fwd_tx = merged_tx;
        let fwd_handle = tokio::spawn(async move {
            let mut rx = normal_rx;
            loop {
                if fwd_shared.shutdown.load(Ordering::Relaxed) {
                    break;
                }
                match rx.recv().await {
                    Some(msg) => {
                        if fwd_tx.send(msg).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        });

        // Spawn writer task
        let w_shared = shared.clone();
        let writer_handle =
            tokio::spawn(
                async move { writer_task(writer_state, ctrl_rx, merged_rx, w_shared).await },
            );

        // Spawn reader task
        let r_node = self.clone();
        let r_shared = shared.clone();
        let r_ctrl_tx = ctrl_tx.clone();
        let r_meta = meta.clone();
        let reader_handle = tokio::spawn(async move {
            r_node
                .reader_task(
                    reader_state,
                    r_shared,
                    r_ctrl_tx,
                    reader_tx,
                    r_meta,
                    getaddr_sent_at,
                    session_id,
                )
                .await
        });

        // Supervisor tick loop.
        // Pings are sent only after a period of inbound inactivity; active
        // read progress counts as liveness and suppresses keepalives during IBD.
        let mut last_bytes_seen = shared.bytes_read.load(Ordering::Relaxed);
        let mut last_read_progress = Instant::now();
        let mut ping_sent_at: Option<Instant> = None;
        let ping_interval = Duration::from_secs(PING_INTERVAL_SECS);
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let mut opt_reader: Option<tokio::task::JoinHandle<Result<(), PeerError>>> =
            Some(reader_handle);
        let mut opt_writer: Option<tokio::task::JoinHandle<Result<(), PeerError>>> =
            Some(writer_handle);
        let supervisor_result: Result<(), PeerError> = loop {
            tokio::select! {
                biased;
                reader_result = async { opt_reader.as_mut().unwrap().await }, if opt_reader.is_some() => {
                    opt_reader.take();
                    match reader_result {
                        Ok(Ok(())) => break Ok(()),
                        Ok(Err(e)) => break Err(e),
                        Err(_join_err) => break Err(PeerError::Io("reader task panicked".into())),
                    }
                }
                writer_result = async { opt_writer.as_mut().unwrap().await }, if opt_writer.is_some() => {
                    opt_writer.take();
                    match writer_result {
                        Ok(Ok(())) => break Ok(()),
                        Ok(Err(e)) => break Err(e),
                        Err(_join_err) => break Err(PeerError::Io("writer task panicked".into())),
                    }
                }
                _ = tick.tick() => {
                    // Check node shutdown
                    if self.shutdown.load(Ordering::SeqCst) {
                        break Err(PeerError::Io("node shutting down".into()));
                    }

                    // Check external shutdown (tiebreaker eviction)
                    if external_shutdown.load(Ordering::Relaxed) {
                        break Err(PeerError::Io("evicted by tiebreaker".into()));
                    }

                    // Check IP/identity bans
                    if self.is_ip_banned(peer_addr.ip()) {
                        break Err(PeerError::RateLimitExceeded);
                    }
                    if self.is_identity_banned(&peer_identity) {
                        break Err(PeerError::RateLimitExceeded);
                    }

                    let now = Instant::now();

                    // Track inbound byte progress. Any authenticated bytes count
                    // as liveness, even if a Pong is queued behind bulk data.
                    let current_bytes = shared.bytes_read.load(Ordering::Relaxed);
                    if current_bytes != last_bytes_seen {
                        last_bytes_seen = current_bytes;
                        last_read_progress = now;
                    }

                    // Pong check: if pong was received, clear awaiting state.
                    if shared.pong_received.swap(false, Ordering::Relaxed) {
                        shared.awaiting_pong.store(false, Ordering::Relaxed);
                        ping_sent_at = None;
                        last_read_progress = now;
                    }

                    // Liveness check
                    if shared.awaiting_pong.load(Ordering::Relaxed) {
                        let deadline_anchor = match ping_sent_at {
                            Some(sent_at) if sent_at > last_read_progress => sent_at,
                            _ => last_read_progress,
                        };
                        if now.duration_since(deadline_anchor)
                            >= Duration::from_secs(PONG_DEADLINE_SECS)
                        {
                            break Err(PeerError::PongTimeout);
                        }
                    } else if now.duration_since(last_read_progress) >= ping_interval {
                        // Connection has been idle long enough: send keepalive ping.
                        if ctrl_tx.try_send(WriterControl::SendPing).is_ok() {
                            ping_sent_at = Some(now);
                            shared.awaiting_pong.store(true, Ordering::Relaxed);
                        }
                    }
                }
            }
        };

        // Shutdown: signal tasks and clean up
        shared.shutdown.store(true, Ordering::Relaxed);
        drop(ctrl_tx); // closes control channel → writer exits
        fwd_handle.abort();

        // Give tasks 2 seconds to finish
        if let Some(rh) = opt_reader.take() {
            let _ = tokio::time::timeout(Duration::from_secs(2), rh).await;
        }
        if let Some(wh) = opt_writer.take() {
            let _ = tokio::time::timeout(Duration::from_secs(2), wh).await;
        }

        supervisor_result
    }

    /// Check if we share the same block at the given height with a peer.
    async fn check_shared_block_via_events(
        &self,
        peer_identity: PeerId,
        session_id: u64,
        height: u64,
        rx: &mut mpsc::Receiver<PeerEvent>,
        deadline: Instant,
    ) -> Result<Option<bool>, String> {
        let msg = Message::GetHeaders(GetHeadersMsg {
            start_height: height,
            max_count: 1,
        });
        if !self.send_to_session(peer_identity, session_id, msg).await {
            return Err("failed to send to peer".into());
        }
        let headers = recv_ibd_headers(self, rx, peer_identity, session_id, deadline).await?;
        if headers.is_empty() {
            return Ok(None);
        }
        if headers[0].height != height {
            return Err(format!(
                "peer returned height {} but expected {}",
                headers[0].height, height
            ));
        }
        let peer_block_id = headers[0].block_id();
        match self.storage.get_block_id_by_height(height) {
            Ok(Some(our_block_id)) => Ok(Some(our_block_id == peer_block_id)),
            Ok(None) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Find common ancestor between our chain and a peer using binary search.
    async fn find_common_ancestor_via_events(
        &self,
        peer_identity: PeerId,
        session_id: u64,
        rx: &mut mpsc::Receiver<PeerEvent>,
    ) -> Result<u64, String> {
        let our_height = self.tip.read().await.height;
        let deadline = Instant::now() + Duration::from_secs(120);

        if let Some(true) = self
            .check_shared_block_via_events(peer_identity, session_id, our_height, rx, deadline)
            .await?
        {
            return Ok(our_height);
        }

        let mut lo: u64 = 0;
        let mut hi: u64 = our_height;
        while lo < hi {
            let mid = lo + (hi - lo).div_ceil(2);
            match self
                .check_shared_block_via_events(peer_identity, session_id, mid, rx, deadline)
                .await?
            {
                Some(true) => lo = mid,
                Some(false) => hi = mid.saturating_sub(1),
                None => hi = mid.saturating_sub(1),
            }
        }
        Ok(lo)
    }
}

/// Receive a HeadersResponse from a specific peer+session via the event channel.
async fn recv_ibd_headers(
    node: &Node,
    rx: &mut mpsc::Receiver<PeerEvent>,
    sync_identity: PeerId,
    sync_session_id: u64,
    deadline: Instant,
) -> Result<Vec<BlockHeader>, String> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("IBD headers deadline exceeded".into());
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(PeerEvent::HeadersResponse { from_identity, session_id, headers }))
                if from_identity == sync_identity && session_id == sync_session_id =>
            {
                return Ok(headers);
            }
            Ok(Some(PeerEvent::HeadersResponse { .. })) => {
                // Stale headers from wrong session or identity — discard
            }
            Ok(Some(PeerEvent::Disconnected { identity, session_id })) => {
                node.peers.lock().await.detach_session_if_current(identity, session_id);
                if identity == sync_identity {
                    return Err("IBD peer disconnected".into());
                }
            }
            Ok(Some(event)) => {
                handle_background_event(node, event).await;
            }
            Ok(None) => return Err("event channel closed".into()),
            Err(_) => return Err("IBD headers timeout".into()),
        }
    }
}

/// Receive a BlockResponse from a specific peer+session via the event channel.
async fn recv_ibd_block(
    node: &Node,
    rx: &mut mpsc::Receiver<PeerEvent>,
    sync_identity: PeerId,
    sync_session_id: u64,
    expected_id: &Hash256,
    deadline: Instant,
) -> Result<Block, String> {
    // If we already have this block (e.g. from replay), skip waiting for it.
    // The reader_task filters already_known blocks, so they'll never arrive
    // on the event channel.
    if node.storage.has_block(expected_id).unwrap_or(false) {
        if let Ok(Some(block)) = node.storage.get_block(expected_id) {
            return Ok(block);
        }
    }
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("IBD block deadline exceeded".into());
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(PeerEvent::BlockResponse {
                from,
                from_identity,
                session_id,
                block,
                pre_validated,
            })) if from_identity == sync_identity && session_id == sync_session_id => {
                if block.header.block_id() == *expected_id {
                    return Ok(block);
                }
                process_block_event(node, from, from_identity, block, pre_validated).await;
            }
            Ok(Some(PeerEvent::BlockResponse {
                from,
                from_identity,
                block,
                pre_validated,
                ..
            })) => {
                // BlockResponse from wrong identity or stale session — process normally
                process_block_event(node, from, from_identity, block, pre_validated).await;
            }
            Ok(Some(PeerEvent::Disconnected { identity, session_id })) => {
                node.peers.lock().await.detach_session_if_current(identity, session_id);
                if identity == sync_identity {
                    return Err("IBD peer disconnected".into());
                }
            }
            Ok(Some(event)) => {
                handle_background_event(node, event).await;
            }
            Ok(None) => return Err("event channel closed".into()),
            Err(_) => return Err("IBD block timeout".into()),
        }
    }
}

/// Handle a non-IBD event that arrives while waiting for an IBD response.
async fn handle_background_event(
    node: &Node,
    event: PeerEvent,
) {
    match event {
        PeerEvent::Connected { .. } => {
            // Tip is already written by attach_session; nothing to do here.
        }
        PeerEvent::Disconnected { identity, session_id } => {
            node.peers.lock().await.detach_session_if_current(identity, session_id);
        }
        PeerEvent::NewBlock {
            from,
            from_identity,
            block,
            pre_validated,
            ..
        } => {
            process_block_event(node, from, from_identity, block, pre_validated).await;
        }
        PeerEvent::BlockResponse {
            from,
            from_identity,
            block,
            pre_validated,
            ..
        } => {
            process_block_event(node, from, from_identity, block, pre_validated).await;
        }
        PeerEvent::HeadersResponse { .. } => {
            // Stale or unexpected headers — ignore
        }
        PeerEvent::TipResponse {
            from_identity,
            session_id,
            height,
            block_id,
            cumulative_work,
        } => {
            // Store tip as unconfirmed — only the main sync loop verifies
            // via header PoW before setting confirmed: true.
            let mut peers = node.peers.lock().await;
            if let Some(lp) = peers.get_mut_by_identity(&from_identity) {
                if lp.session.as_ref().is_some_and(|s| s.session_id == session_id) {
                    lp.tip = Some(PeerTip {
                        height,
                        cumulative_work,
                        block_id,
                        confirmed: false,
                    });
                }
            }
        }
    }
}

/// Process a single block event: PoW verify, process_block, broadcast, orphan drain.
/// This is the central block processing logic, called from the sync manager.
async fn process_block_event(node: &Node, from: SocketAddr, from_identity: PeerId, block: Block, pre_validated: bool) {
    let block_id = block.header.block_id();

    // Parent lookup — orphan if unknown
    let parent_hdr = match node.storage.get_header(&block.header.prev_block_id) {
        Ok(h) => h,
        Err(e) => {
            warn!("Storage error checking parent: {}", e);
            return;
        }
    };
    if parent_hdr.is_none() {
        // Cache as orphan and request parent
        let parent_hash = block.header.prev_block_id;
        let block_size = block.serialize().map(|b| b.len()).unwrap_or(usize::MAX);
        let should_request = {
            let mut orphans = node.orphan_blocks.lock().unwrap_or_else(|e| e.into_inner());
            if block_size <= MAX_ORPHAN_BLOCK_SIZE
                && !orphans
                    .iter()
                    .any(|(_, b, _)| b.header.block_id() == block_id)
            {
                let already_waiting = orphans.iter().any(|(pid, _, _)| *pid == parent_hash);
                while !orphans.is_empty()
                    && (orphans.len() >= MAX_ORPHAN_BLOCKS
                        || orphans
                            .iter()
                            .map(|(_, _, sz)| *sz)
                            .sum::<usize>()
                            .saturating_add(block_size)
                            > MAX_ORPHAN_CACHE_BYTES)
                {
                    orphans.remove(0);
                }
                orphans.push((parent_hash, block, block_size));
                !already_waiting
            } else {
                false
            }
        }; // MutexGuard dropped here
        if should_request {
            node.send_to_peer(&from_identity, Message::GetBlocks(vec![parent_hash]))
                .await;
        }
        return;
    }

    // Height continuity
    let p = parent_hdr.unwrap();
    if p.height + 1 != block.header.height {
        warn!("Rejected block from {} — height discontinuity", from);
        node.record_ip_strike(from.ip(), Some(from_identity));
        return;
    }

    // Difficulty target check (cached) — cheap rejection before consuming budget
    let mut difficulty_ancestry_missing = false;
    match node.cached_expected_difficulty(&block.header.prev_block_id, block.header.height) {
        Ok((expected_target, _)) => {
            if block.header.difficulty_target != expected_target {
                warn!("Rejected block from {} — wrong difficulty", from);
                node.record_ip_strike(from.ip(), Some(from_identity));
                return;
            }
        }
        Err(crate::consensus::difficulty::DifficultyError::AncestorNotFound(_)) => {
            difficulty_ancestry_missing = true;
        }
        Err(e) => {
            warn!("Difficulty computation failed: {}", e);
            return;
        }
    }

    // Global block slot — consume only after orphan, height, and difficulty checks.
    // Cheap rejections don't burn budget; only blocks entering PoW validation count.
    if !node.try_consume_global_block_slot() {
        return;
    }

    // PoW verification (Argon2id) — skipped when difficulty ancestry is missing
    if !difficulty_ancestry_missing && !pre_validated {
        let _pow_permit = match node.pow_semaphore.acquire().await {
            Ok(p) => p,
            Err(_) => return,
        };
        let pow_header = block.header.clone();
        let pow_valid = match tokio::task::spawn_blocking(move || {
            crate::consensus::pow::verify_pow(&pow_header)
        })
        .await
        {
            Ok(Ok(v)) => v,
            _ => {
                warn!("PoW verification failed for block from {}", from);
                return;
            }
        };
        if !pow_valid {
            warn!("Rejected invalid-PoW block from {}", from);
            node.record_ip_strike(from.ip(), Some(from_identity));
            return;
        }
    }

    let wall_clock = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs());
    let block_for_relay = block.clone();
    let process_result = if difficulty_ancestry_missing {
        node.process_block(block, wall_clock).await
    } else {
        node.process_block_pre_validated(block, wall_clock).await
    };
    match process_result {
        Ok(ProcessBlockOutcome::Accepted) => {
            info!("Accepted new block from {}", from);
            node.broadcast(&Message::NewBlock(block_for_relay), Some(from_identity))
                .await;
            node.try_process_orphans(&block_id).await;
        }
        Ok(ProcessBlockOutcome::Stored) => {
            node.try_process_orphans(&block_id).await;
        }
        Ok(ProcessBlockOutcome::BufferedFuture) => {
            info!("Block from {} buffered as future", from);
        }
        Err(ProcessBlockError::MissingReorgAncestor(missing_id)) => {
            info!(
                "Reorg blocked by missing ancestor {}; saving trigger block {}",
                missing_id, block_id
            );
            {
                let mut rt = node
                    .reorg_triggers
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if !rt.insert(missing_id, block_for_relay) {
                    warn!(
                        "Dropping trigger block {}: too many triggers for ancestor {}",
                        block_id, missing_id
                    );
                }
            }
            node.send_to_peer(&from_identity, Message::GetBlocks(vec![missing_id]))
                .await;
        }
        Err(e) if e.is_fatal() => {
            tracing::error!(
                fatal = true,
                error = %e,
                "FATAL: consensus state corrupted, initiating graceful shutdown"
            );
            node.shutdown.store(true, Ordering::SeqCst);
            return;
        }
        Err(e) => {
            warn!("Rejected block from {}: {}", from, e);
            node.record_ip_strike(from.ip(), Some(from_identity));
        }
    }

    // If this block was a missing ancestor for pending reorg triggers, retry them
    node.retry_reorg_triggers(&block_id, wall_clock, Some(from_identity))
        .await;
}

/// Run IBD (Initial Block Download) from a specific peer.
async fn run_ibd(
    node: &Node,
    rx: &mut mpsc::Receiver<PeerEvent>,
    peer_identity: PeerId,
    session_id: u64,
) -> Result<(), String> {
    let their_height = {
        let peers = node.peers.lock().await;
        peers
            .get_by_identity(&peer_identity)
            .and_then(|lp| lp.tip.as_ref().map(|t| t.height))
            .ok_or_else(|| "sync peer not in registry".to_string())?
    };

    let fork_point = node
        .find_common_ancestor_via_events(peer_identity, session_id, rx)
        .await?;

    info!(
        "IBD: syncing from fork point {} to peer height {} via identity {:?}",
        fork_point, their_height, &peer_identity[..4]
    );

    let mut current_height = fork_point + 1;
    let mut prev_batch_tip: Option<Hash256> = None;

    while current_height <= their_height {
        if node.shutdown.load(Ordering::SeqCst) {
            return Err("shutdown".into());
        }

        // Check if sync peer is still connected (by identity + session_id)
        {
            let peers = node.peers.lock().await;
            let still_connected = peers
                .get_by_identity(&peer_identity)
                .and_then(|lp| lp.session.as_ref())
                .is_some_and(|s| s.session_id == session_id);
            if !still_connected {
                return Err("sync peer disconnected".into());
            }
        }

        let batch_size = std::cmp::min(64u64, their_height - current_height + 1) as u32;
        let msg = Message::GetHeaders(GetHeadersMsg {
            start_height: current_height,
            max_count: batch_size,
        });
        if !node.send_to_session(peer_identity, session_id, msg).await {
            return Err("failed to send GetHeaders".into());
        }

        let deadline = Instant::now() + Duration::from_secs(120);
        let headers = recv_ibd_headers(node, rx, peer_identity, session_id, deadline).await?;

        if headers.is_empty() {
            return Err(format!(
                "peer returned empty headers at height {}",
                current_height
            ));
        }

        if headers[0].height != current_height {
            return Err(format!(
                "peer returned header at height {} but expected {}",
                headers[0].height, current_height
            ));
        }
        for w in headers.windows(2) {
            if w[1].height != w[0].height + 1 {
                return Err(format!(
                    "non-contiguous headers: {} then {}",
                    w[0].height, w[1].height
                ));
            }
        }
        if let Some(ref expected_parent) = prev_batch_tip {
            if headers[0].prev_block_id != *expected_parent {
                return Err(format!(
                    "header at height {} prev_block_id does not link to previous batch tip",
                    headers[0].height
                ));
            }
        } else {
            let expected_parent = node
                .storage
                .get_block_id_by_height(current_height - 1)
                .map_err(|e| e.to_string())?;
            if let Some(parent_id) = expected_parent {
                if headers[0].prev_block_id != parent_id {
                    return Err(format!(
                        "first header prev_block_id does not match our block at height {}",
                        current_height - 1
                    ));
                }
            }
        }
        for w in headers.windows(2) {
            if w[1].prev_block_id != w[0].block_id() {
                return Err(format!(
                    "header at height {} does not link to height {}",
                    w[1].height, w[0].height
                ));
            }
        }

        prev_batch_tip = Some(headers.last().unwrap().block_id());
        let block_ids: Vec<Hash256> = headers.iter().map(|h| h.block_id()).collect();

        for chunk in block_ids.chunks(MAX_GETBLOCKS_RESPONSE) {
            let msg = Message::GetBlocks(chunk.to_vec());
            if !node.send_to_session(peer_identity, session_id, msg).await {
                return Err("failed to send GetBlocks".into());
            }

            let block_deadline = Instant::now() + Duration::from_secs(120);
            for expected_id in chunk {
                let block =
                    recv_ibd_block(node, rx, peer_identity, session_id, expected_id, block_deadline)
                        .await?;

                // Skip processing blocks we already have (overlap from IBD retry).
                // Only advance the tip if the block is in the canonical chain
                // (matches height index), not a stored fork block.
                if node.storage.has_block(&block.header.block_id()).unwrap_or(false) {
                    let is_canonical = node.storage
                        .get_block_id_by_height(block.header.height)
                        .ok()
                        .flatten()
                        .map(|id| id == block.header.block_id())
                        .unwrap_or(false);
                    if is_canonical {
                        let mut tip = node.tip.write().await;
                        if block.header.height > tip.height {
                            let work = node.storage.get_cumulative_work(&block.header.block_id())
                                .ok().flatten().unwrap_or(tip.cumulative_work);
                            tip.height = block.header.height;
                            tip.block_id = block.header.block_id();
                            tip.cumulative_work = work;
                        }
                    }
                    continue;
                }

                let our_validated_height = node.tip.read().await.height;
                let ibd_wall_clock = if block.header.height
                    >= our_validated_height.saturating_sub(IBD_DRIFT_WINDOW)
                {
                    Some(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                    )
                } else {
                    None
                };

                // Assume-valid: skip Argon2id only after the checkpoint has been
                // proven (block 130,000 received and hash matched). First IBD
                // verifies full PoW; subsequent syncs skip below the checkpoint.
                let ibd_skip_pow = node.assume_valid
                    && node.assume_valid_verified.load(Ordering::SeqCst)
                    && block.header.height <= ASSUME_VALID_HEIGHT;
                let result = if ibd_skip_pow {
                    node.process_block_pre_validated(block.clone(), ibd_wall_clock).await
                } else {
                    node.process_block(block.clone(), ibd_wall_clock).await
                };
                match result {
                    Ok(_) => {}
                    Err(ProcessBlockError::MissingReorgAncestor(missing_id)) => {
                        const MAX_ANCESTOR_RECOVERY_DEPTH: usize = 4320;
                        const MAX_ANCESTOR_BYTES: usize = 512 * 1024 * 1024;
                        let mut needed_id = missing_id;
                        let mut fetched_ancestors: Vec<Block> = Vec::new();
                        let mut total_bytes: usize = 0;

                        for _depth in 0..MAX_ANCESTOR_RECOVERY_DEPTH {
                            let anc_msg = Message::GetBlocks(vec![needed_id]);
                            if !node.send_to_session(peer_identity, session_id, anc_msg).await {
                                return Err("failed to send GetBlocks for ancestor".into());
                            }
                            let anc_deadline = Instant::now() + Duration::from_secs(120);
                            let ancestor_block = recv_ibd_block(
                                node,
                                rx,
                                peer_identity,
                                session_id,
                                &needed_id,
                                anc_deadline,
                            )
                            .await?;
                            let block_bytes = ancestor_block
                                .serialize()
                                .map(|b| b.len())
                                .unwrap_or(MAX_BLOCK_SIZE);
                            total_bytes = total_bytes.saturating_add(block_bytes);
                            if total_bytes > MAX_ANCESTOR_BYTES {
                                return Err("ancestor recovery byte cap exceeded".into());
                            }

                            let parent_id = ancestor_block.header.prev_block_id;
                            fetched_ancestors.push(ancestor_block);

                            let parent_known = node
                                .storage
                                .has_header(&parent_id)
                                .map_err(|e| e.to_string())?;
                            if parent_known || parent_id == Hash256::ZERO {
                                break;
                            }
                            needed_id = parent_id;
                        }

                        fetched_ancestors.reverse();
                        for anc in fetched_ancestors {
                            let anc_skip = node.assume_valid
                                && node.assume_valid_verified.load(Ordering::SeqCst)
                                && anc.header.height <= ASSUME_VALID_HEIGHT;
                            let anc_result = if anc_skip {
                                node.process_block_pre_validated(anc, ibd_wall_clock).await
                            } else {
                                node.process_block(anc, ibd_wall_clock).await
                            };
                            match anc_result {
                                Ok(_) => {}
                                Err(e) if e.is_fatal() => {
                                    node.shutdown.store(true, Ordering::SeqCst);
                                    return Err(format!("FATAL during ancestor processing: {}", e));
                                }
                                Err(e) => {
                                    return Err(format!("ancestor processing failed: {}", e));
                                }
                            }
                        }

                        let retry_skip = node.assume_valid
                            && node.assume_valid_verified.load(Ordering::SeqCst)
                            && block.header.height <= ASSUME_VALID_HEIGHT;
                        let retry_result = if retry_skip {
                            node.process_block_pre_validated(block, ibd_wall_clock).await
                        } else {
                            node.process_block(block, ibd_wall_clock).await
                        };
                        match retry_result {
                            Ok(_) => {}
                            Err(e) => return Err(format!("block retry failed: {}", e)),
                        }
                    }
                    Err(e) if e.is_fatal() => {
                        node.shutdown.store(true, Ordering::SeqCst);
                        return Err(format!("FATAL during IBD: {}", e));
                    }
                    Err(e) => {
                        return Err(format!("IBD block processing failed: {}", e));
                    }
                }
            }
        }

        current_height += headers.len() as u64;
    }

    let final_height = node.tip.read().await.height;
    if final_height <= fork_point {
        return Err(format!(
            "tip did not advance past fork point {} (final {})",
            fork_point, final_height
        ));
    }

    info!("IBD complete at height {}", final_height);
    Ok(())
}

/// Single node-wide outbound connection manager.
/// Dials identity-known peers first, then bootstrap entries.
pub async fn run_outbound_manager(node: Arc<Node>) {
    loop {
        if node.shutdown.load(Ordering::SeqCst) {
            return;
        }

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        // Count current outbound sessions + in-flight dials toward the cap
        let (outbound_count, in_flight) = {
            let peers = node.peers.lock().await;
            (peers.outbound_count(), peers.pending_outbound_addrs.len())
        };
        if outbound_count + in_flight >= MAX_OUTBOUND_PEERS {
            continue;
        }

        let now = std::time::Instant::now();

        // Phase 1: Identity-known peers (higher priority)
        let identity_candidate: Option<(PeerId, SocketAddr)> = {
            let peers = node.peers.lock().await;
            let mut best: Option<(PeerId, SocketAddr)> = None;
            for (id, lp) in &peers.by_identity {
                if !lp.desired_outbound {
                    continue;
                }
                if lp.session.is_some() {
                    continue;
                }
                let addr = match lp.preferred_dial_addr {
                    Some(a) => a,
                    None => continue,
                };
                if now < lp.retry.next_attempt_at {
                    continue;
                }
                if peers.pending_outbound_addrs.contains(&addr) {
                    continue;
                }
                best = Some((*id, addr));
                break;
            }
            best
        };

        if let Some((_identity, addr)) = identity_candidate {
            let reserved = {
                let mut peers = node.peers.lock().await;
                peers.reserve_outbound_addr(addr)
            };
            if reserved {
                let connect_node = node.clone();
                let session_start = std::time::Instant::now();
                tokio::spawn(async move {
                    match connect_node.clone().connect(addr).await {
                        Ok(identity) => {
                            let mut peers = connect_node.peers.lock().await;
                            if let Some(lp) = peers.get_mut_by_identity(&identity) {
                                Node::reset_retry(lp);
                            }
                            // Remove from bootstraps if present
                            connect_node
                                .outbound_bootstraps
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .remove(&addr);
                        }
                        Err(PeerError::DuplicateIdentity(id)) => {
                            // Read desired_outbound from bootstrap before taking peer lock
                            let bs_desired = {
                                let bootstraps = connect_node
                                    .outbound_bootstraps
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner());
                                bootstraps.get(&addr).map_or(false, |bs| bs.desired_outbound)
                            };
                            let mut peers = connect_node.peers.lock().await;
                            // Ensure logical peer exists
                            if !peers.by_identity.contains_key(&id) {
                                peers.by_identity.insert(id, LogicalPeer {
                                    identity: id,
                                    session: None,
                                    known_addrs: HashSet::new(),
                                    preferred_dial_addr: None,
                                    desired_outbound: false,
                                    retry: RetryState {
                                        backoff_secs: 5,
                                        next_attempt_at: std::time::Instant::now(),
                                    },
                                    tip: None,
                                    ibd_cooldown_until: None,
                                });
                            }
                            peers.bind_dial_addr(id, addr);
                            if let Some(lp) = peers.get_mut_by_identity(&id) {
                                if bs_desired {
                                    lp.desired_outbound = true;
                                }
                                if lp.session.is_none() {
                                    Node::bump_retry(lp);
                                }
                            }
                            drop(peers);
                            connect_node
                                .outbound_bootstraps
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .remove(&addr);
                        }
                        Err(_e) => {
                            let session_duration = session_start.elapsed();
                            let mut peers = connect_node.peers.lock().await;
                            let id_opt = peers
                                .known_dial_addr_to_identity
                                .get(&addr)
                                .copied();
                            if let Some(id) = id_opt {
                                if let Some(lp) = peers.get_mut_by_identity(&id) {
                                    if session_duration
                                        > std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS + 1)
                                    {
                                        Node::reset_retry(lp);
                                    } else {
                                        Node::bump_retry(lp);
                                    }
                                }
                            }
                        }
                    }
                });
                continue;
            }
        }

        // Phase 2: Bootstrap entries
        // Snapshot eligible bootstrap addrs under std::sync::Mutex (no .await!)
        let bootstrap_candidates: Vec<SocketAddr> = {
            let bootstraps = node
                .outbound_bootstraps
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            bootstraps
                .iter()
                .filter(|(_, bs)| now >= bs.retry.next_attempt_at)
                .map(|(addr, _)| *addr)
                .collect()
        };
        // Now check against peers (async lock) without holding bootstraps guard
        let bootstrap_candidate: Option<SocketAddr> = {
            let peers = node.peers.lock().await;
            let mut best: Option<SocketAddr> = None;
            for addr in &bootstrap_candidates {
                if peers.pending_outbound_addrs.contains(addr) {
                    continue;
                }
                if peers.connected_socket_to_identity.contains_key(addr) {
                    continue;
                }
                best = Some(*addr);
                break;
            }
            best
        };

        if let Some(addr) = bootstrap_candidate {
            let reserved = {
                let mut peers = node.peers.lock().await;
                peers.reserve_outbound_addr(addr)
            };
            if reserved {
                let connect_node = node.clone();
                let session_start = std::time::Instant::now();
                tokio::spawn(async move {
                    match connect_node.clone().connect(addr).await {
                        Ok(identity) => {
                            let mut peers = connect_node.peers.lock().await;
                            if let Some(lp) = peers.get_mut_by_identity(&identity) {
                                Node::reset_retry(lp);
                                // Transfer desired_outbound from bootstrap
                                {
                                    let bootstraps = connect_node
                                        .outbound_bootstraps
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner());
                                    if let Some(bs) = bootstraps.get(&addr) {
                                        if bs.desired_outbound {
                                            lp.desired_outbound = true;
                                        }
                                    }
                                }
                            }
                            connect_node
                                .outbound_bootstraps
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .remove(&addr);
                            connect_node.addr_book_record_success(addr);
                        }
                        Err(PeerError::DuplicateIdentity(id)) => {
                            let bs_desired = {
                                let bootstraps = connect_node
                                    .outbound_bootstraps
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner());
                                bootstraps.get(&addr).map_or(false, |bs| bs.desired_outbound)
                            };
                            let mut peers = connect_node.peers.lock().await;
                            if !peers.by_identity.contains_key(&id) {
                                peers.by_identity.insert(id, LogicalPeer {
                                    identity: id,
                                    session: None,
                                    known_addrs: HashSet::new(),
                                    preferred_dial_addr: None,
                                    desired_outbound: false,
                                    retry: RetryState {
                                        backoff_secs: 5,
                                        next_attempt_at: std::time::Instant::now(),
                                    },
                                    tip: None,
                                    ibd_cooldown_until: None,
                                });
                            }
                            peers.bind_dial_addr(id, addr);
                            if let Some(lp) = peers.get_mut_by_identity(&id) {
                                if bs_desired {
                                    lp.desired_outbound = true;
                                }
                                if lp.session.is_none() {
                                    Node::bump_retry(lp);
                                }
                            }
                            drop(peers);
                            connect_node
                                .outbound_bootstraps
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .remove(&addr);
                        }
                        Err(_e) => {
                            let session_duration = session_start.elapsed();
                            let mut bootstraps = connect_node
                                .outbound_bootstraps
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            if let Some(bs) = bootstraps.get_mut(&addr) {
                                if session_duration
                                    > std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS + 1)
                                {
                                    Node::reset_bootstrap_retry(bs);
                                } else {
                                    Node::bump_bootstrap_retry(bs);
                                }
                            }
                            connect_node.addr_book_record_failure(addr);
                        }
                    }
                });
            }
        }
    }
}

/// The central sync manager task. Processes all block events, drives IBD,
/// manages sync state. Runs as a single node-wide task.
///
/// State machine (three-state with hysteresis):
/// - **CatchingUp**: large gap, needs IBD (GetHeaders/GetBlocks).
/// - **Live**: on canonical chain, consuming relay blocks normally. May be
///   a few blocks behind due to processing latency.
/// - **MiningReady** (not a stored state): Live AND our tip's cumulative work
///   >= best confirmed peer's work. Only state where mining runs.
///
/// Transition rules (work-based, not height-based):
/// - CatchingUp → Live: confirmed peer exists AND (our work >= peer's work
///   OR recent tip progress).
/// - Live → CatchingUp: peer has more cumulative work AND no tip progress for 60s.
/// - Bootstrap (no peers ever, >60s): → Live.
/// - Peers disconnecting while Live does NOT revert to CatchingUp.
pub async fn run_sync_manager(node: Arc<Node>, mut rx: mpsc::Receiver<PeerEvent>) {
    let mut last_future_retry = Instant::now();
    let mut last_tip_height: u64 = node.tip.read().await.height;
    let mut last_tip_change = Instant::now();
    let mut last_tip_poll = Instant::now();
    let mut ever_had_peer = false;
    let start_time = Instant::now();

    node.sync_state
        .store(SyncState::CatchingUp as u8, Ordering::Relaxed);
    let mut is_live = false;

    loop {
        if node.shutdown.load(Ordering::SeqCst) {
            return;
        }

        // Update tip tracking
        {
            let tip = node.tip.read().await;
            if tip.height != last_tip_height {
                last_tip_height = tip.height;
                last_tip_change = Instant::now();
            }
        }

        // Derive all state from registry.by_identity
        let (_best_known_tip, best_confirmed_work, connected_count, should_ibd) = {
            let peers = node.peers.lock().await;
            let our_tip = node.tip.read().await.clone();
            let now = std::time::Instant::now();

            let mut best_tip: Option<PeerTip> = None;
            let mut best_conf_work: [u8; 32] = [0u8; 32];
            let mut conn_count: usize = 0;
            let mut best_ibd: Option<(PeerId, u64, PeerTip)> = None;

            for (id, lp) in &peers.by_identity {
                let sess = match &lp.session {
                    Some(s) => s,
                    None => continue,
                };
                conn_count += 1;
                let tip = match &lp.tip {
                    Some(t) => t,
                    None => continue,
                };

                // Track best known tip
                let is_better = best_tip.as_ref().map_or(true, |bt| {
                    tip.cumulative_work
                        .cmp(&bt.cumulative_work)
                        .then_with(|| tip.height.cmp(&bt.height))
                        == std::cmp::Ordering::Greater
                });
                if is_better {
                    best_tip = Some(*tip);
                }

                // Track best confirmed cumulative work
                if tip.confirmed && tip.cumulative_work > best_conf_work {
                    best_conf_work = tip.cumulative_work;
                }

                // IBD candidate check — only confirmed peers can trigger IBD.
                // Unconfirmed handshake tips are just claims; a malicious peer
                // can claim any height/work to suppress mining.
                if !tip.confirmed {
                    continue;
                }
                let cooldown_ok = lp
                    .ibd_cooldown_until
                    .map_or(true, |until| now >= until);
                if !cooldown_ok {
                    continue;
                }
                let peer_ct = ChainTip {
                    block_id: tip.block_id,
                    height: tip.height,
                    cumulative_work: tip.cumulative_work,
                };
                if is_better_chain(&peer_ct, &our_tip) {
                    let is_best_ibd = best_ibd.as_ref().map_or(true, |(_, _, bt)| {
                        tip.cumulative_work > bt.cumulative_work
                    });
                    if is_best_ibd {
                        best_ibd = Some((*id, sess.session_id, *tip));
                    }
                }
            }

            (
                best_tip,
                best_conf_work,
                conn_count,
                best_ibd.map(|(id, sid, _)| (id, sid)),
            )
        };

        if let Some((peer_identity, peer_session_id)) = should_ibd {
            info!("Sync manager: starting IBD from identity {:?}", &peer_identity[..4]);
            is_live = false;
            node.sync_state
                .store(SyncState::CatchingUp as u8, Ordering::Relaxed);
            node.mining_cancel.store(true, Ordering::Relaxed);

            // Protect this peer's session from tiebreaker eviction during IBD.
            *node.active_ibd_peer.lock().unwrap_or_else(|e| e.into_inner()) =
                Some((peer_identity, peer_session_id));

            match run_ibd(&node, &mut rx, peer_identity, peer_session_id).await {
                Ok(()) => {
                    info!("Sync manager: IBD complete");
                    last_tip_height = node.tip.read().await.height;
                    last_tip_change = Instant::now();

                    // Immediately confirm the sync peer via GetTip
                    if node
                        .send_to_session(peer_identity, peer_session_id, Message::GetTip)
                        .await
                    {
                        let deadline = Instant::now() + Duration::from_secs(5);
                        while Instant::now() < deadline {
                            match tokio::time::timeout(Duration::from_secs(1), rx.recv()).await {
                                Ok(Some(PeerEvent::TipResponse {
                                    from_identity,
                                    session_id,
                                    height,
                                    block_id,
                                    cumulative_work,
                                })) => {
                                    // Only confirm the IBD peer (proved chain by delivering it).
                                    // Verify: the claimed block_id must exist at the claimed
                                    // height in our storage (we just IBD'd from them).
                                    let is_ibd_peer = from_identity == peer_identity
                                        && session_id == peer_session_id;
                                    let confirmed = if is_ibd_peer {
                                        // Verify height/block_id binding against our storage
                                        let stored_id = node.storage
                                            .get_block_id_by_height(height)
                                            .ok()
                                            .flatten();
                                        stored_id == Some(block_id)
                                    } else {
                                        false
                                    };
                                    let verified_work = if confirmed {
                                        node.storage
                                            .get_cumulative_work(&block_id)
                                            .ok()
                                            .flatten()
                                            .unwrap_or(node.tip.read().await.cumulative_work)
                                    } else {
                                        cumulative_work // unconfirmed, won't be used for IBD
                                    };
                                                    let mut peers = node.peers.lock().await;
                                    if let Some(lp) = peers.get_mut_by_identity(&from_identity) {
                                        if lp.session.as_ref().is_some_and(|s| s.session_id == session_id) {
                                            lp.tip = Some(PeerTip {
                                                height,
                                                cumulative_work: verified_work,
                                                block_id,
                                                confirmed,
                                            });
                                        }
                                    }
                                    if from_identity == peer_identity
                                        && session_id == peer_session_id
                                    {
                                        break;
                                    }
                                }
                                Ok(Some(other)) => {
                                    handle_background_event(&node, other).await;
                                }
                                Ok(None) => break,
                                Err(_) => {}
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Sync manager: IBD failed: {}", e);
                    if e.contains("checkpoint FAILED") {
                        // Checkpoint hash mismatch — peer served a fake chain.
                        // Shut down; user must delete datadir and re-sync.
                        error!(
                            "Assume-valid checkpoint verification failed — \
                             the peer served a fake chain. Delete the data \
                             directory and restart to re-sync from scratch."
                        );
                        node.shutdown.store(true, Ordering::SeqCst);
                    }
                    let mut peers = node.peers.lock().await;
                    if let Some(lp) = peers.get_mut_by_identity(&peer_identity) {
                        lp.ibd_cooldown_until =
                            Some(std::time::Instant::now() + std::time::Duration::from_secs(60));
                    }
                }
            }
            // Clear IBD protection
            *node.active_ibd_peer.lock().unwrap_or_else(|e| e.into_inner()) = None;
            continue;
        }

        // ── Live/CatchingUp transition logic (work-based) ──
        let our_work = node.tip.try_read()
            .map(|t| t.cumulative_work)
            .unwrap_or([0u8; 32]);
        let recent_progress =
            last_tip_change.elapsed() < Duration::from_secs(RECENT_PROGRESS_SECS);

        *node.best_peer_work.lock().unwrap_or_else(|e| e.into_inner()) = best_confirmed_work;

        // Work "gap": best confirmed peer has more work than us
        let peer_ahead = best_confirmed_work > our_work;

        if !is_live {
            let has_confirmed_peer = best_confirmed_work != [0u8; 32];
            if has_confirmed_peer && (!peer_ahead || recent_progress) {
                is_live = true;
            } else if connected_count == 0 && !ever_had_peer
                && start_time.elapsed() > Duration::from_secs(60)
            {
                info!("Sync manager: no peers after 60s, entering Live (bootstrap)");
                is_live = true;
            }
        } else {
            if peer_ahead && !recent_progress {
                info!(
                    "Sync manager: peer has more work, no recent progress, reverting to CatchingUp"
                );
                is_live = false;
            }
        }

        if is_live {
            node.sync_state
                .store(SyncState::Live as u8, Ordering::Relaxed);
            node.mining_cancel.store(false, Ordering::Relaxed);
        } else {
            node.sync_state
                .store(SyncState::CatchingUp as u8, Ordering::Relaxed);
            node.mining_cancel.store(true, Ordering::Relaxed);
        }

        if is_live && last_future_retry.elapsed() >= Duration::from_secs(10) {
            node.retry_future_blocks().await;
            last_future_retry = Instant::now();
        }

        // Periodic GetTip polling
        if last_tip_poll.elapsed() >= Duration::from_secs(60) {
            let identities: Vec<PeerId> = {
                let peers = node.peers.lock().await;
                peers
                    .by_identity
                    .iter()
                    .filter(|(_, lp)| lp.session.is_some())
                    .map(|(id, _)| *id)
                    .collect()
            };
            for id in identities {
                node.send_to_peer(&id, Message::GetTip).await;
            }
            last_tip_poll = Instant::now();
        }

        // Process next event
        let event = tokio::time::timeout(Duration::from_secs(1), rx.recv()).await;
        match event {
            Ok(Some(PeerEvent::Connected { identity, .. })) => {
                // Tip already written by attach_session (unconfirmed).
                // Immediately request confirmed tip via GetTip so we can
                // decide whether to IBD from this peer.
                ever_had_peer = true;
                node.send_to_peer(&identity, Message::GetTip).await;
            }
            Ok(Some(PeerEvent::Disconnected { identity, session_id })) => {
                node.peers
                    .lock()
                    .await
                    .detach_session_if_current(identity, session_id);
            }
            Ok(Some(PeerEvent::TipResponse {
                from_identity,
                session_id,
                height,
                block_id,
                cumulative_work,
            })) => {
                // Store the claim as unconfirmed first
                {
                    let mut peers = node.peers.lock().await;
                    if let Some(lp) = peers.get_mut_by_identity(&from_identity) {
                        if lp.session.as_ref().is_some_and(|s| s.session_id == session_id) {
                            lp.tip = Some(PeerTip {
                                height,
                                cumulative_work,
                                block_id,
                                confirmed: false,
                            });
                        }
                    }
                }
                // Verify the claim: request the header at the claimed height
                // and check that block_id matches and PoW is valid.
                if height > 0 {
                    use crate::network::protocol::GetHeadersMsg;
                    let sent = node.send_to_session(
                        from_identity,
                        session_id,
                        Message::GetHeaders(GetHeadersMsg {
                            start_height: height,
                            max_count: 1,
                        }),
                    ).await;
                    if sent {
                        // Wait briefly for the HeadersResponse
                        let deadline = Instant::now() + Duration::from_secs(10);
                        let mut verified = false;
                        let mut verified_header_target = Hash256([0xFF; 32]);
                        while Instant::now() < deadline {
                            let remaining = deadline.saturating_duration_since(Instant::now());
                            match tokio::time::timeout(remaining, rx.recv()).await {
                                Ok(Some(PeerEvent::HeadersResponse {
                                    from_identity: hdr_id,
                                    session_id: hdr_sid,
                                    headers,
                                })) if hdr_id == from_identity && hdr_sid == session_id => {
                                    if let Some(header) = headers.first() {
                                        let hdr_block_id = header.block_id();
                                        // Bind header to claimed height AND block_id
                                        if hdr_block_id == block_id && header.height == height {
                                            verified_header_target = header.difficulty_target;
                                            // Validate difficulty target against our chain.
                                            let difficulty_ok = if let Ok(Some(_parent)) = node.storage.get_header(&header.prev_block_id) {
                                                // Parent exists — verify expected difficulty
                                                match node.cached_expected_difficulty(&header.prev_block_id, header.height) {
                                                    Ok((expected_target, _)) => header.difficulty_target == expected_target,
                                                    Err(_) => false,
                                                }
                                            } else {
                                                // Parent unknown (peer is ahead). We can't verify
                                                // the exact difficulty, but PoW validity still
                                                // proves real work was done for the claimed target.
                                                // The full chain will be validated during IBD.
                                                true
                                            };
                                            if difficulty_ok {
                                                // Verify PoW on a blocking thread
                                                let pow_header = header.clone();
                                                let pow_ok = tokio::task::spawn_blocking(move || {
                                                    crate::consensus::pow::verify_pow(&pow_header)
                                                }).await.unwrap_or(Ok(false)).unwrap_or(false);
                                                if pow_ok {
                                                    verified = true;
                                                }
                                            }
                                        }
                                    }
                                    break;
                                }
                                Ok(Some(other)) => {
                                    // Handle other events while waiting
                                    handle_background_event(&node, other).await;
                                }
                                _ => break,
                            }
                        }
                        if verified {
                            // Don't trust peer-supplied cumulative_work.
                            // If we have this block, use our own stored work.
                            // Otherwise, peer is ahead: use our tip's work plus
                            // the verified header's single-block work. This is a
                            // lower bound on their real cumulative work, but enough
                            // to trigger IBD via is_better_chain.
                            let verified_work = node.storage
                                .get_cumulative_work(&block_id)
                                .ok()
                                .flatten()
                                .unwrap_or_else(|| {
                                    let our_work = node.tip.try_read()
                                        .map(|t| t.cumulative_work)
                                        .unwrap_or([0u8; 32]);
                                    let block_work = crate::consensus::difficulty::work_from_target(
                                        &verified_header_target
                                    );
                                    crate::consensus::difficulty::add_work(&our_work, &block_work)
                                });
                            let mut peers = node.peers.lock().await;
                            if let Some(lp) = peers.get_mut_by_identity(&from_identity) {
                                if lp.session.as_ref().is_some_and(|s| s.session_id == session_id) {
                                    lp.tip = Some(PeerTip {
                                        height,
                                        cumulative_work: verified_work,
                                        block_id,
                                        confirmed: true,
                                    });
                                }
                            }
                        } else {
                            warn!("Peer {:?} TipResponse at height {} failed PoW verification", &from_identity[..4], height);
                            // Look up peer's IP to record a strike
                            let peer_ip = {
                                let peers = node.peers.lock().await;
                                peers.get_by_identity(&from_identity)
                                    .and_then(|lp| lp.session.as_ref().map(|s| s.socket_addr.ip()))
                            };
                            if let Some(ip) = peer_ip {
                                node.record_ip_strike(ip, Some(from_identity));
                            }
                        }
                    }
                } else {
                    // Height 0 (genesis) — no PoW check needed, but also no
                    // reason to confirm (can't trigger IBD from genesis).
                    let mut peers = node.peers.lock().await;
                    if let Some(lp) = peers.get_mut_by_identity(&from_identity) {
                        if lp.session.as_ref().is_some_and(|s| s.session_id == session_id) {
                            lp.tip = Some(PeerTip {
                                height,
                                cumulative_work,
                                block_id,
                                confirmed: false,
                            });
                        }
                    }
                }
            }
            Ok(Some(PeerEvent::NewBlock {
                from,
                from_identity,
                block,
                pre_validated,
                ..
            })) => {
                process_block_event(&node, from, from_identity, block, pre_validated).await;
            }
            Ok(Some(PeerEvent::BlockResponse {
                from,
                from_identity,
                block,
                pre_validated,
                ..
            })) => {
                process_block_event(&node, from, from_identity, block, pre_validated).await;
            }
            Ok(Some(PeerEvent::HeadersResponse { .. })) => {}
            Ok(None) => return,
            Err(_) => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Removed: sync_from_peer, find_common_ancestor, check_shared_block,
//          recv_headers, recv_block — replaced by run_sync_manager / run_ibd
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Reorg rollback helpers
// ---------------------------------------------------------------------------

/// Re-apply old-chain blocks to restore the pre-reorg UTXO state.
///
/// `blocks_newest_first` is in most-recent-first order (as collected during
/// the common-ancestor walk). Blocks are applied oldest-first (reverse iter).
///
/// Returns `Err` on first failure — UTXO state is inconsistent (fail closed).
fn redo_old_chain_blocks(
    utxo_set: &mut UtxoSet,
    blocks_newest_first: &[Block],
) -> Result<(), String> {
    for blk in blocks_newest_first.iter().rev() {
        for tx in &blk.transactions {
            utxo_set
                .apply_transaction(tx, blk.header.height)
                .map_err(|e| {
                    format!(
                        "redo_old_chain apply_transaction failed at height {}: {}",
                        blk.header.height, e
                    )
                })?;
        }
    }
    Ok(())
}

/// Undo successfully-applied new-chain blocks in reverse order.
///
/// `blocks_oldest_first` is in oldest-first order (after the `.reverse()` in the
/// apply loop). `all_spent` maps block_id → spent UTXOs collected before each
/// block was applied.
///
/// Returns `Err` on first failure — UTXO state is inconsistent (fail closed).
fn undo_applied_new_chain(
    utxo_set: &mut UtxoSet,
    blocks_oldest_first: &[Block],
    all_spent: &[(Hash256, Vec<(OutPoint, UtxoEntry)>)],
) -> Result<(), String> {
    for blk in blocks_oldest_first.iter().rev() {
        let blk_id = blk.header.block_id();
        let spent = all_spent
            .iter()
            .find(|(id, _)| *id == blk_id)
            .map(|(_, s)| s.as_slice())
            .ok_or_else(|| {
                format!(
                    "missing spent-UTXO metadata for block {} at height {} — cannot undo",
                    blk_id, blk.header.height
                )
            })?;
        for tx in blk.transactions.iter().rev() {
            let tx_spent: Vec<_> = spent
                .iter()
                .filter(|(op, _)| {
                    tx.inputs
                        .iter()
                        .any(|i| i.prev_tx_id == op.tx_id && i.output_index == op.output_index)
                })
                .cloned()
                .collect();
            utxo_set.undo_transaction(tx, &tx_spent).map_err(|e| {
                format!(
                    "undo_applied_new_chain failed at height {}: {}",
                    blk.header.height, e
                )
            })?;
        }
    }
    Ok(())
}
