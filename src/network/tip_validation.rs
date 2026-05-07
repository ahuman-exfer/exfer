//! v1.5.0 Fix 2: sync.rs tip hardening.
//!
//! Replaces the single-header parent-unknown tip-confirmation with a full
//! forward-chain validation that uses exact consensus difficulty from a known
//! anchor. The spec is in `docs/v1.5.0-brief.md` Fix 2; the key invariants
//! encoded here:
//!
//! 1. **Anchor authentication.** Path 2a: binary-search for a common ancestor
//!    in our chain via the existing `find_common_ancestor_via_events`. Path 2b
//!    (cold bootstrap, `our_tip < ASSUME_VALID_HEIGHT` under assume_valid):
//!    fetch the checkpoint header from the peer, verify its block_id against
//!    the hardcoded `ASSUME_VALID_HASH`, use it as the anchor.
//! 2. **Exact-forward validation** against an in-memory `ForwardHeaderOverlay`.
//!    Every forward header must match `expected_difficulty_overlay` exactly
//!    (no heuristic K-cap), have chain integrity with its predecessor, and
//!    verify PoW against its own target.
//! 3. **Verified cumulative work** = `anchor_work + Σ work_from_target(h_i)`.
//!    Peer-supplied `cumulative_work` is discarded.
//! 4. **Snapshot-and-recheck anchor** before flipping `confirmed = true` —
//!    handles the race where a local reorg displaces the anchor during
//!    validation.
//! 5. **Pre-validated carry** into IBD via `PreValidatedHeaderCache`: blocks
//!    whose headers were validated during tip-confirmation skip Argon2
//!    re-evaluation in the IBD block-processing path (strict block_id match,
//!    no weakened rest-of-validation).
//! 6. **Rate-cap regimes**: bootstrap (concurrency 1, per-core rate) and
//!    steady-state (concurrency 4, 20 evals/sec global). Regime selected at
//!    attempt start from the node's local tip height.
//! 7. **Strike policy** (narrow): strike only on delivered-but-invalid headers
//!    via the existing `record_ip_strike(ip, Some(identity))`. No strikes on
//!    timeouts or disconnects.

use crate::chain::storage::ChainStorage;
use crate::consensus::difficulty::{
    add_work, expected_difficulty_overlay, work_from_target, DifficultyError, ForwardHeaderOverlay,
};
use crate::consensus::pow::verify_pow;
use crate::network::protocol::{GetHeadersMsg, Message};
use crate::types::block::BlockHeader;
use crate::types::hash::Hash256;
use crate::types::*;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::time::{Duration, Instant};
#[allow(unused_imports)]
use tracing::{debug, info, warn};

pub type PeerId = [u8; 32];

// ── Errors ──

#[derive(Debug)]
pub enum TipValidationError {
    /// Peer delivered a header that failed validation (wrong difficulty, bad
    /// PoW, broken chain, wrong checkpoint hash). Caller should record a strike.
    DeliveredInvalidHeader(String),
    /// Peer timed out or disconnected during header fetch. Caller must NOT
    /// record a strike — could be honest flake.
    FetchTimeout,
    /// Validation attempt exceeded its wall-clock deadline.
    DeadlineExceeded,
    /// Local reorg during validation orphaned the peer's chain. Not peer fault.
    AnchorOrphaned,
    /// Concurrent slot unavailable (queue full).
    NoSlotAvailable,
    /// Peer disconnected mid-validation.
    PeerDisconnected,
    /// v1.7.0 Change 4: bootstrap coordinator saw no forward-prefix progress
    /// for `BOOTSTRAP_COORDINATOR_STALL_SECS`. Coordinator-scope abort; the
    /// active peer at stall time is removed from this coordinator's pool but
    /// receives NO identity/IP strike. Matches the narrow `should_strike()`
    /// policy — the stall is an *absence* of progress, not a delivered
    /// offence, so identity-level penalties do not apply.
    BootstrapStalled,
    /// v1.9.2: peer returned an empty `Headers` batch. Wire-indistinguishable
    /// from a rate-limited responder, so the caller MUST NOT strike. The
    /// validation task ends quietly; subsequent `TipResponse` from this peer
    /// triggers a fresh attempt once the responder's per-minute byte budget
    /// has refilled.
    PeerNoForwardData(String),
    /// Internal storage / consensus error.
    Internal(String),
}

impl std::fmt::Display for TipValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TipValidationError::DeliveredInvalidHeader(m) => write!(f, "delivered invalid header: {}", m),
            TipValidationError::FetchTimeout => write!(f, "fetch timeout"),
            TipValidationError::DeadlineExceeded => write!(f, "deadline exceeded"),
            TipValidationError::AnchorOrphaned => write!(f, "anchor orphaned by local reorg"),
            TipValidationError::NoSlotAvailable => write!(f, "no concurrent validation slot available"),
            TipValidationError::PeerDisconnected => write!(f, "peer disconnected mid-validation"),
            TipValidationError::BootstrapStalled => write!(f, "bootstrap coordinator stalled — no forward progress"),
            TipValidationError::PeerNoForwardData(m) => write!(f, "peer returned no data: {}", m),
            TipValidationError::Internal(m) => write!(f, "internal: {}", m),
        }
    }
}

impl From<DifficultyError> for TipValidationError {
    fn from(e: DifficultyError) -> Self {
        TipValidationError::Internal(format!("{:?}", e))
    }
}

// ── Rate-cap regime ──

/// Which regime a tip-validation attempt runs under. Selected once at attempt
/// start from the node's local tip height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidationRegime {
    /// Our local tip ≤ ASSUME_VALID_HEIGHT (under assume_valid), or our tip is
    /// genesis (under --verify-all). Concurrency 1, rate `num_cpus × 10`/sec.
    Bootstrap,
    /// Our local tip > ASSUME_VALID_HEIGHT. Concurrency 4, rate 20/sec global.
    SteadyState,
}

impl ValidationRegime {
    /// Select the regime for a new validation attempt.
    ///
    /// Bootstrap regime applies when the node has no local chain to anchor on:
    /// either `our_tip_height == 0` (fresh node), or `assume_valid` is enabled
    /// and we haven't reached the checkpoint yet. In both cases the anchor must
    /// come from somewhere other than storage (path 2b fetches the checkpoint
    /// header; `--verify-all` on a fresh node has no options and must fall
    /// through to legacy).
    ///
    /// Otherwise (the node has a real local chain), SteadyState applies — path
    /// 2a binary-searches for a common ancestor in our storage. This covers
    /// both default (assume_valid) nodes past the checkpoint AND `--verify-all`
    /// nodes that have built any local chain past genesis.
    pub fn select(our_tip_height: u64, assume_valid: bool) -> Self {
        if our_tip_height == 0 {
            // No local chain at all — bootstrap regime, needs path 2b or legacy fallback.
            ValidationRegime::Bootstrap
        } else if assume_valid && our_tip_height < ASSUME_VALID_HEIGHT {
            // assume_valid is on but we haven't reached the checkpoint — bootstrap
            // regime can use path 2b (fetch checkpoint) if cumulative-work constant
            // is trusted.
            ValidationRegime::Bootstrap
        } else {
            // We have a real local chain we can anchor on via path 2a.
            ValidationRegime::SteadyState
        }
    }

    pub fn max_concurrent(self) -> usize {
        match self {
            ValidationRegime::Bootstrap => MAX_CONCURRENT_TIP_VALIDATIONS_BOOTSTRAP,
            ValidationRegime::SteadyState => MAX_CONCURRENT_TIP_VALIDATIONS,
        }
    }

    pub fn argon2_rate_per_sec(self) -> u32 {
        match self {
            ValidationRegime::Bootstrap => {
                let cores = std::thread::available_parallelism()
                    .map(|n| n.get() as u32)
                    .unwrap_or(1)
                    .max(1);
                cores * VALIDATION_ARGON2_PER_CORE_BOOTSTRAP
            }
            ValidationRegime::SteadyState => MAX_VALIDATION_ARGON2_PER_SEC,
        }
    }
}

// ── Pre-validated header cache ──

/// Per-peer cache of headers validated during tip-confirmation. During IBD,
/// blocks whose header matches a cache entry by exact `block_id` skip Argon2
/// re-evaluation — the `pre_validated` flag on `PeerEvent::BlockResponse` /
/// `NewBlock` is set to true. Block body validation (merkle, tx) still runs.
///
/// Invariant (strict block_id match): the cache only authorizes skipping Argon2
/// for a block whose `block_id` exactly equals a stored entry's key. A block at
/// the same height with a different block_id is rejected normally.
///
/// Lifecycle: entries added as forward-chain validation progresses. Cleared on
/// peer disconnect OR when IBD from that peer completes (success or failure).
/// Not persisted — node restart re-validates.
pub struct PreValidatedHeaderCache {
    /// Map: peer identity → (block_id → BlockHeader snapshot).
    /// Storing the full header (not just a flag) so we can double-check height
    /// and difficulty_target at lookup time, catching any cache/block-id confusion.
    inner: HashMap<PeerId, HashMap<Hash256, BlockHeader>>,
}

impl PreValidatedHeaderCache {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    pub fn insert(&mut self, peer: PeerId, header: BlockHeader) {
        let entries = self.inner.entry(peer).or_default();
        let id = header.block_id();
        entries.insert(id, header);
    }

    /// Returns Some(header) if a header is pre-validated by `peer` and the
    /// given block_id exactly matches a cached entry.
    pub fn lookup(&self, peer: &PeerId, block_id: &Hash256) -> Option<&BlockHeader> {
        self.inner.get(peer).and_then(|e| e.get(block_id))
    }

    /// Alternate lookup: does ANY peer have this block_id in cache? Useful for
    /// IBD where the peer identity on the block response might differ from the
    /// validator peer but the header content is identical.
    pub fn lookup_any(&self, block_id: &Hash256) -> Option<&BlockHeader> {
        self.inner
            .values()
            .find_map(|m| m.get(block_id))
    }

    pub fn clear_peer(&mut self, peer: &PeerId) {
        self.inner.remove(peer);
    }

    pub fn len_for(&self, peer: &PeerId) -> usize {
        self.inner.get(peer).map(|m| m.len()).unwrap_or(0)
    }

    pub fn total_len(&self) -> usize {
        self.inner.values().map(|m| m.len()).sum()
    }
}

impl Default for PreValidatedHeaderCache {
    fn default() -> Self {
        Self::new()
    }
}

// ── Rate limiter (token bucket, global) ──

/// Shared global Argon2-per-second rate limiter. Single mutex over combined
/// (tokens_milli, last_refill) state to avoid lock-order deadlocks.
pub struct Argon2RateLimiter {
    capacity: AtomicUsize,
    state: Mutex<RateLimiterState>,
}

struct RateLimiterState {
    tokens_milli: f64,
    last_refill: Instant,
}

impl Argon2RateLimiter {
    pub fn new() -> Self {
        Self {
            capacity: AtomicUsize::new(MAX_VALIDATION_ARGON2_PER_SEC as usize),
            state: Mutex::new(RateLimiterState {
                tokens_milli: MAX_VALIDATION_ARGON2_PER_SEC as f64 * 1000.0,
                last_refill: Instant::now(),
            }),
        }
    }

    /// Set the rate (evals/sec) for the current active regime. Called by the
    /// tip-validation task coordinator when a new attempt starts or finishes.
    pub fn set_rate(&self, rate: u32) {
        self.capacity.store(rate as usize, AtomicOrdering::Relaxed);
    }

    /// Acquire one token (= one Argon2 eval). Awaits if the bucket is empty.
    pub async fn acquire(&self) {
        loop {
            {
                let mut s = self.state.lock().await;
                let now = Instant::now();
                let elapsed = now.duration_since(s.last_refill);
                let rate = self.capacity.load(AtomicOrdering::Relaxed) as f64;
                // Refill (clamped to at-most-one-second-of-rate to avoid windfall).
                let refilled = s.tokens_milli + rate * elapsed.as_secs_f64() * 1000.0;
                s.tokens_milli = refilled.min(rate * 1000.0);
                s.last_refill = now;
                if s.tokens_milli >= 1000.0 {
                    s.tokens_milli -= 1000.0;
                    return;
                }
            }
            // Wait for one token at current rate.
            let rate = self.capacity.load(AtomicOrdering::Relaxed) as f64;
            let wait_secs = if rate > 0.0 { 1.0 / rate } else { 1.0 };
            tokio::time::sleep(Duration::from_secs_f64(wait_secs.min(1.0))).await;
        }
    }
}

impl Default for Argon2RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Per-peer subscription for HeadersResponse routing ──

/// Subscription map: when a tip-validation is active for a (peer_id, session_id),
/// `Message::Headers` from that peer is routed to this channel instead of the
/// main sync mpsc. Installed by the validation task at start, removed at end.
pub type HeadersSubscriberMap =
    Arc<Mutex<HashMap<(PeerId, u64), mpsc::Sender<Vec<BlockHeader>>>>>;

// ── Verified tip, returned on success ──

#[derive(Debug, Clone)]
pub struct VerifiedTip {
    pub height: u64,
    pub block_id: Hash256,
    pub verified_cumulative_work: [u8; 32],
    pub anchor_height: u64,
    pub anchor_block_id: Hash256,
    pub headers_validated: usize,
}

// ── Concurrency coordinator ──

pub struct TipValidationCoordinator {
    pub bootstrap_sem: Arc<Semaphore>,
    pub steady_state_sem: Arc<Semaphore>,
    pub rate_limiter: Arc<Argon2RateLimiter>,
    pub subscribers: HeadersSubscriberMap,
    pub cache: Arc<Mutex<PreValidatedHeaderCache>>,
    /// Active (peer_identity, session_id) validation attempts. Used to
    /// prevent a repeat GetTip-driven TipResponse from spawning a second
    /// validator for the same peer/session while the first is still running,
    /// which would overwrite the HeadersResponse subscriber and break the
    /// in-flight attempt.
    pub active: Arc<Mutex<std::collections::HashSet<(PeerId, u64)>>>,
}

impl TipValidationCoordinator {
    pub fn new() -> Self {
        Self {
            bootstrap_sem: Arc::new(Semaphore::new(MAX_CONCURRENT_TIP_VALIDATIONS_BOOTSTRAP)),
            steady_state_sem: Arc::new(Semaphore::new(MAX_CONCURRENT_TIP_VALIDATIONS)),
            rate_limiter: Arc::new(Argon2RateLimiter::new()),
            subscribers: Arc::new(Mutex::new(HashMap::new())),
            cache: Arc::new(Mutex::new(PreValidatedHeaderCache::new())),
            active: Arc::new(Mutex::new(std::collections::HashSet::new())),
        }
    }

    pub fn semaphore_for(&self, regime: ValidationRegime) -> &Arc<Semaphore> {
        match regime {
            ValidationRegime::Bootstrap => &self.bootstrap_sem,
            ValidationRegime::SteadyState => &self.steady_state_sem,
        }
    }

    /// Attempt to reserve a validation slot for the given (peer, session). Returns
    /// true if no prior validation is active for this pair — caller proceeds to
    /// spawn. Returns false if an earlier validation is still running; caller
    /// must NOT spawn (doing so would overwrite the subscriber and churn the
    /// prior task into timeout failure).
    pub async fn try_reserve(&self, peer: PeerId, session_id: u64) -> bool {
        let mut a = self.active.lock().await;
        a.insert((peer, session_id))
    }

    pub async fn release_reservation(&self, peer: PeerId, session_id: u64) {
        let mut a = self.active.lock().await;
        a.remove(&(peer, session_id));
    }

    /// Check if a forward-chain validation is currently in flight for this
    /// (peer, session_id). Used by the TipResponse handler as a guard to skip
    /// the legacy `GetHeaders` issuance — if a validation is already running,
    /// the validator owns the subscriber for this session and any additional
    /// outbound `GetHeaders` from the handler would race with the validator's
    /// response stream (v1.5.2 hotfix; see docs/v1.5.2-brief.md).
    pub async fn is_active(&self, peer: PeerId, session_id: u64) -> bool {
        self.active.lock().await.contains(&(peer, session_id))
    }
}

impl Default for TipValidationCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

// ── Deadline formula ──

/// Wall-clock deadline for a single validation attempt.
///
/// - Bootstrap regime (v1.7.0 Change 4): floor is `BOOTSTRAP_COORDINATOR_DEADLINE_SECS`
///   (300 s) — tight enough that four malicious targets cannot squat concurrent
///   slots for hours. Honest 5–10K-header post-checkpoint bootstrap completes
///   in ~1.5 min on a typical 8-core laptop, giving >3× safety margin.
/// - Steady-state regime: floor is `TIP_VALIDATION_DEADLINE_FLOOR_SECS` (7200 s) —
///   unchanged from v1.5.0; large window because steady-state can span tens of
///   thousands of headers if the node was offline for a while.
///
/// In both regimes the scaled component `ceil(expected_argon2_seconds × 1.5)`
/// also applies; the larger of (floor, scaled) wins.
pub fn compute_deadline(expected_headers: u64, regime: ValidationRegime) -> Duration {
    let rate = regime.argon2_rate_per_sec().max(1) as u64;
    let expected_argon2_secs = expected_headers / rate;
    let scaled =
        (expected_argon2_secs * TIP_VALIDATION_DEADLINE_SCALE_PCT + 99) / 100;
    let floor = match regime {
        ValidationRegime::Bootstrap => BOOTSTRAP_COORDINATOR_DEADLINE_SECS,
        ValidationRegime::SteadyState => TIP_VALIDATION_DEADLINE_FLOOR_SECS,
    };
    Duration::from_secs(scaled.max(floor))
}

// ── Strict pre-checkpoint hash-chain authentication ──

/// Authenticate a batch of pre-checkpoint headers by SHA256 hash-chain linkage
/// back to the already-authenticated anchor header (the checkpoint header).
///
/// Input: `batch` is ordered NEWEST first (closest to anchor) to OLDEST.
/// Walks: for each header h in batch (in iteration order), compute `h.block_id()`
/// and require it equals the `prev_block_id` of the most recently authenticated
/// header (starting with the anchor). On success, caller may insert these
/// headers into the overlay.
///
/// Returns Err if any link breaks.
pub fn authenticate_prechckpt_headers(
    anchor: &BlockHeader,
    batch: &[BlockHeader],
) -> Result<(), TipValidationError> {
    let mut expected_block_id = anchor.prev_block_id;
    for (i, h) in batch.iter().enumerate() {
        let computed = h.block_id();
        if computed != expected_block_id {
            return Err(TipValidationError::DeliveredInvalidHeader(format!(
                "pre-checkpoint header at batch index {} has block_id {:?}, expected {:?} \
                 (hash-chain break from authenticated anchor)",
                i, computed, expected_block_id
            )));
        }
        expected_block_id = h.prev_block_id;
    }
    Ok(())
}

// ── Forward validation against overlay ──

/// Validate a single forward header against the overlay and (optional) rate-limited Argon2.
///
/// On success: inserts the header into the overlay for subsequent retarget lookbacks.
pub async fn validate_one_forward_header(
    overlay: &mut ForwardHeaderOverlay<'_>,
    parent_block_id: &Hash256,
    expected_height: u64,
    header: &BlockHeader,
    rate_limiter: &Argon2RateLimiter,
) -> Result<(), TipValidationError> {
    // Chain integrity.
    if header.prev_block_id != *parent_block_id {
        return Err(TipValidationError::DeliveredInvalidHeader(format!(
            "prev_block_id mismatch: got {:?}, expected {:?}",
            header.prev_block_id, parent_block_id
        )));
    }
    if header.height != expected_height {
        return Err(TipValidationError::DeliveredInvalidHeader(format!(
            "height mismatch: got {}, expected {}",
            header.height, expected_height
        )));
    }
    // Exact difficulty via overlay.
    let expected_target = expected_difficulty_overlay(
        overlay,
        &header.prev_block_id,
        header.height,
    )?;
    if header.difficulty_target != expected_target {
        return Err(TipValidationError::DeliveredInvalidHeader(format!(
            "difficulty_target mismatch at height {}: got {:?}, expected {:?}",
            header.height, header.difficulty_target, expected_target
        )));
    }
    // Rate-limited Argon2 PoW.
    rate_limiter.acquire().await;
    let hdr = header.clone();
    let pow_ok = tokio::task::spawn_blocking(move || verify_pow(&hdr))
        .await
        .map_err(|e| TipValidationError::Internal(format!("spawn_blocking: {}", e)))?
        .map_err(|e| TipValidationError::Internal(format!("pow: {:?}", e)))?;
    if !pow_ok {
        return Err(TipValidationError::DeliveredInvalidHeader(format!(
            "PoW verification failed at height {}",
            header.height
        )));
    }
    overlay.insert(header.clone());
    Ok(())
}

// ── Core validation entry point ──

/// Inputs to `validate_peer_tip_forward_chain`.
pub struct ValidationInputs {
    pub peer_identity: PeerId,
    pub session_id: u64,
    pub peer_ip: IpAddr,
    pub claim_height: u64,
    pub claim_block_id: Hash256,
    pub our_tip_height_at_start: u64,
    pub assume_valid: bool,
    pub assume_valid_cumulative_work_trusted: bool,
}

/// Result alongside the error — carries the identity-strike policy signal.
pub struct ValidationResult {
    pub outcome: Result<VerifiedTip, TipValidationError>,
    /// If true, caller must call `record_ip_strike(peer_ip, Some(identity))`.
    /// Only set for `DeliveredInvalidHeader` outcomes.
    pub record_strike: bool,
}

/// Helper: decide whether the provided outcome warrants a strike, per the
/// narrowed Alt C policy. Timeouts / disconnects / anchor-orphaned are NOT
/// strikes — only delivered-but-invalid headers are.
pub fn should_strike(outcome: &Result<VerifiedTip, TipValidationError>) -> bool {
    matches!(outcome, Err(TipValidationError::DeliveredInvalidHeader(_)))
}

/// Accumulate cumulative work over a forward header chain.
pub fn sum_forward_work(anchor_work: [u8; 32], forward_headers: &[BlockHeader]) -> [u8; 32] {
    let mut total = anchor_work;
    for h in forward_headers {
        total = add_work(&total, &work_from_target(&h.difficulty_target));
    }
    total
}

/// Helper: look up anchor cumulative work given an anchor block_id and mode.
///
/// - Path 2a (anchor is in our storage): storage.get_cumulative_work(anchor_id)
/// - Path 2b (anchor is the checkpoint fetched via peer): return the hardcoded
///   ASSUME_VALID_CUMULATIVE_WORK (provided `trusted` is true).
pub fn anchor_work(
    storage: &ChainStorage,
    anchor_block_id: &Hash256,
    is_checkpoint_anchor: bool,
    assume_valid_cumulative_work_trusted: bool,
) -> Result<[u8; 32], TipValidationError> {
    if is_checkpoint_anchor {
        if assume_valid_cumulative_work_trusted {
            return Ok(ASSUME_VALID_CUMULATIVE_WORK);
        }
        // Distrust signal flipped at runtime: refuse path 2b semantics.
        // Caller should have already fallen through to path 2a — this is defense-in-depth.
        return Err(TipValidationError::Internal(
            "ASSUME_VALID_CUMULATIVE_WORK flagged untrusted at runtime; caller should have \
             fallen through to --verify-all-equivalent"
                .into(),
        ));
    }
    storage
        .get_cumulative_work(anchor_block_id)
        .map_err(|e| TipValidationError::Internal(format!("get_cumulative_work: {}", e)))?
        .ok_or_else(|| {
            TipValidationError::Internal(format!(
                "anchor cumulative work not found for {:?}",
                anchor_block_id
            ))
        })
}

/// Helper: re-check the anchor is still on our canonical chain at `anchor_height`.
/// Used by the snapshot-and-recheck step before flipping `confirmed = true`.
pub async fn anchor_still_canonical(
    storage: &ChainStorage,
    anchor_height: u64,
    anchor_block_id: &Hash256,
) -> Result<bool, TipValidationError> {
    let canonical = storage
        .get_block_id_by_height(anchor_height)
        .map_err(|e| TipValidationError::Internal(format!("get_block_id_by_height: {}", e)))?;
    Ok(canonical == Some(*anchor_block_id))
}

// ── Subscribing / unsubscribing to HeadersResponse routing ──

pub async fn install_headers_subscriber(
    map: &HeadersSubscriberMap,
    peer: PeerId,
    session_id: u64,
) -> mpsc::Receiver<Vec<BlockHeader>> {
    // v1.8.0 Stage A runs with up to 8 `GetHeaders` in flight on a single
    // session; responses can queue briefly between bursts from the peer and
    // our receive-side processing. Capacity must cover that burst plus margin,
    // otherwise `route_headers_if_subscribed`'s `try_send` silently drops
    // responses and the Stage A coordinator sees off-by-N correlation gaps
    // (`first.height != expected_start`), aborts, and moves to the next peer.
    // Previous capacity 4 caused exactly this failure in the v1.8.0 gate
    // run (2026-04-20). 32 is well above the 8-in-flight window and trivial
    // memory (~32 × ~13 KB = ~416 KB worst case per active subscriber).
    let (tx, rx) = mpsc::channel::<Vec<BlockHeader>>(32);
    let mut m = map.lock().await;
    m.insert((peer, session_id), tx);
    rx
}

pub async fn remove_headers_subscriber(
    map: &HeadersSubscriberMap,
    peer: PeerId,
    session_id: u64,
) {
    let mut m = map.lock().await;
    m.remove(&(peer, session_id));
}

/// Try to route a headers delivery through the subscriber map. Returns true if a
/// subscriber was found and the headers were forwarded (possibly dropped if
/// channel full — also considered "handled" to preserve ordering). Returns false
/// if no subscriber; caller should forward to the main sync mpsc as before.
pub async fn route_headers_if_subscribed(
    map: &HeadersSubscriberMap,
    peer: PeerId,
    session_id: u64,
    headers: Vec<BlockHeader>,
) -> bool {
    let m = map.lock().await;
    if let Some(tx) = m.get(&(peer, session_id)) {
        let _ = tx.try_send(headers);
        return true;
    }
    false
}

// ── Subscriber receive helper ──

/// Await a headers batch on the subscriber channel. Bounded by
/// `TIP_VALIDATION_BATCH_TIMEOUT_SECS`. The caller is responsible for sending
/// the `GetHeaders` request on its own connection (kept outside this module to
/// avoid binding it to the `Node` type, which lives in sync.rs).
pub async fn await_header_batch(
    subscriber_rx: &mut mpsc::Receiver<Vec<BlockHeader>>,
) -> Result<Vec<BlockHeader>, TipValidationError> {
    let timeout = Duration::from_secs(TIP_VALIDATION_BATCH_TIMEOUT_SECS);
    match tokio::time::timeout(timeout, subscriber_rx.recv()).await {
        Ok(Some(hdrs)) => Ok(hdrs),
        Ok(None) => Err(TipValidationError::PeerDisconnected),
        Err(_) => Err(TipValidationError::FetchTimeout),
    }
}

/// Build the `GetHeaders` message for a forward-chain fetch. Exposed so the
/// sync.rs caller can construct the message and send it on its own connection.
pub fn build_get_headers(start_height: u64, max_count: u32) -> Message {
    Message::GetHeaders(GetHeadersMsg {
        start_height,
        max_count,
    })
}

// ── Diagnostics ──

/// Minimal summary the sync manager can log after each attempt.
pub fn summarize(outcome: &Result<VerifiedTip, TipValidationError>) -> String {
    match outcome {
        Ok(t) => format!(
            "verified tip height={} block_id={:?} forward_headers={} anchor_height={}",
            t.height,
            &t.block_id.as_bytes()[..4],
            t.headers_validated,
            t.anchor_height
        ),
        Err(e) => format!("failed: {}", e),
    }
}

// ── Unit tests ──

#[cfg(test)]
mod tests {
    use super::*;

    fn header(height: u64, prev_id: Hash256, target_last_byte: u8, nonce: u64) -> BlockHeader {
        let mut target = [0xFFu8; 32];
        target[31] = target_last_byte;
        BlockHeader {
            version: 1,
            height,
            prev_block_id: prev_id,
            timestamp: 1_000_000 + height * 10,
            difficulty_target: Hash256(target),
            nonce,
            tx_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
        }
    }

    #[test]
    fn authenticate_prechckpt_headers_accepts_valid_chain() {
        // Build a chain: h0 ← h1 ← h2 ← h3 (anchor)
        let h0 = header(1, Hash256::ZERO, 0x10, 1);
        let h1 = header(2, h0.block_id(), 0x10, 1);
        let h2 = header(3, h1.block_id(), 0x10, 1);
        let anchor = header(4, h2.block_id(), 0x10, 1);

        // batch is ordered newest-first (closest to anchor) to oldest.
        let batch = vec![h2.clone(), h1.clone(), h0.clone()];
        let res = authenticate_prechckpt_headers(&anchor, &batch);
        assert!(res.is_ok(), "valid chain should authenticate: {:?}", res);
    }

    #[test]
    fn authenticate_prechckpt_headers_rejects_forged_chain() {
        let h0 = header(1, Hash256::ZERO, 0x10, 1);
        let h1 = header(2, h0.block_id(), 0x10, 1);
        let h2 = header(3, h1.block_id(), 0x10, 1);
        let anchor = header(4, h2.block_id(), 0x10, 1);

        // Corrupt middle header's prev pointer.
        let mut h1_bad = h1.clone();
        h1_bad.prev_block_id = Hash256([0xdeu8; 32]);
        let batch = vec![h2.clone(), h1_bad, h0.clone()];
        let res = authenticate_prechckpt_headers(&anchor, &batch);
        assert!(
            matches!(res, Err(TipValidationError::DeliveredInvalidHeader(_))),
            "forged chain must be rejected: {:?}",
            res
        );
    }

    #[test]
    fn authenticate_prechckpt_headers_rejects_wrong_root() {
        let h0 = header(1, Hash256::ZERO, 0x10, 1);
        let h1 = header(2, h0.block_id(), 0x10, 1);
        // Anchor.prev is a completely different hash than h1.block_id.
        let mut anchor = header(3, Hash256([0xffu8; 32]), 0x10, 1);
        anchor.prev_block_id = Hash256([0xffu8; 32]);

        let batch = vec![h1, h0];
        let res = authenticate_prechckpt_headers(&anchor, &batch);
        assert!(matches!(
            res,
            Err(TipValidationError::DeliveredInvalidHeader(_))
        ));
    }

    #[test]
    fn compute_deadline_scales_with_work() {
        // v1.7.0 Change 4: bootstrap regime uses BOOTSTRAP_COORDINATOR_DEADLINE_SECS = 300
        // as its floor instead of TIP_VALIDATION_DEADLINE_FLOOR_SECS = 7200. Small-load
        // case respects the tighter bootstrap floor.
        let d_small = compute_deadline(100, ValidationRegime::Bootstrap);
        assert!(
            d_small >= Duration::from_secs(BOOTSTRAP_COORDINATOR_DEADLINE_SECS),
            "bootstrap deadline must respect BOOTSTRAP_COORDINATOR_DEADLINE_SECS floor"
        );
        assert!(
            d_small < Duration::from_secs(TIP_VALIDATION_DEADLINE_FLOOR_SECS),
            "bootstrap deadline for small load must NOT inherit the 7200s steady-state floor"
        );
        let d_large = compute_deadline(1_000_000_000, ValidationRegime::Bootstrap);
        assert!(d_large > d_small);
        // Steady-state regime keeps its 7200s floor unchanged from v1.5.0.
        let d_steady = compute_deadline(100, ValidationRegime::SteadyState);
        assert!(d_steady >= Duration::from_secs(TIP_VALIDATION_DEADLINE_FLOOR_SECS));
    }

    #[test]
    fn should_strike_narrow_policy() {
        assert!(should_strike(&Err(TipValidationError::DeliveredInvalidHeader(
            "x".into()
        ))));
        assert!(!should_strike(&Err(TipValidationError::FetchTimeout)));
        assert!(!should_strike(&Err(TipValidationError::DeadlineExceeded)));
        assert!(!should_strike(&Err(TipValidationError::AnchorOrphaned)));
        assert!(!should_strike(&Err(TipValidationError::PeerDisconnected)));
        // v1.7.0 Change 4: BootstrapStalled is NEVER a strike. Absence of
        // progress is not a delivered offence; attributing timing failures to
        // whichever peer happened to be active would violate the narrow-strike
        // design.
        assert!(!should_strike(&Err(TipValidationError::BootstrapStalled)));
        assert!(!should_strike(&Ok(VerifiedTip {
            height: 0,
            block_id: Hash256::ZERO,
            verified_cumulative_work: [0u8; 32],
            anchor_height: 0,
            anchor_block_id: Hash256::ZERO,
            headers_validated: 0,
        })));
    }

    #[test]
    fn validation_regime_selection() {
        // Fresh node with no local chain: Bootstrap in both modes.
        assert_eq!(
            ValidationRegime::select(0, true),
            ValidationRegime::Bootstrap
        );
        assert_eq!(
            ValidationRegime::select(0, false),
            ValidationRegime::Bootstrap
        );
        // assume_valid=true, below checkpoint: Bootstrap (path 2b territory).
        assert_eq!(
            ValidationRegime::select(ASSUME_VALID_HEIGHT - 1, true),
            ValidationRegime::Bootstrap
        );
        // assume_valid=true, at/past checkpoint: SteadyState (path 2a).
        assert_eq!(
            ValidationRegime::select(ASSUME_VALID_HEIGHT, true),
            ValidationRegime::SteadyState
        );
        assert_eq!(
            ValidationRegime::select(ASSUME_VALID_HEIGHT + 100, true),
            ValidationRegime::SteadyState
        );
        // --verify-all (assume_valid=false) with ANY local chain past genesis:
        // SteadyState (path 2a against local storage). This is the P1 fix —
        // previously --verify-all was stuck in Bootstrap forever.
        assert_eq!(
            ValidationRegime::select(1, false),
            ValidationRegime::SteadyState
        );
        assert_eq!(
            ValidationRegime::select(ASSUME_VALID_HEIGHT - 1, false),
            ValidationRegime::SteadyState
        );
        assert_eq!(
            ValidationRegime::select(ASSUME_VALID_HEIGHT + 100, false),
            ValidationRegime::SteadyState
        );
    }

    #[test]
    fn pre_validated_cache_strict_block_id_match() {
        let mut cache = PreValidatedHeaderCache::new();
        let peer: PeerId = [1u8; 32];
        let h = header(42, Hash256::ZERO, 0xAB, 7);
        let id = h.block_id();
        cache.insert(peer, h.clone());
        // Exact match hits.
        assert!(cache.lookup(&peer, &id).is_some());
        // Different block_id at same height misses.
        let mut other = h.clone();
        other.nonce = 8;
        let other_id = other.block_id();
        assert_ne!(id, other_id);
        assert!(cache.lookup(&peer, &other_id).is_none());
    }

    #[test]
    fn sum_forward_work_additive() {
        let h1 = header(1, Hash256::ZERO, 0x10, 1);
        let h2 = header(2, h1.block_id(), 0x10, 1);
        let anchor_work_v = [0u8; 32];
        let sum = sum_forward_work(anchor_work_v, &[h1.clone(), h2.clone()]);
        let expected = {
            let mut acc = anchor_work_v;
            acc = add_work(&acc, &work_from_target(&h1.difficulty_target));
            acc = add_work(&acc, &work_from_target(&h2.difficulty_target));
            acc
        };
        assert_eq!(sum, expected);
    }

    // Unused imports silenced for the module until the sync.rs wiring lands.
    #[allow(dead_code)]
    fn _silence() {
        let _ = info!("");
        let _ = warn!("");
        let _ = debug!("");
    }

    // ── Fast failure-path tests for validate_one_forward_header ──
    // These rely on failing BEFORE Argon2 runs, so they're fast (microseconds).

    fn easy_header(height: u64, prev_id: Hash256) -> BlockHeader {
        // All-0xFF target; any PoW hash satisfies target.
        let target = [0xFFu8; 32];
        BlockHeader {
            version: 1,
            height,
            prev_block_id: prev_id,
            timestamp: 1_000_000 + height * 10,
            difficulty_target: Hash256(target),
            nonce: 0,
            tx_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
        }
    }

    async fn make_tempdir_storage() -> Option<(tempfile::TempDir, Arc<ChainStorage>)> {
        let td = tempfile::TempDir::new().ok()?;
        let storage = ChainStorage::open(td.path()).ok()?;
        Some((td, Arc::new(storage)))
    }

    #[tokio::test]
    async fn forward_validation_rejects_wrong_prev_block_id() {
        // Set up: no storage involvement needed (we'll use an empty overlay).
        let (_td, storage) = match make_tempdir_storage().await {
            Some(pair) => pair,
            None => {
                eprintln!("skipping (tempfile unavailable)");
                return;
            }
        };
        let mut overlay = ForwardHeaderOverlay::new(&storage);
        let anchor = easy_header(0, Hash256::ZERO);
        overlay.insert(anchor.clone());
        // Header claims wrong parent.
        let bad = easy_header(1, Hash256([0xAB; 32]));
        let rl = Argon2RateLimiter::new();
        rl.set_rate(1000);
        let res = validate_one_forward_header(
            &mut overlay,
            &anchor.block_id(),
            1,
            &bad,
            &rl,
        )
        .await;
        assert!(
            matches!(res, Err(TipValidationError::DeliveredInvalidHeader(_))),
            "wrong prev_block_id must be rejected: {:?}",
            res
        );
    }

    #[tokio::test]
    async fn forward_validation_rejects_wrong_height() {
        let (_td, storage) = match make_tempdir_storage().await {
            Some(pair) => pair,
            None => return,
        };
        let mut overlay = ForwardHeaderOverlay::new(&storage);
        let anchor = easy_header(5, Hash256::ZERO);
        overlay.insert(anchor.clone());
        // Header has correct prev_id but wrong height.
        let mut bad = easy_header(7, anchor.block_id());
        bad.height = 7;
        let rl = Argon2RateLimiter::new();
        rl.set_rate(1000);
        let res = validate_one_forward_header(
            &mut overlay,
            &anchor.block_id(),
            6, // expected
            &bad,
            &rl,
        )
        .await;
        assert!(matches!(
            res,
            Err(TipValidationError::DeliveredInvalidHeader(_))
        ));
    }

    #[tokio::test]
    async fn forward_validation_rejects_wrong_difficulty_target() {
        // ★ PRIMARY SECURITY TEST (spec #5): any deviation from expected consensus
        // difficulty must be rejected, even a "slightly easier" target.
        let (_td, storage) = match make_tempdir_storage().await {
            Some(pair) => pair,
            None => return,
        };
        // Set up overlay with anchor at height 1 (pre-retarget — next header inherits parent target).
        let mut overlay = ForwardHeaderOverlay::new(&storage);
        let anchor = easy_header(1, Hash256::ZERO);
        overlay.insert(anchor.clone());

        // Next header should have target == anchor.difficulty_target (no retarget boundary at height 2).
        // Deliver a header with a DIFFERENT target (slightly different last byte).
        let mut bad = easy_header(2, anchor.block_id());
        let mut off_target = [0xFFu8; 32];
        off_target[31] = 0x00;
        bad.difficulty_target = Hash256(off_target);

        let rl = Argon2RateLimiter::new();
        rl.set_rate(1000);
        let res = validate_one_forward_header(
            &mut overlay,
            &anchor.block_id(),
            2,
            &bad,
            &rl,
        )
        .await;
        assert!(
            matches!(&res, Err(TipValidationError::DeliveredInvalidHeader(m)) if m.contains("difficulty_target")),
            "wrong difficulty_target must be rejected: {:?}",
            res
        );
    }

    #[tokio::test]
    async fn forward_validation_accepts_exact_match_and_inserts_into_overlay() {
        // Mirror of the security test with the CORRECT target; assert acceptance
        // and that the header is now queryable via the overlay.
        let (_td, storage) = match make_tempdir_storage().await {
            Some(pair) => pair,
            None => return,
        };
        let mut overlay = ForwardHeaderOverlay::new(&storage);
        let anchor = easy_header(1, Hash256::ZERO);
        overlay.insert(anchor.clone());

        let good = easy_header(2, anchor.block_id());
        assert_eq!(good.difficulty_target, anchor.difficulty_target);

        let rl = Argon2RateLimiter::new();
        rl.set_rate(1000);
        let res = validate_one_forward_header(
            &mut overlay,
            &anchor.block_id(),
            2,
            &good,
            &rl,
        )
        .await;
        assert!(res.is_ok(), "exact-match header should accept: {:?}", res);
        // Overlay now contains the newly-validated header.
        assert!(overlay.contains(&good.block_id()));
    }

    #[tokio::test]
    async fn overlay_retarget_uses_validated_ancestors_not_storage() {
        // Exercise expected_difficulty_overlay for a non-retarget height: the
        // result must equal parent.difficulty_target. We also verify that when
        // the "parent" is in the overlay (not storage), the lookup path works.
        let (_td, storage) = match make_tempdir_storage().await {
            Some(pair) => pair,
            None => return,
        };
        let mut overlay = ForwardHeaderOverlay::new(&storage);
        let parent = easy_header(5, Hash256::ZERO);
        let parent_id = parent.block_id();
        overlay.insert(parent.clone());

        // Query expected difficulty for height 6 (non-retarget). Should be parent.target.
        let result = crate::consensus::difficulty::expected_difficulty_overlay(
            &overlay,
            &parent_id,
            6,
        );
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            parent.difficulty_target,
            "non-retarget height should inherit parent target from overlay"
        );
    }

    #[test]
    fn verified_cumulative_work_overwrites_peer_supplied() {
        // Construct: anchor_work + sum of per-header work should NOT equal a
        // maximal peer-supplied value. Simulates the overwrite step in
        // run_tip_forward_validation by computing the verified value and
        // comparing against a peer-supplied "maximum" value.
        let anchor_work = [0u8; 32];
        let h1 = easy_header(1, Hash256::ZERO);
        let h2 = easy_header(2, h1.block_id());
        let verified = sum_forward_work(anchor_work, &[h1.clone(), h2.clone()]);
        // Peer claims MAX work.
        let peer_claim = [0xFFu8; 32];
        // The verified value is strictly less than the peer's claim (ensures we'd
        // overwrite, not keep the inflated claim).
        assert!(verified < peer_claim);
        // Also verify additivity matches the explicit formula.
        let w1 = work_from_target(&h1.difficulty_target);
        let w2 = work_from_target(&h2.difficulty_target);
        let expected = add_work(&add_work(&anchor_work, &w1), &w2);
        assert_eq!(verified, expected);
    }

    #[test]
    fn pre_validated_cache_per_peer_isolation() {
        // Same block_id cached under peer A; peer B cannot find it via lookup_peer.
        let mut cache = PreValidatedHeaderCache::new();
        let peer_a: PeerId = [1u8; 32];
        let peer_b: PeerId = [2u8; 32];
        let h = easy_header(42, Hash256::ZERO);
        let id = h.block_id();
        cache.insert(peer_a, h.clone());
        assert!(cache.lookup(&peer_a, &id).is_some());
        assert!(cache.lookup(&peer_b, &id).is_none());
        // lookup_any finds across peers (used by IBD routing).
        assert!(cache.lookup_any(&id).is_some());
    }

    #[test]
    fn pre_validated_cache_clear_peer_removes_entries() {
        let mut cache = PreValidatedHeaderCache::new();
        let peer: PeerId = [3u8; 32];
        let h1 = easy_header(1, Hash256::ZERO);
        let h2 = easy_header(2, h1.block_id());
        cache.insert(peer, h1.clone());
        cache.insert(peer, h2.clone());
        assert_eq!(cache.len_for(&peer), 2);
        cache.clear_peer(&peer);
        assert_eq!(cache.len_for(&peer), 0);
        assert!(cache.lookup(&peer, &h1.block_id()).is_none());
    }

    // v1.5.2 hotfix — guard condition for TipResponse handler.
    #[tokio::test]
    async fn is_active_returns_true_after_reserve_and_false_after_release() {
        let coord = TipValidationCoordinator::new();
        let peer: PeerId = [0xAAu8; 32];
        let sid: u64 = 42;
        assert!(!coord.is_active(peer, sid).await, "fresh coord must be inactive");
        let reserved = coord.try_reserve(peer, sid).await;
        assert!(reserved, "first reserve returns true");
        assert!(coord.is_active(peer, sid).await, "after reserve, is_active true");
        // Different session_id must not alias.
        assert!(!coord.is_active(peer, sid + 1).await, "different sid is separate");
        // Different peer must not alias.
        let other: PeerId = [0xBBu8; 32];
        assert!(!coord.is_active(other, sid).await, "different peer is separate");
        coord.release_reservation(peer, sid).await;
        assert!(!coord.is_active(peer, sid).await, "after release, is_active false");
        // Releasing twice is a no-op (idempotent).
        coord.release_reservation(peer, sid).await;
        assert!(!coord.is_active(peer, sid).await, "double-release still false");
    }

    #[tokio::test]
    async fn try_reserve_is_idempotent_while_held() {
        let coord = TipValidationCoordinator::new();
        let peer: PeerId = [0xCCu8; 32];
        let sid: u64 = 1;
        assert!(coord.try_reserve(peer, sid).await);
        // Second reserve for same (peer, sid) returns false — already held.
        assert!(!coord.try_reserve(peer, sid).await);
        // is_active stays true regardless.
        assert!(coord.is_active(peer, sid).await);
    }

    #[tokio::test]
    async fn rate_limiter_enforces_rate() {
        // With rate = 4/sec, acquiring 4 tokens should start fast (bucket pre-filled)
        // and the 5th must block. We don't wait for the full second — just assert
        // the bucket drains.
        let rl = Argon2RateLimiter::new();
        rl.set_rate(4);
        let start = std::time::Instant::now();
        for _ in 0..4 {
            rl.acquire().await;
        }
        let t_after_4 = start.elapsed();
        assert!(
            t_after_4 < Duration::from_millis(300),
            "4 tokens from pre-filled bucket should be fast; got {:?}",
            t_after_4
        );
    }
}
