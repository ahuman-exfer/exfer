//! Per-peer + global in-flight pre-verification frame-buffer budget (v1.4.2 Fix 3).
//!
//! ## Why
//! The peer transport reads an entire frame payload into memory before
//! verifying the HMAC (streaming HMAC would be a much larger change). With
//! `MAX_INBOUND_PEERS = 256` and payloads up to `MAX_BLOCK_SIZE = 4 MiB`,
//! distinct peers could force ~1 GiB of in-flight unverified buffer. Small
//! miners running on low-RAM VPS instances OOM'd.
//!
//! ## Honest accounting (updated after first expert re-review)
//! For each frame the reader holds **two** transient pre-verification
//! buffers concurrently at the peak:
//!
//!   1. The `payload: Vec<u8>` of `payload_len` bytes (read from the
//!      socket).
//!   2. The reconstructed `full: Vec<u8>` of `FRAME_HEADER_SIZE +
//!      payload_len` bytes (needed as a single contiguous slice to pass
//!      into [`verify_frame_hmac`]).
//!
//! Both are resident at the moment HMAC verification runs. So the actual
//! peak per frame is `payload_len + (FRAME_HEADER_SIZE + payload_len)`
//! = `2 · payload_len + FRAME_HEADER_SIZE`. The reservation
//! computed in [`crate::network::peer::peak_prever_bytes`] uses exactly
//! this formula — it is the single source of truth, and the
//! instrumented drift-catching test
//! (`reservation_always_geq_actual_peak` in `peer.rs`) fails if a
//! future change to the reader introduces additional allocations
//! without updating the formula.
//!
//! ## What
//! Two layers of bookkeeping:
//! - **Global budget** ([`FrameBudget`]): a single shared counter of
//!   pre-verification bytes currently resident across all peers. Capped at
//!   [`GLOBAL_FRAME_BUDGET_BYTES`] (128 MiB) — same memory ceiling
//!   operators have been running, now honestly accounted.
//! - **Per-peer budget** ([`PeerBudget`]): one per peer, counting that
//!   peer's current in-flight bytes. Capped at
//!   [`PER_PEER_FRAME_BUDGET_BYTES`] (16 MiB). Prior to honest accounting
//!   this cap was encoded as 8 MiB but actually allowed a transient
//!   ~16 MiB peak — the literal cap was dishonestly half the real peak.
//!   The constant is now 16 MiB to match the pre-existing design intent
//!   of "2× MAX_BLOCK_SIZE" (one block-sized frame plus room for the
//!   reader to begin the next), now correctly accounted.
//!
//! Before allocating a payload buffer, the reader calls
//! [`PeerBudget::try_reserve`] with `peak_prever_bytes(payload_len)`. If
//! either the per-peer or the global cap would be exceeded, the
//! reservation fails with a [`BudgetError`] and the reader sheds its
//! connection. On success a [`FrameReservation`] RAII guard is returned;
//! its `Drop` releases bytes back to both counters regardless of whether
//! the frame later passed or failed HMAC verification.
//!
//! ## Shedding policy
//! When a reservation fails, the reader returns an error from its read
//! loop; the surrounding task closes the connection, releases every
//! outstanding [`FrameReservation`] this peer holds (via Drop), and logs
//! the shed event with the peer address and reason. Choosing a "biggest
//! holder across peers" eviction policy (instead of shedding only the
//! peer that triggered the overage) is a deliberately-deferred refinement
//! — doing it safely requires cross-peer shutdown coordination and
//! carries a real risk of deadlock under legitimate bursty load, which
//! would itself be a regression for the v1.4.2 security patch. The
//! current design is deadlock-free by construction: every failing
//! `try_reserve` returns immediately, never blocks, and never waits on
//! another peer.
//!
//! ## Deadlock-freedom
//! All operations are non-blocking atomic CAS. No lock is held across a
//! reservation attempt. `try_reserve` never retries — the caller decides.
//! `FrameReservation::drop` is `fetch_sub` only. There is no path in this
//! module that waits on I/O or on other peers.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Bounds node-global actual peak in-flight pre-verification memory across
/// all peers. Under honest accounting
/// (`2 · payload_len + FRAME_HEADER_SIZE` per frame — see module doc) this
/// admits approximately **15 concurrent block-sized frames** across all
/// peers, which is well above legitimate peak IBD throughput (a node
/// normally runs IBD against a single peer).
pub const GLOBAL_FRAME_BUDGET_BYTES: usize = 128 * 1024 * 1024; // 128 MiB

/// Bounds per-peer actual peak in-flight pre-verification memory. Sized at
/// `2× MAX_BLOCK_SIZE` = 16 MiB to allow one block-sized frame to be
/// resident for HMAC verification with room to begin reading the next
/// small frame — accounting honestly for both the payload buffer and the
/// full-frame HMAC-verification buffer held simultaneously at the peak.
///
/// (Prior to v1.4.2's first expert re-review this constant was literal
/// 8 MiB, under accounting that counted only the payload buffer. Actual
/// peak memory was already ~16 MiB. The cap value now matches the real
/// peak — no operator-visible change, just honest bookkeeping.)
pub const PER_PEER_FRAME_BUDGET_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

/// Global in-flight frame-buffer accounting. Single instance per node,
/// shared via [`Arc`] with every peer task.
pub struct FrameBudget {
    global_used: AtomicUsize,
    global_cap: usize,
}

impl FrameBudget {
    /// Create a new [`FrameBudget`] with the production default cap.
    pub fn new() -> Arc<Self> {
        Self::with_cap(GLOBAL_FRAME_BUDGET_BYTES)
    }

    /// Create a [`FrameBudget`] with an explicit cap. For tests.
    pub fn with_cap(cap: usize) -> Arc<Self> {
        Arc::new(Self {
            global_used: AtomicUsize::new(0),
            global_cap: cap,
        })
    }

    /// Total in-flight bytes across all peers. For metrics / tests.
    pub fn global_used(&self) -> usize {
        self.global_used.load(Ordering::Acquire)
    }

    /// Configured global cap.
    #[allow(dead_code)]
    pub fn global_cap(&self) -> usize {
        self.global_cap
    }
}

impl std::fmt::Debug for FrameBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrameBudget")
            .field("used", &self.global_used())
            .field("cap", &self.global_cap)
            .finish()
    }
}

/// Per-peer in-flight frame-buffer accounting. One instance per connected
/// peer; shared with the peer's reader task via [`Arc`].
pub struct PeerBudget {
    global: Arc<FrameBudget>,
    peer_used: AtomicUsize,
    peer_cap: usize,
}

impl PeerBudget {
    /// Attach a new per-peer counter to the given global budget, with the
    /// production default per-peer cap.
    pub fn new(global: Arc<FrameBudget>) -> Arc<Self> {
        Self::with_peer_cap(global, PER_PEER_FRAME_BUDGET_BYTES)
    }

    /// Attach with an explicit per-peer cap. For tests.
    pub fn with_peer_cap(global: Arc<FrameBudget>, peer_cap: usize) -> Arc<Self> {
        Arc::new(Self {
            global,
            peer_used: AtomicUsize::new(0),
            peer_cap,
        })
    }

    /// Attempt to reserve `bytes` of in-flight budget. Returns a
    /// [`FrameReservation`] that releases the bytes when dropped, or a
    /// [`BudgetError`] if either the per-peer or global cap would be
    /// exceeded. Never blocks.
    ///
    /// The peer cap is checked first to short-circuit obvious misbehaviour
    /// without touching the globally-contended counter.
    pub fn try_reserve(self: &Arc<Self>, bytes: usize) -> Result<FrameReservation, BudgetError> {
        // Peer-cap check (CAS loop).
        let mut peer_prev = self.peer_used.load(Ordering::Acquire);
        loop {
            let new = peer_prev.saturating_add(bytes);
            if new > self.peer_cap {
                return Err(BudgetError::PerPeer {
                    requested: bytes,
                    held: peer_prev,
                    cap: self.peer_cap,
                });
            }
            match self.peer_used.compare_exchange_weak(
                peer_prev,
                new,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => peer_prev = actual,
            }
        }

        // Global-cap check (CAS loop). On failure, roll back the peer reservation.
        let mut global_prev = self.global.global_used.load(Ordering::Acquire);
        loop {
            let new = global_prev.saturating_add(bytes);
            if new > self.global.global_cap {
                self.peer_used.fetch_sub(bytes, Ordering::AcqRel);
                return Err(BudgetError::Global {
                    requested: bytes,
                    used: global_prev,
                    cap: self.global.global_cap,
                });
            }
            match self.global.global_used.compare_exchange_weak(
                global_prev,
                new,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => global_prev = actual,
            }
        }

        Ok(FrameReservation {
            budget: Arc::clone(self),
            bytes,
        })
    }

    pub fn peer_used(&self) -> usize {
        self.peer_used.load(Ordering::Acquire)
    }

    #[allow(dead_code)]
    pub fn peer_cap(&self) -> usize {
        self.peer_cap
    }
}

impl std::fmt::Debug for PeerBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerBudget")
            .field("peer_used", &self.peer_used())
            .field("peer_cap", &self.peer_cap)
            .finish()
    }
}

/// RAII reservation token. Releases the reserved bytes back to both the
/// per-peer and global counters when dropped — regardless of whether the
/// frame was verified successfully, failed HMAC, or errored out during
/// deserialization.
#[derive(Debug)]
pub struct FrameReservation {
    budget: Arc<PeerBudget>,
    bytes: usize,
}

impl FrameReservation {
    #[cfg(test)]
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Drop for FrameReservation {
    fn drop(&mut self) {
        self.budget.peer_used.fetch_sub(self.bytes, Ordering::AcqRel);
        self.budget
            .global
            .global_used
            .fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// Reservation failure. Carries enough detail to build a clear log line
/// at the caller (peer address + reason).
#[derive(Debug, Clone)]
pub enum BudgetError {
    /// Global in-flight cap would be exceeded.
    Global {
        requested: usize,
        used: usize,
        cap: usize,
    },
    /// This peer already holds (or would hold) more than its per-peer cap.
    PerPeer {
        requested: usize,
        held: usize,
        cap: usize,
    },
}

impl std::fmt::Display for BudgetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BudgetError::Global {
                requested,
                used,
                cap,
            } => write!(
                f,
                "global in-flight frame budget exhausted: requested {} bytes, \
                 {} already in flight, cap {}",
                requested, used, cap
            ),
            BudgetError::PerPeer {
                requested,
                held,
                cap,
            } => write!(
                f,
                "per-peer in-flight budget exhausted: requested {} bytes, \
                 peer already holds {}, cap {}",
                requested, held, cap
            ),
        }
    }
}

impl std::error::Error for BudgetError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_reservation_and_release() {
        let g = FrameBudget::with_cap(1024);
        let p = PeerBudget::with_peer_cap(Arc::clone(&g), 512);
        {
            let r = p.try_reserve(100).unwrap();
            assert_eq!(r.bytes(), 100);
            assert_eq!(p.peer_used(), 100);
            assert_eq!(g.global_used(), 100);
        }
        assert_eq!(p.peer_used(), 0, "peer_used must return to 0 after Drop");
        assert_eq!(g.global_used(), 0, "global_used must return to 0 after Drop");
    }

    /// Brief Fix 3 test — single peer attempts to hold more than its
    /// per-peer cap; rejected. After the first expert re-review, the
    /// per-peer cap is 16 MiB (honestly accounted peak), so the
    /// over-limit probe is 17 MiB.
    #[test]
    fn single_peer_cannot_exceed_per_peer_cap() {
        let g = FrameBudget::with_cap(GLOBAL_FRAME_BUDGET_BYTES);
        let p = PeerBudget::with_peer_cap(Arc::clone(&g), PER_PEER_FRAME_BUDGET_BYTES);

        // A 17 MiB reservation exceeds the 16 MiB per-peer cap outright.
        let err = p.try_reserve(17 * 1024 * 1024).expect_err("rejected");
        assert!(
            matches!(err, BudgetError::PerPeer { .. }),
            "expected PerPeer, got {:?}",
            err
        );
        // Global counter must not have been incremented by the failed reservation.
        assert_eq!(g.global_used(), 0);

        // Sanity: the per-peer cap itself fits.
        let _r = p
            .try_reserve(PER_PEER_FRAME_BUDGET_BYTES)
            .expect("exactly cap fits");
    }

    /// Brief Fix 3 test — 256 peers each sending a 4 MiB-payload frame
    /// simultaneously; at most 128 MiB in-flight, excess peers shed.
    ///
    /// Under honest accounting each 4 MiB-payload frame reserves
    /// `2 · 4 MiB + FRAME_HEADER_SIZE` = 8 MiB + 5 bytes. The number
    /// that fits is therefore `128 MiB / (8 MiB + 5)` — computed from
    /// the formula here rather than hardcoded, so this test auto-updates
    /// if `FRAME_HEADER_SIZE` ever changes.
    #[test]
    fn global_cap_sheds_excess_peers_at_128mib() {
        let g = FrameBudget::with_cap(GLOBAL_FRAME_BUDGET_BYTES);
        let mut peers: Vec<Arc<PeerBudget>> = (0..256)
            .map(|_| {
                PeerBudget::with_peer_cap(Arc::clone(&g), PER_PEER_FRAME_BUDGET_BYTES)
            })
            .collect();

        // 4 MiB payload reservation = 2*payload + FRAME_HEADER_SIZE.
        let payload_len: usize = 4 * 1024 * 1024;
        let reservation = crate::network::peer::peak_prever_bytes(payload_len);
        let expected_fit = GLOBAL_FRAME_BUDGET_BYTES / reservation;
        assert!(
            expected_fit < 256 && expected_fit > 0,
            "test precondition: some but not all peers should fit (got {})",
            expected_fit
        );
        // Under current constants this resolves to 15.
        assert_eq!(expected_fit, 15, "regression canary on the formula");

        let mut successes = 0usize;
        let mut shed = 0usize;
        let mut reservations = Vec::new();
        for p in peers.iter_mut() {
            match p.try_reserve(reservation) {
                Ok(r) => {
                    successes += 1;
                    reservations.push(r);
                }
                Err(BudgetError::Global { .. }) => {
                    shed += 1;
                }
                Err(other) => panic!("unexpected error: {:?}", other),
            }
        }
        assert_eq!(successes, expected_fit);
        assert_eq!(shed, 256 - expected_fit);
        assert!(g.global_used() <= GLOBAL_FRAME_BUDGET_BYTES);

        // After one peer drops its reservation, a peer that was
        // previously shed can now reserve. Use a peer past `expected_fit`
        // (it has no prior reservation, so there's no per-peer-cap
        // interaction with the retry).
        drop(reservations.pop());
        let _r = peers[expected_fit]
            .try_reserve(reservation)
            .expect("slot freed up after drop");
    }

    /// Brief Fix 3 test — legitimate traffic pattern unaffected. After
    /// the first expert re-review this test also exercises the specific
    /// regression we almost introduced: a single 4 MiB block-sized frame
    /// must fit under the per-peer cap when honest accounting is applied.
    #[test]
    fn legitimate_traffic_never_trips_cap() {
        let g = FrameBudget::with_cap(GLOBAL_FRAME_BUDGET_BYTES);
        let peers: Vec<Arc<PeerBudget>> = (0..256)
            .map(|_| {
                PeerBudget::with_peer_cap(Arc::clone(&g), PER_PEER_FRAME_BUDGET_BYTES)
            })
            .collect();

        // Most frames are small: Inv-sized (~2 KiB) per peer. All 256
        // peers in parallel. Each reserves 2*2KiB + header = ~4 KiB.
        let inv_reservation = crate::network::peer::peak_prever_bytes(2048);
        let mut reservations = Vec::new();
        for p in peers.iter() {
            reservations.push(p.try_reserve(inv_reservation).expect("tiny inv frame fits"));
        }
        assert_eq!(reservations.len(), 256);
        assert!(g.global_used() < g.global_cap());

        // Regression test for the honest-accounting fix: one peer
        // receiving a single MAX_BLOCK_SIZE (4 MiB) block frame must
        // reserve successfully under the per-peer cap. If the per-peer
        // cap were left at 8 MiB (pre-fix value), this reservation of
        // `2 · 4 MiB + FRAME_HEADER_SIZE = 8 MiB + 5` would be rejected.
        let block_reservation = crate::network::peer::peak_prever_bytes(4 * 1024 * 1024);
        let _block = peers[0]
            .try_reserve(block_reservation)
            .expect("legitimate 4 MiB block frame must fit per-peer cap");

        // Two peers simultaneously handling a 500 KiB block each — still fine.
        let half_block = crate::network::peer::peak_prever_bytes(500 * 1024);
        let _r1 = peers[1].try_reserve(half_block).expect("500 KiB block fits");
        let _r2 = peers[2].try_reserve(half_block).expect("500 KiB block fits");
        assert!(g.global_used() < g.global_cap());
    }

    #[test]
    fn rollback_on_global_overflow_does_not_leak_peer_bytes() {
        let g = FrameBudget::with_cap(1000);
        let p1 = PeerBudget::with_peer_cap(Arc::clone(&g), 2000);
        let p2 = PeerBudget::with_peer_cap(Arc::clone(&g), 2000);

        // p1 reserves 800 (fits).
        let _r1 = p1.try_reserve(800).expect("ok");
        // p2 tries to reserve 500 — fits per-peer but not global (800 + 500 > 1000).
        let err = p2.try_reserve(500).expect_err("rejected");
        assert!(matches!(err, BudgetError::Global { .. }));
        // p2's peer_used must not be left as 500 after rollback.
        assert_eq!(p2.peer_used(), 0);
        // Global still only has p1's 800.
        assert_eq!(g.global_used(), 800);
    }

    #[test]
    fn many_drops_are_idempotent_and_atomic() {
        let g = FrameBudget::with_cap(1_000_000);
        let p = PeerBudget::with_peer_cap(Arc::clone(&g), 1_000_000);

        let mut rs = Vec::new();
        for _ in 0..100 {
            rs.push(p.try_reserve(100).unwrap());
        }
        assert_eq!(p.peer_used(), 10_000);
        assert_eq!(g.global_used(), 10_000);
        rs.clear();
        assert_eq!(p.peer_used(), 0);
        assert_eq!(g.global_used(), 0);
    }

    #[test]
    fn zero_byte_reservation_is_cheap_noop_shape() {
        let g = FrameBudget::with_cap(1024);
        let p = PeerBudget::with_peer_cap(Arc::clone(&g), 1024);
        let r = p.try_reserve(0).expect("zero-byte reservation ok");
        assert_eq!(r.bytes(), 0);
        assert_eq!(p.peer_used(), 0);
        assert_eq!(g.global_used(), 0);
    }

    #[test]
    fn try_reserve_never_blocks_under_contention() {
        use std::sync::Arc;
        use std::thread;
        let g = FrameBudget::with_cap(10 * 1024 * 1024);
        let peers: Vec<Arc<PeerBudget>> = (0..32)
            .map(|_| PeerBudget::with_peer_cap(Arc::clone(&g), 1 * 1024 * 1024))
            .collect();

        let mut handles = Vec::new();
        for p in peers.iter().cloned() {
            handles.push(thread::spawn(move || {
                let mut r_count = 0;
                for _ in 0..1000 {
                    if let Ok(r) = p.try_reserve(64 * 1024) {
                        r_count += 1;
                        drop(r);
                    }
                }
                r_count
            }));
        }
        let _total: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        // All threads terminate (no deadlock) and counters are back to zero.
        assert_eq!(g.global_used(), 0);
    }
}
