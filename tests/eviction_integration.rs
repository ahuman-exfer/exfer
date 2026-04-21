//! v1.6.0 Fix 1 redesign — integration tests for utility-based inbound eviction.
//!
//! These exercise `PeerRegistry::decide_inbound_eviction_utility` +
//! `attach_session` through a full admission loop without TCP.
//!
//! Two tests per spec (docs/v1.6.0-brief.md):
//! - 11. `eviction_mechanism_avoids_thrash_cascade` — direct regression for
//!   the v1.5.0 failure mode. A stream of incoming connections against a
//!   full pool should not cause mean-peer-age to collapse to the
//!   post-handshake grace window.
//! - 12. `colonization_resistance_long_horizon` — single-operator fleet
//!   pressure vs. diverse arrivals; diverse peers' share should stabilize
//!   near the arrival-rate ratio, not be driven to zero.

use exfer::network::sync::{
    EvictionConfig, EvictionDecision, LogicalPeer, PeerRegistry, PeerSession, RetryState,
};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};

type PeerId = [u8; 32];

fn pid(fleet: u8, idx: u16) -> PeerId {
    let mut p = [0u8; 32];
    p[0] = fleet;
    p[1..3].copy_from_slice(&idx.to_le_bytes());
    p
}

fn fleet_of(p: &PeerId) -> u8 {
    p[0]
}

fn addr_of(octets: [u8; 4]) -> SocketAddr {
    SocketAddr::from((octets, 8333))
}

fn make_session(session_id: u64, addr: SocketAddr, established_at: Instant) -> PeerSession {
    let (tx, _rx) = mpsc::channel::<exfer::network::protocol::Message>(1);
    PeerSession {
        session_id,
        socket_addr: addr,
        is_outbound: false,
        tx,
        shutdown: Arc::new(AtomicBool::new(false)),
        established_at,
    }
}

fn insert_inbound(reg: &mut PeerRegistry, identity: PeerId, session: PeerSession) {
    reg.connected_socket_to_identity
        .insert(session.socket_addr, identity);
    reg.by_identity.insert(
        identity,
        LogicalPeer {
            identity,
            session: Some(session),
            known_addrs: HashSet::new(),
            preferred_dial_addr: None,
            desired_outbound: false,
            retry: RetryState {
                backoff_secs: 5,
                next_attempt_at: std::time::Instant::now(),
            },
            tip: None,
            ibd_cooldown_until: None,
            last_useful_message_at: None,
        },
    );
}

/// Post-handshake admission + maybe-eviction flow. Matches the code path
/// in `handle_inbound`. Returns the eviction decision enum variant
/// (structural match).
fn admit_arrival(
    reg: &mut PeerRegistry,
    identity: PeerId,
    addr: SocketAddr,
    session_id: u64,
    max_inbound: usize,
    config: &EvictionConfig,
) -> AdmissionOutcome {
    match reg.decide_inbound_eviction_utility(&identity, addr.ip(), None, max_inbound, config) {
        EvictionDecision::IpCapReached | EvictionDecision::NoEligibleCandidates => {
            return AdmissionOutcome::Rejected
        }
        EvictionDecision::Evict(victim) => {
            victim
                .shutdown
                .store(true, std::sync::atomic::Ordering::Release);
            reg.detach_session_if_current(victim.identity, victim.session_id);
        }
        EvictionDecision::NotNeeded | EvictionDecision::DuplicateIdentity => {}
    }
    let sess = make_session(session_id, addr, Instant::now());
    let already = reg
        .by_identity
        .get(&identity)
        .is_some_and(|lp| lp.session.is_some());
    if already {
        // DuplicateIdentity path — emulate attach_session swap
        if let Some(lp) = reg.by_identity.get_mut(&identity) {
            if let Some(old) = lp.session.take() {
                old.shutdown
                    .store(true, std::sync::atomic::Ordering::Release);
                reg.connected_socket_to_identity.remove(&old.socket_addr);
            }
            reg.connected_socket_to_identity.insert(addr, identity);
            lp.session = Some(sess);
            lp.last_useful_message_at = None;
        }
        AdmissionOutcome::Replaced
    } else {
        insert_inbound(reg, identity, sess);
        AdmissionOutcome::Admitted
    }
}

#[derive(Debug, PartialEq, Eq)]
enum AdmissionOutcome {
    Admitted,
    Replaced,
    Rejected,
}

// ── Test 11: thrash-cascade regression ──

#[tokio::test(flavor = "current_thread")]
async fn eviction_mechanism_avoids_thrash_cascade() {
    const SLOTS: usize = 32;
    // Shorter post-handshake-grace to keep the test tight.
    let config = EvictionConfig {
        post_handshake_grace_secs: 1,
        protect_useful_n: 4,
        protect_oldest_n: 4,
        protect_groups_n: 8,
        useful_protection_secs: 600,
    };

    let mut reg = PeerRegistry::new();
    let now_start = Instant::now();
    let mut session_id = 0u64;

    // Fill the slot pool with peers of staggered ages (2s..130s).
    // The oldest peers are at the head, newest (barely past grace) at the tail.
    for i in 0..SLOTS as u16 {
        let age_secs = 2 + i as u64 * 4;
        let est = now_start - Duration::from_secs(age_secs);
        let fleet = if i < 16 { 0xA0 } else { 0xB0 };
        let id = pid(fleet, i);
        let ip = if fleet == 0xA0 {
            [10, 0, 0, i as u8]
        } else {
            [192, 168, 0, (i - 16) as u8]
        };
        let addr = addr_of(ip);
        session_id += 1;
        insert_inbound(&mut reg, id, make_session(session_id, addr, est));
    }
    assert_eq!(reg.inbound_count(), SLOTS);

    // Record the identities of the protect_oldest_n=4 eldest peers
    // (oldest = i=31, then i=30, i=29, i=28 — all fleet 0xB0).
    let oldest_ids: Vec<PeerId> = (28..32u16).map(|i| pid(0xB0, i)).collect();

    // Let time age past grace.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Inject 200 incoming connection attempts from a DIVERSE group distribution.
    for iter in 0..200u32 {
        let fleet = 0xC0 + ((iter % 8) as u8);
        let new_id = pid(fleet, iter as u16);
        let new_ip = [fleet, (iter >> 8) as u8, (iter & 0xff) as u8, 1];
        session_id += 1;
        admit_arrival(
            &mut reg,
            new_id,
            addr_of(new_ip),
            session_id,
            SLOTS,
            &config,
        );
    }

    // After churn, assert the pool hasn't collapsed into newest-only.
    // The protect_oldest_n=4 eldest peers MUST still be present.
    for oid in &oldest_ids {
        assert!(
            reg.by_identity
                .get(oid)
                .is_some_and(|lp| lp.session.is_some()),
            "oldest-protected peer {:?} must survive 200-attempt churn",
            &oid[..2]
        );
    }
}

// ── Test 12: colonization resistance ──

#[tokio::test(flavor = "current_thread")]
async fn colonization_resistance_long_horizon() {
    const SLOTS: usize = 16;
    let config = EvictionConfig {
        post_handshake_grace_secs: 1,
        protect_useful_n: 2,
        protect_oldest_n: 2,
        protect_groups_n: 8,
        useful_protection_secs: 600,
    };

    // Pool: 8 fleet_A (colonizer in 192.168/16), 8 diverse peers in distinct /16s.
    let mut reg = PeerRegistry::new();
    let now_start = Instant::now();
    let mut session_id = 0u64;

    for i in 0..8u16 {
        let id = pid(0xAA, i);
        let addr = addr_of([192, 168, 0, i as u8]);
        session_id += 1;
        insert_inbound(
            &mut reg,
            id,
            make_session(session_id, addr, now_start - Duration::from_secs(300)),
        );
    }
    for i in 0..8u16 {
        let id = pid(0xBB, i);
        // Each diverse peer in a distinct /16 to exercise group protection.
        let addr = addr_of([10 + i as u8, 0, 0, 1]);
        session_id += 1;
        insert_inbound(
            &mut reg,
            id,
            make_session(session_id, addr, now_start - Duration::from_secs(300)),
        );
    }
    assert_eq!(reg.inbound_count(), SLOTS);

    // Wait past grace.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Fleet_A tries to colonize: 500 incoming attempts from 192.168/16.
    for iter in 0..500u32 {
        let new_id = pid(0xAF, iter as u16);
        let new_ip = [192, 168, (iter >> 8) as u8, iter as u8];
        session_id += 1;
        admit_arrival(
            &mut reg,
            new_id,
            addr_of(new_ip),
            session_id,
            SLOTS,
            &config,
        );
    }

    // Count surviving diverse peers (fleet 0xBB).
    let surviving_diverse: usize = reg
        .by_identity
        .iter()
        .filter(|(id, lp)| fleet_of(id) == 0xBB && lp.session.is_some())
        .count();

    // Under random eviction (v1.5.0), fleet_A's sustained pressure drove
    // surviving_diverse to near zero. Under utility eviction, diverse
    // peers' distinct /16s earn group-diversity protection — at least
    // half should remain.
    assert!(
        surviving_diverse >= 4,
        "diverse peers must not be crowded out by single-/16 colonizer; got {}/8",
        surviving_diverse
    );
}
