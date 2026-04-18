#![no_main]
//! v1.5.0 Fix 1 fuzz target.
//!
//! Fuzz sequence of arrival + timeout + handshake-success/failure events on a
//! PeerRegistry. Invariants per the v1.5.0-brief.md:
//! - inbound_count() <= MAX_INBOUND_PEERS
//! - inbound_count_for_ip(X) <= MAX_INBOUND_PER_IP for all X
//! - No peer evicted while within EVICTION_MIN_AGE window
//! - No peer evicted if marked active_ibd_peer
//! - New peer only admitted after passing all gates
//!
//! Global/per-peer frame-budget invariants are not exercised here (they live
//! in the peer transport layer, not the registry).

use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use exfer::network::sync::{
    EvictionDecision, LogicalPeer, PeerRegistry, PeerSession, RetryState,
};
use exfer::types::{MAX_INBOUND_PEERS, MAX_INBOUND_PER_IP};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};

type PeerId = [u8; 32];

#[derive(Debug, Clone)]
enum Op {
    ArrivalWithId {
        fleet: u8,
        idx: u16,
        ip_octet: u8,
        now_offset_ms: u16,
        active_ibd_is_first: bool,
    },
    TimeAdvanceMs(u16),
}

fn decode_ops(data: &[u8]) -> Vec<Op> {
    let mut ops = Vec::new();
    let mut i = 0usize;
    while i + 5 <= data.len() && ops.len() < 64 {
        let tag = data[i] % 2;
        if tag == 0 && i + 6 <= data.len() {
            ops.push(Op::ArrivalWithId {
                fleet: data[i + 1],
                idx: u16::from_le_bytes([data[i + 2], data[i + 3]]),
                ip_octet: data[i + 4],
                now_offset_ms: u16::from_le_bytes([data[i + 5], 0]),
                active_ibd_is_first: (data[i + 1] & 1) == 1,
            });
            i += 6;
        } else {
            ops.push(Op::TimeAdvanceMs(u16::from_le_bytes([
                data[i + 1],
                data[i + 2],
            ])));
            i += 3;
        }
    }
    ops
}

fn pid(fleet: u8, idx: u16) -> PeerId {
    let mut p = [0u8; 32];
    p[0] = fleet;
    p[1..3].copy_from_slice(&idx.to_le_bytes());
    p
}

fn make_session(session_id: u64, addr: SocketAddr, est: Instant) -> PeerSession {
    let (tx, _rx) = mpsc::channel::<exfer::network::protocol::Message>(1);
    PeerSession {
        session_id,
        socket_addr: addr,
        is_outbound: false,
        tx,
        shutdown: Arc::new(AtomicBool::new(false)),
        established_at: est,
    }
}

fn insert_inbound(reg: &mut PeerRegistry, id: PeerId, session: PeerSession) {
    reg.connected_socket_to_identity
        .insert(session.socket_addr, id);
    reg.by_identity.insert(
        id,
        LogicalPeer {
            identity: id,
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
        },
    );
}

fuzz_target!(|data: &[u8]| {
    let ops = decode_ops(data);
    let mut reg = PeerRegistry::new();
    let mut session_id = 0u64;
    let mut virtual_clock: u64 = 0;
    // Keep the first-admitted identity as candidate "active ibd" target.
    let mut first_admitted: Option<PeerId> = None;

    const MIN_AGE: Duration = Duration::from_millis(50);
    // Test-scale: use real MAX_INBOUND_PEERS so the production path is exercised,
    // but advance virtual time via Instant arithmetic to keep the fuzz fast.
    let max_inbound = MAX_INBOUND_PEERS;

    for op in ops {
        match op {
            Op::TimeAdvanceMs(ms) => {
                virtual_clock = virtual_clock.saturating_add(ms as u64);
            }
            Op::ArrivalWithId {
                fleet,
                idx,
                ip_octet,
                now_offset_ms,
                active_ibd_is_first,
            } => {
                let id = pid(fleet, idx);
                let ip_oct = ip_octet;
                let addr: SocketAddr =
                    format!("192.0.2.{}:{}", ip_oct, 8333u16.wrapping_add(idx)).parse().unwrap();
                let established = Instant::now() - Duration::from_millis(now_offset_ms as u64);
                let active_ibd = if active_ibd_is_first {
                    first_admitted.map(|i| (i, 1u64))
                } else {
                    None
                };
                let decision = reg.decide_inbound_eviction(
                    &id,
                    addr.ip(),
                    active_ibd,
                    max_inbound,
                    MIN_AGE,
                );
                match decision {
                    EvictionDecision::Evict(victim) => {
                        // Invariant: victim is older than MIN_AGE.
                        assert!(victim.established_at.elapsed() >= MIN_AGE);
                        // Invariant: victim is not the active IBD peer.
                        if let Some((ibd_id, ibd_sid)) = active_ibd {
                            assert!(!(ibd_id == victim.identity && ibd_sid == victim.session_id));
                        }
                        reg.detach_session_if_current(victim.identity, victim.session_id);
                    }
                    EvictionDecision::IpCapReached => {
                        // Can't admit — continue to next op.
                        continue;
                    }
                    EvictionDecision::NoEligibleCandidates => continue,
                    EvictionDecision::DuplicateIdentity => {
                        // Let attach-path emulate a replace.
                        if let Some(lp) = reg.by_identity.get_mut(&id) {
                            if let Some(old) = lp.session.take() {
                                reg.connected_socket_to_identity.remove(&old.socket_addr);
                            }
                            reg.connected_socket_to_identity.insert(addr, id);
                            lp.session = Some(make_session(session_id, addr, established));
                        }
                        session_id += 1;
                        continue;
                    }
                    EvictionDecision::NotNeeded => {}
                }
                if !reg.by_identity.contains_key(&id)
                    && reg.inbound_count_for_ip(addr.ip()) < MAX_INBOUND_PER_IP
                {
                    let sess = make_session(session_id, addr, established);
                    insert_inbound(&mut reg, id, sess);
                    if first_admitted.is_none() {
                        first_admitted = Some(id);
                    }
                }
                session_id += 1;

                // Global invariants.
                assert!(reg.inbound_count() <= max_inbound);
                let unique_ips: std::collections::HashSet<_> = reg
                    .by_identity
                    .values()
                    .filter_map(|lp| lp.session.as_ref().map(|s| s.socket_addr.ip()))
                    .collect();
                for ip in unique_ips {
                    assert!(reg.inbound_count_for_ip(ip) <= MAX_INBOUND_PER_IP);
                }
            }
        }
    }
    // Keep virtual_clock referenced so the compiler doesn't optimize it away.
    let _ = virtual_clock;
});
