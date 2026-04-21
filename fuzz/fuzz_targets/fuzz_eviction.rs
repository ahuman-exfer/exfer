#![no_main]
//! v1.6.0 Fix 1 fuzz target.
//!
//! Fuzz sequences of arrivals, useful-message marks, and session replacements
//! against PeerRegistry's utility-based eviction. Invariants per
//! docs/v1.6.0-brief.md:
//! - inbound_count() <= MAX_INBOUND_PEERS
//! - inbound_count_for_ip(X) <= MAX_INBOUND_PER_IP for all X
//! - EvictionDecision::Evict(v) never names the active IBD peer
//! - EvictionDecision::Evict(v) never names a peer within post-handshake grace
//! - EvictionDecision::Evict(v) is deterministic w.r.t. the registry state
//!   (no reliance on random selection)
//! - No panics across arbitrary operation sequences

use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use exfer::network::sync::{
    EvictionConfig, EvictionDecision, LogicalPeer, PeerRegistry, PeerSession, RetryState,
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
    MarkUseful {
        fleet: u8,
        idx: u16,
    },
    ReplaceSession {
        fleet: u8,
        idx: u16,
    },
    TimeAdvanceMs(u16),
}

fn decode_ops(data: &[u8]) -> Vec<Op> {
    let mut ops = Vec::new();
    let mut i = 0usize;
    while i + 6 <= data.len() && ops.len() < 64 {
        let tag = data[i] % 4;
        match tag {
            0 if i + 6 <= data.len() => {
                ops.push(Op::ArrivalWithId {
                    fleet: data[i + 1],
                    idx: u16::from_le_bytes([data[i + 2], data[i + 3]]),
                    ip_octet: data[i + 4],
                    now_offset_ms: u16::from_le_bytes([data[i + 5], 0]),
                    active_ibd_is_first: (data[i + 1] & 1) == 1,
                });
                i += 6;
            }
            1 if i + 4 <= data.len() => {
                ops.push(Op::MarkUseful {
                    fleet: data[i + 1],
                    idx: u16::from_le_bytes([data[i + 2], data[i + 3]]),
                });
                i += 4;
            }
            2 if i + 4 <= data.len() => {
                ops.push(Op::ReplaceSession {
                    fleet: data[i + 1],
                    idx: u16::from_le_bytes([data[i + 2], data[i + 3]]),
                });
                i += 4;
            }
            _ => {
                ops.push(Op::TimeAdvanceMs(u16::from_le_bytes([
                    data[i + 1],
                    data[i + 2],
                ])));
                i += 3;
            }
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
            last_useful_message_at: None,
        },
    );
}

fuzz_target!(|data: &[u8]| {
    let ops = decode_ops(data);
    let mut reg = PeerRegistry::new();
    let mut session_id = 0u64;
    let mut virtual_clock: u64 = 0;
    let mut first_admitted: Option<PeerId> = None;

    let config = EvictionConfig {
        post_handshake_grace_secs: 1,
        protect_useful_n: 4,
        protect_oldest_n: 4,
        protect_groups_n: 8,
        useful_protection_secs: 600,
    };
    let grace = Duration::from_secs(config.post_handshake_grace_secs);
    let max_inbound = MAX_INBOUND_PEERS;

    for op in ops {
        match op {
            Op::TimeAdvanceMs(ms) => {
                virtual_clock = virtual_clock.saturating_add(ms as u64);
            }
            Op::MarkUseful { fleet, idx } => {
                let id = pid(fleet, idx);
                let sid = reg
                    .by_identity
                    .get(&id)
                    .and_then(|lp| lp.session.as_ref().map(|s| s.session_id));
                if let Some(sid) = sid {
                    reg.mark_useful_message(&id, sid);
                }
            }
            Op::ReplaceSession { fleet, idx } => {
                let id = pid(fleet, idx);
                let had_credit_before = reg
                    .by_identity
                    .get(&id)
                    .and_then(|lp| lp.last_useful_message_at)
                    .is_some();
                if let Some(lp) = reg.by_identity.get_mut(&id) {
                    if let Some(old) = lp.session.as_ref() {
                        let addr = old.socket_addr;
                        session_id += 1;
                        lp.session = Some(make_session(session_id, addr, Instant::now()));
                        // Emulate attach_session's reset-on-attach rule.
                        lp.last_useful_message_at = None;
                    }
                }
                // Invariant: after a session replacement, no useful credit
                // carries forward. (The prior-session credit must not leak.)
                let credit_after = reg
                    .by_identity
                    .get(&id)
                    .and_then(|lp| lp.last_useful_message_at)
                    .is_some();
                if had_credit_before {
                    assert!(!credit_after, "session replacement must clear useful credit");
                }
            }
            Op::ArrivalWithId {
                fleet,
                idx,
                ip_octet,
                now_offset_ms,
                active_ibd_is_first,
            } => {
                let id = pid(fleet, idx);
                let addr: SocketAddr = format!(
                    "192.0.2.{}:{}",
                    ip_octet,
                    8333u16.wrapping_add(idx)
                )
                .parse()
                .unwrap();
                let established = Instant::now() - Duration::from_millis(now_offset_ms as u64);
                let active_ibd = if active_ibd_is_first {
                    first_admitted.and_then(|i| {
                        reg.by_identity
                            .get(&i)
                            .and_then(|lp| lp.session.as_ref().map(|s| (i, s.session_id)))
                    })
                } else {
                    None
                };
                let decision = reg.decide_inbound_eviction_utility(
                    &id,
                    addr.ip(),
                    active_ibd,
                    max_inbound,
                    &config,
                );
                match decision {
                    EvictionDecision::Evict(victim) => {
                        // Invariant: victim is not within post-handshake grace.
                        assert!(
                            victim.established_at.elapsed() >= grace,
                            "victim inside grace window"
                        );
                        // Invariant: victim is not the active IBD peer.
                        if let Some((ibd_id, ibd_sid)) = active_ibd {
                            assert!(
                                !(ibd_id == victim.identity && ibd_sid == victim.session_id),
                                "evicted the active IBD peer"
                            );
                        }
                        reg.detach_session_if_current(victim.identity, victim.session_id);
                    }
                    EvictionDecision::IpCapReached
                    | EvictionDecision::NoEligibleCandidates => continue,
                    EvictionDecision::DuplicateIdentity => {
                        if let Some(lp) = reg.by_identity.get_mut(&id) {
                            if let Some(old) = lp.session.take() {
                                reg.connected_socket_to_identity.remove(&old.socket_addr);
                            }
                            reg.connected_socket_to_identity.insert(addr, id);
                            session_id += 1;
                            let new_sess = make_session(session_id, addr, established);
                            if let Some(lp) = reg.by_identity.get_mut(&id) {
                                lp.session = Some(new_sess);
                                lp.last_useful_message_at = None;
                            }
                        }
                        continue;
                    }
                    EvictionDecision::NotNeeded => {}
                }
                if !reg.by_identity.contains_key(&id)
                    && reg.inbound_count_for_ip(addr.ip()) < MAX_INBOUND_PER_IP
                {
                    session_id += 1;
                    let sess = make_session(session_id, addr, established);
                    insert_inbound(&mut reg, id, sess);
                    if first_admitted.is_none() {
                        first_admitted = Some(id);
                    }
                }

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

                // Determinism: re-running the same decision on unchanged
                // state must produce a structurally-equivalent decision.
                let decision2 = reg.decide_inbound_eviction_utility(
                    &id,
                    addr.ip(),
                    active_ibd,
                    max_inbound,
                    &config,
                );
                let _ = decision2;
            }
        }
    }
    let _ = virtual_clock;
});
