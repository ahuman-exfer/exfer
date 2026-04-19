//! v1.5.2 hotfix — TipResponse handler guard.
//!
//! These tests cover the coordinator-side guarantees that the TipResponse
//! handler relies on to decide whether to skip its legacy `GetHeaders`
//! issuance. The handler's call is `coord.is_active(peer, session).await`;
//! if true it must `continue` to the next event without emitting a
//! `GetHeaders`. These tests pin the `is_active` contract against concurrent
//! try_reserve/release activity — the exact race the hotfix prevents.
//!
//! The full handler wiring (the `continue` in `src/network/sync.rs:5224`
//! area) is validated by code review; this file exercises the coordinator
//! invariants the wiring depends on.

use exfer::network::tip_validation::TipValidationCoordinator;
use std::sync::Arc;

type PeerId = [u8; 32];

fn pid(n: u8) -> PeerId {
    let mut p = [0u8; 32];
    p[0] = n;
    p
}

#[tokio::test]
async fn is_active_consistent_across_concurrent_reserve_release() {
    // Under a realistic sync-manager loop, `is_active` is called from the
    // TipResponse handler while the spawned validator may be reserving or
    // releasing in parallel. Assert the coordinator remains consistent.
    let coord = Arc::new(TipValidationCoordinator::new());
    let peer = pid(1);
    let sid = 100u64;

    // Baseline: inactive.
    assert!(!coord.is_active(peer, sid).await);

    // Spawn a "validator" task that reserves, holds, then releases.
    let c1 = coord.clone();
    let validator = tokio::spawn(async move {
        assert!(c1.try_reserve(peer, sid).await);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        c1.release_reservation(peer, sid).await;
    });

    // Spawn 20 "TipResponse handler" tasks that read is_active repeatedly.
    let mut handler_handles = Vec::new();
    for _ in 0..20 {
        let c = coord.clone();
        handler_handles.push(tokio::spawn(async move {
            let mut saw_active = false;
            for _ in 0..50 {
                if c.is_active(peer, sid).await {
                    saw_active = true;
                }
                tokio::time::sleep(std::time::Duration::from_millis(3)).await;
            }
            saw_active
        }));
    }

    validator.await.unwrap();
    let mut any_saw_active = false;
    for h in handler_handles {
        if h.await.unwrap() {
            any_saw_active = true;
        }
    }
    assert!(any_saw_active, "at least one handler task must have observed is_active=true during the validator's hold");

    // Final state: all reservations released, is_active must be false.
    assert!(!coord.is_active(peer, sid).await);
}

#[tokio::test]
async fn is_active_per_session_isolation() {
    // Two sessions for the same peer: reserving one must not mark the other active.
    let coord = TipValidationCoordinator::new();
    let peer = pid(7);
    assert!(coord.try_reserve(peer, 1).await);
    assert!(coord.is_active(peer, 1).await);
    assert!(!coord.is_active(peer, 2).await, "session 2 must be independent");
    // Different peer, same sid also independent.
    assert!(!coord.is_active(pid(8), 1).await);
    coord.release_reservation(peer, 1).await;
    assert!(!coord.is_active(peer, 1).await);
}

#[tokio::test]
async fn tipresponse_guard_contract() {
    // Pin the guard contract: the handler's decision flow is
    //   if coord.is_active(peer, sid).await { skip emitting GetHeaders } else { proceed }
    // Assert both branches yield the expected coordinator state.
    let coord = TipValidationCoordinator::new();
    let peer = pid(9);
    let sid = 42u64;

    // Branch 1: no active validation → handler proceeds → coordinator state
    // unchanged by the is_active check (is_active is read-only).
    assert!(!coord.is_active(peer, sid).await);
    let _read = coord.is_active(peer, sid).await; // handler's guard call
    assert!(!coord.is_active(peer, sid).await, "is_active must not mutate state");

    // Branch 2: active validation → handler skips → coordinator state also unchanged.
    coord.try_reserve(peer, sid).await;
    let _read = coord.is_active(peer, sid).await;
    assert!(coord.is_active(peer, sid).await, "reservation held across is_active call");
    // Validator eventually releases.
    coord.release_reservation(peer, sid).await;
    assert!(!coord.is_active(peer, sid).await);
}
