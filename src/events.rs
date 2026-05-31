//! Server-side event bus for SSE push subscriptions (issue #15 Tier 2).
//!
//! Route A from the design discussion: a per-script subscriber map. Emits
//! events only to subscribers actually interested in the affected script,
//! so the cost is O(actual subscribers per event) rather than O(N
//! connections). Suited to public nodes carrying 100+ thin-wallet streams.
//!
//! Lock layering: emit paths take `routes.read()` then `subscribers.read()`
//! then `try_send`. All non-blocking. Subscribers never hold any chain lock,
//! so emit can be called from inside the mempool or chain locks without
//! risk of inversion.
//!
//! Backpressure: each subscriber has a bounded mpsc with capacity
//! `SUBSCRIBER_BUFFER`. On `TrySendError::Full` we mark the subscriber
//! as lagged and let the next successful send carry an additional
//! `ChainEvent::Resync` so the client can recover; we never block the
//! emitter on a slow consumer.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use tokio::sync::mpsc;

/// Outgoing event identifier. Cheap to clone.
pub type SubscriberId = u64;

/// On-the-wire key for an address / script. We match the bytes the mempool
/// and UTXO set already key their `by_script` index by, so callers don't
/// have to re-hash.
pub type ScriptKey = Vec<u8>;

/// One event the bus may emit to subscribers. Stays minimal on purpose:
/// the nudge model is "something changed for this script — go re-pull
/// via the JSON-RPC". No amounts, no per-tx detail, no event log.
#[derive(Clone, Debug)]
pub enum ChainEvent {
    /// Mempool or confirmed state for this script changed. Client should
    /// re-pull `get_address_mempool` + `get_balance` / `get_address_utxos`.
    ScriptChanged(ScriptKey),
    /// Tip advanced. Useful as a global heartbeat and for clients that
    /// want to refresh non-address state (e.g. chain height).
    TipChanged { height: u64 },
    /// Bus dropped events for this subscriber. Client should re-pull
    /// for its full subscribed address set.
    Resync,
}

/// Buffer size per subscriber. Bounds memory at `SUBSCRIBER_BUFFER` events
/// × number of connections, and forces backpressure to surface as a
/// resync nudge rather than RAM growth.
const SUBSCRIBER_BUFFER: usize = 1024;

struct SubscriberSender {
    tx: mpsc::Sender<ChainEvent>,
    /// Set the first time a `try_send` fails for this subscriber. On the
    /// next successful send the bus prepends a `ChainEvent::Resync` so
    /// the client knows it has missed events.
    lagged: AtomicBool,
}

/// The bus itself. Cheap to share via `Arc`. Held by the mempool and by
/// the chain commit path (which emit) and by every SSE connection
/// handler (which subscribes / unsubscribes).
pub struct EventBus {
    /// script bytes -> set of subscribers interested in that script
    routes: RwLock<HashMap<ScriptKey, HashSet<SubscriberId>>>,
    /// subscriber id -> the per-conn sender owned by its SSE task
    subscribers: RwLock<HashMap<SubscriberId, SubscriberSender>>,
    /// monotonic id allocator
    next_id: AtomicU64,
}

impl EventBus {
    pub fn new() -> Arc<Self> {
        Arc::new(EventBus {
            routes: RwLock::new(HashMap::new()),
            subscribers: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        })
    }

    /// Subscribe to a set of scripts. Returns the new subscriber's id and
    /// a receiver the SSE handler should drain onto its socket.
    ///
    /// The caller is responsible for calling `unsubscribe(id)` when the
    /// connection closes — otherwise the per-script routing entries leak.
    pub fn subscribe(&self, scripts: &[ScriptKey]) -> (SubscriberId, mpsc::Receiver<ChainEvent>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(SUBSCRIBER_BUFFER);

        {
            let mut subs = self.subscribers.write().expect("subscribers lock poisoned");
            subs.insert(
                id,
                SubscriberSender {
                    tx,
                    lagged: AtomicBool::new(false),
                },
            );
        }

        {
            let mut routes = self.routes.write().expect("routes lock poisoned");
            for script in scripts {
                routes.entry(script.clone()).or_default().insert(id);
            }
        }

        (id, rx)
    }

    /// Cancel a subscription. Removes the per-script routing entries and
    /// drops the sender; the receiver in the SSE task will see the channel
    /// close on its next `recv`.
    pub fn unsubscribe(&self, id: SubscriberId) {
        let mut routes = self.routes.write().expect("routes lock poisoned");
        // O(scripts subscribed) by iterating routes; the per-conn cap on
        // address-set size keeps this small in practice. Alternative would
        // be to mirror each subscriber's address set on the subscriber
        // struct, trading memory for unsubscribe speed.
        routes.retain(|_script, set| {
            set.remove(&id);
            !set.is_empty()
        });

        let mut subs = self.subscribers.write().expect("subscribers lock poisoned");
        subs.remove(&id);
    }

    /// Notify subscribers that this script's mempool or confirmed state
    /// changed.
    pub fn emit_script_changed(&self, script: &[u8]) {
        // Fast path: nobody subscribed to this script.
        let interested: Vec<SubscriberId> = {
            let routes = self.routes.read().expect("routes lock poisoned");
            match routes.get(script) {
                Some(set) => set.iter().copied().collect(),
                None => return,
            }
        };
        if interested.is_empty() {
            return;
        }
        let event = ChainEvent::ScriptChanged(script.to_vec());
        self.send_to(&interested, event);
    }

    /// Bulk emit. Useful from the block commit path which knows the full
    /// set of scripts touched in one shot.
    pub fn emit_scripts_changed<I, S>(&self, scripts: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<[u8]>,
    {
        // Dedup before fanning out so a script affected by multiple txs in
        // the same block emits once per subscriber.
        let mut unique: HashSet<ScriptKey> = HashSet::new();
        for s in scripts {
            unique.insert(s.as_ref().to_vec());
        }
        if unique.is_empty() {
            return;
        }
        for script in unique {
            self.emit_script_changed(&script);
        }
    }

    /// Tip advanced. Sent to every active subscriber.
    pub fn emit_tip_changed(&self, height: u64) {
        let ids: Vec<SubscriberId> = {
            let subs = self.subscribers.read().expect("subscribers lock poisoned");
            subs.keys().copied().collect()
        };
        if ids.is_empty() {
            return;
        }
        self.send_to(&ids, ChainEvent::TipChanged { height });
    }

    fn send_to(&self, ids: &[SubscriberId], event: ChainEvent) {
        let subs = self.subscribers.read().expect("subscribers lock poisoned");
        for id in ids {
            let Some(sub) = subs.get(id) else { continue };

            // If this subscriber had previously fallen behind, prepend
            // a Resync nudge before catching it up with the new event.
            if sub.lagged.swap(false, Ordering::Relaxed)
                && sub.tx.try_send(ChainEvent::Resync).is_err()
            {
                // Couldn't even fit the resync — mark it lagged again for
                // the next try.
                sub.lagged.store(true, Ordering::Relaxed);
                continue;
            }

            if sub.tx.try_send(event.clone()).is_err() {
                // Channel full or closed. Full → mark lagged so we send a
                // Resync next time. Closed is fine — `unsubscribe` will
                // clear the routes shortly when the SSE task notices.
                sub.lagged.store(true, Ordering::Relaxed);
            }
        }
    }

    /// Observability: number of live subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.read().expect("subscribers lock poisoned").len()
    }

    /// Observability: number of script routes (≤ Σ per-subscriber address set
    /// sizes; cheaper to compute than walking subscribers).
    pub fn route_count(&self) -> usize {
        self.routes.read().expect("routes lock poisoned").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script_of(b: u8) -> ScriptKey {
        vec![b; 32]
    }

    #[tokio::test]
    async fn subscribe_receives_emitted_event_for_its_script() {
        let bus = EventBus::new();
        let s = script_of(7);
        let (_id, mut rx) = bus.subscribe(&[s.clone()]);
        bus.emit_script_changed(&s);
        match rx.recv().await {
            Some(ChainEvent::ScriptChanged(got)) => assert_eq!(got, s),
            other => panic!("expected ScriptChanged, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn subscribe_does_not_receive_events_for_other_scripts() {
        let bus = EventBus::new();
        let (_id, mut rx) = bus.subscribe(&[script_of(1)]);
        bus.emit_script_changed(&script_of(2));
        bus.emit_tip_changed(100); // ensure something else doesn't accidentally fire
        match rx.try_recv() {
            Err(mpsc::error::TryRecvError::Empty) => {} // good: filtered out
            Ok(ChainEvent::TipChanged { height: 100 }) => {} // tip emit is global, also OK
            other => panic!("subscriber for script 1 got unrelated event: {:?}", other),
        }
    }

    #[tokio::test]
    async fn unsubscribe_removes_routes_and_closes_channel() {
        let bus = EventBus::new();
        let s = script_of(3);
        let (id, mut rx) = bus.subscribe(&[s.clone()]);
        assert_eq!(bus.subscriber_count(), 1);
        assert_eq!(bus.route_count(), 1);
        bus.unsubscribe(id);
        assert_eq!(bus.subscriber_count(), 0);
        assert_eq!(bus.route_count(), 0);
        // Channel closed → recv yields None.
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn lagged_subscriber_gets_resync_before_next_event() {
        let bus = EventBus::new();
        let s = script_of(9);
        let (_id, mut rx) = bus.subscribe(&[s.clone()]);
        // Step 1: overflow the buffer to force a try_send failure and flip
        // the lagged flag. SUBSCRIBER_BUFFER + 1 emits → last one fails.
        for _ in 0..(SUBSCRIBER_BUFFER + 1) {
            bus.emit_script_changed(&s);
        }
        // Step 2: drain enough so the channel has room again.
        for _ in 0..(SUBSCRIBER_BUFFER / 2) {
            assert!(matches!(rx.try_recv(), Ok(ChainEvent::ScriptChanged(_))));
        }
        // Step 3: one more emit. The lagged flag should now turn into a
        // Resync prepended to the next event.
        bus.emit_script_changed(&s);
        let mut saw_resync = false;
        loop {
            match rx.try_recv() {
                Ok(ChainEvent::Resync) => {
                    saw_resync = true;
                    break;
                }
                Ok(_) => continue, // skip the queued ScriptChanged events
                Err(_) => break,
            }
        }
        assert!(saw_resync, "expected Resync after channel made room post-overflow");
    }

    #[tokio::test]
    async fn emit_scripts_changed_dedups_within_one_block() {
        let bus = EventBus::new();
        let s = script_of(5);
        let (_id, mut rx) = bus.subscribe(&[s.clone()]);
        // Same script repeated → subscriber should still only get one event.
        bus.emit_scripts_changed(vec![s.clone(), s.clone(), s.clone()]);
        let first = rx.try_recv();
        let second = rx.try_recv();
        assert!(matches!(first, Ok(ChainEvent::ScriptChanged(_))));
        assert!(
            matches!(second, Err(mpsc::error::TryRecvError::Empty)),
            "expected dedup to collapse repeated script emits, got {:?}",
            second
        );
    }
}
