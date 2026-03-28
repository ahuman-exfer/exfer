//! Behavioral tests for:
//!
//! 1. Node-level reorg triggers survive peer disconnection (peer A saves, peer B retries)
//! 2. Orphan recursion for fork-stored blocks (Ok(false) triggers child processing)

// ── Fix 1: Node-level reorg triggers ──

#[test]
fn reorg_trigger_survives_peer_disconnect() {
    // Verify that ReorgTriggerState (node-level shared state) survives
    // peer disconnection: peer A inserts a trigger, then "disconnects"
    // (drops its references), and peer B can still take and retry the
    // trigger blocks.
    use exfer::network::sync::ReorgTriggerState;
    use exfer::types::block::{Block, BlockHeader};
    use exfer::types::hash::Hash256;

    let state = std::sync::Mutex::new(ReorgTriggerState::new());

    let missing_ancestor = Hash256::sha256(b"missing_ancestor");

    let trigger_block = Block {
        header: BlockHeader {
            version: 1,
            height: 100,
            prev_block_id: missing_ancestor,
            timestamp: 2000,
            difficulty_target: Hash256([0xFF; 32]),
            nonce: 42,
            tx_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
        },
        transactions: vec![],
    };
    let trigger_id = trigger_block.header.block_id();

    // "Peer A" inserts trigger
    {
        let mut rt = state.lock().unwrap();
        assert!(rt.insert(missing_ancestor, trigger_block));
    }
    // "Peer A disconnects" — the state is node-level, so it persists

    // "Peer B" delivers the missing ancestor and retrieves trigger blocks
    {
        let mut rt = state.lock().unwrap();
        let triggers = rt.take(&missing_ancestor);
        assert!(
            triggers.is_some(),
            "triggers must survive peer disconnection"
        );
        let trigger_blocks = triggers.unwrap();
        assert_eq!(trigger_blocks.len(), 1);
        assert_eq!(trigger_blocks[0].header.block_id(), trigger_id);
    }
}

#[test]
fn reorg_trigger_multiple_peers_share_state() {
    // Multiple "peers" can insert triggers for different ancestors,
    // and any peer can take triggers for any ancestor.
    use exfer::network::sync::ReorgTriggerState;
    use exfer::types::block::{Block, BlockHeader};
    use exfer::types::hash::Hash256;

    let state = std::sync::Mutex::new(ReorgTriggerState::new());

    let ancestor_a = Hash256::sha256(b"ancestor_a");
    let ancestor_b = Hash256::sha256(b"ancestor_b");

    let block_from_peer_a = Block {
        header: BlockHeader {
            version: 1,
            height: 10,
            prev_block_id: ancestor_a,
            timestamp: 1000,
            difficulty_target: Hash256([0xFF; 32]),
            nonce: 1,
            tx_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
        },
        transactions: vec![],
    };
    let block_from_peer_b = Block {
        header: BlockHeader {
            version: 1,
            height: 20,
            prev_block_id: ancestor_b,
            timestamp: 2000,
            difficulty_target: Hash256([0xFF; 32]),
            nonce: 2,
            tx_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
        },
        transactions: vec![],
    };

    // Peer A inserts trigger for ancestor_a
    {
        let mut rt = state.lock().unwrap();
        rt.insert(ancestor_a, block_from_peer_a);
    }
    // Peer B inserts trigger for ancestor_b
    {
        let mut rt = state.lock().unwrap();
        rt.insert(ancestor_b, block_from_peer_b);
    }

    // Peer B delivers ancestor_a — gets peer A's trigger
    {
        let mut rt = state.lock().unwrap();
        let triggers = rt.take(&ancestor_a).unwrap();
        assert_eq!(triggers.len(), 1);
        assert_eq!(triggers[0].header.height, 10, "must get peer A's block");
    }

    // Peer A delivers ancestor_b — gets peer B's trigger
    {
        let mut rt = state.lock().unwrap();
        let triggers = rt.take(&ancestor_b).unwrap();
        assert_eq!(triggers.len(), 1);
        assert_eq!(triggers[0].header.height, 20, "must get peer B's block");
    }
}

#[test]
fn reorg_trigger_global_cap_evicts_oldest() {
    use exfer::network::sync::{ReorgTriggerState, MAX_GLOBAL_TRIGGERS};
    use exfer::types::block::{Block, BlockHeader};
    use exfer::types::hash::Hash256;

    let mut state = ReorgTriggerState::new();

    // Insert MAX_GLOBAL_TRIGGERS + 1 triggers, each for a unique ancestor
    let mut ancestors = Vec::new();
    for i in 0..=(MAX_GLOBAL_TRIGGERS as u64) {
        let ancestor = Hash256::sha256(&i.to_le_bytes());
        ancestors.push(ancestor);
        let block = Block {
            header: BlockHeader {
                version: 1,
                height: i,
                prev_block_id: ancestor,
                timestamp: 1000 + i,
                difficulty_target: Hash256([0xFF; 32]),
                nonce: i,
                tx_root: Hash256::ZERO,
                state_root: Hash256::ZERO,
            },
            transactions: vec![],
        };
        state.insert(ancestor, block);
    }

    // Total triggers must not exceed MAX_GLOBAL_TRIGGERS
    let total: usize = state.triggers.values().map(|v| v.len()).sum();
    assert!(
        total <= MAX_GLOBAL_TRIGGERS,
        "total triggers ({}) must not exceed MAX_GLOBAL_TRIGGERS ({})",
        total,
        MAX_GLOBAL_TRIGGERS
    );

    // The first (oldest) ancestor's trigger should have been evicted
    assert!(
        state.take(&ancestors[0]).is_none(),
        "oldest trigger (ancestor 0) must have been evicted"
    );

    // The last (newest) ancestor's trigger should still be present
    let last = state.take(&ancestors[MAX_GLOBAL_TRIGGERS]);
    assert!(last.is_some(), "newest trigger must still be present");
}

// ── Fix 2: Orphan recursion for fork-stored blocks ──
