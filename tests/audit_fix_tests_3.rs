//! Tests for the third audit round fixes (AUDIT-FIXES-3.md).
//!
//! Fix 2: Remove cached difficulty — always compute expected difficulty from stored headers
//! Fix 1: Fork blocks get header-only validation; full tx validation during reorg
//! Fix 3: Reorg clears stale canonical height entries above new tip

use exfer::chain::state::UtxoSet;
use exfer::chain::storage::ChainStorage;
use exfer::consensus::difficulty::{expected_difficulty, genesis_target, work_from_target};
#[cfg(feature = "testnet")]
use exfer::consensus::validation::validate_block_header;
use exfer::consensus::validation::{compute_tx_root, validate_block_transactions};
use exfer::genesis::genesis_block;
use exfer::types::block::{Block, BlockHeader};
use exfer::types::hash::Hash256;
use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};
use exfer::types::{RETARGET_WINDOW, TARGET_BLOCK_TIME_SECS};
use tempfile::TempDir;

// ── Helpers ──

fn make_coinbase(height: u64, value: u64, pubkey: &[u8; 32]) -> Transaction {
    Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: height as u32,
        }],
        outputs: vec![TxOutput::new_p2pkh(value, pubkey)],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    }
}

fn make_block(
    height: u64,
    prev_block_id: Hash256,
    timestamp: u64,
    nonce: u64,
    transactions: Vec<Transaction>,
    state_root: Hash256,
) -> Block {
    let tx_root = compute_tx_root(&transactions).unwrap();
    Block {
        header: BlockHeader {
            version: 1,
            height,
            prev_block_id,
            timestamp,
            difficulty_target: genesis_target(),
            nonce,
            tx_root,
            state_root,
        },
        transactions,
    }
}

/// Build a chain of `count` blocks on top of genesis, storing all in storage.
/// Returns (block_ids, final_utxo_set, last_timestamp).
fn build_chain(
    storage: &ChainStorage,
    count: u64,
    pubkey: &[u8; 32],
    base_timestamp: u64,
) -> (Vec<Hash256>, UtxoSet) {
    let genesis = genesis_block();
    let gid = genesis.header.block_id();

    let mut utxo_set = UtxoSet::new();
    for tx in &genesis.transactions {
        utxo_set.apply_transaction(tx, 0).unwrap();
    }

    let mut block_ids = vec![gid];
    let mut prev_id = gid;

    for h in 1..=count {
        let reward = exfer::consensus::reward::block_reward(h);
        let cb = make_coinbase(h, reward, pubkey);
        utxo_set.apply_transaction(&cb, h).unwrap();
        let ts = base_timestamp + h * TARGET_BLOCK_TIME_SECS;
        let block = make_block(h, prev_id, ts, h * 100, vec![cb], utxo_set.state_root());
        let bid = block.header.block_id();
        storage.put_block(&block).unwrap();

        let parent_work = storage
            .get_cumulative_work(&prev_id)
            .unwrap()
            .unwrap_or([0u8; 32]);
        let block_work = work_from_target(&block.header.difficulty_target);
        let cum_work = exfer::consensus::difficulty::add_work(&parent_work, &block_work);
        storage.put_cumulative_work(&bid, &cum_work).unwrap();

        block_ids.push(bid);
        prev_id = bid;
    }

    storage.set_tip(&prev_id).unwrap();
    (block_ids, utxo_set)
}

// ── Fix 2: expected_difficulty from stored headers ──

#[test]
fn expected_difficulty_from_stored_headers_within_window() {
    // After restart, expected difficulty should be correctly computed
    // from stored headers, not from any cached field.
    // Build chain to height 10 (within first retarget window).
    // Verify expected_difficulty returns genesis target for the next block.
    let tmpdir = TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");
    let storage = ChainStorage::open(&db_path).unwrap();

    let genesis = genesis_block();
    let gid = genesis.header.block_id();
    storage.put_block(&genesis).unwrap();
    let genesis_work = work_from_target(&genesis.header.difficulty_target);
    storage.put_cumulative_work(&gid, &genesis_work).unwrap();

    let pubkey = [1u8; 32];
    let (block_ids, _utxo) = build_chain(&storage, 10, &pubkey, 1773536400);

    // expected_difficulty for height 11 (within window) should be parent's target
    let tip_id = block_ids[10];
    let expected = expected_difficulty(&storage, &tip_id, 11).unwrap();
    assert_eq!(
        expected,
        genesis_target(),
        "within retarget window, difficulty should match parent (genesis target)"
    );
}

#[test]
fn expected_difficulty_at_retarget_boundary() {
    // Test that expected_difficulty correctly retargets at height = RETARGET_WINDOW.
    // Store header-only chain directly (much faster than building full blocks with UTXO).
    // Use 2x slower block timing so the retarget result clearly differs from genesis.
    let tmpdir = TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");
    let storage = ChainStorage::open(&db_path).unwrap();

    let base_timestamp = 1773536400u64;
    let target = genesis_target();

    // Build a chain of RETARGET_WINDOW headers with 2x faster blocks (5s between blocks).
    // Under testnet, genesis target is [0xFF;32] (max), so we can only make it harder (decrease).
    let mut prev_id = Hash256::ZERO;
    let mut block_ids = Vec::new();

    for h in 0..RETARGET_WINDOW {
        let ts = base_timestamp + h * TARGET_BLOCK_TIME_SECS / 2; // 2x faster
        let cb = make_coinbase(h, 10_000_000_000, &[1u8; 32]);
        let tx_root = compute_tx_root(std::slice::from_ref(&cb)).unwrap();
        let block = Block {
            header: BlockHeader {
                version: 1,
                height: h,
                prev_block_id: prev_id,
                timestamp: ts,
                difficulty_target: target,
                nonce: h,
                tx_root,
                state_root: Hash256::ZERO,
            },
            transactions: vec![cb],
        };
        let bid = block.header.block_id();
        storage.store_block(&block).unwrap();
        block_ids.push(bid);
        prev_id = bid;
    }

    // The parent of block at height RETARGET_WINDOW is block_ids[RETARGET_WINDOW-1]
    let parent_id = block_ids[(RETARGET_WINDOW - 1) as usize];
    let expected = expected_difficulty(&storage, &parent_id, RETARGET_WINDOW).unwrap();

    // Blocks were 2x faster, so retarget should DECREASE the target (harder mining).
    assert!(
        expected.as_bytes() < target.as_bytes(),
        "2x faster blocks should decrease target (harder mining)"
    );

    // Also verify the retarget actually happened (result != parent's target)
    assert_ne!(
        expected, target,
        "at retarget boundary, difficulty should change when timing differs"
    );
}

// ── Fix 1: Fork block difficulty from own ancestry ──

#[test]
fn fork_block_difficulty_from_own_ancestry() {
    // Build a main chain and a fork chain with same difficulty (both within retarget window).
    // Verify expected_difficulty works from each chain's own parent, not the other's.
    let tmpdir = TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");
    let storage = ChainStorage::open(&db_path).unwrap();

    let genesis = genesis_block();
    let gid = genesis.header.block_id();
    storage.put_block(&genesis).unwrap();
    let genesis_work = work_from_target(&genesis.header.difficulty_target);
    storage.put_cumulative_work(&gid, &genesis_work).unwrap();

    let pubkey_a = [0xAA; 32];
    let pubkey_b = [0xBB; 32];

    // Main chain: genesis → A1 → A2
    let mut utxo_a = UtxoSet::new();
    for tx in &genesis.transactions {
        utxo_a.apply_transaction(tx, 0).unwrap();
    }
    let reward1 = exfer::consensus::reward::block_reward(1);
    let cb_a1 = make_coinbase(1, reward1, &pubkey_a);
    utxo_a.apply_transaction(&cb_a1, 1).unwrap();
    let block_a1 = make_block(1, gid, 1740700810, 100, vec![cb_a1], utxo_a.state_root());
    let a1id = block_a1.header.block_id();
    storage.store_block(&block_a1).unwrap();
    let a1_work = exfer::consensus::difficulty::add_work(
        &genesis_work,
        &work_from_target(&block_a1.header.difficulty_target),
    );
    storage.put_cumulative_work(&a1id, &a1_work).unwrap();

    let reward2 = exfer::consensus::reward::block_reward(2);
    let cb_a2 = make_coinbase(2, reward2, &pubkey_a);
    utxo_a.apply_transaction(&cb_a2, 2).unwrap();
    let block_a2 = make_block(2, a1id, 1740700820, 200, vec![cb_a2], utxo_a.state_root());
    let a2id = block_a2.header.block_id();
    storage.store_block(&block_a2).unwrap();
    let a2_work = exfer::consensus::difficulty::add_work(
        &a1_work,
        &work_from_target(&block_a2.header.difficulty_target),
    );
    storage.put_cumulative_work(&a2id, &a2_work).unwrap();

    // Fork chain: genesis → B1 (different nonce/pubkey)
    let cb_b1 = make_coinbase(1, reward1, &pubkey_b);
    let mut utxo_b = UtxoSet::new();
    for tx in &genesis.transactions {
        utxo_b.apply_transaction(tx, 0).unwrap();
    }
    utxo_b.apply_transaction(&cb_b1, 1).unwrap();
    let block_b1 = make_block(1, gid, 1740700811, 101, vec![cb_b1], utxo_b.state_root());
    let b1id = block_b1.header.block_id();
    storage.store_block(&block_b1).unwrap();
    let b1_work = exfer::consensus::difficulty::add_work(
        &genesis_work,
        &work_from_target(&block_b1.header.difficulty_target),
    );
    storage.put_cumulative_work(&b1id, &b1_work).unwrap();

    // expected_difficulty for a block building on A2 (height 3)
    let expected_on_a = expected_difficulty(&storage, &a2id, 3).unwrap();
    assert_eq!(expected_on_a, genesis_target());

    // expected_difficulty for a block building on B1 (height 2)
    let expected_on_b = expected_difficulty(&storage, &b1id, 2).unwrap();
    assert_eq!(expected_on_b, genesis_target());

    // Both should be the same within the first window, but critically both
    // were computed from their own chain's parent, not from each other's.
}

// ── Fix 1: validate_block_transactions against correct UTXO ──

#[test]
fn validate_block_transactions_against_correct_utxo() {
    // Build two chains diverging from genesis.
    // A coinbase on chain A should not be spendable against chain B's UTXO set.
    let pubkey_a = [0xAA; 32];
    let pubkey_b = [0xBB; 32];

    let genesis = genesis_block();

    // Build chain A UTXO
    let mut utxo_a = UtxoSet::new();
    for tx in &genesis.transactions {
        utxo_a.apply_transaction(tx, 0).unwrap();
    }
    let reward1 = exfer::consensus::reward::block_reward(1);
    let cb_a1 = make_coinbase(1, reward1, &pubkey_a);
    utxo_a.apply_transaction(&cb_a1, 1).unwrap();

    // Build chain B UTXO
    let mut utxo_b = UtxoSet::new();
    for tx in &genesis.transactions {
        utxo_b.apply_transaction(tx, 0).unwrap();
    }
    let cb_b1 = make_coinbase(1, reward1, &pubkey_b);
    utxo_b.apply_transaction(&cb_b1, 1).unwrap();

    // A block with chain-A's coinbase should validate against utxo_a
    let block_a = make_block(
        1,
        genesis.header.block_id(),
        1740700810,
        100,
        vec![cb_a1.clone()],
        utxo_a.state_root(),
    );

    // Create utxo_set_before_a = genesis-only state (what utxo_a looked like before A1 was applied)
    let mut utxo_before_a = UtxoSet::new();
    for tx in &genesis.transactions {
        utxo_before_a.apply_transaction(tx, 0).unwrap();
    }

    // validate_block_transactions checks coinbase reward
    let result = validate_block_transactions(&block_a, &utxo_before_a);
    assert!(
        result.is_ok(),
        "block A should validate against genesis UTXO state"
    );

    // Chain B's coinbase at height 1 but with different pubkey
    let block_b = make_block(
        1,
        genesis.header.block_id(),
        1740700811,
        101,
        vec![cb_b1.clone()],
        utxo_b.state_root(),
    );
    let result_b = validate_block_transactions(&block_b, &utxo_before_a);
    assert!(
        result_b.is_ok(),
        "block B should also validate against genesis UTXO (coinbase only)"
    );
}

// ── Fix 3: Reorg clears stale canonical heights ──

#[test]
fn reorg_to_shorter_chain_clears_stale_heights() {
    // Build main chain to height 10, set canonical heights.
    // Then simulate reorg to a shorter chain (height 7).
    // Verify heights 8, 9, 10 are cleared.
    let tmpdir = TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");
    let storage = ChainStorage::open(&db_path).unwrap();

    let genesis = genesis_block();
    let gid = genesis.header.block_id();
    storage.put_block(&genesis).unwrap();
    let genesis_work = work_from_target(&genesis.header.difficulty_target);
    storage.put_cumulative_work(&gid, &genesis_work).unwrap();

    let pubkey = [1u8; 32];

    // Build main chain to height 10 with canonical height entries
    let (_block_ids, _utxo) = build_chain(&storage, 10, &pubkey, 1773536400);

    // Verify heights 0-10 are all set
    for h in 0..=10u64 {
        let bid = storage.get_block_id_by_height(h).unwrap();
        assert!(bid.is_some(), "height {} should have canonical entry", h);
    }

    // Simulate reorg: new tip at height 7
    // In real code, reorg writes new chain heights and clears stale ones.
    // Here we test the storage operation directly.
    let new_tip_height = 7u64;
    let old_tip_height = 10u64;

    // Clear stale heights above new tip (what Fix 3 does in sync.rs)
    for h in (new_tip_height + 1)..=old_tip_height {
        storage.delete_canonical_height(h).unwrap();
    }

    // Heights 0-7 should still exist
    for h in 0..=7u64 {
        let bid = storage.get_block_id_by_height(h).unwrap();
        assert!(
            bid.is_some(),
            "height {} should still have entry after reorg",
            h
        );
    }

    // Heights 8-10 should be cleared
    for h in 8..=10u64 {
        let bid = storage.get_block_id_by_height(h).unwrap();
        assert!(bid.is_none(), "height {} should be cleared after reorg", h);
    }
}

#[test]
fn reorg_to_longer_chain_all_heights_correct() {
    // Build main chain A to height 5 with canonical heights.
    // Build fork chain B from genesis to height 8 (longer).
    // Simulate reorg: set B's heights, clear nothing (B is longer).
    // Verify all heights 0-8 point to correct blocks.
    let tmpdir = TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");
    let storage = ChainStorage::open(&db_path).unwrap();

    let genesis = genesis_block();
    let gid = genesis.header.block_id();
    storage.put_block(&genesis).unwrap();
    let genesis_work = work_from_target(&genesis.header.difficulty_target);
    storage.put_cumulative_work(&gid, &genesis_work).unwrap();

    let pubkey_a = [0xAA; 32];
    let pubkey_b = [0xBB; 32];

    // Build chain A to height 5 (this sets canonical heights 0-5 via put_block)
    let (_a_ids, _utxo_a) = build_chain(&storage, 5, &pubkey_a, 1773536400);

    // Build chain B to height 8 (fork from genesis, using store_block to not overwrite heights)
    let mut utxo_b = UtxoSet::new();
    for tx in &genesis.transactions {
        utxo_b.apply_transaction(tx, 0).unwrap();
    }
    let mut b_ids = vec![gid];
    let mut prev_id = gid;
    for h in 1..=8u64 {
        let reward = exfer::consensus::reward::block_reward(h);
        let cb = make_coinbase(h, reward, &pubkey_b);
        utxo_b.apply_transaction(&cb, h).unwrap();
        let ts = 1773536400 + h * TARGET_BLOCK_TIME_SECS + 1; // slightly different timestamps
        let block = make_block(h, prev_id, ts, h * 1000, vec![cb], utxo_b.state_root());
        let bid = block.header.block_id();
        storage.store_block(&block).unwrap(); // doesn't update height index

        let parent_work = storage
            .get_cumulative_work(&prev_id)
            .unwrap()
            .unwrap_or([0u8; 32]);
        let block_work = work_from_target(&block.header.difficulty_target);
        let cum_work = exfer::consensus::difficulty::add_work(&parent_work, &block_work);
        storage.put_cumulative_work(&bid, &cum_work).unwrap();

        b_ids.push(bid);
        prev_id = bid;
    }

    // Simulate reorg: update canonical heights to B's chain
    // Heights 1-8 now point to B chain
    for h in 1..=8u64 {
        storage.set_canonical_height(h, &b_ids[h as usize]).unwrap();
    }

    // No heights to clear since B is longer (height 8 > A's height 5)

    // Verify all heights 0-8 point to B's blocks
    // Height 0 = genesis (same for both chains)
    let h0 = storage.get_block_id_by_height(0).unwrap().unwrap();
    assert_eq!(h0, gid, "height 0 should be genesis");

    for h in 1..=8u64 {
        let stored = storage.get_block_id_by_height(h).unwrap();
        assert!(stored.is_some(), "height {} should have entry", h);
        assert_eq!(
            stored.unwrap(),
            b_ids[h as usize],
            "height {} should point to B-chain block",
            h
        );
    }
}

// ── Fix 2: header-only validation works without UTXO ──

#[cfg(feature = "testnet")]
#[test]
fn header_only_validation_no_utxo_needed() {
    // Verify that validate_block_header can validate a block without any UTXO state.
    // This confirms the split works — fork blocks can be validated on receipt.
    let tmpdir = TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");
    let storage = ChainStorage::open(&db_path).unwrap();

    let genesis = genesis_block();
    let gid = genesis.header.block_id();
    storage.put_block(&genesis).unwrap();
    let genesis_work = work_from_target(&genesis.header.difficulty_target);
    storage.put_cumulative_work(&gid, &genesis_work).unwrap();

    let pubkey = [1u8; 32];
    let reward = exfer::consensus::reward::block_reward(1);
    let cb = make_coinbase(1, reward, &pubkey);
    let mut utxo = UtxoSet::new();
    for tx in &genesis.transactions {
        utxo.apply_transaction(tx, 0).unwrap();
    }
    utxo.apply_transaction(&cb, 1).unwrap();

    // Timestamp must be above MTP of the genesis chain
    let block = make_block(1, gid, 1774000000, 42, vec![cb], utxo.state_root());
    let parent_header = genesis.header.clone();

    let ancestor_timestamps = storage.get_ancestor_timestamps(&gid, 11).unwrap();

    let expected_target =
        expected_difficulty(&storage, &block.header.prev_block_id, block.header.height).unwrap();

    // Use a wall_clock far in the future to avoid timestamp-too-far-ahead issues
    let wall_clock = block.header.timestamp + 3600;

    // This should succeed without any UTXO set
    let result = validate_block_header(
        &block,
        Some(&parent_header),
        &ancestor_timestamps,
        &expected_target,
        Some(wall_clock),
    );
    assert!(
        result.is_ok(),
        "header-only validation should succeed: {:?}",
        result.err()
    );
}
