//! Tests for the second audit round fixes (AUDIT-FIXES-2.md).
//!
//! Fix 2: Cumulative work stored during genesis init & replay
//! Fix 1: Reorg implementation with spent UTXO undo
//! Fix 3: Genesis difficulty with testnet feature flag

use exfer::chain::state::{UtxoEntry, UtxoSet};
use exfer::chain::storage::ChainStorage;
use exfer::consensus::difficulty::{
    add_work, genesis_target, production_genesis_target, work_from_target,
};
use exfer::genesis::genesis_block;
use exfer::types::block::{Block, BlockHeader};
use exfer::types::hash::Hash256;
use exfer::types::transaction::{OutPoint, Transaction, TxInput, TxOutput, TxWitness};
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
    let tx_root = exfer::consensus::validation::compute_tx_root(&transactions).unwrap();
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

// ── Fix 2: Cumulative work stored during genesis init & replay ──

#[test]
fn genesis_cumulative_work_stored() {
    // Simulate the genesis init path from main.rs (None branch)
    let tmpdir = TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");
    let storage = ChainStorage::open(&db_path).unwrap();

    let genesis = genesis_block();
    let gid = genesis.header.block_id();
    storage.put_block(&genesis).unwrap();
    storage.set_tip(&gid).unwrap();

    // Store genesis cumulative work (matches what main.rs now does)
    let genesis_work = work_from_target(&genesis.header.difficulty_target);
    storage.put_cumulative_work(&gid, &genesis_work).unwrap();

    // Verify: cumulative work must be stored and non-zero
    let retrieved = storage.get_cumulative_work(&gid).unwrap();
    assert!(
        retrieved.is_some(),
        "genesis cumulative work must be stored"
    );
    let work = retrieved.unwrap();
    assert_ne!(work, [0u8; 32], "genesis cumulative work must be non-zero");
    assert_eq!(work, genesis_work, "stored work must match computed work");
}

#[test]
fn replay_stores_cumulative_work() {
    // Store genesis + 2 blocks, then replay the chain and verify all have stored work
    let tmpdir = TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");
    let storage = ChainStorage::open(&db_path).unwrap();

    let pubkey = [1u8; 32];
    let genesis = genesis_block();
    let gid = genesis.header.block_id();
    storage.put_block(&genesis).unwrap();

    // Build block 1
    let mut utxo_set = UtxoSet::new();
    for tx in &genesis.transactions {
        utxo_set.apply_transaction(tx, 0).unwrap();
    }
    let cb1 = make_coinbase(1, 10_000_000_000, &pubkey);
    utxo_set.apply_transaction(&cb1, 1).unwrap();
    let block1 = make_block(1, gid, 1740700810, 1, vec![cb1], utxo_set.state_root());
    let b1id = block1.header.block_id();
    storage.put_block(&block1).unwrap();

    // Build block 2
    let cb2 = make_coinbase(2, 10_000_000_000, &pubkey);
    utxo_set.apply_transaction(&cb2, 2).unwrap();
    let block2 = make_block(2, b1id, 1740700820, 2, vec![cb2], utxo_set.state_root());
    let b2id = block2.header.block_id();
    storage.put_block(&block2).unwrap();
    storage.set_tip(&b2id).unwrap();

    // Simulate replay (matches the updated main.rs replay path)
    let tip_id = storage.get_tip().unwrap().unwrap();
    let mut chain = Vec::new();
    let mut current_id = tip_id;
    loop {
        let block = storage.get_block(&current_id).unwrap().unwrap();
        let prev = block.header.prev_block_id;
        chain.push(block);
        if prev == Hash256::ZERO {
            break;
        }
        current_id = prev;
    }
    chain.reverse();

    let mut cumulative_work = [0u8; 32];
    for block in &chain {
        let block_work = work_from_target(&block.header.difficulty_target);
        cumulative_work = add_work(&cumulative_work, &block_work);
        let bid = block.header.block_id();
        storage.put_cumulative_work(&bid, &cumulative_work).unwrap();
    }

    // Verify all three blocks have cumulative work stored
    let gw = storage.get_cumulative_work(&gid).unwrap();
    assert!(
        gw.is_some(),
        "genesis must have cumulative work after replay"
    );

    let b1w = storage.get_cumulative_work(&b1id).unwrap();
    assert!(
        b1w.is_some(),
        "block 1 must have cumulative work after replay"
    );

    let b2w = storage.get_cumulative_work(&b2id).unwrap();
    assert!(
        b2w.is_some(),
        "block 2 must have cumulative work after replay"
    );

    // Work should be monotonically increasing
    let gw = gw.unwrap();
    let b1w = b1w.unwrap();
    let b2w = b2w.unwrap();
    assert!(b1w > gw, "block 1 work should exceed genesis work");
    assert!(b2w > b1w, "block 2 work should exceed block 1 work");
}

// ── Fix 1: Reorg / spent UTXO undo ──

#[test]
fn spent_utxos_store_and_retrieve() {
    let tmpdir = TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");
    let storage = ChainStorage::open(&db_path).unwrap();

    let block_id = Hash256::sha256(b"block_with_spent");
    let tx_id = Hash256::sha256(b"spent_tx");

    let spent = vec![
        (
            OutPoint::new(tx_id, 0),
            UtxoEntry {
                output: TxOutput {
                    value: 5_000_000_000,
                    script: vec![1u8; 32],
                    datum: None,
                    datum_hash: None,
                },
                height: 10,
                is_coinbase: true,
            },
        ),
        (
            OutPoint::new(tx_id, 1),
            UtxoEntry {
                output: TxOutput {
                    value: 3_000_000_000,
                    script: vec![2u8; 32],
                    datum: None,
                    datum_hash: None,
                },
                height: 10,
                is_coinbase: false,
            },
        ),
    ];

    storage.store_spent_utxos(&block_id, &spent).unwrap();
    let retrieved = storage.get_spent_utxos(&block_id).unwrap();
    assert!(retrieved.is_some(), "spent UTXOs should be retrievable");

    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.len(), 2);
    assert_eq!(retrieved[0].0, spent[0].0);
    assert_eq!(retrieved[0].1.output.value, spent[0].1.output.value);
    assert_eq!(retrieved[0].1.height, spent[0].1.height);
    assert_eq!(retrieved[0].1.is_coinbase, spent[0].1.is_coinbase);
    assert_eq!(retrieved[1].0, spent[1].0);
    assert_eq!(retrieved[1].1.output.value, spent[1].1.output.value);
    assert_eq!(retrieved[1].1.is_coinbase, spent[1].1.is_coinbase);
}

#[test]
fn spent_utxos_missing_block_returns_none() {
    let tmpdir = TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");
    let storage = ChainStorage::open(&db_path).unwrap();

    let missing_id = Hash256::sha256(b"no_such_block");
    let result = storage.get_spent_utxos(&missing_id).unwrap();
    assert!(result.is_none());
}

#[test]
fn undo_block_restores_spent_utxos() {
    // Apply a coinbase, then spend it, then undo the spend
    let mut utxo_set = UtxoSet::new();
    let pubkey_a = [1u8; 32];
    let pubkey_b = [2u8; 32];

    // Create a coinbase UTXO
    let cb = make_coinbase(0, 10_000_000_000, &pubkey_a);
    let cb_tx_id = cb.tx_id().unwrap();
    utxo_set.apply_transaction(&cb, 0).unwrap();
    let root_before_spend = utxo_set.state_root();

    // Spend the coinbase
    let spend_tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: cb_tx_id,
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(9_000_000_000, &pubkey_b)],
        witnesses: vec![TxWitness {
            witness: vec![0u8; 96],
            redeemer: None,
        }],
    };

    // Collect spent UTXOs before applying (as reorg code does)
    let outpoint = OutPoint::new(cb_tx_id, 0);
    let spent_entry = utxo_set.get(&outpoint).unwrap().clone();
    let spent_utxos = vec![(outpoint, spent_entry)];

    utxo_set.apply_transaction(&spend_tx, 1).unwrap();
    assert!(
        !utxo_set.contains(&outpoint),
        "original UTXO should be gone"
    );
    assert_ne!(utxo_set.state_root(), root_before_spend);

    // Undo the spend
    utxo_set.undo_transaction(&spend_tx, &spent_utxos).unwrap();
    assert!(
        utxo_set.contains(&outpoint),
        "original UTXO should be restored"
    );
    assert_eq!(
        utxo_set.state_root(),
        root_before_spend,
        "state root should match pre-spend"
    );
}

#[test]
fn reorg_applies_correct_state() {
    // Build chain A: genesis → A1 → A2 → A3
    // Build chain B: genesis → B1 → B2 → B3 → B4 (more blocks, same difficulty)
    // After applying B-chain, UTXO state should reflect B-chain
    let pubkey_a = [0xAA; 32];
    let pubkey_b = [0xBB; 32];

    let genesis = genesis_block();
    let gid = genesis.header.block_id();

    // Build A-chain state
    let mut utxo_a = UtxoSet::new();
    for tx in &genesis.transactions {
        utxo_a.apply_transaction(tx, 0).unwrap();
    }

    // A1
    let cb_a1 = make_coinbase(1, 10_000_000_000, &pubkey_a);
    utxo_a.apply_transaction(&cb_a1, 1).unwrap();
    let block_a1 = make_block(
        1,
        gid,
        1740700810,
        100,
        vec![cb_a1.clone()],
        utxo_a.state_root(),
    );
    let a1id = block_a1.header.block_id();

    // A2
    let cb_a2 = make_coinbase(2, 10_000_000_000, &pubkey_a);
    utxo_a.apply_transaction(&cb_a2, 2).unwrap();
    let block_a2 = make_block(
        2,
        a1id,
        1740700820,
        200,
        vec![cb_a2.clone()],
        utxo_a.state_root(),
    );
    let a2id = block_a2.header.block_id();

    // A3
    let cb_a3 = make_coinbase(3, 10_000_000_000, &pubkey_a);
    utxo_a.apply_transaction(&cb_a3, 3).unwrap();
    let block_a3 = make_block(
        3,
        a2id,
        1740700830,
        300,
        vec![cb_a3.clone()],
        utxo_a.state_root(),
    );

    // Build B-chain state
    let mut utxo_b = UtxoSet::new();
    for tx in &genesis.transactions {
        utxo_b.apply_transaction(tx, 0).unwrap();
    }

    // B1 — same height as A1 but different nonce/pubkey
    let cb_b1 = make_coinbase(1, 10_000_000_000, &pubkey_b);
    utxo_b.apply_transaction(&cb_b1, 1).unwrap();
    let block_b1 = make_block(
        1,
        gid,
        1740700811,
        101,
        vec![cb_b1.clone()],
        utxo_b.state_root(),
    );
    let b1id = block_b1.header.block_id();

    // B2
    let cb_b2 = make_coinbase(2, 10_000_000_000, &pubkey_b);
    utxo_b.apply_transaction(&cb_b2, 2).unwrap();
    let block_b2 = make_block(
        2,
        b1id,
        1740700821,
        201,
        vec![cb_b2.clone()],
        utxo_b.state_root(),
    );
    let b2id = block_b2.header.block_id();

    // B3
    let cb_b3 = make_coinbase(3, 10_000_000_000, &pubkey_b);
    utxo_b.apply_transaction(&cb_b3, 3).unwrap();
    let block_b3 = make_block(
        3,
        b2id,
        1740700831,
        301,
        vec![cb_b3.clone()],
        utxo_b.state_root(),
    );
    let b3id = block_b3.header.block_id();

    // B4 — makes B chain longer
    let cb_b4 = make_coinbase(4, 10_000_000_000, &pubkey_b);
    utxo_b.apply_transaction(&cb_b4, 4).unwrap();
    let block_b4 = make_block(
        4,
        b3id,
        1740700841,
        401,
        vec![cb_b4.clone()],
        utxo_b.state_root(),
    );

    // Now simulate what the reorg code does:
    // Start with A-chain applied
    let mut live_utxo = UtxoSet::new();
    for tx in &genesis.transactions {
        live_utxo.apply_transaction(tx, 0).unwrap();
    }

    // Apply A-chain, collecting spent UTXOs
    let a_blocks = [&block_a1, &block_a2, &block_a3];
    let mut a_spent: Vec<Vec<(OutPoint, UtxoEntry)>> = Vec::new();
    for blk in &a_blocks {
        let mut spent = Vec::new();
        for tx in &blk.transactions {
            if !tx.is_coinbase() {
                for input in &tx.inputs {
                    let op = OutPoint::new(input.prev_tx_id, input.output_index);
                    if let Some(e) = live_utxo.get(&op) {
                        spent.push((op, e.clone()));
                    }
                }
            }
        }
        for tx in &blk.transactions {
            live_utxo.apply_transaction(tx, blk.header.height).unwrap();
        }
        a_spent.push(spent);
    }
    assert_eq!(live_utxo.state_root(), utxo_a.state_root());

    // Undo A-chain (most recent first)
    for (i, blk) in a_blocks.iter().rev().enumerate() {
        let spent = &a_spent[a_blocks.len() - 1 - i];
        for tx in blk.transactions.iter().rev() {
            let tx_spent: Vec<_> = spent
                .iter()
                .filter(|(op, _)| {
                    tx.inputs.iter().any(|inp| {
                        inp.prev_tx_id == op.tx_id && inp.output_index == op.output_index
                    })
                })
                .cloned()
                .collect();
            live_utxo.undo_transaction(tx, &tx_spent).unwrap();
        }
    }

    // Apply B-chain
    let b_blocks = [&block_b1, &block_b2, &block_b3, &block_b4];
    for blk in &b_blocks {
        for tx in &blk.transactions {
            live_utxo.apply_transaction(tx, blk.header.height).unwrap();
        }
    }

    // State should now match B-chain
    assert_eq!(
        live_utxo.state_root(),
        utxo_b.state_root(),
        "after reorg, state must reflect B-chain"
    );
}

// ── Fix 3: Genesis difficulty with testnet feature flag ──

#[test]
fn genesis_difficulty_is_2_248() {
    // Verify the production 2^248 constant directly, independent of feature flag
    let target = production_genesis_target();
    assert_eq!(target.0[0], 0x01, "byte[0] must be 0x01 for 2^248");
    for i in 1..32 {
        assert_eq!(target.0[i], 0x00, "byte[{}] must be 0", i);
    }
}

#[cfg(feature = "testnet")]
#[test]
fn testnet_genesis_block_valid() {
    // Under testnet, genesis difficulty is [0xFF;32] — any hash valid
    let genesis = genesis_block();
    assert_eq!(
        genesis.header.difficulty_target,
        Hash256([0xFF; 32]),
        "testnet genesis should have trivial difficulty"
    );
    assert_eq!(
        genesis.header.nonce, 259,
        "genesis nonce should be the mined value"
    );

    // Verify PoW passes trivially
    let pow = exfer::consensus::pow::compute_pow(&genesis.header).unwrap();
    assert!(
        exfer::consensus::pow::verify_pow(&genesis.header).unwrap(),
        "testnet genesis block PoW should pass: pow={:?}",
        pow
    );
}

#[test]
fn genesis_target_matches_genesis_block() {
    // genesis_target() and the genesis block difficulty_target should agree
    let target = genesis_target();
    let genesis = genesis_block();
    assert_eq!(
        target, genesis.header.difficulty_target,
        "genesis_target() must match genesis block difficulty_target"
    );
}
