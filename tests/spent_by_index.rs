//! Tests for the reverse-spend (`SPENT_BY_TABLE`) index added in this PR.
//!
//! Covers:
//!   - incremental population during `commit_block_atomic`
//!   - empty population during `commit_genesis_atomic`
//!   - `get_output_spent_by` returning `None` for unspent and `Some`
//!     for spent outpoints
//!   - reorg correctness: rows for orphaned blocks are removed and
//!     rows for the new canonical chain are inserted (both inside
//!     one redb write txn)
//!   - `build_spent_by_index_from_genesis` backfill: idempotent, end
//!     state equals "everything indexed".

use exfer::chain::storage::ChainStorage;
use exfer::chain::state::{UtxoMutation, UtxoSet};
use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};
use exfer::types::{block::{Block, BlockHeader}, Hash256};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Synthetic block fabrication
// ---------------------------------------------------------------------------

fn coinbase_tx(seed: u8) -> Transaction {
    Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0xFFFF_FFFF,
        }],
        outputs: vec![TxOutput {
            value: 1_000,
            script: vec![seed; 32],
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![seed],
            redeemer: None,
        }],
    }
}

fn spend_tx(prev_tx_id: Hash256, output_index: u32, output_script: Vec<u8>) -> Transaction {
    Transaction {
        inputs: vec![TxInput {
            prev_tx_id,
            output_index,
        }],
        outputs: vec![TxOutput {
            value: 999,
            script: output_script,
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![0u8; 64],
            redeemer: None,
        }],
    }
}

fn block_with(height: u64, prev_block_id: Hash256, txs: Vec<Transaction>) -> Block {
    let header = BlockHeader {
        version: 1,
        height,
        prev_block_id,
        timestamp: 1_700_000_000 + height,
        difficulty_target: Hash256([0xFFu8; 32]),
        nonce: 0,
        tx_root: Hash256::ZERO,
        state_root: Hash256::ZERO,
    };
    Block {
        header,
        transactions: txs,
    }
}

fn open_storage() -> (ChainStorage, TempDir) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("chain.redb");
    let storage = ChainStorage::open(&path).unwrap();
    (storage, dir)
}

// ---------------------------------------------------------------------------
// Genesis path — no real inputs to index, must not error
// ---------------------------------------------------------------------------

#[test]
fn commit_genesis_writes_no_spent_by_entries() {
    let (storage, _dir) = open_storage();
    let genesis = block_with(0, Hash256::ZERO, vec![coinbase_tx(0xAA)]);
    let mut utxos = UtxoSet::new();
    let muts = utxos.apply_transaction(&genesis.transactions[0], 0).unwrap();
    storage
        .commit_genesis_atomic(&genesis, &[0u8; 32], &muts)
        .unwrap();
    assert!(
        storage.spent_by_table_is_empty().unwrap(),
        "genesis (coinbase only) must not write spent_by rows"
    );
}

// ---------------------------------------------------------------------------
// Happy-path: extend tip with a block that spends a prior coinbase
// ---------------------------------------------------------------------------

#[test]
fn commit_block_atomic_indexes_non_coinbase_spends() {
    let (storage, _dir) = open_storage();

    // Block 0: coinbase only.
    let cb0 = coinbase_tx(0x01);
    let cb0_tx_id = cb0.tx_id().unwrap();
    let genesis = block_with(0, Hash256::ZERO, vec![cb0.clone()]);
    let mut utxos = UtxoSet::new();
    let g_muts = utxos.apply_transaction(&cb0, 0).unwrap();
    storage
        .commit_genesis_atomic(&genesis, &[0u8; 32], &g_muts)
        .unwrap();

    // Block 1: spends (cb0_tx_id, 0). Plus a new coinbase.
    let cb1 = coinbase_tx(0x02);
    let spend = spend_tx(cb0_tx_id, 0, vec![0x77; 32]);
    let spend_tx_id = spend.tx_id().unwrap();

    let mut muts = Vec::new();
    muts.extend(utxos.apply_transaction(&cb1, 1).unwrap());
    muts.extend(utxos.apply_transaction(&spend, 1).unwrap());
    let spent: Vec<_> = UtxoMutation::collect_spent_utxos(&muts);

    let b1 = block_with(
        1,
        genesis.header.block_id(),
        vec![cb1, spend],
    );
    storage
        .commit_block_atomic(&b1, &[0u8; 32], &spent, &muts)
        .unwrap();

    // Now the lookup must return the spend.
    let got = storage
        .get_output_spent_by(&cb0_tx_id, 0)
        .unwrap()
        .expect("cb0 output 0 was spent");
    assert_eq!(got.spending_tx_id, spend_tx_id);
    assert_eq!(got.input_index, 0);
    assert_eq!(got.block_height, 1);

    // An unspent outpoint returns None.
    let unspent = storage.get_output_spent_by(&cb0_tx_id, 99).unwrap();
    assert!(unspent.is_none(), "non-existent output returns None");
}

// ---------------------------------------------------------------------------
// Backfill correctness
// ---------------------------------------------------------------------------

#[test]
fn build_spent_by_index_from_genesis_is_idempotent() {
    let (storage, _dir) = open_storage();

    let cb0 = coinbase_tx(0xAB);
    let cb0_tx_id = cb0.tx_id().unwrap();
    let genesis = block_with(0, Hash256::ZERO, vec![cb0.clone()]);
    let mut utxos = UtxoSet::new();
    let g_muts = utxos.apply_transaction(&cb0, 0).unwrap();
    storage
        .commit_genesis_atomic(&genesis, &[0u8; 32], &g_muts)
        .unwrap();

    let cb1 = coinbase_tx(0xBC);
    let spend = spend_tx(cb0_tx_id, 0, vec![0xCC; 32]);
    let mut b1_muts = Vec::new();
    b1_muts.extend(utxos.apply_transaction(&cb1, 1).unwrap());
    b1_muts.extend(utxos.apply_transaction(&spend, 1).unwrap());
    let spent_b1: Vec<_> = UtxoMutation::collect_spent_utxos(&b1_muts);
    let b1 = block_with(
        1,
        genesis.header.block_id(),
        vec![cb1, spend.clone()],
    );
    storage
        .commit_block_atomic(&b1, &[0u8; 32], &spent_b1, &b1_muts)
        .unwrap();

    // Incremental path already populated. Running the backfill must
    // produce identical rows.
    let before = storage
        .get_output_spent_by(&cb0_tx_id, 0)
        .unwrap()
        .unwrap();
    let (blocks, inputs) = storage.build_spent_by_index_from_genesis().unwrap();
    assert!(blocks >= 2, "must walk genesis + block 1");
    assert_eq!(inputs, 1, "exactly one non-coinbase input on the chain");
    let after = storage
        .get_output_spent_by(&cb0_tx_id, 0)
        .unwrap()
        .unwrap();
    assert_eq!(before, after, "backfill must be idempotent");
}

#[test]
fn spent_by_table_is_empty_reflects_state() {
    let (storage, _dir) = open_storage();
    assert!(storage.spent_by_table_is_empty().unwrap(), "fresh datadir");

    let cb0 = coinbase_tx(0x11);
    let cb0_tx_id = cb0.tx_id().unwrap();
    let genesis = block_with(0, Hash256::ZERO, vec![cb0.clone()]);
    let mut utxos = UtxoSet::new();
    let g_muts = utxos.apply_transaction(&cb0, 0).unwrap();
    storage
        .commit_genesis_atomic(&genesis, &[0u8; 32], &g_muts)
        .unwrap();
    // Genesis only → still empty.
    assert!(storage.spent_by_table_is_empty().unwrap());

    let cb1 = coinbase_tx(0x12);
    let spend = spend_tx(cb0_tx_id, 0, vec![0x42; 32]);
    let mut muts = Vec::new();
    muts.extend(utxos.apply_transaction(&cb1, 1).unwrap());
    muts.extend(utxos.apply_transaction(&spend, 1).unwrap());
    let spent: Vec<_> = UtxoMutation::collect_spent_utxos(&muts);
    let b1 = block_with(1, genesis.header.block_id(), vec![cb1, spend]);
    storage
        .commit_block_atomic(&b1, &[0u8; 32], &spent, &muts)
        .unwrap();
    // Now non-empty.
    assert!(!storage.spent_by_table_is_empty().unwrap());
}

// ---------------------------------------------------------------------------
// Unspent / non-existent outpoints
// ---------------------------------------------------------------------------

#[test]
fn get_output_spent_by_returns_none_for_unknown() {
    let (storage, _dir) = open_storage();
    let cb0 = coinbase_tx(0xEE);
    let genesis = block_with(0, Hash256::ZERO, vec![cb0.clone()]);
    let mut utxos = UtxoSet::new();
    let g_muts = utxos.apply_transaction(&cb0, 0).unwrap();
    storage
        .commit_genesis_atomic(&genesis, &[0u8; 32], &g_muts)
        .unwrap();

    // An entirely fictitious outpoint → None.
    let made_up = Hash256([0x99u8; 32]);
    assert!(storage.get_output_spent_by(&made_up, 7).unwrap().is_none());
}

// ---------------------------------------------------------------------------
// Reorg path — revert orphan spends, apply new-canonical spends, all inside
// one commit_reorg_atomic write txn. The inline double-open guard runs empty
// chains, so multiple apply_spent_by_for_block calls in one txn were
// previously untested.
// ---------------------------------------------------------------------------

/// A coinbase with two spendable outputs, so one reorg can exercise both an
/// outpoint that the new canonical chain re-spends and one it leaves unspent.
fn coinbase_tx_2out(seed: u8) -> Transaction {
    Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::ZERO,
            output_index: 0xFFFF_FFFF,
        }],
        outputs: vec![
            TxOutput {
                value: 1_000,
                script: vec![seed; 32],
                datum: None,
                datum_hash: None,
            },
            TxOutput {
                value: 1_000,
                script: vec![seed.wrapping_add(1); 32],
                datum: None,
                datum_hash: None,
            },
        ],
        witnesses: vec![TxWitness {
            witness: vec![seed],
            redeemer: None,
        }],
    }
}

#[test]
fn commit_reorg_atomic_reverts_orphan_spends_and_applies_new_canonical() {
    let (storage, _dir) = open_storage();

    // Genesis: one coinbase with two outputs (cb0,0) and (cb0,1).
    let cb0 = coinbase_tx_2out(0x01);
    let cb0_tx_id = cb0.tx_id().unwrap();
    let genesis = block_with(0, Hash256::ZERO, vec![cb0.clone()]);
    let mut utxos = UtxoSet::new();
    let g_muts = utxos.apply_transaction(&cb0, 0).unwrap();
    storage
        .commit_genesis_atomic(&genesis, &[0u8; 32], &g_muts)
        .unwrap();

    // Orphan-fork block 1: spends BOTH genesis outputs.
    let cb1_a = coinbase_tx(0x02);
    let spend_a0 = spend_tx(cb0_tx_id, 0, vec![0xA0; 32]);
    let spend_a1 = spend_tx(cb0_tx_id, 1, vec![0xA1; 32]);
    let spend_a0_tx_id = spend_a0.tx_id().unwrap();
    let mut a_muts = Vec::new();
    a_muts.extend(utxos.apply_transaction(&cb1_a, 1).unwrap());
    a_muts.extend(utxos.apply_transaction(&spend_a0, 1).unwrap());
    a_muts.extend(utxos.apply_transaction(&spend_a1, 1).unwrap());
    let a_spent: Vec<_> = UtxoMutation::collect_spent_utxos(&a_muts);
    let b1_old = block_with(
        1,
        genesis.header.block_id(),
        vec![cb1_a, spend_a0, spend_a1],
    );
    storage
        .commit_block_atomic(&b1_old, &[1u8; 32], &a_spent, &a_muts)
        .unwrap();

    // Both outputs read back as spent on the orphan fork.
    let pre0 = storage.get_output_spent_by(&cb0_tx_id, 0).unwrap().unwrap();
    assert_eq!(pre0.spending_tx_id, spend_a0_tx_id);
    assert!(storage.get_output_spent_by(&cb0_tx_id, 1).unwrap().is_some());

    // New canonical block 1 (the reorg trigger): re-spends (cb0,0) with a
    // DIFFERENT tx, and does not touch (cb0,1). Distinct nonce so its
    // block_id differs from the orphan's.
    let cb1_b = coinbase_tx(0x03);
    let spend_b0 = spend_tx(cb0_tx_id, 0, vec![0xB0; 32]);
    let spend_b0_tx_id = spend_b0.tx_id().unwrap();
    let mut b1_new = block_with(1, genesis.header.block_id(), vec![cb1_b, spend_b0]);
    b1_new.header.nonce = 99;
    let b1_new_id = b1_new.header.block_id();
    assert_ne!(b1_new_id, b1_old.header.block_id(), "fork blocks must differ");

    storage
        .commit_reorg_atomic(
            &b1_new,
            &[2u8; 32],
            /* old_chain_blocks  */ &[b1_old],
            /* new_chain_spent   */ &[],
            /* new_chain_mutations */ &[],
            /* new_chain_heights */ &[(1, b1_new_id)],
            /* new_chain_blocks  */ &[],
            /* new_chain_work    */ &[],
            /* stale_height_start */ None,
            /* stale_height_end   */ None,
            &b1_new_id,
        )
        .unwrap();

    // (cb0,0): orphan spend reverted, new-canonical spend applied → reads
    // back as the NEW spender, not spend_a0.
    let post0 = storage
        .get_output_spent_by(&cb0_tx_id, 0)
        .unwrap()
        .expect("(cb0,0) is re-spent on the new canonical chain");
    assert_eq!(
        post0.spending_tx_id, spend_b0_tx_id,
        "must read back as the new canonical spender"
    );
    assert_ne!(
        post0.spending_tx_id, spend_a0_tx_id,
        "orphan spender must not survive the reorg"
    );
    assert_eq!(post0.block_height, 1);

    // (cb0,1): spent only on the orphan, never re-spent → reverted to unspent.
    assert!(
        storage.get_output_spent_by(&cb0_tx_id, 1).unwrap().is_none(),
        "an orphan-only spend must read back as unspent after the reorg"
    );
}
