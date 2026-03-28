//! Behavioral tests for the three fixes:
//!
//! 1. Retarget ancestor recovery returns actual missing ancestor hash
//! 2. Global pending_reorg_triggers cap evicts oldest entries

use exfer::chain::storage::ChainStorage;
use exfer::consensus::difficulty::{expected_difficulty, genesis_target, DifficultyError};
use exfer::types::block::{Block, BlockHeader};
use exfer::types::hash::Hash256;
use exfer::types::RETARGET_WINDOW;
use tempfile::TempDir;

// ── Fix 1: Retarget ancestor recovery returns the actual missing hash ──

/// Build a chain of `count` blocks (heights 0..count-1) with linked prev_block_id.
/// Returns Vec<Block> where blocks[i] has height i.
fn build_chain(count: u64) -> Vec<Block> {
    let target = genesis_target();
    let mut blocks: Vec<Block> = Vec::with_capacity(count as usize);

    for h in 0..count {
        let prev_id = if h == 0 {
            Hash256::ZERO
        } else {
            blocks[h as usize - 1].header.block_id()
        };
        let block = Block {
            header: BlockHeader {
                version: 1,
                height: h,
                prev_block_id: prev_id,
                timestamp: 1_740_000_000 + h * 10,
                difficulty_target: target,
                nonce: h, // unique nonce per block
                tx_root: Hash256::ZERO,
                state_root: Hash256::ZERO,
            },
            transactions: vec![],
        };
        blocks.push(block);
    }
    blocks
}

#[test]
fn retarget_missing_deep_ancestor_returns_actual_hash() {
    // Build a chain of RETARGET_WINDOW+1 blocks (heights 0..RETARGET_WINDOW).
    // Store all except one deep ancestor in the middle.
    // Call expected_difficulty for the retarget boundary (height = RETARGET_WINDOW).
    // Verify the error contains the hash of the ACTUALLY missing block,
    // not the parent of the block being verified.

    let chain = build_chain(RETARGET_WINDOW + 1);

    let tmpdir = TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");
    let storage = ChainStorage::open(&db_path).unwrap();

    // The missing block: somewhere deep in the chain, say height 1000
    let missing_height = 1000usize;
    let missing_block_id = chain[missing_height].header.block_id();

    // Store all blocks EXCEPT the one at missing_height
    for (i, block) in chain.iter().enumerate() {
        if i == missing_height {
            continue;
        }
        storage.store_block(block).unwrap();
    }

    // Now call expected_difficulty for the retarget boundary.
    // prev_block_id = block at height RETARGET_WINDOW - 1
    let prev_block_id = chain[RETARGET_WINDOW as usize - 1].header.block_id();

    let result = expected_difficulty(&storage, &prev_block_id, RETARGET_WINDOW);
    assert!(
        result.is_err(),
        "expected_difficulty should fail with missing ancestor"
    );

    match result.unwrap_err() {
        DifficultyError::AncestorNotFound(hash) => {
            // The error must contain the hash of the ACTUALLY missing block,
            // not the parent of the block being verified.
            assert_eq!(
                hash, missing_block_id,
                "AncestorNotFound must report the actual missing block hash (height {}), \
                 not the parent of the queried block. Got: {}, Expected: {}",
                missing_height, hash, missing_block_id
            );
            // Crucially, it must NOT be the prev_block_id we passed in
            assert_ne!(
                hash, prev_block_id,
                "AncestorNotFound must NOT be the prev_block_id (parent of queried block)"
            );
        }
        DifficultyError::Other(s) => {
            panic!("expected AncestorNotFound, got Other: {}", s);
        }
    }
}

#[test]
fn retarget_missing_parent_returns_parent_hash() {
    // When the immediate parent is missing, AncestorNotFound should
    // correctly identify the parent hash (not some deeper ancestor).
    let chain = build_chain(RETARGET_WINDOW + 1);

    let tmpdir = TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");
    let storage = ChainStorage::open(&db_path).unwrap();

    // Store all blocks except the immediate parent (height RETARGET_WINDOW - 1)
    let parent_height = (RETARGET_WINDOW - 1) as usize;
    let parent_block_id = chain[parent_height].header.block_id();

    for (i, block) in chain.iter().enumerate() {
        if i == parent_height {
            continue;
        }
        storage.store_block(block).unwrap();
    }

    let result = expected_difficulty(&storage, &parent_block_id, RETARGET_WINDOW);
    assert!(result.is_err());

    match result.unwrap_err() {
        DifficultyError::AncestorNotFound(hash) => {
            assert_eq!(
                hash, parent_block_id,
                "when parent itself is missing, AncestorNotFound must report the parent hash"
            );
        }
        DifficultyError::Other(s) => {
            panic!("expected AncestorNotFound, got Other: {}", s);
        }
    }
}

#[test]
fn retarget_all_ancestors_present_succeeds() {
    // Sanity check: with all ancestors present, expected_difficulty succeeds.
    let chain = build_chain(RETARGET_WINDOW + 1);

    let tmpdir = TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");
    let storage = ChainStorage::open(&db_path).unwrap();

    for block in &chain {
        storage.store_block(block).unwrap();
    }

    let prev_block_id = chain[RETARGET_WINDOW as usize - 1].header.block_id();
    let result = expected_difficulty(&storage, &prev_block_id, RETARGET_WINDOW);
    assert!(
        result.is_ok(),
        "expected_difficulty should succeed with all ancestors present: {:?}",
        result.err()
    );
}

// ── Fix 3: Global pending_reorg_triggers cap ──
