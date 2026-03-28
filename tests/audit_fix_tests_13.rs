//! AUDIT-FIXES-14 regression tests.
//!
//! Fix 1 [P1]: Per-transaction script budget cap (MAX_TX_SCRIPT_BUDGET)
//! Fix 2 [P1]: IBD sync only counts Ok(true) as progress
//! Fix 3 [P1]: Outbound peer slot leak on sync failure
//! Fix 4 [P2]: IBD returns errors on bad peer behavior
//! Fix 5 [P2]: Atomic storage commits for crash consistency

// ── Fix 1: Per-transaction script budget cap ─────────────────────────

mod tx_script_budget_tests {

#[test]
    fn max_tx_script_budget_constant_exists() {
        assert_eq!(exfer::types::MAX_TX_SCRIPT_BUDGET, 20_000_000);
    }

#[test]
    fn max_tx_script_budget_exceeds_per_input_cap() {
        // Per-tx budget must be >= per-input cap (otherwise no single input could pass)
        assert!(
            exfer::types::MAX_TX_SCRIPT_BUDGET >= exfer::types::MAX_SCRIPT_STEPS as u128,
            "per-tx budget must be >= per-input cap"
        );
    }

#[test]
    fn commit_block_atomic_round_trip() {
        // Functional: commit_block_atomic writes all data recoverable by individual reads
        use exfer::chain::storage::ChainStorage;
        use exfer::types::block::{Block, BlockHeader};
        use exfer::types::hash::Hash256;
        use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};
        use tempfile::TempDir;

        let tmpdir = TempDir::new().unwrap();
        let db_path = tmpdir.path().join("test.redb");
        let storage = ChainStorage::open(&db_path).unwrap();

        let coinbase = Transaction {
            inputs: vec![TxInput {
                prev_tx_id: Hash256::ZERO,
                output_index: 0,
            }],
            outputs: vec![TxOutput::new_p2pkh(10_000_000_000, &[1u8; 32])],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        };

        let block = Block {
            header: BlockHeader {
                version: 1,
                height: 1,
                prev_block_id: Hash256::ZERO,
                timestamp: 1700000000,
                difficulty_target: Hash256([0xFF; 32]),
                nonce: 42,
                tx_root: Hash256::ZERO,
                state_root: Hash256::ZERO,
            },
            transactions: vec![coinbase],
        };

        let block_id = block.header.block_id();
        let work = [0x01u8; 32];

        storage.commit_block_atomic(&block, &work, &[]).unwrap();

        // Verify all data was written
        assert!(storage.has_block(&block_id).unwrap());
        assert_eq!(
            storage.get_header(&block_id).unwrap().unwrap(),
            block.header
        );
        assert_eq!(
            storage.get_cumulative_work(&block_id).unwrap().unwrap(),
            work
        );
        assert_eq!(
            storage.get_block_id_by_height(1).unwrap().unwrap(),
            block_id
        );
        assert_eq!(storage.get_tip().unwrap().unwrap(), block_id);
    }
}
