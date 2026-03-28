//! AUDIT-FIXES-15 regression tests.
//!
//! Fix 1 [P1]: GetBlocks/GetHeaders rate limiting (MAX_REQUESTS_PER_MIN)
//! Fix 2 [P1]: Genesis PoW validation + mining infrastructure
//! Fix 3 [P1]: Atomic non-winning fork metadata (store_fork_block_atomic)
//! Fix 4 [P2]: Outbound peer cap race (slot reserved before handshake)
//! Fix 5 [P2]: Genesis spec divergence documented

// ── Fix 1: GetBlocks/GetHeaders rate limiting ─────────────────────────

mod request_rate_limit_tests {

#[test]
    fn max_requests_per_min_constant_exists() {
        assert_eq!(exfer::types::MAX_REQUESTS_PER_MIN, 30);
    }

#[cfg(feature = "testnet")]
    #[test]
    fn testnet_genesis_pow_is_valid() {
        // Testnet uses trivial target, so nonce=0 should pass
        use exfer::consensus::pow::verify_pow;
        use exfer::genesis::genesis_block;

        let genesis = genesis_block();
        assert!(
            verify_pow(&genesis.header).unwrap(),
            "testnet genesis PoW should be valid with nonce=0"
        );
    }
}

// ── Fix 3: Atomic non-winning fork metadata ───────────────────────────

mod atomic_fork_metadata_tests {

#[test]
    fn store_fork_block_atomic_round_trip() {
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
                height: 5,
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
        let work = [0x02u8; 32];

        storage.store_fork_block_atomic(&block, &work).unwrap();

        // Verify block was written
        assert!(storage.has_block(&block_id).unwrap());
        assert_eq!(
            storage.get_header(&block_id).unwrap().unwrap(),
            block.header
        );

        // Verify cumulative work was written
        assert_eq!(
            storage.get_cumulative_work(&block_id).unwrap().unwrap(),
            work
        );

        // Height index should NOT be written (fork block is non-canonical)
        assert!(
            storage.get_block_id_by_height(5).unwrap().is_none(),
            "fork block should not appear in height index"
        );
    }
}

// ── Fix 4: Outbound peer cap race ────────────────────────────────────
