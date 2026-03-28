//! AUDIT-FIXES-10 regression tests.
//!
//! Fix 1 [P0]: jet_slice overflow — saturating_add prevents panic
//! Fix 2 [P1]: Wall-clock timestamp is policy — None skips drift check
//! Fix 3 [P1]: Recursion depth guard — RecursionDepthExceeded error
//! Fix 4 [P2]: Protocol decoder caps — InvalidLength on oversized counts
//! Fix 5 [P2]: IBD strict block responses — non-BlockResponse aborts sync

// ── Fix 1: jet_slice overflow ──────────────────────────────────────

mod jet_slice_overflow_tests {
    use exfer::script::jets::bytes::jet_slice;
    use exfer::script::value::Value;

#[test]
    fn slice_max_start_and_len_no_panic() {
        // start + len would overflow usize on 64-bit, but saturating_add clamps
        let data = vec![1u8, 2, 3, 4];
        let input = Value::Pair(
            Box::new(Value::Bytes(data)),
            Box::new(Value::Pair(
                Box::new(Value::U64(u64::MAX)),
                Box::new(Value::U64(u64::MAX)),
            )),
        );
        // Should not panic; start > data.len() → empty result
        let result = jet_slice(&input).unwrap();
        assert_eq!(result, Value::Bytes(vec![]));
    }

#[test]
    fn slice_large_len_no_panic() {
        let data = vec![10u8; 100];
        let input = Value::Pair(
            Box::new(Value::Bytes(data)),
            Box::new(Value::Pair(
                Box::new(Value::U64(50)),
                Box::new(Value::U64(u64::MAX)),
            )),
        );
        let result = jet_slice(&input).unwrap();
        // start=50, len=MAX → clamped to bytes.len()=100
        assert_eq!(result, Value::Bytes(vec![10u8; 50]));
    }

#[test]
    fn slice_normal_case_still_works() {
        let data = vec![0, 1, 2, 3, 4, 5, 6, 7];
        let input = Value::Pair(
            Box::new(Value::Bytes(data)),
            Box::new(Value::Pair(
                Box::new(Value::U64(2)),
                Box::new(Value::U64(3)),
            )),
        );
        let result = jet_slice(&input).unwrap();
        assert_eq!(result, Value::Bytes(vec![2, 3, 4]));
    }

#[test]
    fn slice_start_beyond_end_returns_empty() {
        let data = vec![1, 2, 3];
        let input = Value::Pair(
            Box::new(Value::Bytes(data)),
            Box::new(Value::Pair(
                Box::new(Value::U64(100)),
                Box::new(Value::U64(5)),
            )),
        );
        let result = jet_slice(&input).unwrap();
        assert_eq!(result, Value::Bytes(vec![]));
    }
}

// ── Fix 2: Wall-clock timestamp as policy ──────────────────────────

#[cfg(feature = "testnet")]
mod wall_clock_policy_tests {
    use exfer::consensus::validation::{compute_tx_root, validate_block_header};
    use exfer::types::block::{Block, BlockHeader};
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};

    fn easy_target() -> Hash256 {
        Hash256([0xFF; 32])
    }

    fn make_coinbase(height: u64) -> Transaction {
        Transaction {
            inputs: vec![TxInput {
                prev_tx_id: Hash256::ZERO,
                output_index: height as u32,
            }],
            outputs: vec![TxOutput {
                value: 100_000_000,
                script: vec![0u8; 32],
                datum: None,
                datum_hash: None,
            }],
            witnesses: vec![TxWitness {
                witness: vec![],
                redeemer: None,
            }],
        }
    }

    fn make_genesis() -> BlockHeader {
        let coinbase = make_coinbase(0);
        let tx_root = compute_tx_root(&[coinbase]).unwrap();
        BlockHeader {
            version: 1,
            height: 0,
            prev_block_id: Hash256::ZERO,
            timestamp: 1_700_000_000,
            difficulty_target: easy_target(),
            nonce: 0,
            tx_root,
            state_root: Hash256::ZERO,
        }
    }

    fn make_child_block(genesis: &BlockHeader, timestamp: u64) -> Block {
        let coinbase = make_coinbase(1);
        let tx_root = compute_tx_root(std::slice::from_ref(&coinbase)).unwrap();
        let mut header = BlockHeader {
            version: 1,
            height: 1,
            prev_block_id: genesis.block_id(),
            timestamp,
            difficulty_target: easy_target(),
            nonce: 0,
            tx_root,
            state_root: Hash256::ZERO,
        };

        for n in 0..u64::MAX {
            header.nonce = n;
            if exfer::consensus::pow::verify_pow(&header).unwrap() {
                break;
            }
        }

        Block {
            header,
            transactions: vec![coinbase],
        }
    }

#[test]
    fn none_wall_clock_skips_drift_check() {
        let genesis = make_genesis();
        // Timestamp far in the future but within MAX_TIMESTAMP_GAP of parent
        let block = make_child_block(&genesis, genesis.timestamp + 500_000);

        let ancestor_timestamps = vec![genesis.timestamp];

        // With wall_clock=None, the drift check is skipped entirely
        let result = validate_block_header(
            &block,
            Some(&genesis),
            &ancestor_timestamps,
            &easy_target(),
            None,
        );
        assert!(
            result.is_ok(),
            "None wall_clock should skip drift check: {:?}",
            result.err()
        );
    }

#[test]
    fn some_wall_clock_enforces_drift_check() {
        let genesis = make_genesis();
        // Timestamp in the future but within MAX_TIMESTAMP_GAP
        let block = make_child_block(&genesis, genesis.timestamp + 500_000);

        let ancestor_timestamps = vec![genesis.timestamp];

        // wall_clock = genesis.timestamp, block is 500_000s ahead >> MAX_TIMESTAMP_DRIFT (120)
        let result = validate_block_header(
            &block,
            Some(&genesis),
            &ancestor_timestamps,
            &easy_target(),
            Some(genesis.timestamp),
        );
        assert!(
            result.is_err(),
            "Some(wall_clock) should enforce drift check"
        );
    }

#[test]
    fn some_wall_clock_passes_when_within_drift() {
        let genesis = make_genesis();
        let block = make_child_block(&genesis, genesis.timestamp + 50);

        let ancestor_timestamps = vec![genesis.timestamp];

        let result = validate_block_header(
            &block,
            Some(&genesis),
            &ancestor_timestamps,
            &easy_target(),
            Some(genesis.timestamp + 60), // wall_clock 60s after genesis
        );
        assert!(
            result.is_ok(),
            "Within-drift timestamp should pass: {:?}",
            result.err()
        );
    }
}

// ── Fix 3: Recursion depth guard ───────────────────────────────────

mod recursion_depth_tests {
    use exfer::script::ast::{Combinator, Program};
    use exfer::script::eval::{evaluate_with_context, Budget, EvalError};
    use exfer::script::jets::context::ScriptContext;
    use exfer::script::value::Value;

#[test]
    fn deep_comp_chain_exceeds_depth_limit() {
        // Build a program with Comp(Comp(Comp(...Iden...))) 200 levels deep.
        // This should trigger RecursionDepthExceeded (limit=128) before exhausting the stack.
        // Root at 0, Iden at the end.
        let depth = 200u32;
        let iden_idx = depth;
        let mut nodes = Vec::with_capacity((depth + 1) as usize);
        for i in 0..depth {
            nodes.push(Combinator::Comp(i + 1, iden_idx));
        }
        nodes.push(Combinator::Iden);
        let program = Program { nodes, root: 0 };

        let mut budget = Budget::new(1_000_000, 1_000_000);
        let result = evaluate_with_context(
            &program,
            Value::Unit,
            &[],
            &mut budget,
            &ScriptContext::empty(),
        );

        assert!(
            matches!(result, Err(EvalError::RecursionDepthExceeded)),
            "Expected RecursionDepthExceeded, got {:?}",
            result
        );
    }

#[test]
    fn shallow_program_succeeds() {
        // Simple Comp(Iden, Iden) — depth 3, well within limit
        // Root at 0, children at higher indices
        let program = Program {
            nodes: vec![
                Combinator::Comp(1, 1), // node 0: root
                Combinator::Iden,       // node 1: leaf
            ],
            root: 0,
        };
        let mut budget = Budget::new(1_000, 1_000);
        let result = evaluate_with_context(
            &program,
            Value::Unit,
            &[],
            &mut budget,
            &ScriptContext::empty(),
        );
        assert!(
            result.is_ok(),
            "Shallow program should succeed: {:?}",
            result.err()
        );
    }

#[test]
    fn depth_at_limit_succeeds() {
        // Build a chain of exactly 128 Comp nodes — should be at the limit but succeed
        // Root at 0, Iden at the end. Comp(i) references i+1 and last_iden.
        let depth = 128u32;
        let iden_idx = depth; // Iden is the last node
        let mut nodes = Vec::with_capacity((depth + 1) as usize);
        for i in 0..depth {
            nodes.push(Combinator::Comp(i + 1, iden_idx));
        }
        nodes.push(Combinator::Iden); // iden_idx
        let program = Program { nodes, root: 0 };

        let mut budget = Budget::new(1_000_000, 1_000_000);
        let result = evaluate_with_context(
            &program,
            Value::Unit,
            &[],
            &mut budget,
            &ScriptContext::empty(),
        );
        assert!(
            result.is_ok(),
            "Depth exactly at limit should succeed: {:?}",
            result.err()
        );
    }

#[test]
    fn depth_just_over_limit_fails() {
        // Build a chain of 129 Comp nodes — should exceed the limit
        let depth = 129u32;
        let iden_idx = depth;
        let mut nodes = Vec::with_capacity((depth + 1) as usize);
        for i in 0..depth {
            nodes.push(Combinator::Comp(i + 1, iden_idx));
        }
        nodes.push(Combinator::Iden);
        let program = Program { nodes, root: 0 };

        let mut budget = Budget::new(1_000_000, 1_000_000);
        let result = evaluate_with_context(
            &program,
            Value::Unit,
            &[],
            &mut budget,
            &ScriptContext::empty(),
        );
        assert!(
            matches!(result, Err(EvalError::RecursionDepthExceeded)),
            "Depth just over limit should fail: {:?}",
            result
        );
    }
}

// ── Fix 4: Protocol decoder caps ───────────────────────────────────

mod protocol_decoder_cap_tests {
    use exfer::network::protocol::Message;

    fn make_wire_message(msg_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(5 + payload.len());
        data.push(msg_type);
        data.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        data.extend_from_slice(payload);
        data
    }

#[test]
    fn oversized_hash_list_rejected() {
        // Construct a GetBlocks payload claiming 1000 hashes (MAX_GETBLOCKS_ITEMS = 64).
        // The count cap rejects before checking payload length, so we just need count bytes
        // plus enough padding that the payload_len check in deserialize passes.
        let count: u32 = 1000;
        let mut payload = Vec::new();
        payload.extend_from_slice(&count.to_le_bytes());
        // Pad with enough zeros so that the top-level payload_len check passes,
        // but the hash_list deserializer hits the count cap first.
        payload.extend_from_slice(&vec![0u8; count as usize * 32]);

        let wire = make_wire_message(0x11, &payload); // 0x11 = MSG_GET_BLOCKS
        let result = Message::deserialize(&wire);
        assert!(result.is_err(), "Oversized hash list should be rejected");
    }

#[test]
    fn valid_hash_list_accepted() {
        // 2 hashes — well within limit
        let count: u32 = 2;
        let mut payload = Vec::new();
        payload.extend_from_slice(&count.to_le_bytes());
        payload.extend_from_slice(&[0u8; 64]); // 2 × 32 bytes

        let wire = make_wire_message(0x11, &payload);
        let result = Message::deserialize(&wire);
        assert!(
            result.is_ok(),
            "Small hash list should succeed: {:?}",
            result.err()
        );
    }

#[test]
    fn oversized_headers_list_rejected() {
        let count: u32 = 1000;
        let mut payload = Vec::new();
        payload.extend_from_slice(&count.to_le_bytes());
        payload.extend_from_slice(&vec![0u8; count as usize * 156]);

        let wire = make_wire_message(0x22, &payload); // 0x22 = MSG_HEADERS
        let result = Message::deserialize(&wire);
        assert!(result.is_err(), "Oversized headers list should be rejected");
    }

#[test]
    fn inv_list_cap_applied() {
        // Inv messages also use deserialize_hash_list
        let count: u32 = 1000;
        let mut payload = Vec::new();
        payload.extend_from_slice(&count.to_le_bytes());
        payload.extend_from_slice(&vec![0u8; count as usize * 32]);

        let wire = make_wire_message(0x15, &payload); // 0x15 = MSG_INV
        let result = Message::deserialize(&wire);
        assert!(result.is_err(), "Oversized inv list should be rejected");
    }
}

// ── Fix 5: IBD strict block responses ──────────────────────────────
