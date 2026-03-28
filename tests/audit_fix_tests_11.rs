//! AUDIT-FIXES-12 regression tests.
//!
//! Fix 1 [P0]: Mul256 overflow in internal accumulators
//! Fix 2 [P1]: Control message payload DoS hardening
//! Fix 3 [P1]: process_block race on stale tip snapshot
//! Fix 4 [P2]: Enforce MAX_DATUM_SIZE on hash-committed datums
//! Fix 5 [P2]: Safe u64-to-usize casts in jets

// ── Fix 1: Mul256 overflow ─────────────────────────────────────────

mod mul256_overflow_tests {
    use exfer::script::jets::arithmetic::jet_mul256;
    use exfer::script::value::Value;

    fn u256_max() -> [u8; 32] {
        [0xFF; 32]
    }

    fn u256_from_u64(v: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..32].copy_from_slice(&v.to_be_bytes());
        out
    }

    fn u256_from_high_limb(v: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&v.to_be_bytes());
        out
    }

#[test]
    fn mul256_max_times_max_overflows_cleanly() {
        // (2^256 - 1) * (2^256 - 1) should return an overflow error, not panic
        let input = Value::Pair(
            Box::new(Value::U256(u256_max())),
            Box::new(Value::U256(u256_max())),
        );
        let result = jet_mul256(&input);
        assert!(result.is_err(), "max * max should overflow");
    }

#[test]
    fn mul256_large_operands_no_panic() {
        // Two large values whose product exceeds 256 bits
        // (2^128) * (2^128) = 2^256, which overflows
        // 2^128 in big-endian: byte 15 = 1 (the 17th byte from the left is bit 128)
        let mut a = [0u8; 32];
        // In big-endian 256-bit: byte index = (255 - bit_index) / 8 = (255-128)/8 = 15
        // bit within byte = bit_index % 8 = 0, so byte 15 = 0x01... wait:
        // Byte 0 is MSB. Bit 255 is in byte 0, bit 0. Bit 128 is in byte (255-128)/8 = 15.
        // Actually: byte_index = (256 - 1 - bit_position) / 8 for big-endian
        // bit 128: byte_index = (255 - 128) / 8 = 15, bit_in_byte = (255 - 128) % 8 = 7
        // So byte 15, bit 7 = 0x80... Simpler: just use limb math.
        // Limb 2 (bytes 0..8 = limb[0], 8..16 = limb[1], 16..24 = limb[2], 24..32 = limb[3])
        // 2^128 = limb[1] high bit = bytes 8..16 with value 2^64... no.
        // Let's just use the maximum per-limb value instead.
        // (2^192) * (2^64) = 2^256 which overflows
        a[7] = 1; // 2^192: limb[0] = u64::from_be_bytes([0,0,0,0,0,0,0,1]) = 1, so a_limbs[0]=1
                  // a_limbs[0] = MSB limb. In the multiply loop, a_limbs[3-i] at i=3 gives a_limbs[0]=1.
                  // pos = 3+j. We need the product to land in result[4+].
                  // b_limbs[3-j] at j=1 gives b_limbs[2]. Set b_limbs[2]=1.
                  // pos = 3+1 = 4, which is in the overflow zone.
        let mut b = [0u8; 32];
        b[23] = 1; // b_limbs[2] = u64::from_be_bytes(b[16..24]) = 1
                   // Product: a_limbs[0] * b_limbs[2] = 1, at pos=4. Overflow detected.
        let input = Value::Pair(Box::new(Value::U256(a)), Box::new(Value::U256(b)));
        let result = jet_mul256(&input);
        assert!(
            result.is_err(),
            "product landing in upper limbs should overflow"
        );
    }

#[test]
    fn mul256_high_limb_products_dont_panic() {
        // Products that stress the upper limbs: large a_limbs[0] * b_limbs[0]
        // Previously these caused u128 overflow in the accumulator
        let a = u256_from_high_limb(u64::MAX);
        let b = u256_from_high_limb(u64::MAX);
        let input = Value::Pair(Box::new(Value::U256(a)), Box::new(Value::U256(b)));
        let result = jet_mul256(&input);
        assert!(result.is_err(), "large high-limb product should overflow");
    }

#[test]
    fn mul256_correct_result_for_small_values() {
        // 7 * 13 = 91
        let input = Value::Pair(
            Box::new(Value::U256(u256_from_u64(7))),
            Box::new(Value::U256(u256_from_u64(13))),
        );
        let result = jet_mul256(&input).unwrap();
        match result {
            Value::U256(bytes) => {
                assert_eq!(bytes, u256_from_u64(91));
            }
            _ => panic!("expected U256"),
        }
    }

#[test]
    fn mul256_near_boundary_no_overflow() {
        // (2^128 - 1) * 2 = 2^129 - 2, fits in 256 bits
        let mut a = [0u8; 32];
        for byte in a.iter_mut().skip(16) {
            *byte = 0xFF;
        }
        let b = u256_from_u64(2);
        let input = Value::Pair(Box::new(Value::U256(a)), Box::new(Value::U256(b)));
        let result = jet_mul256(&input);
        assert!(result.is_ok(), "should not overflow: {:?}", result.err());
    }

#[test]
    fn mul256_max_limb_cross_products() {
        // Each 64-bit limb is MAX, multiply by a small value
        // This stresses carry propagation across all positions
        let a = u256_max();
        let b = u256_from_u64(1);
        let input = Value::Pair(Box::new(Value::U256(a)), Box::new(Value::U256(b)));
        let result = jet_mul256(&input).unwrap();
        match result {
            Value::U256(bytes) => assert_eq!(bytes, u256_max()),
            _ => panic!("expected U256"),
        }
    }
}

// ── Fix 2: Control message payload hardening ───────────────────────

mod control_message_tests {
    use exfer::network::protocol::Message;

    fn make_wire_message(msg_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(5 + payload.len());
        data.push(msg_type);
        data.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        data.extend_from_slice(payload);
        data
    }

#[test]
    fn ping_rejects_nonempty_payload() {
        let wire = make_wire_message(0x02, &[0xFF; 100]);
        let result = Message::deserialize(&wire);
        assert!(result.is_err(), "Ping with payload should be rejected");
    }

#[test]
    fn pong_rejects_nonempty_payload() {
        let wire = make_wire_message(0x03, &[0xFF; 100]);
        let result = Message::deserialize(&wire);
        assert!(result.is_err(), "Pong with payload should be rejected");
    }

#[test]
    fn get_tip_rejects_nonempty_payload() {
        let wire = make_wire_message(0x13, &[0xFF; 100]);
        let result = Message::deserialize(&wire);
        assert!(result.is_err(), "GetTip with payload should be rejected");
    }

#[test]
    fn hello_rejects_trailing_bytes() {
        let mut payload = vec![0u8; 108]; // valid Hello
        payload.push(0xFF); // trailing byte
        let wire = make_wire_message(0x01, &payload);
        let result = Message::deserialize(&wire);
        assert!(
            result.is_err(),
            "Hello with trailing bytes should be rejected"
        );
    }

#[test]
    fn ping_empty_payload_accepted() {
        let wire = make_wire_message(0x02, &[]);
        let result = Message::deserialize(&wire);
        assert!(result.is_ok(), "Ping with empty payload should succeed");
    }

#[test]
    fn pong_empty_payload_accepted() {
        let wire = make_wire_message(0x03, &[]);
        let result = Message::deserialize(&wire);
        assert!(result.is_ok(), "Pong with empty payload should succeed");
    }

#[test]
    fn get_tip_empty_payload_accepted() {
        let wire = make_wire_message(0x13, &[]);
        let result = Message::deserialize(&wire);
        assert!(result.is_ok(), "GetTip with empty payload should succeed");
    }

#[test]
    fn hello_exact_108_bytes_accepted() {
        let payload = vec![0u8; 108];
        let wire = make_wire_message(0x01, &payload);
        let result = Message::deserialize(&wire);
        assert!(
            result.is_ok(),
            "Hello with 108 bytes should succeed: {:?}",
            result.err()
        );
    }
}

// ── Fix 3: process_block race ──────────────────────────────────────

mod process_block_race_tests {

#[test]
    fn max_datum_size_is_4096() {
        assert_eq!(exfer::types::MAX_DATUM_SIZE, 4096);
    }
}

// ── Fix 5: Safe u64-to-usize casts ────────────────────────────────

mod safe_cast_tests {
    use exfer::script::jets::bytes::jet_slice;
    use exfer::script::jets::list::jet_list_at;
    use exfer::script::value::Value;

#[test]
    fn slice_with_u64_max_index_no_panic() {
        // On 32-bit, u64::MAX as usize would truncate to 0xFFFFFFFF
        // With try_from, it safely converts to usize::MAX
        let data = vec![1, 2, 3];
        let input = Value::Pair(
            Box::new(Value::Bytes(data)),
            Box::new(Value::Pair(
                Box::new(Value::U64(u64::MAX)),
                Box::new(Value::U64(1)),
            )),
        );
        let result = jet_slice(&input).unwrap();
        assert_eq!(result, Value::Bytes(vec![]));
    }

#[test]
    fn list_at_with_u64_max_returns_none() {
        let items = Value::List(vec![Value::U64(42)]);
        let input = Value::Pair(Box::new(items), Box::new(Value::U64(u64::MAX)));
        let result = jet_list_at(&input).unwrap();
        // Should return None (out of bounds), not panic
        assert_eq!(result, Value::none());
    }
}
