//! AUDIT-FIXES-11 regression tests.
//!
//! Fix 1 [P1]: Sync/IBD passes Some(now) wall_clock for future-timestamp check
//! Fix 2 [P2]: Inbound peer cap reserved atomically before handshake
//! Fix 3 [P2]: Trailing bytes rejected in list-based protocol decoders

// ── Fix 1: wall_clock None during sync ─────────────────────────────

mod sync_wall_clock_tests {
    use exfer::network::protocol::Message;

    fn make_wire_message(msg_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(5 + payload.len());
        data.push(msg_type);
        data.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        data.extend_from_slice(payload);
        data
    }

#[test]
    fn hash_list_rejects_trailing_bytes() {
        // GetBlocks (0x11) with 1 hash + 1 trailing byte
        let count: u32 = 1;
        let mut payload = Vec::new();
        payload.extend_from_slice(&count.to_le_bytes());
        payload.extend_from_slice(&[0u8; 32]); // 1 hash
        payload.push(0xFF); // trailing byte

        let wire = make_wire_message(0x11, &payload);
        let result = Message::deserialize(&wire);
        assert!(
            result.is_err(),
            "hash list with trailing byte should be rejected"
        );
    }

#[test]
    fn hash_list_exact_size_accepted() {
        // GetBlocks with exactly 1 hash, no trailing bytes
        let count: u32 = 1;
        let mut payload = Vec::new();
        payload.extend_from_slice(&count.to_le_bytes());
        payload.extend_from_slice(&[0u8; 32]);

        let wire = make_wire_message(0x11, &payload);
        let result = Message::deserialize(&wire);
        assert!(
            result.is_ok(),
            "exact-size hash list should succeed: {:?}",
            result.err()
        );
    }

#[test]
    fn inv_rejects_trailing_bytes() {
        // Inv (0x15) with 2 hashes + trailing bytes
        let count: u32 = 2;
        let mut payload = Vec::new();
        payload.extend_from_slice(&count.to_le_bytes());
        payload.extend_from_slice(&[0u8; 64]); // 2 hashes
        payload.extend_from_slice(&[0xAB; 10]); // trailing garbage

        let wire = make_wire_message(0x15, &payload);
        let result = Message::deserialize(&wire);
        assert!(
            result.is_err(),
            "inv with trailing bytes should be rejected"
        );
    }

#[test]
    fn headers_reject_trailing_bytes() {
        // Headers (0x22) with 1 header (156 bytes) + trailing byte
        let count: u32 = 1;
        let mut payload = Vec::new();
        payload.extend_from_slice(&count.to_le_bytes());
        payload.extend_from_slice(&[0u8; 156]); // 1 header
        payload.push(0xFF); // trailing byte

        let wire = make_wire_message(0x22, &payload);
        let result = Message::deserialize(&wire);
        assert!(
            result.is_err(),
            "headers with trailing byte should be rejected"
        );
    }

#[test]
    fn headers_exact_size_accepted() {
        // Headers with exactly 1 header, no trailing bytes
        let count: u32 = 1;
        let mut payload = Vec::new();
        payload.extend_from_slice(&count.to_le_bytes());
        payload.extend_from_slice(&[0u8; 156]);

        let wire = make_wire_message(0x22, &payload);
        let result = Message::deserialize(&wire);
        assert!(
            result.is_ok(),
            "exact-size headers should succeed: {:?}",
            result.err()
        );
    }

#[test]
    fn tip_response_rejects_trailing_bytes() {
        // TipResponse (0x14) should be exactly 72 bytes (v5: height + block_id + cumulative_work)
        let mut payload = vec![0u8; 72];
        payload.push(0xFF); // trailing byte

        let wire = make_wire_message(0x14, &payload);
        let result = Message::deserialize(&wire);
        assert!(
            result.is_err(),
            "tip response with trailing byte should be rejected"
        );
    }

#[test]
    fn tip_response_exact_size_accepted() {
        let payload = vec![0u8; 72];
        let wire = make_wire_message(0x14, &payload);
        let result = Message::deserialize(&wire);
        assert!(
            result.is_ok(),
            "exact-size tip response should succeed: {:?}",
            result.err()
        );
    }

#[test]
    fn get_headers_rejects_trailing_bytes() {
        // GetHeaders (0x21) should be exactly 12 bytes
        let mut payload = vec![0u8; 12];
        payload.push(0xFF); // trailing byte

        let wire = make_wire_message(0x21, &payload);
        let result = Message::deserialize(&wire);
        assert!(
            result.is_err(),
            "get_headers with trailing byte should be rejected"
        );
    }

#[test]
    fn get_headers_exact_size_accepted() {
        let payload = vec![0u8; 12];
        let wire = make_wire_message(0x21, &payload);
        let result = Message::deserialize(&wire);
        assert!(
            result.is_ok(),
            "exact-size get_headers should succeed: {:?}",
            result.err()
        );
    }

#[test]
    fn empty_hash_list_exact_size() {
        // 0 hashes — payload should be exactly 4 bytes (count only)
        let count: u32 = 0;
        let mut payload = Vec::new();
        payload.extend_from_slice(&count.to_le_bytes());

        let wire = make_wire_message(0x11, &payload);
        let result = Message::deserialize(&wire);
        assert!(
            result.is_ok(),
            "empty hash list should succeed: {:?}",
            result.err()
        );
    }
}
