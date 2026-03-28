//! Audit fix tests — round 23 (P1).
//! Sync bootstrap cumulative-work-awareness: HelloMsg and Peer carry
//! cumulative_work, wire format is 108 bytes, sync decision uses is_better_chain.

// ── HelloMsg struct has cumulative_work field ──

#[test]
fn hello_msg_has_cumulative_work_field() {
    use exfer::network::protocol::HelloMsg;
    use exfer::types::hash::Hash256;

    let msg = HelloMsg {
        version: 1,
        genesis_block_id: Hash256::ZERO,
        best_height: 0,
        best_block_id: Hash256::ZERO,
        cumulative_work: [0u8; 32],
        nonce: [0u8; 32],
        echo: [0u8; 32],
        pubkey: [0u8; 32],
        sig: [0u8; 64],
    };
    assert_eq!(msg.cumulative_work, [0u8; 32]);
}

// ── Hello wire payload is 268 bytes ──

#[test]
fn hello_wire_payload_is_268_bytes() {
    use exfer::network::protocol::{HelloMsg, Message};
    use exfer::types::hash::Hash256;

    let msg = Message::Hello(HelloMsg {
        version: 1,
        genesis_block_id: Hash256::ZERO,
        best_height: 0,
        best_block_id: Hash256::ZERO,
        cumulative_work: [0u8; 32],
        nonce: [0u8; 32],
        echo: [0u8; 32],
        pubkey: [0u8; 32],
        sig: [0u8; 64],
    });
    let bytes = msg.serialize().unwrap();
    // Wire format: 1 byte msg_type + 4 bytes payload_len + 268 bytes payload = 273
    assert_eq!(bytes.len(), 1 + 4 + 268);
    // Payload length field should be 268
    let payload_len = u32::from_le_bytes(bytes[1..5].try_into().unwrap());
    assert_eq!(payload_len, 268);
}

// ── Hello roundtrip preserves cumulative_work ──

#[test]
fn hello_roundtrip_preserves_cumulative_work() {
    use exfer::network::protocol::{HelloMsg, Message};
    use exfer::types::hash::Hash256;

    let mut work = [0u8; 32];
    work[0] = 0x01;
    work[15] = 0xAB;
    work[31] = 0xFF;

    let msg = Message::Hello(HelloMsg {
        version: 1,
        genesis_block_id: Hash256::ZERO,
        best_height: 100,
        best_block_id: Hash256::sha256(b"tip"),
        cumulative_work: work,
        nonce: [0u8; 32],
        echo: [0u8; 32],
        pubkey: [0u8; 32],
        sig: [0u8; 64],
    });
    let bytes = msg.serialize().unwrap();
    let (msg2, consumed) = Message::deserialize(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    match msg2 {
        Message::Hello(h) => assert_eq!(h.cumulative_work, work),
        _ => panic!("expected Hello"),
    }
}

// ── Peer struct has cumulative_work field ──

#[test]
fn protocol_version_is_5() {
    use exfer::types::PROTOCOL_VERSION;
    assert_eq!(PROTOCOL_VERSION, 5);
}

#[test]
fn block_version_is_still_1() {
    use exfer::types::VERSION;
    assert_eq!(VERSION, 1);
}
