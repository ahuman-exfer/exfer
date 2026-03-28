//! Audit R125 tests: P1a (nonce-echo handshake), P1b (peer discovery),
//! P2a (ban persistence), P2b (testnet guard strengthening).

use exfer::chain::storage::ChainStorage;
use exfer::network::protocol::{
    deserialize_hello, is_routable, AddrEntry, HelloMsg, Message, MSG_ADDR, MSG_GET_ADDR,
};
use exfer::types::hash::Hash256;
use exfer::types::*;

use std::net::SocketAddr;
use tempfile::TempDir;

// ═══════════════════════════════════════════════════
// P1a: Liveness Challenge (Nonce-Echo)
// ═══════════════════════════════════════════════════

#[test]
fn p1a_hellomsg_has_nonce() {
    let hello = HelloMsg {
        version: PROTOCOL_VERSION,
        genesis_block_id: Hash256::ZERO,
        best_height: 0,
        best_block_id: Hash256::ZERO,
        cumulative_work: [0u8; 32],
        nonce: [0xAA; 32],
        echo: [0u8; 32],
        pubkey: [0u8; 32],
        sig: [0u8; 64],
    };
    assert_eq!(hello.nonce, [0xAA; 32]);
}

#[test]
fn p1a_hellomsg_has_echo() {
    let hello = HelloMsg {
        version: PROTOCOL_VERSION,
        genesis_block_id: Hash256::ZERO,
        best_height: 0,
        best_block_id: Hash256::ZERO,
        cumulative_work: [0u8; 32],
        nonce: [0u8; 32],
        echo: [0xBB; 32],
        pubkey: [0u8; 32],
        sig: [0u8; 64],
    };
    assert_eq!(hello.echo, [0xBB; 32]);
}

#[test]
fn p1a_hello_serializes_268_bytes() {
    let hello = HelloMsg {
        version: PROTOCOL_VERSION,
        genesis_block_id: Hash256::ZERO,
        best_height: 42,
        best_block_id: Hash256::ZERO,
        cumulative_work: [0u8; 32],
        nonce: [1u8; 32],
        echo: [2u8; 32],
        pubkey: [0u8; 32],
        sig: [0u8; 64],
    };
    let msg = Message::Hello(hello);
    let bytes = msg.serialize().unwrap();
    // msg_type (1) + payload_len (4) + payload (268) = 273
    assert_eq!(bytes.len(), 273);
    let payload_len = u32::from_le_bytes(bytes[1..5].try_into().unwrap());
    assert_eq!(payload_len, 268);
}

#[test]
fn p1a_v2_compat_path() {
    // Wire parser accepts 108-byte legacy payloads (deserialization only).
    // The handshake rejects v2 peers at the protocol version check, but
    // the parser itself is lenient for robustness.
    let mut payload = Vec::with_capacity(108);
    payload.extend_from_slice(&2u32.to_le_bytes()); // version=2
    payload.extend_from_slice(&[0u8; 32]); // genesis
    payload.extend_from_slice(&42u64.to_le_bytes()); // height
    payload.extend_from_slice(&[0u8; 32]); // best_block_id
    payload.extend_from_slice(&[0u8; 32]); // cumulative_work
    assert_eq!(payload.len(), 108);

    let hello = deserialize_hello(&payload).unwrap();
    assert_eq!(hello.version, 2);
    assert_eq!(hello.best_height, 42);
    // Legacy hellos get zero nonce/echo
    assert_eq!(hello.nonce, [0u8; 32]);
    assert_eq!(hello.echo, [0u8; 32]);
}

#[test]
fn p1a_legacy_hello_108_accepted() {
    // Build a 108-byte payload, wrap in Message envelope, deserialize
    let mut payload = Vec::with_capacity(108);
    payload.extend_from_slice(&2u32.to_le_bytes());
    payload.extend_from_slice(&[0u8; 32]); // genesis
    payload.extend_from_slice(&100u64.to_le_bytes()); // height
    payload.extend_from_slice(&[0u8; 32]); // best_block_id
    payload.extend_from_slice(&[0u8; 32]); // cumulative_work

    // Wrap in wire format: msg_type(1) + payload_len(4) + payload
    let mut wire = Vec::with_capacity(5 + payload.len());
    wire.push(0x01); // MSG_HELLO
    wire.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    wire.extend_from_slice(&payload);

    let (msg, consumed) = Message::deserialize(&wire).unwrap();
    assert_eq!(consumed, wire.len());
    match msg {
        Message::Hello(h) => {
            assert_eq!(h.version, 2);
            assert_eq!(h.best_height, 100);
            assert_eq!(h.nonce, [0u8; 32]);
            assert_eq!(h.echo, [0u8; 32]);
        }
        _ => panic!("expected Hello"),
    }
}

#[test]
fn p1a_nonce_mismatch_error() {
    // Verify PeerError::NonceMismatch variant exists and displays correctly
    let err = exfer::network::peer::PeerError::NonceMismatch;
    let msg = format!("{}", err);
    assert!(msg.contains("nonce"));
}

#[test]
fn p1a_version_mismatch_error() {
    // Verify PeerError::VersionMismatch variant exists — used when peer
    // advertises a protocol version below PROTOCOL_VERSION (no downgrade).
    let err = exfer::network::peer::PeerError::VersionMismatch;
    let msg = format!("{}", err);
    assert!(msg.contains("version"));
}

#[test]
fn p1a_handshake_rejects_downgrade() {
    // Verify the handshake code enforces exact version match by inspecting
    // the source. A peer claiming any version != PROTOCOL_VERSION must be
    // rejected (no downgrade, no forward-compat).
    let peer_rs = std::fs::read_to_string("src/network/peer.rs").expect("peer.rs should exist");
    assert!(
        peer_rs.contains("their_hello.version != PROTOCOL_VERSION"),
        "handshake must enforce exact protocol version match"
    );
    // The old v2 compat path that skipped nonce verification must be gone
    assert!(
        !peer_rs.contains("skipping nonce verification"),
        "v2 compat path must be removed — no downgrade allowed"
    );
}

#[test]
fn p1a_hello_roundtrip_v4() {
    let hello = HelloMsg {
        version: PROTOCOL_VERSION,
        genesis_block_id: Hash256::sha256(b"genesis"),
        best_height: 1000,
        best_block_id: Hash256::sha256(b"tip"),
        cumulative_work: {
            let mut w = [0u8; 32];
            w[31] = 42;
            w
        },
        nonce: [0xCC; 32],
        echo: [0xDD; 32],
        pubkey: [0u8; 32],
        sig: [0u8; 64],
    };
    let msg = Message::Hello(hello.clone());
    let bytes = msg.serialize().unwrap();
    let (msg2, consumed) = Message::deserialize(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    match msg2 {
        Message::Hello(h2) => {
            assert_eq!(h2.version, hello.version);
            assert_eq!(h2.genesis_block_id, hello.genesis_block_id);
            assert_eq!(h2.best_height, hello.best_height);
            assert_eq!(h2.nonce, hello.nonce);
            assert_eq!(h2.echo, hello.echo);
        }
        _ => panic!("expected Hello"),
    }
}

// ═══════════════════════════════════════════════════
// P1b: Peer Discovery (Addr/GetAddr)
// ═══════════════════════════════════════════════════

#[test]
fn p1b_getaddr_message_exists() {
    assert_eq!(MSG_GET_ADDR, 0x16);
}

#[test]
fn p1b_addr_message_exists() {
    assert_eq!(MSG_ADDR, 0x17);
}

#[test]
fn p1b_addr_entry_struct() {
    let entry = AddrEntry {
        addr: "1.2.3.4:9333".parse().unwrap(),
        last_seen: 1700000000,
    };
    assert_eq!(entry.addr.port(), 9333);
    assert_eq!(entry.last_seen, 1700000000);
}

#[test]
fn p1b_getaddr_roundtrip() {
    let msg = Message::GetAddr;
    let bytes = msg.serialize().unwrap();
    let (msg2, consumed) = Message::deserialize(&bytes).unwrap();
    assert_eq!(msg, msg2);
    assert_eq!(consumed, bytes.len());
}

#[test]
fn p1b_addr_roundtrip() {
    let entries = vec![
        AddrEntry {
            addr: "1.2.3.4:9333".parse().unwrap(),
            last_seen: 1700000000,
        },
        AddrEntry {
            addr: "5.6.7.8:9334".parse().unwrap(),
            last_seen: 1700000001,
        },
    ];
    let msg = Message::Addr(entries.clone());
    let bytes = msg.serialize().unwrap();
    let (msg2, consumed) = Message::deserialize(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    match msg2 {
        Message::Addr(e2) => {
            assert_eq!(e2.len(), 2);
            assert_eq!(e2[0].addr, entries[0].addr);
            assert_eq!(e2[1].last_seen, entries[1].last_seen);
        }
        _ => panic!("expected Addr"),
    }
}

#[test]
fn p1b_addr_rejects_private_ips() {
    let private_addrs: Vec<SocketAddr> = vec![
        "10.0.0.1:9333".parse().unwrap(),
        "192.168.1.1:9333".parse().unwrap(),
        "127.0.0.1:9333".parse().unwrap(),
        "172.16.0.1:9333".parse().unwrap(),
    ];
    for addr in &private_addrs {
        assert!(!is_routable(addr), "Expected {} to be non-routable", addr);
    }
    // Public IP should be routable
    assert!(is_routable(&"8.8.8.8:9333".parse().unwrap()));
}

#[test]
fn p1b_addr_rejects_port_zero() {
    assert!(!is_routable(&"1.2.3.4:0".parse().unwrap()));
}

#[test]
fn p1b_addr_table_in_storage() {
    let tmpdir = TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");
    let storage = ChainStorage::open(&db_path).unwrap();

    // Write and read back
    let addrs = vec![
        ("1.2.3.4:9333".parse::<SocketAddr>().unwrap(), 1700000000u64),
        ("5.6.7.8:9334".parse::<SocketAddr>().unwrap(), 1700000001u64),
    ];
    storage.put_known_addrs(&addrs).unwrap();
    let loaded = storage.get_known_addrs().unwrap();
    assert_eq!(loaded.len(), 2);
    assert!(loaded.iter().any(|(a, _)| a.to_string() == "1.2.3.4:9333"));
}

#[test]
fn p1b_addr_put_replaces_not_appends() {
    let tmpdir = TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");
    let storage = ChainStorage::open(&db_path).unwrap();

    // Write batch 1
    let addrs1 = vec![
        ("1.2.3.4:9333".parse::<SocketAddr>().unwrap(), 1000u64),
        ("5.6.7.8:9333".parse::<SocketAddr>().unwrap(), 2000u64),
    ];
    storage.put_known_addrs(&addrs1).unwrap();
    assert_eq!(storage.get_known_addrs().unwrap().len(), 2);

    // Write batch 2 — should replace, not append
    let addrs2 = vec![("9.10.11.12:9333".parse::<SocketAddr>().unwrap(), 3000u64)];
    storage.put_known_addrs(&addrs2).unwrap();
    let loaded = storage.get_known_addrs().unwrap();
    assert_eq!(loaded.len(), 1, "put_known_addrs must replace, not append");
    assert_eq!(loaded[0].0.to_string(), "9.10.11.12:9333");
}

#[test]
fn p1b_addr_load_capped() {
    let tmpdir = TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");
    let storage = ChainStorage::open(&db_path).unwrap();

    // Write more than MAX_ADDR_BOOK_SIZE entries
    let mut addrs: Vec<(SocketAddr, u64)> = Vec::new();
    for i in 0..1030u32 {
        let a = (i >> 8) as u8;
        let b = (i & 0xFF) as u8;
        let addr: SocketAddr = format!("1.2.{}.{}:9333", a, b).parse().unwrap();
        addrs.push((addr, i as u64));
    }
    storage.put_known_addrs(&addrs).unwrap();

    let loaded = storage.get_known_addrs().unwrap();
    assert!(
        loaded.len() <= MAX_ADDR_BOOK_SIZE,
        "get_known_addrs must cap at MAX_ADDR_BOOK_SIZE (got {})",
        loaded.len()
    );
    // Verify it kept the entries with the highest last_seen values
    for (_, last_seen) in &loaded {
        assert!(
            *last_seen >= 6, // 1030 - 1024 = 6, so all returned should be >= 6
            "should keep most recent entries"
        );
    }
}

#[test]
fn p1b_addr_constants_exist() {
    assert_eq!(MAX_ADDR_ITEMS, 64);
    assert_eq!(MAX_ADDR_BOOK_SIZE, 1024);
    assert_eq!(MAX_ADDR_PER_MSG_ACCEPT, 16);
    assert_eq!(MAX_GETADDR_PER_CONN, 2);
    assert_eq!(MAX_UNSOLICITED_ADDR_PER_MIN, 3);
    assert_eq!(ADDR_FLUSH_INTERVAL_SECS, 300);
}

// ═══════════════════════════════════════════════════
// P2a: Abuse/Ban State Persistence
// ═══════════════════════════════════════════════════

#[test]
fn p2a_ip_ban_table() {
    let tmpdir = TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");
    let storage = ChainStorage::open(&db_path).unwrap();

    // Table exists (open didn't fail)
    let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
    let future_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600;

    storage.put_ip_ban(ip, future_unix).unwrap();
    let bans = storage.load_ip_bans().unwrap();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].0, ip);
    assert_eq!(bans[0].1, future_unix);
}

#[test]
fn p2a_ban_survives_reload() {
    let tmpdir = TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");

    let ip: std::net::IpAddr = "10.20.30.40".parse().unwrap();
    let future_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;

    // Write ban
    {
        let storage = ChainStorage::open(&db_path).unwrap();
        storage.put_ip_ban(ip, future_unix).unwrap();
    }

    // Reopen and verify
    {
        let storage = ChainStorage::open(&db_path).unwrap();
        let bans = storage.load_ip_bans().unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].0, ip);
        assert_eq!(bans[0].1, future_unix);
    }
}

#[test]
fn p2a_expired_ban_cleaned_on_load() {
    let tmpdir = TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");

    let ip: std::net::IpAddr = "10.20.30.40".parse().unwrap();
    let past_unix = 1000; // Way in the past

    {
        let storage = ChainStorage::open(&db_path).unwrap();
        storage.put_ip_ban(ip, past_unix).unwrap();
    }

    {
        let storage = ChainStorage::open(&db_path).unwrap();
        let bans = storage.load_ip_bans().unwrap();
        // Expired ban should be filtered out
        assert!(bans.is_empty());
    }
}

#[test]
fn p2a_put_ip_ban_method() {
    let tmpdir = TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");
    let storage = ChainStorage::open(&db_path).unwrap();

    let ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    // Method exists and succeeds
    storage.put_ip_ban(ip, 9999999999).unwrap();
}

#[test]
fn p2a_load_ip_bans_method() {
    let tmpdir = TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");
    let storage = ChainStorage::open(&db_path).unwrap();

    // Method exists and returns empty vec for fresh DB
    let bans = storage.load_ip_bans().unwrap();
    assert!(bans.is_empty());
}

#[test]
fn p2a_remove_ip_ban() {
    let tmpdir = TempDir::new().unwrap();
    let db_path = tmpdir.path().join("test.redb");
    let storage = ChainStorage::open(&db_path).unwrap();

    let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
    let future_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600;

    storage.put_ip_ban(ip, future_unix).unwrap();
    assert_eq!(storage.load_ip_bans().unwrap().len(), 1);

    storage.remove_ip_ban(ip).unwrap();
    assert!(storage.load_ip_bans().unwrap().is_empty());
}

// ═══════════════════════════════════════════════════
// P2b: Testnet Guard Strengthening
// ═══════════════════════════════════════════════════

#[test]
fn p2b_build_rs_checks_env() {
    let build_rs = std::fs::read_to_string("build.rs").expect("build.rs should exist");
    assert!(
        build_rs.contains("EXFER_TESTNET_OVERRIDE"),
        "build.rs must check EXFER_TESTNET_OVERRIDE env var"
    );
    assert!(
        build_rs.contains("testnet_override_missing"),
        "build.rs must set testnet_override_missing cfg"
    );
}

#[test]
fn p2b_lib_has_override_guard() {
    let lib_rs = std::fs::read_to_string("src/lib.rs").expect("src/lib.rs should exist");
    assert!(
        lib_rs.contains("testnet_override_missing"),
        "lib.rs must contain testnet_override_missing compile_error guard"
    );
}

#[test]
fn p2b_build_rs_registers_cfg() {
    let build_rs = std::fs::read_to_string("build.rs").expect("build.rs should exist");
    assert!(
        build_rs.contains("rustc-check-cfg"),
        "build.rs must register custom cfg to prevent lint warnings"
    );
}

// ═══════════════════════════════════════════════════
// Protocol version
// ═══════════════════════════════════════════════════

#[test]
fn protocol_version_is_5() {
    assert_eq!(PROTOCOL_VERSION, 5);
}
