//! Tests for cryptographic peer identity authentication (v4 protocol).
//!
//! 1. Invalid signature rejected
//! 2. Replayed first-flight fails (wrong nonce echo)
//! 3. Version downgrade rejected
//! 4. Duplicate identity rejected
//! 5. Identity ban persistence across restart
//! 6. Self-connection rejected
//! 7. Structural tests for protocol types

// ── Structural tests (no network needed) ──

mod structural {
    use exfer::network::peer::PeerError;
    use exfer::network::protocol::{
        compute_auth_transcript, tip_commitment, AuthAckMsg, HelloMsg, Message,
        HELLO_V4_PAYLOAD_SIZE, MSG_AUTH_ACK,
    };
    use exfer::types::hash::Hash256;
    use exfer::types::{DS_AUTH, PROTOCOL_VERSION};

    const ZERO_TIP: [u8; 72] = [0u8; 72];

    #[test]
    fn protocol_version_is_5() {
        assert_eq!(PROTOCOL_VERSION, 5);
    }

    #[test]
    fn hello_v4_payload_is_268() {
        assert_eq!(HELLO_V4_PAYLOAD_SIZE, 268);
    }

    #[test]
    fn hellomsg_has_pubkey_and_sig() {
        let hello = HelloMsg {
            version: PROTOCOL_VERSION,
            genesis_block_id: Hash256::ZERO,
            best_height: 0,
            best_block_id: Hash256::ZERO,
            cumulative_work: [0u8; 32],
            nonce: [0xAA; 32],
            echo: [0xBB; 32],
            pubkey: [0xCC; 32],
            sig: [0xDD; 64],
        };
        assert_eq!(hello.pubkey, [0xCC; 32]);
        assert_eq!(hello.sig, [0xDD; 64]);
    }

    #[test]
    fn hello_serializes_to_268_payload() {
        let hello = HelloMsg {
            version: PROTOCOL_VERSION,
            genesis_block_id: Hash256::ZERO,
            best_height: 0,
            best_block_id: Hash256::ZERO,
            cumulative_work: [0u8; 32],
            nonce: [0u8; 32],
            echo: [0u8; 32],
            pubkey: [0u8; 32],
            sig: [0u8; 64],
        };
        let bytes = Message::Hello(hello).serialize().unwrap();
        // 1 (type) + 4 (length) + 268 (payload) = 273
        assert_eq!(bytes.len(), 273);
        let payload_len = u32::from_le_bytes(bytes[1..5].try_into().unwrap());
        assert_eq!(payload_len, 268);
    }

    #[test]
    fn auth_ack_msg_exists() {
        let ack = AuthAckMsg { sig: [0xEE; 64] };
        assert_eq!(ack.sig, [0xEE; 64]);
    }

    #[test]
    fn msg_auth_ack_constant_is_0x18() {
        assert_eq!(MSG_AUTH_ACK, 0x18);
    }

    #[test]
    fn auth_ack_roundtrip() {
        let ack = AuthAckMsg { sig: [0x42; 64] };
        let bytes = Message::AuthAck(ack.clone()).serialize().unwrap();
        let (msg, consumed) = Message::deserialize(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(msg, Message::AuthAck(ack));
    }

    #[test]
    fn ds_auth_constant_exists() {
        assert_eq!(DS_AUTH, b"EXFER-AUTH");
    }

    #[test]
    fn auth_transcript_includes_role_marker() {
        let genesis = Hash256::ZERO;
        let nonce_a = [1u8; 32];
        let nonce_b = [2u8; 32];
        let t0 =
            compute_auth_transcript(&genesis, 4, &nonce_a, &nonce_b, 0x00, &ZERO_TIP, &ZERO_TIP);
        let t1 =
            compute_auth_transcript(&genesis, 4, &nonce_a, &nonce_b, 0x01, &ZERO_TIP, &ZERO_TIP);
        // Different roles produce different transcripts (prevents reflection)
        assert_ne!(t0, t1);
    }

    #[test]
    fn auth_transcript_binds_genesis() {
        let g1 = Hash256([1u8; 32]);
        let g2 = Hash256([2u8; 32]);
        let nonce_a = [0xAA; 32];
        let nonce_b = [0xBB; 32];
        let t1 = compute_auth_transcript(&g1, 4, &nonce_a, &nonce_b, 0x00, &ZERO_TIP, &ZERO_TIP);
        let t2 = compute_auth_transcript(&g2, 4, &nonce_a, &nonce_b, 0x00, &ZERO_TIP, &ZERO_TIP);
        assert_ne!(t1, t2);
    }

    #[test]
    fn auth_transcript_binds_nonces() {
        let genesis = Hash256::ZERO;
        let na1 = [1u8; 32];
        let na2 = [2u8; 32];
        let nb = [3u8; 32];
        let t1 = compute_auth_transcript(&genesis, 4, &na1, &nb, 0x00, &ZERO_TIP, &ZERO_TIP);
        let t2 = compute_auth_transcript(&genesis, 4, &na2, &nb, 0x00, &ZERO_TIP, &ZERO_TIP);
        assert_ne!(t1, t2);
    }

    #[test]
    fn auth_transcript_binds_tip_metadata() {
        let genesis = Hash256::ZERO;
        let nonce_a = [0xAA; 32];
        let nonce_b = [0xBB; 32];

        // Different initiator height → different transcript
        let tip_h0 = tip_commitment(0, &Hash256::ZERO, &[0u8; 32]);
        let tip_h1 = tip_commitment(1, &Hash256::ZERO, &[0u8; 32]);
        let t1 = compute_auth_transcript(&genesis, 4, &nonce_a, &nonce_b, 0x00, &tip_h0, &ZERO_TIP);
        let t2 = compute_auth_transcript(&genesis, 4, &nonce_a, &nonce_b, 0x00, &tip_h1, &ZERO_TIP);
        assert_ne!(
            t1, t2,
            "different initiator height must produce different transcript"
        );

        // Different responder cumulative_work → different transcript
        let work_a = [0u8; 32];
        let mut work_b = [0u8; 32];
        work_b[31] = 1;
        let tip_wa = tip_commitment(0, &Hash256::ZERO, &work_a);
        let tip_wb = tip_commitment(0, &Hash256::ZERO, &work_b);
        let t3 = compute_auth_transcript(&genesis, 4, &nonce_a, &nonce_b, 0x00, &ZERO_TIP, &tip_wa);
        let t4 = compute_auth_transcript(&genesis, 4, &nonce_a, &nonce_b, 0x00, &ZERO_TIP, &tip_wb);
        assert_ne!(
            t3, t4,
            "different responder work must produce different transcript"
        );

        // Different best_block_id → different transcript
        let tip_id0 = tip_commitment(0, &Hash256::ZERO, &[0u8; 32]);
        let tip_id1 = tip_commitment(0, &Hash256([0xFF; 32]), &[0u8; 32]);
        let t5 =
            compute_auth_transcript(&genesis, 4, &nonce_a, &nonce_b, 0x00, &tip_id0, &ZERO_TIP);
        let t6 =
            compute_auth_transcript(&genesis, 4, &nonce_a, &nonce_b, 0x00, &tip_id1, &ZERO_TIP);
        assert_ne!(
            t5, t6,
            "different best_block_id must produce different transcript"
        );
    }

    #[test]
    fn peer_error_auth_failed_exists() {
        let err = PeerError::AuthFailed;
        let msg = format!("{}", err);
        assert!(msg.contains("auth"), "AuthFailed error: {}", msg);
    }

    #[test]
    fn peer_error_self_connection_exists() {
        let err = PeerError::SelfConnection;
        let msg = format!("{}", err);
        assert!(
            msg.contains("self") || msg.contains("Self"),
            "SelfConnection error: {}",
            msg
        );
    }

    #[test]
    fn peer_error_nonce_mismatch_exists() {
        let err = PeerError::NonceMismatch;
        let msg = format!("{}", err);
        assert!(msg.contains("nonce"), "NonceMismatch error: {}", msg);
    }

    #[test]
    fn peer_error_version_mismatch_exists() {
        let err = PeerError::VersionMismatch;
        let msg = format!("{}", err);
        assert!(msg.contains("version"), "VersionMismatch error: {}", msg);
    }
}

// ── Identity ban persistence tests ──

mod identity_ban_persistence {
    use exfer::chain::storage::ChainStorage;

    #[test]
    fn identity_ban_table_exists() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let db_path = tmpdir.path().join("test.redb");
        let storage = ChainStorage::open(&db_path).unwrap();
        // Should not panic — table was created during open()
        let result = storage.load_identity_bans();
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn put_and_load_identity_ban() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let db_path = tmpdir.path().join("test.redb");
        let storage = ChainStorage::open(&db_path).unwrap();

        let pubkey = [0x42u8; 32];
        let future_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        storage.put_identity_ban(&pubkey, future_unix).unwrap();

        let bans = storage.load_identity_bans().unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].0, pubkey);
        assert_eq!(bans[0].1, future_unix);
    }

    #[test]
    fn remove_identity_ban() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let db_path = tmpdir.path().join("test.redb");
        let storage = ChainStorage::open(&db_path).unwrap();

        let pubkey = [0x42u8; 32];
        let future_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        storage.put_identity_ban(&pubkey, future_unix).unwrap();
        storage.remove_identity_ban(&pubkey).unwrap();

        let bans = storage.load_identity_bans().unwrap();
        assert!(bans.is_empty());
    }

    #[test]
    fn expired_bans_cleaned_on_load() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let db_path = tmpdir.path().join("test.redb");
        let storage = ChainStorage::open(&db_path).unwrap();

        let pubkey_expired = [0x01u8; 32];
        let pubkey_active = [0x02u8; 32];
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // One expired, one active
        storage
            .put_identity_ban(&pubkey_expired, now_unix.saturating_sub(100))
            .unwrap();
        storage
            .put_identity_ban(&pubkey_active, now_unix + 3600)
            .unwrap();

        let bans = storage.load_identity_bans().unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].0, pubkey_active);
    }

    #[test]
    fn ban_survives_reopen() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let db_path = tmpdir.path().join("test.redb");

        let pubkey = [0x99u8; 32];
        let future_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        // Write ban, drop storage
        {
            let storage = ChainStorage::open(&db_path).unwrap();
            storage.put_identity_ban(&pubkey, future_unix).unwrap();
        }

        // Reopen and verify
        {
            let storage = ChainStorage::open(&db_path).unwrap();
            let bans = storage.load_identity_bans().unwrap();
            assert_eq!(bans.len(), 1);
            assert_eq!(bans[0].0, pubkey);
            assert_eq!(bans[0].1, future_unix);
        }
    }
}

// ── Integration tests requiring TCP + testnet ──

#[cfg(feature = "testnet")]
mod handshake_tests {
    use ed25519_dalek::SigningKey;
    use exfer::network::peer::{Peer, PeerError};
    use exfer::network::protocol::{compute_auth_transcript, tip_commitment, HelloMsg, Message};
    use exfer::types::hash::Hash256;
    use exfer::types::PROTOCOL_VERSION;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    fn make_hello() -> HelloMsg {
        HelloMsg {
            version: PROTOCOL_VERSION,
            genesis_block_id: Hash256::ZERO,
            best_height: 0,
            best_block_id: Hash256::ZERO,
            cumulative_work: [0u8; 32],
            nonce: [0u8; 32],
            echo: [0u8; 32],
            pubkey: [0u8; 32],
            sig: [0u8; 64],
        }
    }

    /// Two different signing keys for a valid handshake pair.
    fn key_pair() -> (SigningKey, SigningKey) {
        let a = SigningKey::from_bytes(&[0x11u8; 32]);
        let b = SigningKey::from_bytes(&[0x22u8; 32]);
        (a, b)
    }

    /// Helper: perform a full authenticated handshake between two loopback peers.
    async fn make_authed_pair() -> (Peer, Peer) {
        let (key_a, key_b) = key_pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hello = make_hello();

        let server_hello = hello.clone();
        let server = tokio::spawn(async move {
            let (stream, peer_addr) = listener.accept().await.unwrap();
            Peer::handshake(stream, peer_addr, server_hello, true, &key_b, &mut None)
                .await
                .unwrap()
        });

        let client_hello = hello.clone();
        let client = tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            Peer::handshake(stream, addr, client_hello, false, &key_a, &mut None)
                .await
                .unwrap()
        });

        let (server_peer, client_peer) = tokio::join!(server, client);
        (server_peer.unwrap(), client_peer.unwrap())
    }

    #[tokio::test]
    async fn authenticated_handshake_succeeds() {
        let (server, client) = make_authed_pair().await;
        let (key_a, key_b) = key_pair();
        // Server sees client's identity (key_a)
        assert_eq!(server.identity, key_a.verifying_key().to_bytes());
        // Client sees server's identity (key_b)
        assert_eq!(client.identity, key_b.verifying_key().to_bytes());
    }

    #[tokio::test]
    async fn session_keys_match_after_handshake() {
        let (server, client) = make_authed_pair().await;
        // Server's send_key must match client's recv_key (R→I direction)
        assert_eq!(server.send_key, client.recv_key);
        // Client's send_key must match server's recv_key (I→R direction)
        assert_eq!(client.send_key, server.recv_key);
        // Directional keys must differ (direction binding)
        assert_ne!(server.send_key, server.recv_key);
        // Keys must not be all zeros (derived from random nonces)
        assert_ne!(server.send_key, [0u8; 32]);
        assert_ne!(server.recv_key, [0u8; 32]);
    }

    #[tokio::test]
    async fn hmac_authenticated_ping_pong() {
        let (mut server, mut client) = make_authed_pair().await;
        // Client sends Ping with HMAC, server receives and verifies
        client.send(&Message::Ping).await.unwrap();
        let msg = server
            .recv_with_timeout(std::time::Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(msg, Message::Ping);

        // Server sends Pong back, client receives and verifies
        server.send(&Message::Pong).await.unwrap();
        let msg = client
            .recv_with_timeout(std::time::Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(msg, Message::Pong);
    }

    #[tokio::test]
    async fn hmac_tampered_frame_rejected() {
        let (mut server, mut client) = make_authed_pair().await;
        use tokio::io::AsyncWriteExt;

        // Manually write a frame with a bad HMAC tag.
        // Wire format: counter_u64_le || frame || tag
        let frame = Message::Ping.serialize().unwrap();
        let counter: u64 = client.send_counter;
        let bad_tag = [0xFFu8; 16]; // wrong HMAC
        let mut buf = Vec::with_capacity(8 + frame.len() + 16);
        buf.extend_from_slice(&counter.to_le_bytes());
        buf.extend_from_slice(&frame);
        buf.extend_from_slice(&bad_tag);
        client.stream.write_all(&buf).await.unwrap();

        // Server should reject with an I/O error (HMAC failure)
        let result = server
            .recv_with_timeout(std::time::Duration::from_secs(5))
            .await;
        assert!(result.is_err(), "tampered frame must be rejected");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("HMAC"),
            "error should mention HMAC: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn version_downgrade_rejected() {
        let (key_a, key_b) = key_pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server expects v4, but client sends v3
        let server = tokio::spawn(async move {
            let (stream, peer_addr) = listener.accept().await.unwrap();
            let hello = make_hello();
            Peer::handshake(stream, peer_addr, hello, true, &key_b, &mut None).await
        });

        let client = tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut hello = make_hello();
            hello.version = 3; // downgrade
            Peer::handshake(stream, addr, hello, false, &key_a, &mut None).await
        });

        let (server_result, _client_result) = tokio::join!(server, client);
        match server_result.unwrap() {
            Err(PeerError::VersionMismatch) => {} // expected
            Err(e) => panic!("expected VersionMismatch, got: {}", e),
            Ok(_) => panic!("expected handshake to fail"),
        }
    }

    #[tokio::test]
    async fn self_connection_rejected() {
        let key = SigningKey::from_bytes(&[0x33u8; 32]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Both sides use the same key → self-connection
        let key_clone = SigningKey::from_bytes(&[0x33u8; 32]);
        let server = tokio::spawn(async move {
            let (stream, peer_addr) = listener.accept().await.unwrap();
            let hello = make_hello();
            Peer::handshake(stream, peer_addr, hello, true, &key_clone, &mut None).await
        });

        let client = tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let hello = make_hello();
            Peer::handshake(stream, addr, hello, false, &key, &mut None).await
        });

        let (server_result, client_result) = tokio::join!(server, client);
        // At least one side should get SelfConnection
        let server_err = server_result.unwrap();
        let client_err = client_result.unwrap();
        let has_self_conn = matches!(server_err, Err(PeerError::SelfConnection))
            || matches!(client_err, Err(PeerError::SelfConnection));
        assert!(
            has_self_conn,
            "expected SelfConnection from at least one side"
        );
    }

    #[tokio::test]
    async fn invalid_auth_sig_rejected() {
        // Manually craft a responder Hello with a bad signature, verify initiator rejects it.
        let key_a = SigningKey::from_bytes(&[0x11u8; 32]);
        let key_b = SigningKey::from_bytes(&[0x22u8; 32]);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Malicious server: sends a Hello with a garbage signature
        let server = tokio::spawn(async move {
            let (mut stream, _peer_addr) = listener.accept().await.unwrap();
            // Read initiator's Hello
            let mut buf = vec![0u8; 1 + 4 + 268];
            use tokio::io::AsyncReadExt;
            stream.read_exact(&mut buf).await.unwrap();

            // Parse their nonce (payload offset 108: after version(4)+genesis(32)+height(8)+best_id(32)+cum_work(32))
            let their_nonce: [u8; 32] = buf[5 + 108..5 + 140].try_into().unwrap();

            // Build a response Hello with garbage sig
            let response_hello = HelloMsg {
                version: PROTOCOL_VERSION,
                genesis_block_id: Hash256::ZERO,
                best_height: 0,
                best_block_id: Hash256::ZERO,
                cumulative_work: [0u8; 32],
                nonce: [0xBB; 32],
                echo: their_nonce,
                pubkey: key_b.verifying_key().to_bytes(),
                sig: [0xFF; 64], // GARBAGE signature
            };
            let bytes = Message::Hello(response_hello).serialize().unwrap();
            stream.write_all(&bytes).await.unwrap();

            // Don't bother with AuthAck — client should fail on sig verify
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        });

        let client = tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let hello = make_hello();
            Peer::handshake(stream, addr, hello, false, &key_a, &mut None).await
        });

        let (_server_result, client_result) = tokio::join!(server, client);
        match client_result.unwrap() {
            Err(PeerError::AuthFailed) => {} // expected
            Err(e) => panic!("expected AuthFailed, got: {}", e),
            Ok(_) => panic!("expected handshake to fail"),
        }
    }

    #[tokio::test]
    async fn replayed_first_flight_fails_nonce() {
        // Initiator sends Hello with nonce_a. If responder echoes wrong nonce,
        // initiator should reject with NonceMismatch.
        let key_a = SigningKey::from_bytes(&[0x11u8; 32]);
        let key_b = SigningKey::from_bytes(&[0x22u8; 32]);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Malicious server: sends a correctly signed Hello but with wrong echo
        let server = tokio::spawn(async move {
            let (mut stream, _peer_addr) = listener.accept().await.unwrap();
            use tokio::io::AsyncReadExt;
            let mut buf = vec![0u8; 1 + 4 + 268];
            stream.read_exact(&mut buf).await.unwrap();

            // Respond with wrong echo (all zeros instead of their nonce)
            let wrong_echo = [0u8; 32];
            let nonce_b = [0xBB; 32];

            use ed25519_dalek::Signer;
            // Both hellos use zero tips (make_hello() defaults)
            let zero_tip = [0u8; 72];
            let transcript = compute_auth_transcript(
                &Hash256::ZERO,
                PROTOCOL_VERSION,
                &wrong_echo, // wrong: should be their nonce
                &nonce_b,
                0x00,
                &zero_tip, // initiator tip
                &zero_tip, // responder tip
            );
            let sig = key_b.sign(&transcript);

            let response = HelloMsg {
                version: PROTOCOL_VERSION,
                genesis_block_id: Hash256::ZERO,
                best_height: 0,
                best_block_id: Hash256::ZERO,
                cumulative_work: [0u8; 32],
                nonce: nonce_b,
                echo: wrong_echo, // WRONG echo
                pubkey: key_b.verifying_key().to_bytes(),
                sig: sig.to_bytes(),
            };
            let bytes = Message::Hello(response).serialize().unwrap();
            stream.write_all(&bytes).await.unwrap();

            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        });

        let client = tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let hello = make_hello();
            Peer::handshake(stream, addr, hello, false, &key_a, &mut None).await
        });

        let (_server_result, client_result) = tokio::join!(server, client);
        match client_result.unwrap() {
            Err(PeerError::NonceMismatch) => {} // expected
            Err(e) => panic!("expected NonceMismatch, got: {}", e),
            Ok(_) => panic!("expected handshake to fail"),
        }
    }
}
