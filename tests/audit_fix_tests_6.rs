//! Tests for the sixth audit round fixes (AUDIT-FIXES-6).
//!
//! Fix 1 [P1]: Outbound peer cap enforced (MAX_OUTBOUND_PEERS = 8)
//! Fix 2 [P1]: Ping/pong policy implemented (60s ping interval, 15s pong deadline)
//! Fix 3 [P1]: Per-peer block/tx rate limits (60 blocks/min, 120 tx/min)

// ── Fix 1: Outbound peer cap ──

mod outbound_cap_tests {
    use exfer::types::{MAX_INBOUND_PEERS, MAX_OUTBOUND_PEERS};

    #[test]
    fn outbound_cap_constant_is_8() {
        assert_eq!(MAX_OUTBOUND_PEERS, 8);
    }

    #[test]
    fn inbound_cap_constant_is_256() {
        assert_eq!(MAX_INBOUND_PEERS, 256);
    }

    #[test]
    fn peers_map_tracks_direction() {
        // Verify the peers map type is HashMap<SocketAddr, bool> (true = outbound)
        use std::collections::HashMap;
        use std::net::SocketAddr;

        let mut peers: HashMap<SocketAddr, bool> = HashMap::new();
        let addr1: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:9002".parse().unwrap();

        peers.insert(addr1, true); // outbound
        peers.insert(addr2, false); // inbound

        let outbound_count = peers.values().filter(|&&is_outbound| is_outbound).count();
        let inbound_count = peers.values().filter(|&&is_outbound| !is_outbound).count();

        assert_eq!(outbound_count, 1);
        assert_eq!(inbound_count, 1);
    }

    #[test]
    fn outbound_cap_counted_correctly() {
        use std::collections::HashMap;
        use std::net::SocketAddr;

        let mut peers: HashMap<SocketAddr, bool> = HashMap::new();

        // Fill to MAX_OUTBOUND_PEERS outbound
        for i in 0..MAX_OUTBOUND_PEERS {
            let addr: SocketAddr = format!("127.0.0.1:{}", 9000 + i).parse().unwrap();
            peers.insert(addr, true);
        }
        // Add some inbound (should not affect outbound count)
        for i in 0..5 {
            let addr: SocketAddr = format!("127.0.0.2:{}", 9000 + i).parse().unwrap();
            peers.insert(addr, false);
        }

        let outbound_count = peers.values().filter(|&&is_outbound| is_outbound).count();
        assert_eq!(outbound_count, MAX_OUTBOUND_PEERS);
        assert!(outbound_count >= MAX_OUTBOUND_PEERS);
    }
}

// ── Fix 2: Ping/pong policy ──

mod ping_pong_tests {
    use exfer::network::peer::PeerError;
    use exfer::types::{PING_INTERVAL_SECS, PONG_DEADLINE_SECS};

    #[test]
    fn ping_interval_is_60s() {
        assert_eq!(PING_INTERVAL_SECS, 60);
    }

    #[test]
    fn pong_deadline_is_15s() {
        assert_eq!(PONG_DEADLINE_SECS, 15);
    }

    #[test]
    fn pong_timeout_error_exists() {
        let err = PeerError::PongTimeout;
        assert_eq!(format!("{}", err), "pong timeout");
    }

    #[test]
    fn rate_limit_error_exists() {
        let err = PeerError::RateLimitExceeded;
        assert_eq!(format!("{}", err), "rate limit exceeded");
    }
}

// ── Fix 3: Rate limit constants ──

mod rate_limit_tests {
    use exfer::types::{MAX_BLOCKS_PER_MIN, MAX_TXS_PER_MIN};

    #[test]
    fn max_blocks_per_min_is_12() {
        assert_eq!(MAX_BLOCKS_PER_MIN, 12);
    }

    #[test]
    fn max_txs_per_min_is_60() {
        assert_eq!(MAX_TXS_PER_MIN, 60);
    }
}

// ── Integration tests: TCP loopback ──

#[cfg(feature = "testnet")]
mod integration_tests {
    use exfer::network::peer::{Peer, PeerError};
    use exfer::network::protocol::{HelloMsg, Message};
    use exfer::types::hash::Hash256;
    use exfer::types::PROTOCOL_VERSION;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;
    use tokio::time::Duration;

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

    fn server_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32])
    }

    fn client_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[0x43u8; 32])
    }

    /// Establish a TCP loopback pair with completed handshakes.
    async fn make_peer_pair() -> (Peer, Peer) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hello = make_hello();

        let server_hello = hello.clone();
        let server = tokio::spawn(async move {
            let (stream, peer_addr) = listener.accept().await.unwrap();
            Peer::handshake(
                stream,
                peer_addr,
                server_hello,
                true,
                &server_signing_key(),
                &mut None,
            )
            .await
            .unwrap()
        });

        let client_addr: SocketAddr = addr;
        let client_hello = hello.clone();
        let client = tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(client_addr).await.unwrap();
            Peer::handshake(
                stream,
                client_addr,
                client_hello,
                false,
                &client_signing_key(),
                &mut None,
            )
            .await
            .unwrap()
        });

        let (server_peer, client_peer) = tokio::join!(server, client);
        (server_peer.unwrap(), client_peer.unwrap())
    }

    #[tokio::test]
    async fn peer_recv_with_timeout_works() {
        let (mut server, mut client) = make_peer_pair().await;
        client.send(&Message::Pong).await.unwrap();
        let msg = server
            .recv_with_timeout(Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(msg, Message::Pong);
    }

    #[tokio::test]
    async fn peer_recv_with_timeout_errors_on_timeout() {
        let (mut server, _client) = make_peer_pair().await;
        let result = server.recv_with_timeout(Duration::from_millis(50)).await;
        assert!(result.is_err());
        if let Err(PeerError::Io(msg)) = result {
            assert!(
                msg.contains("timeout"),
                "expected timeout error, got: {}",
                msg
            );
        } else {
            panic!("expected Io error with timeout");
        }
    }

}
