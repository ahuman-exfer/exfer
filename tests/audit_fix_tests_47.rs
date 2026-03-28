//! Audit fix tests — round 47.
//!
//! Pre-allocation DoS in inbound message handling.
//!
//! Fix: chunked payload reads with per-chunk throughput enforcement,
//! shortened frame timeouts, SlowPeer error variant for trickle disconnect.

// ── Structural: chunked read infrastructure exists ──

#[test]
fn slow_peer_error_display() {
    use exfer::network::peer::PeerError;
    let err = PeerError::SlowPeer("chunk read timed out".into());
    let msg = format!("{}", err);
    assert!(
        msg.contains("slow peer"),
        "SlowPeer display must mention 'slow peer': got {}",
        msg
    );
}

// ── Structural: recv_with_timeout maps IO errors to SlowPeer ──
