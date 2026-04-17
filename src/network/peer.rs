use crate::network::protocol::{
    compute_auth_transcript, compute_session_key, tip_commitment, AuthAckMsg, HelloMsg, Message,
    HELLO_V4_PAYLOAD_SIZE, HMAC_TAG_SIZE, MSG_AUTH_ACK,
};
use crate::types::block::HEADER_SIZE;
use crate::types::hash::Hash256;
use crate::types::*;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};
use tracing::{debug, warn};

type HmacSha256 = Hmac<Sha256>;

/// A connected, authenticated peer.
#[allow(dead_code)]
pub struct Peer {
    pub addr: SocketAddr,
    pub stream: TcpStream,
    pub version: u32,
    pub genesis_block_id: Hash256,
    pub best_height: u64,
    pub best_block_id: Hash256,
    pub cumulative_work: [u8; 32],
    pub is_inbound: bool,
    /// Remote peer's Ed25519 public key, verified via mutual proof-of-possession.
    pub identity: [u8; 32],
    /// Directional MAC key for outbound frames (initiator→responder or vice versa).
    pub send_key: [u8; 32],
    /// Directional MAC key for inbound frames (the peer's send direction).
    pub recv_key: [u8; 32],
    /// Monotonic counter for outbound frames (included in HMAC to prevent replay).
    pub send_counter: u64,
    /// Minimum acceptable inbound frame counter (reject counter < this value).
    pub recv_counter: u64,
    /// Persistent buffer for the 8-byte frame counter prefix.
    /// Tracks how many bytes have been read so far, so a cancelled
    /// `poll_read` doesn't lose partial data.
    counter_buf: [u8; 8],
    /// Number of valid bytes in `counter_buf` (0..=8).
    counter_buf_len: usize,
    /// When the first byte of the current frame counter arrived.
    /// Used to enforce a 5-second hard cap on counter accumulation
    /// across multiple `try_recv` calls (prevents slowloris).
    counter_started: Option<std::time::Instant>,
}

impl Peer {
    /// Perform a 3-step mutually authenticated handshake.
    ///
    /// Both sides prove possession of their Ed25519 key by signing a
    /// domain-separated transcript that binds genesis, version, both
    /// nonces, and a role marker (preventing reflection).
    ///
    /// **Outbound** (initiator, is_inbound=false):
    ///   1. Send Hello(nonce_a, pubkey_a, sig=[0])
    ///   2. Read Hello(nonce_b, pubkey_b, echo=nonce_a, sig_b) — verify sig_b
    ///   3. Send AuthAck(sig_a)
    ///
    /// **Inbound** (responder, is_inbound=true):
    ///   1. Read Hello(nonce_a, pubkey_a)
    ///   2. Send Hello(nonce_b, pubkey_b, echo=nonce_a, sig_b)
    ///   3. Read AuthAck(sig_a) — verify sig_a
    ///
    /// Rejects peers with version != PROTOCOL_VERSION (exact match, no downgrade).
    /// Rejects self-connections (same public key).
    pub async fn handshake(
        mut stream: TcpStream,
        addr: SocketAddr,
        mut our_hello: HelloMsg,
        is_inbound: bool,
        signing_key: &ed25519_dalek::SigningKey,
        peer_identity_out: &mut Option<[u8; 32]>,
    ) -> Result<Self, PeerError> {
        let our_nonce: [u8; 32] = rand::random();
        let our_pubkey = signing_key.verifying_key().to_bytes();

        if is_inbound {
            // ── Responder path ──

            // Step 1: Read initiator's Hello
            let their_msg = timeout(
                Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
                read_hello(&mut stream),
            )
            .await
            .map_err(|_| PeerError::HandshakeTimeout)?
            .map_err(|e| PeerError::Io(e.to_string()))?;

            let their_hello = match their_msg {
                Message::Hello(h) => h,
                _ => return Err(PeerError::UnexpectedMessage),
            };

            if their_hello.version != PROTOCOL_VERSION {
                warn!(
                    "Rejecting {}: protocol v{} != our v{}",
                    addr, their_hello.version, PROTOCOL_VERSION
                );
                return Err(PeerError::VersionMismatch);
            }
            if their_hello.genesis_block_id != our_hello.genesis_block_id {
                return Err(PeerError::GenesisMismatch);
            }
            if their_hello.pubkey == our_pubkey {
                return Err(PeerError::SelfConnection);
            }

            let nonce_a = their_hello.nonce;
            let nonce_b = our_nonce;

            // Tip commitments: initiator (nonce_a side) then responder (nonce_b side).
            // Binding both tips prevents a MITM from modifying height/work claims.
            let tip_a = tip_commitment(
                their_hello.best_height,
                &their_hello.best_block_id,
                &their_hello.cumulative_work,
            );
            let tip_b = tip_commitment(
                our_hello.best_height,
                &our_hello.best_block_id,
                &our_hello.cumulative_work,
            );

            // Step 2: Send our Hello with echo + signature (role 0x00 = responder)
            let transcript_resp = compute_auth_transcript(
                &our_hello.genesis_block_id,
                PROTOCOL_VERSION,
                &nonce_a,
                &nonce_b,
                0x00,
                &tip_a,
                &tip_b,
            );
            let sig_b = signing_key.sign(&transcript_resp);

            our_hello.nonce = nonce_b;
            our_hello.echo = nonce_a;
            our_hello.pubkey = our_pubkey;
            our_hello.sig = sig_b.to_bytes();

            let hello_bytes = Message::Hello(our_hello)
                .serialize()
                .map_err(|e| PeerError::SerializationError(e.to_string()))?;
            stream
                .write_all(&hello_bytes)
                .await
                .map_err(|e| PeerError::Io(e.to_string()))?;

            // Step 3: Read AuthAck and verify initiator's signature (role 0x01 = initiator)
            let sig_a_bytes = timeout(
                Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
                read_auth_ack(&mut stream),
            )
            .await
            .map_err(|_| PeerError::HandshakeTimeout)?
            .map_err(|e| PeerError::Io(e.to_string()))?;

            let transcript_init = compute_auth_transcript(
                &their_hello.genesis_block_id,
                PROTOCOL_VERSION,
                &nonce_a,
                &nonce_b,
                0x01,
                &tip_a,
                &tip_b,
            );
            verify_peer_sig(&their_hello.pubkey, &transcript_init, &sig_a_bytes, addr)?;

            // Identity is now cryptographically authenticated — safe to expose
            // to the caller for identity-level strike recording.
            *peer_identity_out = Some(their_hello.pubkey);

            // Derive X25519 DH shared secret from authenticated identity keys.
            // MITM cannot compute this without holding a peer's private key.
            let their_vk = VerifyingKey::from_bytes(&their_hello.pubkey)
                .expect("already verified during handshake");
            let dh_shared_secret = their_vk
                .to_montgomery()
                .mul_clamped(signing_key.to_scalar_bytes())
                .to_bytes();
            let session_key = compute_session_key(
                &their_hello.genesis_block_id,
                PROTOCOL_VERSION,
                &nonce_a,
                &nonce_b,
                &dh_shared_secret,
            );

            debug!(
                "Handshake complete with {} (inbound, height: {}, v{}, id: {})",
                addr,
                their_hello.best_height,
                their_hello.version,
                hex::encode(&their_hello.pubkey[..8])
            );

            // Responder sends R→I, receives I→R
            let (i2r_key, r2i_key) = derive_directional_keys(&session_key);
            Ok(Peer {
                addr,
                stream,
                version: their_hello.version,
                genesis_block_id: their_hello.genesis_block_id,
                best_height: their_hello.best_height,
                best_block_id: their_hello.best_block_id,
                cumulative_work: their_hello.cumulative_work,
                is_inbound,
                identity: their_hello.pubkey,
                send_key: r2i_key,
                recv_key: i2r_key,
                send_counter: 0,
                recv_counter: 0,
                counter_buf: [0u8; 8],
                counter_buf_len: 0,
                counter_started: None,
            })
        } else {
            // ── Initiator path ──

            // Step 1: Send Hello with our nonce and pubkey (sig zeroed — nothing to sign yet)
            our_hello.nonce = our_nonce;
            our_hello.echo = [0u8; 32];
            our_hello.pubkey = our_pubkey;
            our_hello.sig = [0u8; 64];

            let hello_bytes = Message::Hello(our_hello.clone())
                .serialize()
                .map_err(|e| PeerError::SerializationError(e.to_string()))?;
            stream
                .write_all(&hello_bytes)
                .await
                .map_err(|e| PeerError::Io(e.to_string()))?;

            // Step 2: Read responder's Hello — verify echo, version, genesis, signature
            let their_msg = timeout(
                Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
                read_hello(&mut stream),
            )
            .await
            .map_err(|_| PeerError::HandshakeTimeout)?
            .map_err(|e| PeerError::Io(e.to_string()))?;

            let their_hello = match their_msg {
                Message::Hello(h) => h,
                _ => return Err(PeerError::UnexpectedMessage),
            };

            if their_hello.version != PROTOCOL_VERSION {
                warn!(
                    "Rejecting {}: protocol v{} != our v{}",
                    addr, their_hello.version, PROTOCOL_VERSION
                );
                return Err(PeerError::VersionMismatch);
            }
            if their_hello.genesis_block_id != our_hello.genesis_block_id {
                return Err(PeerError::GenesisMismatch);
            }
            if their_hello.echo != our_nonce {
                warn!("Nonce mismatch from {}", addr);
                return Err(PeerError::NonceMismatch);
            }
            if their_hello.pubkey == our_pubkey {
                return Err(PeerError::SelfConnection);
            }

            let nonce_a = our_nonce;
            let nonce_b = their_hello.nonce;

            // Tip commitments: initiator (us) then responder (them).
            let tip_a = tip_commitment(
                our_hello.best_height,
                &our_hello.best_block_id,
                &our_hello.cumulative_work,
            );
            let tip_b = tip_commitment(
                their_hello.best_height,
                &their_hello.best_block_id,
                &their_hello.cumulative_work,
            );

            // Verify responder's signature (role 0x00 = responder)
            let transcript_resp = compute_auth_transcript(
                &our_hello.genesis_block_id,
                PROTOCOL_VERSION,
                &nonce_a,
                &nonce_b,
                0x00,
                &tip_a,
                &tip_b,
            );
            verify_peer_sig(
                &their_hello.pubkey,
                &transcript_resp,
                &their_hello.sig,
                addr,
            )?;

            // Identity is now cryptographically authenticated.
            *peer_identity_out = Some(their_hello.pubkey);

            // Step 3: Send AuthAck with our signature (role 0x01 = initiator)
            let transcript_init = compute_auth_transcript(
                &our_hello.genesis_block_id,
                PROTOCOL_VERSION,
                &nonce_a,
                &nonce_b,
                0x01,
                &tip_a,
                &tip_b,
            );
            let sig_a = signing_key.sign(&transcript_init);
            let ack_bytes = Message::AuthAck(AuthAckMsg {
                sig: sig_a.to_bytes(),
            })
            .serialize()
            .map_err(|e| PeerError::SerializationError(e.to_string()))?;
            stream
                .write_all(&ack_bytes)
                .await
                .map_err(|e| PeerError::Io(e.to_string()))?;

            // Derive X25519 DH shared secret from authenticated identity keys.
            let their_vk = VerifyingKey::from_bytes(&their_hello.pubkey)
                .expect("already verified during handshake");
            let dh_shared_secret = their_vk
                .to_montgomery()
                .mul_clamped(signing_key.to_scalar_bytes())
                .to_bytes();
            let session_key = compute_session_key(
                &their_hello.genesis_block_id,
                PROTOCOL_VERSION,
                &nonce_a,
                &nonce_b,
                &dh_shared_secret,
            );

            debug!(
                "Handshake complete with {} (outbound, height: {}, v{}, id: {})",
                addr,
                their_hello.best_height,
                their_hello.version,
                hex::encode(&their_hello.pubkey[..8])
            );

            // Initiator sends I→R, receives R→I
            let (i2r_key, r2i_key) = derive_directional_keys(&session_key);
            Ok(Peer {
                addr,
                stream,
                version: their_hello.version,
                genesis_block_id: their_hello.genesis_block_id,
                best_height: their_hello.best_height,
                best_block_id: their_hello.best_block_id,
                cumulative_work: their_hello.cumulative_work,
                is_inbound,
                identity: their_hello.pubkey,
                send_key: i2r_key,
                recv_key: r2i_key,
                send_counter: 0,
                recv_counter: 0,
                counter_buf: [0u8; 8],
                counter_buf_len: 0,
                counter_started: None,
            })
        }
    }

    /// Send a message to this peer with a write deadline.
    /// Thin wrapper around `write_framed_message` for the handshake path
    /// (before the stream is split).
    pub async fn send(&mut self, msg: &Message) -> Result<(), PeerError> {
        write_framed_message(
            &mut self.stream,
            msg,
            &self.send_key,
            &mut self.send_counter,
        )
        .await
    }

    /// Split this peer into reader/writer halves and metadata for the
    /// reader/writer/supervisor task architecture.
    pub fn into_split(self) -> (ReaderState, WriterState, PeerMetadata) {
        let (read_half, write_half) = self.stream.into_split();
        let reader = ReaderState {
            stream: read_half,
            recv_key: self.recv_key,
            recv_counter: self.recv_counter,
            counter_buf: self.counter_buf,
            counter_buf_len: self.counter_buf_len,
            counter_started: self.counter_started,
        };
        let writer = WriterState {
            stream: write_half,
            send_key: self.send_key,
            send_counter: self.send_counter,
        };
        let meta = PeerMetadata {
            addr: self.addr,
            identity: self.identity,
        };
        (reader, writer, meta)
    }

    /// Receive a message from this peer with a custom timeout.
    /// Verifies the 16-byte HMAC tag and monotonic frame counter.
    #[allow(dead_code)]
    pub async fn recv_with_timeout(&mut self, dur: Duration) -> Result<Message, PeerError> {
        let (msg, counter) = timeout(
            dur,
            read_message_with_counter(&mut self.stream, true, &self.recv_key, None, None),
        )
        .await
        .map_err(|_| PeerError::Io("read timeout".into()))?
        .map_err(|e| {
            if e.to_string().contains("HMAC verification failed") {
                PeerError::HmacFailure
            } else {
                PeerError::SlowPeer(e.to_string())
            }
        })?;
        if counter < self.recv_counter {
            return Err(PeerError::SlowPeer("frame counter replay".into()));
        }
        self.recv_counter = counter
            .checked_add(1)
            .ok_or_else(|| PeerError::Io("recv counter overflow".into()))?;
        Ok(msg)
    }

}

// ── Reader/Writer/Supervisor types and functions ──

/// Lock-free shared state between reader, writer, and supervisor tasks.
pub struct PeerSharedState {
    /// Total bytes read by the reader task. Updated after each chunk read.
    pub bytes_read: AtomicU64,
    /// Set by reader when a Pong is received; cleared by supervisor.
    pub pong_received: AtomicBool,
    /// Set by supervisor when a Ping is sent; read by reader to classify Pong.
    pub awaiting_pong: AtomicBool,
    /// Set by supervisor to signal both tasks to shut down.
    pub shutdown: AtomicBool,
    /// v1.4.2 Fix 3: this peer's slice of the node-wide in-flight frame
    /// budget. The reader reserves `payload_len` bytes against this before
    /// allocating a pre-verification buffer; the reservation releases
    /// on drop (after HMAC verify or error). `None` in test / legacy paths
    /// that don't construct a full node.
    pub frame_budget: Option<Arc<crate::network::frame_budget::PeerBudget>>,
}

impl PeerSharedState {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            bytes_read: AtomicU64::new(0),
            pong_received: AtomicBool::new(false),
            awaiting_pong: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
            frame_budget: None,
        }
    }

    pub fn with_frame_budget(
        frame_budget: Arc<crate::network::frame_budget::PeerBudget>,
    ) -> Self {
        Self {
            bytes_read: AtomicU64::new(0),
            pong_received: AtomicBool::new(false),
            awaiting_pong: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
            frame_budget: Some(frame_budget),
        }
    }
}

/// Control messages sent to the writer task with priority over normal messages.
#[derive(Debug)]
pub enum WriterControl {
    SendPong,
    SendPing,
}

/// Reader task state: owns the read half of the TCP stream and crypto state.
pub struct ReaderState {
    pub stream: OwnedReadHalf,
    pub recv_key: [u8; 32],
    pub recv_counter: u64,
    pub counter_buf: [u8; 8],
    pub counter_buf_len: usize,
    pub counter_started: Option<std::time::Instant>,
}

/// Writer task state: owns the write half of the TCP stream and crypto state.
pub struct WriterState {
    pub stream: OwnedWriteHalf,
    pub send_key: [u8; 32],
    pub send_counter: u64,
}

/// Immutable peer metadata shared (via Arc) across tasks.
pub struct PeerMetadata {
    pub addr: SocketAddr,
    pub identity: [u8; 32],
}

/// Write a framed, HMAC-authenticated message to any `AsyncWrite` stream.
/// Used by both `Peer::send()` (handshake path) and the writer task.
pub async fn write_framed_message<W: AsyncWrite + Unpin>(
    stream: &mut W,
    msg: &Message,
    send_key: &[u8; 32],
    send_counter: &mut u64,
) -> Result<(), PeerError> {
    const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
    let frame = msg
        .serialize()
        .map_err(|e| PeerError::SerializationError(e.to_string()))?;
    let counter = *send_counter;
    *send_counter = counter
        .checked_add(1)
        .ok_or_else(|| PeerError::Io("send counter overflow".into()))?;
    let tag = compute_frame_hmac(send_key, counter, &frame);
    let mut buf = Vec::with_capacity(8 + frame.len() + HMAC_TAG_SIZE);
    buf.extend_from_slice(&counter.to_le_bytes());
    buf.extend_from_slice(&frame);
    buf.extend_from_slice(&tag);
    timeout(WRITE_TIMEOUT, stream.write_all(&buf))
        .await
        .map_err(|_| PeerError::Io("write timeout: peer not reading".into()))?
        .map_err(|e| PeerError::Io(e.to_string()))
}

/// Read a single framed message from the reader's stream, updating crypto state.
/// This is the reader task's main read primitive — combines counter accumulation,
/// frame read, HMAC verification, and byte-progress reporting.
pub async fn reader_recv(
    state: &mut ReaderState,
    shared: &PeerSharedState,
) -> Result<Option<Message>, PeerError> {
    const COUNTER_DEADLINE_SECS: u64 = 5;
    const POLL_TIMEOUT: Duration = Duration::from_secs(1);
    const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(10);

    let had_partial = state.counter_buf_len > 0;
    if had_partial {
        if let Some(started) = state.counter_started {
            if started.elapsed() >= Duration::from_secs(COUNTER_DEADLINE_SECS) {
                state.counter_buf_len = 0;
                state.counter_started = None;
                return Err(PeerError::SlowPeer(
                    "frame counter trickle timeout (5s)".into(),
                ));
            }
        }
    }

    // Phase 1: Accumulate 8-byte frame counter
    while state.counter_buf_len < 8 {
        use std::pin::Pin;
        use std::task::Context;

        let remaining = &mut state.counter_buf[state.counter_buf_len..];
        let mut read_buf = tokio::io::ReadBuf::new(remaining);
        let read_fut = std::future::poll_fn(|cx: &mut Context<'_>| {
            Pin::new(&mut state.stream).poll_read(cx, &mut read_buf)
        });
        match timeout(POLL_TIMEOUT, read_fut).await {
            Ok(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    return Err(PeerError::Io("connection closed".into()));
                }
                state.counter_buf_len += n;
                shared.bytes_read.fetch_add(n as u64, Ordering::Relaxed);
                if state.counter_started.is_none() {
                    state.counter_started = Some(std::time::Instant::now());
                }
            }
            Ok(Err(e)) => return Err(PeerError::Io(e.to_string())),
            Err(_) => {
                if !had_partial && state.counter_buf_len == 0 {
                    return Ok(None); // clean timeout, no data
                }
                return Err(PeerError::SlowPeer(
                    "timeout during partial frame counter read".into(),
                ));
            }
        }
    }

    let counter = u64::from_le_bytes(state.counter_buf);
    state.counter_buf_len = 0;
    state.counter_started = None;

    // Phase 2: Read the rest of the frame
    let msg = match timeout(
        FRAME_READ_TIMEOUT,
        read_message(
            &mut state.stream,
            true,
            &state.recv_key,
            counter,
            Some(&shared.bytes_read),
            shared.frame_budget.as_ref(),
        ),
    )
    .await
    {
        Ok(Ok(msg)) => msg,
        Ok(Err(e)) => {
            return Err(if e.to_string().contains("HMAC verification failed") {
                PeerError::HmacFailure
            } else {
                PeerError::SlowPeer(e.to_string())
            })
        }
        Err(_) => {
            return Err(PeerError::SlowPeer(
                "frame read timeout: peer too slow mid-message".into(),
            ))
        }
    };

    if counter < state.recv_counter {
        return Err(PeerError::SlowPeer("frame counter replay".into()));
    }
    state.recv_counter = counter
        .checked_add(1)
        .ok_or_else(|| PeerError::Io("recv counter overflow".into()))?;
    Ok(Some(msg))
}

/// Writer task: drains control and normal channels, writes frames to the socket.
pub async fn writer_task(
    mut state: WriterState,
    mut ctrl_rx: mpsc::Receiver<WriterControl>,
    mut normal_rx: mpsc::Receiver<Message>,
    shared: Arc<PeerSharedState>,
) -> Result<(), PeerError> {
    loop {
        if shared.shutdown.load(Ordering::Relaxed) {
            return Ok(());
        }

        // Drain all pending control messages first (non-blocking)
        loop {
            match ctrl_rx.try_recv() {
                Ok(WriterControl::SendPong) => {
                    write_framed_message(
                        &mut state.stream,
                        &Message::Pong,
                        &state.send_key,
                        &mut state.send_counter,
                    )
                    .await?;
                }
                Ok(WriterControl::SendPing) => {
                    write_framed_message(
                        &mut state.stream,
                        &Message::Ping,
                        &state.send_key,
                        &mut state.send_counter,
                    )
                    .await?;
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => return Ok(()),
            }
        }

        // select! with bias: control channel takes priority
        tokio::select! {
            biased;
            ctrl = ctrl_rx.recv() => {
                match ctrl {
                    Some(WriterControl::SendPong) => {
                        write_framed_message(
                            &mut state.stream,
                            &Message::Pong,
                            &state.send_key,
                            &mut state.send_counter,
                        ).await?;
                    }
                    Some(WriterControl::SendPing) => {
                        write_framed_message(
                            &mut state.stream,
                            &Message::Ping,
                            &state.send_key,
                            &mut state.send_counter,
                        ).await?;
                    }
                    None => return Ok(()),
                }
            }
            msg = normal_rx.recv() => {
                match msg {
                    Some(m) => {
                        write_framed_message(
                            &mut state.stream,
                            &m,
                            &state.send_key,
                            &mut state.send_counter,
                        ).await?;
                    }
                    None => return Ok(()),
                }
            }
        }
    }
}

/// Verify a peer's Ed25519 signature over a transcript.
fn verify_peer_sig(
    pubkey: &[u8; 32],
    transcript: &[u8; 32],
    sig_bytes: &[u8; 64],
    addr: SocketAddr,
) -> Result<(), PeerError> {
    // Reject small-order (weak) keys — they produce predictable DH shared
    // secrets and can forge handshake signatures across unrelated transcripts.
    if crate::types::is_weak_ed25519_key(pubkey) {
        warn!("Rejected weak (small-order) identity key from {}", addr);
        return Err(PeerError::AuthFailed);
    }
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| {
        warn!("Invalid public key from {}", addr);
        PeerError::AuthFailed
    })?;
    let sig = Signature::from_bytes(sig_bytes);
    vk.verify(transcript.as_ref(), &sig).map_err(|_| {
        warn!("Auth signature verification failed from {}", addr);
        PeerError::AuthFailed
    })
}

/// Read a Hello message during handshake.
///
/// Only accepts msg_type 0x01 (Hello) with payload ≤ 268 bytes.
/// Prevents unauthenticated peers from triggering large allocations.
pub async fn read_hello(stream: &mut TcpStream) -> Result<Message, std::io::Error> {
    let msg_type = stream.read_u8().await?;
    if msg_type != 0x01 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("handshake: expected Hello (0x01), got 0x{:02x}", msg_type),
        ));
    }

    let payload_len = stream.read_u32_le().await? as usize;
    if payload_len > HELLO_V4_PAYLOAD_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "handshake: Hello payload too large",
        ));
    }

    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;

    let mut full = Vec::with_capacity(5 + payload_len);
    full.push(msg_type);
    full.extend_from_slice(&(payload_len as u32).to_le_bytes());
    full.extend_from_slice(&payload);

    match Message::deserialize(&full) {
        Ok((msg, _)) => Ok(msg),
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("deserialization error: {}", e),
        )),
    }
}

/// Read an AuthAck message during handshake (responder only).
///
/// Only accepts msg_type 0x18 (AuthAck) with payload == 64 bytes.
pub async fn read_auth_ack(stream: &mut TcpStream) -> Result<[u8; 64], std::io::Error> {
    let msg_type = stream.read_u8().await?;
    if msg_type != MSG_AUTH_ACK {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "handshake: expected AuthAck (0x{:02x}), got 0x{:02x}",
                MSG_AUTH_ACK, msg_type
            ),
        ));
    }
    let payload_len = stream.read_u32_le().await? as usize;
    if payload_len != 64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "handshake: AuthAck payload must be 64 bytes",
        ));
    }
    let mut sig = [0u8; 64];
    stream.read_exact(&mut sig).await?;
    Ok(sig)
}

/// Read a single framed message from a stream and verify its HMAC tag.
/// Reads the 8-byte frame counter, then msg_type, payload, and HMAC tag.
/// Returns the deserialized message and the frame counter.
///
/// `frame_budget` is the per-peer in-flight budget (v1.4.2 Fix 3). Pass
/// `None` only from legacy / test paths that don't have a budget in scope
/// — the main reader task passes `Some(...)` and the cap is enforced.
#[allow(dead_code)]
async fn read_message_with_counter<S: AsyncRead + Unpin>(
    stream: &mut S,
    allow_heavy: bool,
    session_key: &[u8; 32],
    bytes_read: Option<&AtomicU64>,
    frame_budget: Option<&Arc<crate::network::frame_budget::PeerBudget>>,
) -> Result<(Message, u64), std::io::Error> {
    // 5-second timeout on the 8-byte frame counter to prevent slowloris
    // attacks where a peer trickles one byte per second to hold the connection.
    let counter = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_u64_le())
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "frame counter read timeout")
        })??;
    let msg = read_message(
        stream,
        allow_heavy,
        session_key,
        counter,
        bytes_read,
        frame_budget,
    )
    .await?;
    Ok((msg, counter))
}

/// Read a message after the frame counter has already been consumed.
/// Reads msg_type, payload_length, payload, and HMAC tag.
async fn read_message<S: AsyncRead + Unpin>(
    stream: &mut S,
    allow_heavy: bool,
    session_key: &[u8; 32],
    counter: u64,
    bytes_read: Option<&AtomicU64>,
    frame_budget: Option<&Arc<crate::network::frame_budget::PeerBudget>>,
) -> Result<Message, std::io::Error> {
    let msg_type = stream.read_u8().await?;
    read_message_after_type(
        stream,
        msg_type,
        allow_heavy,
        session_key,
        counter,
        bytes_read,
        frame_budget,
    )
    .await
}

/// Maximum bytes to allocate eagerly for small frames (no chunked read needed).
/// Payloads above this threshold are read in chunks with throughput enforcement.
const EAGER_ALLOC_LIMIT: usize = 32_768; // 32 KiB

/// Chunk size for incremental reads of large payloads.
const READ_CHUNK_SIZE: usize = 32_768; // 32 KiB

/// Per-chunk read deadline. A peer must deliver each 32 KiB chunk within this
/// window or be disconnected. At 32 KiB / 5s this enforces a ~6.4 KB/s floor.
const CHUNK_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Wire-header bytes that precede every frame payload: `msg_type: u8` +
/// `payload_len: u32 LE` = 5 bytes. Excludes the trailing HMAC tag, which
/// lives on the stack as a fixed 16-byte array and is not heap-allocated.
pub(crate) const FRAME_HEADER_SIZE: usize = 5;

/// Honest peak pre-HMAC-verification heap memory held by
/// [`read_message_after_type`] for a single frame of the given payload size.
///
/// The reader keeps two buffers alive simultaneously at the peak (the moment
/// HMAC verification runs):
///
///   1. `payload: Vec<u8>` of length `payload_len` — read from the socket.
///   2. `full: Vec<u8>` of length `FRAME_HEADER_SIZE + payload_len` — the
///      frame header + payload copy required to feed HMAC verification
///      with a single contiguous slice.
///
/// Peak = `payload_len + (FRAME_HEADER_SIZE + payload_len)`
///      = `2 · payload_len + FRAME_HEADER_SIZE`.
///
/// This is the **single source of truth** for the frame-budget
/// reservation: `read_message_after_type` reserves exactly this many
/// bytes from the peer's frame budget before allocating the payload
/// buffer. The drift-catching test `reservation_always_geq_actual_peak`
/// in this file invokes the full read path through a duplex stream and
/// asserts this formula is not an underestimate for any legitimate
/// `payload_len`. If a future change to the reader introduces an
/// additional transient allocation, the drift test will fail until this
/// formula is updated.
///
/// Not intended for production callers outside `read_message_after_type`
/// and this module's tests.
pub(crate) fn peak_prever_bytes(payload_len: usize) -> usize {
    // payload buffer + reconstructed full-frame buffer held concurrently.
    // `saturating_add` is cheap insurance against an attacker-controlled
    // payload_len near usize::MAX; the caller already bounds payload_len
    // to `MAX_MESSAGE_SIZE` (8 MiB) before reaching this helper.
    payload_len
        .saturating_mul(2)
        .saturating_add(FRAME_HEADER_SIZE)
}

/// Test-only probe into the frame-budget reservation path. Each
/// [`record`] captures one invocation of `read_message_after_type` that
/// used a `FrameBudget`; tests drain the buffer with [`take`] and assert
/// invariants (typically that `reserved >= actual_peak`).
#[cfg(test)]
pub(crate) mod test_probe {
    use std::sync::Mutex;

    #[derive(Debug, Clone)]
    pub struct FrameBudgetRecord {
        pub payload_len: usize,
        pub reserved: usize,
        pub actual_peak: usize,
    }

    static RECORDS: Mutex<Vec<FrameBudgetRecord>> = Mutex::new(Vec::new());

    pub fn clear() {
        RECORDS.lock().unwrap().clear();
    }

    pub fn take() -> Vec<FrameBudgetRecord> {
        std::mem::take(&mut *RECORDS.lock().unwrap())
    }

    pub(crate) fn record(payload_len: usize, reserved: usize, actual_peak: usize) {
        RECORDS.lock().unwrap().push(FrameBudgetRecord {
            payload_len,
            reserved,
            actual_peak,
        });
    }
}

/// Read the remainder of a frame after the msg_type byte has been consumed.
///
/// For large payloads (> EAGER_ALLOC_LIMIT), reads in fixed-size chunks with
/// per-chunk deadlines to prevent pre-allocation DoS (trickle attacks).
/// Small payloads are read in a single `read_exact` since the allocation is bounded.
///
/// After reading the payload, reads and verifies a 16-byte HMAC-SHA256 tag.
/// Returns an error on HMAC mismatch (caller should disconnect).
async fn read_message_after_type<S: AsyncRead + Unpin>(
    stream: &mut S,
    msg_type: u8,
    allow_heavy: bool,
    session_key: &[u8; 32],
    counter: u64,
    bytes_read: Option<&AtomicU64>,
    frame_budget: Option<&Arc<crate::network::frame_budget::PeerBudget>>,
) -> Result<Message, std::io::Error> {
    let payload_len = stream.read_u32_le().await? as usize;

    if payload_len > MAX_MESSAGE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "message too large",
        ));
    }

    let max_payload = match msg_type {
        0x01 => HELLO_V4_PAYLOAD_SIZE,               // Hello (v4: 268)
        0x02 | 0x03 | 0x13 => 0,                     // Ping, Pong, GetTip
        0x10 => MAX_BLOCK_SIZE,                      // NewBlock
        0x12 => MAX_BLOCK_SIZE,                      // BlockResponse
        0x16 => 0,                                   // GetAddr (empty payload)
        0x17 => 4 + MAX_ADDR_ITEMS * 26,             // Addr
        0x18 => 64,                                  // AuthAck
        0x20 => MAX_TX_SIZE,                         // NewTx
        0x11 | 0x15 => 4 + MAX_GETBLOCKS_ITEMS * 32, // GetBlocks, Inv
        0x14 => 72, // TipResponse (v5: height + block_id + cumulative_work)
        0x21 => 12, // GetHeaders
        0x22 => {
            if allow_heavy {
                4 + MAX_GETBLOCKS_ITEMS * HEADER_SIZE
            } else {
                0
            }
        }
        _ => 0,
    };
    if payload_len > max_payload {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "message payload too large",
        ));
    }

    // v1.4.2 Fix 3: reserve in-flight buffer budget BEFORE allocating.
    // The reservation RAII-releases on any return path — HMAC pass, HMAC
    // fail, deserialization error, or I/O error — so the budget is freed
    // whether the frame was honest or not. `_reservation` is held across
    // the payload read, HMAC verify, and deserialize.
    //
    // Updated after the first expert re-review: `peak_prever_bytes` now
    // accounts for BOTH the payload buffer and the reconstructed full-frame
    // buffer held concurrently during HMAC verification — pre-fix the
    // reservation was `payload_len` alone, which undercounted by ~2×.
    let reservation_bytes = peak_prever_bytes(payload_len);
    let _reservation = if let Some(budget) = frame_budget {
        match budget.try_reserve(reservation_bytes) {
            Ok(r) => Some(r),
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("frame budget exhausted — shedding peer: {}", e),
                ));
            }
        }
    } else {
        None
    };

    // Read the payload — chunked for large frames, eager for small ones.
    let payload = if payload_len <= EAGER_ALLOC_LIMIT {
        // Small payload: single allocation + read is safe (bounded at 32 KiB).
        let mut buf = vec![0u8; payload_len];
        if !buf.is_empty() {
            stream.read_exact(&mut buf).await?;
        }
        buf
    } else {
        // Large payload: allocate and read in chunks with per-chunk deadlines.
        // This prevents a malicious peer from forcing a 4 MiB allocation then
        // trickling bytes to hold memory/IO for the full frame timeout.
        read_payload_chunked(stream, payload_len, bytes_read).await?
    };

    // Read the 16-byte HMAC tag that follows the payload.
    let mut received_tag = [0u8; HMAC_TAG_SIZE];
    stream.read_exact(&mut received_tag).await?;

    // Reconstruct the frame for HMAC verification and deserialization.
    let mut full = Vec::with_capacity(FRAME_HEADER_SIZE + payload_len);
    full.push(msg_type);
    full.extend_from_slice(&(payload_len as u32).to_le_bytes());
    full.extend_from_slice(&payload);

    // v1.4.2: drift-catching probe. In test builds, record the actual
    // peak bytes held at this moment (payload + full reconstruction)
    // alongside the reservation size. `reservation_always_geq_actual_peak`
    // (below) asserts reserved >= actual_peak across a range of frame
    // sizes and catches the class of accounting drift the first expert
    // re-review identified.
    #[cfg(test)]
    {
        if frame_budget.is_some() {
            // Measure *logical* bytes in the two live buffers, not
            // `capacity()`, so the check is independent of allocator
            // rounding. Any future transient allocation added to this
            // function MUST both update `peak_prever_bytes` above AND
            // extend this sum — the drift test will only catch omissions
            // from the formula, not from this probe.
            let actual_peak = payload.len() + full.len();
            test_probe::record(payload_len, reservation_bytes, actual_peak);
        }
    }

    // Verify HMAC before deserializing — reject tampered frames early.
    if !verify_frame_hmac(session_key, counter, &full, &received_tag) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HMAC verification failed",
        ));
    }

    match Message::deserialize(&full) {
        Ok((msg, _)) => Ok(msg),
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("deserialization error: {}", e),
        )),
    }
}

/// Read `total` bytes from `stream` in fixed-size chunks with per-chunk deadlines.
///
/// Instead of allocating the full buffer upfront and calling `read_exact` (which
/// lets an attacker claim N bytes then trickle), this reads one chunk at a time:
///   1. Allocate chunk-sized buffer (32 KiB)
///   2. Read up to `min(remaining, 32 KiB)` with a 5-second deadline
///   3. Append to output, repeat
///
/// If any chunk times out, the peer is too slow and we return an error immediately.
/// This enforces a minimum throughput of ~6.4 KB/s and bounds inflight allocation
/// to one chunk above what's already been received.
///
/// When `bytes_read` is provided, updates the atomic counter after each chunk
/// to report read progress to the supervisor for liveness detection.
async fn read_payload_chunked<S: AsyncRead + Unpin>(
    stream: &mut S,
    total: usize,
    bytes_read: Option<&AtomicU64>,
) -> Result<Vec<u8>, std::io::Error> {
    let mut payload = Vec::new();
    let mut remaining = total;

    while remaining > 0 {
        let chunk_size = remaining.min(READ_CHUNK_SIZE);
        let start = payload.len();
        payload.resize(start + chunk_size, 0);

        match timeout(CHUNK_READ_TIMEOUT, stream.read_exact(&mut payload[start..])).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "slow peer: chunk read timed out ({} of {} bytes received)",
                        total - remaining,
                        total
                    ),
                ));
            }
        }

        remaining -= chunk_size;
        if let Some(counter) = bytes_read {
            counter.fetch_add(chunk_size as u64, Ordering::Relaxed);
        }
    }

    Ok(payload)
}

/// Derive directional MAC keys from the shared session key.
///
/// Returns `(initiator_to_responder_key, responder_to_initiator_key)`.
/// Each direction gets its own key so that a reflected frame (captured
/// from one direction and replayed on the other) will fail HMAC verification.
fn derive_directional_keys(session_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(crate::types::DS_MAC_IR);
    h.update(session_key);
    let i2r: [u8; 32] = h.finalize().into();

    let mut h = Sha256::new();
    h.update(crate::types::DS_MAC_RI);
    h.update(session_key);
    let r2i: [u8; 32] = h.finalize().into();

    (i2r, r2i)
}

/// Compute truncated HMAC-SHA256 tag over a serialized frame.
/// HMAC covers: counter_u64_le || frame (msg_type || payload_length || payload).
fn compute_frame_hmac(session_key: &[u8; 32], counter: u64, frame: &[u8]) -> [u8; HMAC_TAG_SIZE] {
    let mut mac =
        HmacSha256::new_from_slice(session_key).expect("HMAC-SHA256 accepts any key size");
    mac.update(&counter.to_le_bytes());
    mac.update(frame);
    let result = mac.finalize().into_bytes();
    let mut tag = [0u8; HMAC_TAG_SIZE];
    tag.copy_from_slice(&result[..HMAC_TAG_SIZE]);
    tag
}

/// Verify a truncated HMAC-SHA256 tag. Returns false on mismatch.
fn verify_frame_hmac(
    session_key: &[u8; 32],
    counter: u64,
    frame: &[u8],
    received_tag: &[u8; HMAC_TAG_SIZE],
) -> bool {
    let expected = compute_frame_hmac(session_key, counter, frame);
    // Constant-time comparison to avoid timing side-channels.
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(received_tag.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[derive(Debug)]
pub enum PeerError {
    Io(String),
    HandshakeTimeout,
    GenesisMismatch,
    VersionMismatch,
    UnexpectedMessage,
    PongTimeout,
    RateLimitExceeded,
    SerializationError(String),
    NonceMismatch,
    AuthFailed,
    SelfConnection,
    /// Peer is too slow delivering frame data (trickle attack or genuinely
    /// poor connection). Per-chunk throughput floor or frame deadline exceeded.
    SlowPeer(String),
    /// Per-frame HMAC verification failed — tampered or corrupted message.
    /// An authenticated peer sending tampered frames is compromised or malicious.
    HmacFailure,
    /// Connection rejected because this identity already has a live session.
    /// Carries the authenticated identity so the reconnect loop can suppress.
    DuplicateIdentity([u8; 32]),
}

impl std::fmt::Display for PeerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerError::Io(e) => write!(f, "I/O error: {}", e),
            PeerError::HandshakeTimeout => write!(f, "handshake timeout"),
            PeerError::GenesisMismatch => write!(f, "genesis block mismatch"),
            PeerError::VersionMismatch => write!(f, "protocol version mismatch"),
            PeerError::UnexpectedMessage => write!(f, "unexpected message during handshake"),
            PeerError::PongTimeout => write!(f, "pong timeout"),
            PeerError::RateLimitExceeded => write!(f, "rate limit exceeded"),
            PeerError::SerializationError(e) => write!(f, "serialization error: {}", e),
            PeerError::NonceMismatch => write!(f, "nonce-echo mismatch (liveness check failed)"),
            PeerError::AuthFailed => write!(f, "authentication failed (invalid signature)"),
            PeerError::SelfConnection => write!(f, "self-connection detected (same identity key)"),
            PeerError::SlowPeer(e) => write!(f, "slow peer: {}", e),
            PeerError::HmacFailure => write!(f, "HMAC verification failed (tampered frame)"),
            PeerError::DuplicateIdentity(_) => write!(f, "duplicate identity"),
        }
    }
}

impl std::error::Error for PeerError {}

#[cfg(test)]
mod frame_budget_drift_tests {
    use super::*;
    use crate::network::frame_budget::{FrameBudget, PeerBudget};
    use tokio::io::AsyncWriteExt;

    /// v1.4.2 drift-catching test (added after first expert re-review).
    ///
    /// Runs a full `read_message_after_type` against an in-memory
    /// duplex stream for a spread of payload sizes spanning the eager
    /// allocation boundary and up to `MAX_BLOCK_SIZE`. For each frame
    /// the probe records the reservation size and the actual peak data
    /// bytes held at HMAC verification time. Asserts reservation ≥
    /// actual peak.
    ///
    /// This test exists to prevent the class of accounting drift the
    /// first expert re-review identified: the reader originally held
    /// a payload buffer AND a reconstructed full-frame buffer at the
    /// peak, but the reservation accounted only for the payload — the
    /// caps were "half-honest". Any future change that introduces a
    /// new transient allocation in the read path must update
    /// `peak_prever_bytes` AND the probe in `read_message_after_type`;
    /// this test fails otherwise.
    ///
    /// The frames carry bogus HMAC tags so the function returns an
    /// error after the probe runs — we only need to reach the probe
    /// point, not complete the read successfully.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn reservation_always_geq_actual_peak() {
        test_probe::clear();

        // Payload sizes spanning: empty, small, eager/chunked boundary,
        // large, MAX_BLOCK_SIZE. msg_type 0x10 (NewBlock) permits payloads
        // up to MAX_BLOCK_SIZE.
        let sizes: &[usize] = &[
            0,
            1,
            100,
            EAGER_ALLOC_LIMIT - 1,
            EAGER_ALLOC_LIMIT,
            EAGER_ALLOC_LIMIT + 1,
            100_000,
            1_048_576,       // 1 MiB
            4 * 1024 * 1024, // MAX_BLOCK_SIZE
        ];

        for &payload_len in sizes {
            // Wire format read_message_after_type consumes (msg_type has
            // already been pulled by the caller and is passed as an
            // argument): 4 bytes payload_len u32 LE, N bytes payload,
            // 16 bytes HMAC tag.
            let mut wire = Vec::with_capacity(4 + payload_len + HMAC_TAG_SIZE);
            wire.extend_from_slice(&(payload_len as u32).to_le_bytes());
            wire.extend(std::iter::repeat(0x42u8).take(payload_len));
            wire.extend_from_slice(&[0u8; HMAC_TAG_SIZE]);

            let (mut client, mut server) = tokio::io::duplex(wire.len() + 1024);
            client.write_all(&wire).await.unwrap();
            // Close the client so read_payload_chunked's inner read_exact
            // gets EOF rather than hanging if payload_len is 0.
            drop(client);

            let global = FrameBudget::new();
            let peer_budget = PeerBudget::new(global);

            // HMAC will fail (bogus tag) — we don't care. The probe
            // fires BEFORE HMAC verification, so we still capture.
            let _ = read_message_after_type(
                &mut server,
                0x10, // NewBlock — allows MAX_BLOCK_SIZE payloads
                true,
                &[0u8; 32],
                0,
                None,
                Some(&peer_budget),
            )
            .await;
        }

        let records = test_probe::take();
        assert_eq!(
            records.len(),
            sizes.len(),
            "expected one probe record per frame ({} sizes), got {}",
            sizes.len(),
            records.len()
        );

        for r in &records {
            assert!(
                r.reserved >= r.actual_peak,
                "accounting drift: payload_len={} reserved={} actual_peak={} \
                 — a new transient allocation was added to read_message_after_type \
                 without updating peak_prever_bytes",
                r.payload_len,
                r.reserved,
                r.actual_peak,
            );
            // Also verify the formula matches exactly for the current
            // allocation set — this is the tighter invariant. If the
            // reader starts over-allocating (e.g. someone changes
            // `Vec::with_capacity(FRAME_HEADER_SIZE + payload_len)` to
            // a larger expression), this catches it.
            assert_eq!(
                r.reserved,
                2 * r.payload_len + FRAME_HEADER_SIZE,
                "peak_prever_bytes formula diverged from 2·payload+header"
            );
            assert_eq!(
                r.actual_peak,
                2 * r.payload_len + FRAME_HEADER_SIZE,
                "actual_peak diverged from the two-buffer invariant for payload_len {}",
                r.payload_len
            );
        }
    }
}
