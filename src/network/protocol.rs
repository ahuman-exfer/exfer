use crate::types::block::{Block, BlockHeader, HEADER_SIZE};
use crate::types::hash::Hash256;
use crate::types::transaction::{SerError, Transaction};
use crate::types::{DS_AUTH, DS_SESSION, MAX_ADDR_ITEMS, MAX_GETBLOCKS_ITEMS, MAX_MESSAGE_SIZE};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

/// Wire protocol message types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Hello(HelloMsg),
    AuthAck(AuthAckMsg),
    Ping,
    Pong,
    NewBlock(Block),
    GetBlocks(Vec<Hash256>),
    BlockResponse(Block),
    GetTip,
    TipResponse(TipResponseMsg),
    Inv(Vec<Hash256>),
    NewTx(Transaction),
    GetHeaders(GetHeadersMsg),
    Headers(Vec<BlockHeader>),
    GetAddr,
    Addr(Vec<AddrEntry>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloMsg {
    pub version: u32,
    pub genesis_block_id: Hash256,
    pub best_height: u64,
    pub best_block_id: Hash256,
    pub cumulative_work: [u8; 32],
    /// Liveness challenge nonce.
    pub nonce: [u8; 32],
    /// Echo of the remote peer's nonce.
    pub echo: [u8; 32],
    /// Ed25519 public key for mutual authentication (v4+).
    pub pubkey: [u8; 32],
    /// Ed25519 signature over the auth transcript (v4+).
    /// Zero in the initiator's first Hello; set by the responder.
    pub sig: [u8; 64],
}

/// AuthAck message: initiator's signature sent after verifying the responder's Hello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthAckMsg {
    pub sig: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TipResponseMsg {
    pub height: u64,
    pub block_id: Hash256,
    pub cumulative_work: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetHeadersMsg {
    pub start_height: u64,
    pub max_count: u32,
}

/// Peer address entry for addr relay.
/// Wire format: 16-byte IPv4-mapped-v6 address + 2-byte port LE + 8-byte last_seen LE = 26 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrEntry {
    pub addr: SocketAddr,
    pub last_seen: u64,
}

/// Size in bytes of one serialized AddrEntry on the wire.
pub const ADDR_ENTRY_WIRE_SIZE: usize = 26;

// Message type IDs
const MSG_HELLO: u8 = 0x01;
const MSG_PING: u8 = 0x02;
const MSG_PONG: u8 = 0x03;
const MSG_NEW_BLOCK: u8 = 0x10;
const MSG_GET_BLOCKS: u8 = 0x11;
const MSG_BLOCK_RESPONSE: u8 = 0x12;
const MSG_GET_TIP: u8 = 0x13;
const MSG_TIP_RESPONSE: u8 = 0x14;
const MSG_INV: u8 = 0x15;
pub const MSG_GET_ADDR: u8 = 0x16;
pub const MSG_ADDR: u8 = 0x17;
pub const MSG_AUTH_ACK: u8 = 0x18;
const MSG_NEW_TX: u8 = 0x20;
const MSG_GET_HEADERS: u8 = 0x21;
const MSG_HEADERS: u8 = 0x22;

impl Message {
    /// Serialize to wire format: [msg_type: u8][payload_len: u32 LE][payload]
    /// Returns Err if any contained transaction has fields exceeding wire limits.
    pub fn serialize(&self) -> Result<Vec<u8>, SerError> {
        let (msg_type, payload) = match self {
            Message::Hello(h) => (MSG_HELLO, serialize_hello(h)),
            Message::AuthAck(a) => (MSG_AUTH_ACK, a.sig.to_vec()),
            Message::Ping => (MSG_PING, vec![]),
            Message::Pong => (MSG_PONG, vec![]),
            Message::NewBlock(b) => (MSG_NEW_BLOCK, b.serialize()?),
            Message::GetBlocks(hashes) => (MSG_GET_BLOCKS, serialize_hash_list(hashes)),
            Message::BlockResponse(b) => (MSG_BLOCK_RESPONSE, b.serialize()?),
            Message::GetTip => (MSG_GET_TIP, vec![]),
            Message::TipResponse(t) => (MSG_TIP_RESPONSE, serialize_tip_response(t)),
            Message::Inv(hashes) => (MSG_INV, serialize_hash_list(hashes)),
            Message::NewTx(tx) => (MSG_NEW_TX, tx.serialize()?),
            Message::GetHeaders(g) => (MSG_GET_HEADERS, serialize_get_headers(g)),
            Message::Headers(hdrs) => (MSG_HEADERS, serialize_headers(hdrs)),
            Message::GetAddr => (MSG_GET_ADDR, vec![]),
            Message::Addr(entries) => (MSG_ADDR, serialize_addr_list(entries)),
        };

        let mut buf = Vec::with_capacity(5 + payload.len());
        buf.push(msg_type);
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&payload);
        Ok(buf)
    }

    /// Deserialize from wire format.
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), SerError> {
        if data.len() < 5 {
            return Err(SerError::UnexpectedEof);
        }

        let msg_type = data[0];
        let payload_len = u32::from_le_bytes(data[1..5].try_into().unwrap()) as usize;

        if payload_len > MAX_MESSAGE_SIZE {
            return Err(SerError::InvalidData("message too large".into()));
        }

        if data.len() < 5 + payload_len {
            return Err(SerError::UnexpectedEof);
        }

        let payload = &data[5..5 + payload_len];

        let msg = match msg_type {
            MSG_HELLO => Message::Hello(deserialize_hello(payload)?),
            MSG_PING => {
                if !payload.is_empty() {
                    return Err(SerError::InvalidData("Ping must have empty payload".into()));
                }
                Message::Ping
            }
            MSG_PONG => {
                if !payload.is_empty() {
                    return Err(SerError::InvalidData("Pong must have empty payload".into()));
                }
                Message::Pong
            }
            MSG_NEW_BLOCK => {
                let (block, consumed) = Block::deserialize(payload)?;
                if consumed != payload.len() {
                    return Err(SerError::InvalidData(
                        "trailing bytes in NewBlock payload".into(),
                    ));
                }
                Message::NewBlock(block)
            }
            MSG_GET_BLOCKS => Message::GetBlocks(deserialize_hash_list(payload)?),
            MSG_BLOCK_RESPONSE => {
                let (block, consumed) = Block::deserialize(payload)?;
                if consumed != payload.len() {
                    return Err(SerError::InvalidData(
                        "trailing bytes in BlockResponse payload".into(),
                    ));
                }
                Message::BlockResponse(block)
            }
            MSG_GET_TIP => {
                if !payload.is_empty() {
                    return Err(SerError::InvalidData(
                        "GetTip must have empty payload".into(),
                    ));
                }
                Message::GetTip
            }
            MSG_TIP_RESPONSE => Message::TipResponse(deserialize_tip_response(payload)?),
            MSG_INV => Message::Inv(deserialize_hash_list(payload)?),
            MSG_NEW_TX => {
                let (tx, consumed) = Transaction::deserialize(payload)?;
                if consumed != payload.len() {
                    return Err(SerError::InvalidData(
                        "trailing bytes in NewTx payload".into(),
                    ));
                }
                Message::NewTx(tx)
            }
            MSG_GET_HEADERS => Message::GetHeaders(deserialize_get_headers(payload)?),
            MSG_HEADERS => Message::Headers(deserialize_headers(payload)?),
            MSG_GET_ADDR => {
                if !payload.is_empty() {
                    return Err(SerError::InvalidData(
                        "GetAddr must have empty payload".into(),
                    ));
                }
                Message::GetAddr
            }
            MSG_ADDR => Message::Addr(deserialize_addr_list(payload)?),
            MSG_AUTH_ACK => {
                if payload.len() != 64 {
                    return Err(SerError::InvalidData(
                        "AuthAck payload must be 64 bytes".into(),
                    ));
                }
                let mut sig = [0u8; 64];
                sig.copy_from_slice(payload);
                Message::AuthAck(AuthAckMsg { sig })
            }
            _ => {
                return Err(SerError::InvalidData(format!(
                    "unknown message type: {:#x}",
                    msg_type
                )))
            }
        };

        Ok((msg, 5 + payload_len))
    }
}

/// Hello payload size: 108 (base) + 32 (nonce) + 32 (echo) + 32 (pubkey) + 64 (sig) = 268.
pub const HELLO_V4_PAYLOAD_SIZE: usize = 268;

fn serialize_hello(h: &HelloMsg) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HELLO_V4_PAYLOAD_SIZE);
    buf.extend_from_slice(&h.version.to_le_bytes());
    buf.extend_from_slice(h.genesis_block_id.as_bytes());
    buf.extend_from_slice(&h.best_height.to_le_bytes());
    buf.extend_from_slice(h.best_block_id.as_bytes());
    buf.extend_from_slice(&h.cumulative_work);
    buf.extend_from_slice(&h.nonce);
    buf.extend_from_slice(&h.echo);
    buf.extend_from_slice(&h.pubkey);
    buf.extend_from_slice(&h.sig);
    buf
}

/// Deserialize Hello payload. Accepts 108 (legacy v2), 172 (v3), or 268 (v4+) bytes.
/// Legacy payloads get zero nonce/echo/pubkey/sig. Handshake rejects old versions.
pub fn deserialize_hello(data: &[u8]) -> Result<HelloMsg, SerError> {
    if data.len() < 108 {
        return Err(SerError::UnexpectedEof);
    }
    if data.len() != 108 && data.len() != 172 && data.len() != HELLO_V4_PAYLOAD_SIZE {
        return Err(SerError::InvalidData(
            "Hello payload must be 108, 172, or 268 bytes".into(),
        ));
    }
    let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let mut genesis = [0u8; 32];
    genesis.copy_from_slice(&data[4..36]);
    let best_height = u64::from_le_bytes(data[36..44].try_into().unwrap());
    let mut best_id = [0u8; 32];
    best_id.copy_from_slice(&data[44..76]);
    let mut cumulative_work = [0u8; 32];
    cumulative_work.copy_from_slice(&data[76..108]);

    let (nonce, echo) = if data.len() >= 172 {
        let mut n = [0u8; 32];
        n.copy_from_slice(&data[108..140]);
        let mut e = [0u8; 32];
        e.copy_from_slice(&data[140..172]);
        (n, e)
    } else {
        ([0u8; 32], [0u8; 32])
    };

    let (pubkey, sig) = if data.len() >= HELLO_V4_PAYLOAD_SIZE {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&data[172..204]);
        let mut s = [0u8; 64];
        s.copy_from_slice(&data[204..268]);
        (pk, s)
    } else {
        ([0u8; 32], [0u8; 64])
    };

    Ok(HelloMsg {
        version,
        genesis_block_id: Hash256(genesis),
        best_height,
        best_block_id: Hash256(best_id),
        cumulative_work,
        nonce,
        echo,
        pubkey,
        sig,
    })
}

/// Build the 72-byte tip commitment for the auth transcript:
/// `best_height_le (8) || best_block_id (32) || cumulative_work (32)`.
pub fn tip_commitment(
    best_height: u64,
    best_block_id: &Hash256,
    cumulative_work: &[u8; 32],
) -> [u8; 72] {
    let mut buf = [0u8; 72];
    buf[0..8].copy_from_slice(&best_height.to_le_bytes());
    buf[8..40].copy_from_slice(best_block_id.as_bytes());
    buf[40..72].copy_from_slice(cumulative_work);
    buf
}

/// Compute the domain-separated auth transcript for handshake signature.
///
/// ```text
/// transcript = SHA-256(
///     "EXFER-AUTH" || genesis_id || version_le ||
///     nonce_a || nonce_b || role ||
///     tip_a || tip_b
/// )
/// ```
///
/// `tip_a` / `tip_b` are 72-byte commitments (height || block_id || work)
/// from the initiator (nonce_a side) and responder (nonce_b side) respectively.
/// Binding both tips prevents a MITM from modifying either peer's height or
/// cumulative work claims without invalidating the authenticated signature.
///
/// Role 0x00 = responder, 0x01 = initiator. Both sides sign different messages
/// to prevent reflection attacks.
pub fn compute_auth_transcript(
    genesis_id: &Hash256,
    version: u32,
    nonce_a: &[u8; 32],
    nonce_b: &[u8; 32],
    role: u8,
    tip_a: &[u8; 72],
    tip_b: &[u8; 72],
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(DS_AUTH);
    hasher.update(genesis_id.as_bytes());
    hasher.update(version.to_le_bytes());
    hasher.update(nonce_a);
    hasher.update(nonce_b);
    hasher.update([role]);
    hasher.update(tip_a.as_slice());
    hasher.update(tip_b.as_slice());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Size of the truncated HMAC tag appended to each post-handshake frame.
pub const HMAC_TAG_SIZE: usize = 16;

/// Compute the session MAC key for post-handshake frame authentication.
///
/// Both sides derive the same key by mixing the handshake transcript with an
/// X25519 Diffie-Hellman shared secret derived from their authenticated
/// Ed25519 identity keys:
///   `transcript = SHA-256("EXFER-AUTH" || genesis_id || version_le || nonce_a || nonce_b)`
///   `session_key = SHA-256("EXFER-SESSION" || transcript || dh_shared_secret)`
///
/// The DH shared secret binds the session key to both peers' private keys,
/// so a MITM who lacks either identity key cannot compute valid frame MACs.
/// The transcript binds the session to the specific handshake nonces and genesis.
pub fn compute_session_key(
    genesis_id: &Hash256,
    version: u32,
    nonce_a: &[u8; 32],
    nonce_b: &[u8; 32],
    dh_shared_secret: &[u8; 32],
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(DS_AUTH);
    hasher.update(genesis_id.as_bytes());
    hasher.update(version.to_le_bytes());
    hasher.update(nonce_a);
    hasher.update(nonce_b);
    let transcript = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(DS_SESSION);
    hasher.update(transcript);
    hasher.update(dh_shared_secret);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

fn serialize_hash_list(hashes: &[Hash256]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + hashes.len() * 32);
    buf.extend_from_slice(&(hashes.len() as u32).to_le_bytes());
    for h in hashes {
        buf.extend_from_slice(h.as_bytes());
    }
    buf
}

fn deserialize_hash_list(data: &[u8]) -> Result<Vec<Hash256>, SerError> {
    if data.len() < 4 {
        return Err(SerError::UnexpectedEof);
    }
    let count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if count > MAX_GETBLOCKS_ITEMS {
        return Err(SerError::InvalidLength);
    }
    let expected_len = 4 + count * 32;
    if data.len() < expected_len {
        return Err(SerError::UnexpectedEof);
    }
    if data.len() != expected_len {
        return Err(SerError::InvalidData("trailing bytes in hash list".into()));
    }
    let mut hashes = Vec::with_capacity(count);
    for i in 0..count {
        let offset = 4 + i * 32;
        let mut h = [0u8; 32];
        h.copy_from_slice(&data[offset..offset + 32]);
        hashes.push(Hash256(h));
    }
    Ok(hashes)
}

fn serialize_tip_response(t: &TipResponseMsg) -> Vec<u8> {
    let mut buf = Vec::with_capacity(72);
    buf.extend_from_slice(&t.height.to_le_bytes());
    buf.extend_from_slice(t.block_id.as_bytes());
    buf.extend_from_slice(&t.cumulative_work);
    buf
}

fn deserialize_tip_response(data: &[u8]) -> Result<TipResponseMsg, SerError> {
    if data.len() < 72 {
        return Err(SerError::UnexpectedEof);
    }
    if data.len() != 72 {
        return Err(SerError::InvalidData(
            "trailing bytes in tip response".into(),
        ));
    }
    let height = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let mut id = [0u8; 32];
    id.copy_from_slice(&data[8..40]);
    let mut work = [0u8; 32];
    work.copy_from_slice(&data[40..72]);
    Ok(TipResponseMsg {
        height,
        block_id: Hash256(id),
        cumulative_work: work,
    })
}

fn serialize_get_headers(g: &GetHeadersMsg) -> Vec<u8> {
    let mut buf = Vec::with_capacity(12);
    buf.extend_from_slice(&g.start_height.to_le_bytes());
    buf.extend_from_slice(&g.max_count.to_le_bytes());
    buf
}

fn deserialize_get_headers(data: &[u8]) -> Result<GetHeadersMsg, SerError> {
    if data.len() < 12 {
        return Err(SerError::UnexpectedEof);
    }
    if data.len() != 12 {
        return Err(SerError::InvalidData(
            "trailing bytes in get_headers".into(),
        ));
    }
    let start_height = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let max_count = u32::from_le_bytes(data[8..12].try_into().unwrap());
    Ok(GetHeadersMsg {
        start_height,
        max_count,
    })
}

fn serialize_headers(headers: &[BlockHeader]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + headers.len() * HEADER_SIZE);
    buf.extend_from_slice(&(headers.len() as u32).to_le_bytes());
    for h in headers {
        buf.extend_from_slice(&h.serialize());
    }
    buf
}

fn deserialize_headers(data: &[u8]) -> Result<Vec<BlockHeader>, SerError> {
    if data.len() < 4 {
        return Err(SerError::UnexpectedEof);
    }
    let count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if count > MAX_GETBLOCKS_ITEMS {
        return Err(SerError::InvalidLength);
    }
    let expected_len = 4 + count * HEADER_SIZE;
    if data.len() < expected_len {
        return Err(SerError::UnexpectedEof);
    }
    if data.len() != expected_len {
        return Err(SerError::InvalidData(
            "trailing bytes in headers list".into(),
        ));
    }
    let mut headers = Vec::with_capacity(count);
    for i in 0..count {
        let offset = 4 + i * HEADER_SIZE;
        let arr: [u8; HEADER_SIZE] = data[offset..offset + HEADER_SIZE].try_into().unwrap();
        headers.push(BlockHeader::deserialize(&arr));
    }
    Ok(headers)
}

/// Serialize a SocketAddr as 16-byte IPv4-mapped-v6 + 2-byte port LE.
fn serialize_socket_addr(addr: &SocketAddr) -> [u8; 18] {
    let mut buf = [0u8; 18];
    let v6 = match addr.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    buf[0..16].copy_from_slice(&v6.octets());
    buf[16..18].copy_from_slice(&addr.port().to_le_bytes());
    buf
}

/// Deserialize a SocketAddr from 16-byte IPv4-mapped-v6 + 2-byte port LE.
fn deserialize_socket_addr(data: &[u8; 18]) -> SocketAddr {
    let v6 = Ipv6Addr::from(<[u8; 16]>::try_from(&data[0..16]).unwrap());
    let port = u16::from_le_bytes([data[16], data[17]]);
    // Convert IPv4-mapped-v6 back to v4 for cleaner display
    let ip = match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    };
    SocketAddr::new(ip, port)
}

/// Serialize an AddrEntry: 18 bytes addr + 8 bytes last_seen LE = 26 bytes.
pub fn serialize_addr_entry(entry: &AddrEntry) -> [u8; ADDR_ENTRY_WIRE_SIZE] {
    let mut buf = [0u8; ADDR_ENTRY_WIRE_SIZE];
    buf[0..18].copy_from_slice(&serialize_socket_addr(&entry.addr));
    buf[18..26].copy_from_slice(&entry.last_seen.to_le_bytes());
    buf
}

/// Deserialize an AddrEntry from 26 bytes.
pub fn deserialize_addr_entry(data: &[u8; ADDR_ENTRY_WIRE_SIZE]) -> AddrEntry {
    let addr = deserialize_socket_addr(<&[u8; 18]>::try_from(&data[0..18]).unwrap());
    let last_seen = u64::from_le_bytes(data[18..26].try_into().unwrap());
    AddrEntry { addr, last_seen }
}

fn serialize_addr_list(entries: &[AddrEntry]) -> Vec<u8> {
    let count = entries.len().min(MAX_ADDR_ITEMS);
    let mut buf = Vec::with_capacity(4 + count * ADDR_ENTRY_WIRE_SIZE);
    buf.extend_from_slice(&(count as u32).to_le_bytes());
    for entry in entries.iter().take(count) {
        buf.extend_from_slice(&serialize_addr_entry(entry));
    }
    buf
}

fn deserialize_addr_list(data: &[u8]) -> Result<Vec<AddrEntry>, SerError> {
    if data.len() < 4 {
        return Err(SerError::UnexpectedEof);
    }
    let count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if count > MAX_ADDR_ITEMS {
        return Err(SerError::InvalidLength);
    }
    let expected_len = 4 + count * ADDR_ENTRY_WIRE_SIZE;
    if data.len() < expected_len {
        return Err(SerError::UnexpectedEof);
    }
    if data.len() != expected_len {
        return Err(SerError::InvalidData("trailing bytes in addr list".into()));
    }
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let offset = 4 + i * ADDR_ENTRY_WIRE_SIZE;
        let arr: [u8; ADDR_ENTRY_WIRE_SIZE] = data[offset..offset + ADDR_ENTRY_WIRE_SIZE]
            .try_into()
            .unwrap();
        entries.push(deserialize_addr_entry(&arr));
    }
    Ok(entries)
}

/// Check if a SocketAddr is routable (not private, not loopback, not port 0).
pub fn is_routable(addr: &SocketAddr) -> bool {
    if addr.port() == 0 {
        return false;
    }
    match addr.ip() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                // 0.0.0.0/8 "this network" (RFC 1122)
                || o[0] == 0
                // 100.64.0.0/10 CGNAT (RFC 6598)
                || (o[0] == 100 && (o[1] & 0xC0) == 64)
                // 192.0.0.0/24 IETF protocol assignments (RFC 6890)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                // 192.0.2.0/24 TEST-NET-1 documentation (RFC 5737)
                || (o[0] == 192 && o[1] == 0 && o[2] == 2)
                // 198.51.100.0/24 TEST-NET-2 documentation (RFC 5737)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                // 203.0.113.0/24 TEST-NET-3 documentation (RFC 5737)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
                // 198.18.0.0/15 benchmarking (RFC 2544)
                || (o[0] == 198 && (o[1] & 0xFE) == 18)
                // 224.0.0.0/4 multicast (RFC 5771) + 240.0.0.0/4 reserved (RFC 1112)
                || o[0] >= 224)
        }
        IpAddr::V6(v6) => {
            // Check if IPv4-mapped first — delegate to IPv4 rules
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_routable(&SocketAddr::new(IpAddr::V4(v4), addr.port()));
            }
            let segs = v6.segments();
            !v6.is_loopback()              // ::1
                && !v6.is_unspecified()     // ::
                && !v6.is_multicast()       // ff00::/8
                // fe80::/10 link-local
                && (segs[0] & 0xffc0) != 0xfe80
                // fc00::/7 ULA (unique local address, RFC 4193)
                && (segs[0] & 0xfe00) != 0xfc00
                // 100::/64 discard prefix (RFC 6666)
                && !(segs[0] == 0x0100 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0)
                // 2001:db8::/32 documentation (RFC 3849)
                && !(segs[0] == 0x2001 && segs[1] == 0x0db8)
                // 2001::/32 Teredo tunneling (RFC 4380) — unreliable
                && !(segs[0] == 0x2001 && segs[1] == 0x0000)
                // 64:ff9b::/96 NAT64 translation (RFC 6052)
                && !(segs[0] == 0x0064 && segs[1] == 0xff9b)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_roundtrip() {
        let msg = Message::Hello(HelloMsg {
            version: 1,
            genesis_block_id: Hash256::ZERO,
            best_height: 42,
            best_block_id: Hash256::sha256(b"tip"),
            cumulative_work: {
                let mut w = [0u8; 32];
                w[31] = 42;
                w
            },
            nonce: [0xAA; 32],
            echo: [0xBB; 32],
            pubkey: [0xCC; 32],
            sig: [0xDD; 64],
        });
        let bytes = msg.serialize().unwrap();
        let (msg2, consumed) = Message::deserialize(&bytes).unwrap();
        assert_eq!(msg, msg2);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn test_hello_legacy_108_accepted() {
        // Simulate a v2 peer sending 108-byte Hello (no nonce/echo)
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
        assert_eq!(hello.nonce, [0u8; 32]);
        assert_eq!(hello.echo, [0u8; 32]);
    }

    #[test]
    fn test_ping_pong_roundtrip() {
        for msg in [Message::Ping, Message::Pong] {
            let bytes = msg.serialize().unwrap();
            let (msg2, _) = Message::deserialize(&bytes).unwrap();
            assert_eq!(msg, msg2);
        }
    }

    #[test]
    fn test_get_tip_roundtrip() {
        let msg = Message::GetTip;
        let bytes = msg.serialize().unwrap();
        let (msg2, _) = Message::deserialize(&bytes).unwrap();
        assert_eq!(msg, msg2);
    }

    #[test]
    fn test_tip_response_roundtrip() {
        let msg = Message::TipResponse(TipResponseMsg {
            height: 1000,
            block_id: Hash256::sha256(b"block"),
            cumulative_work: [0x42; 32],
        });
        let bytes = msg.serialize().unwrap();
        let (msg2, _) = Message::deserialize(&bytes).unwrap();
        assert_eq!(msg, msg2);
    }

    #[test]
    fn test_inv_roundtrip() {
        let hashes = vec![Hash256::sha256(b"a"), Hash256::sha256(b"b")];
        let msg = Message::Inv(hashes);
        let bytes = msg.serialize().unwrap();
        let (msg2, _) = Message::deserialize(&bytes).unwrap();
        assert_eq!(msg, msg2);
    }

    #[test]
    fn test_little_endian_wire_format() {
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
        // First byte is message type
        assert_eq!(bytes[0], MSG_HELLO);
        // Next 4 bytes are payload length in little-endian
        let payload_len = u32::from_le_bytes(bytes[1..5].try_into().unwrap());
        assert_eq!(payload_len as usize, bytes.len() - 5);
    }

    #[test]
    fn test_getaddr_roundtrip() {
        let msg = Message::GetAddr;
        let bytes = msg.serialize().unwrap();
        let (msg2, consumed) = Message::deserialize(&bytes).unwrap();
        assert_eq!(msg, msg2);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn test_addr_roundtrip() {
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
        let msg = Message::Addr(entries);
        let bytes = msg.serialize().unwrap();
        let (msg2, consumed) = Message::deserialize(&bytes).unwrap();
        assert_eq!(msg, msg2);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn test_is_routable() {
        assert!(!is_routable(&"127.0.0.1:9333".parse().unwrap()));
        assert!(!is_routable(&"10.0.0.1:9333".parse().unwrap()));
        assert!(!is_routable(&"192.168.1.1:9333".parse().unwrap()));
        assert!(!is_routable(&"172.16.0.1:9333".parse().unwrap()));
        assert!(!is_routable(&"1.2.3.4:0".parse().unwrap()));
        assert!(is_routable(&"1.2.3.4:9333".parse().unwrap()));
        assert!(is_routable(&"8.8.8.8:9333".parse().unwrap()));
        // IPv4 special-use non-routable
        assert!(!is_routable(&"192.0.0.1:9333".parse().unwrap())); // IETF protocol
        assert!(!is_routable(&"192.0.2.1:9333".parse().unwrap())); // TEST-NET-1
        assert!(!is_routable(&"198.51.100.1:9333".parse().unwrap())); // TEST-NET-2
        assert!(!is_routable(&"203.0.113.1:9333".parse().unwrap())); // TEST-NET-3
        assert!(!is_routable(&"198.18.0.1:9333".parse().unwrap())); // benchmarking
        assert!(!is_routable(&"198.19.0.1:9333".parse().unwrap())); // benchmarking
        assert!(!is_routable(&"240.0.0.1:9333".parse().unwrap())); // reserved
        assert!(!is_routable(&"255.255.255.254:9333".parse().unwrap())); // reserved
                                                                         // 0.0.0.0/8 "this network"
        assert!(!is_routable(&"0.0.0.0:9333".parse().unwrap()));
        assert!(!is_routable(&"0.1.0.0:9333".parse().unwrap()));
        assert!(!is_routable(&"0.255.255.255:9333".parse().unwrap()));
        // 224.0.0.0/4 multicast
        assert!(!is_routable(&"224.0.0.1:9333".parse().unwrap()));
        assert!(!is_routable(&"230.0.0.1:9333".parse().unwrap()));
        assert!(!is_routable(&"239.255.255.255:9333".parse().unwrap()));
        // 255.255.255.255 broadcast
        assert!(!is_routable(&"255.255.255.255:9333".parse().unwrap()));
        // IPv6 non-routable
        assert!(!is_routable(&"[::1]:9333".parse().unwrap())); // loopback
        assert!(!is_routable(&"[::]:9333".parse().unwrap())); // unspecified
        assert!(!is_routable(&"[fe80::1]:9333".parse().unwrap())); // link-local
        assert!(!is_routable(&"[fc00::1]:9333".parse().unwrap())); // ULA
        assert!(!is_routable(&"[fd12::1]:9333".parse().unwrap())); // ULA (fd prefix)
        assert!(!is_routable(&"[ff02::1]:9333".parse().unwrap())); // multicast
        assert!(!is_routable(&"[ff05::1]:9333".parse().unwrap())); // multicast (site)
        assert!(!is_routable(&"[100::]:9333".parse().unwrap())); // discard
        assert!(!is_routable(&"[2001:db8::1]:9333".parse().unwrap())); // documentation
        assert!(!is_routable(&"[2001::1]:9333".parse().unwrap())); // Teredo
        assert!(!is_routable(&"[64:ff9b::1]:9333".parse().unwrap())); // NAT64
                                                                      // IPv6 routable
        assert!(is_routable(
            &"[2607:f8b0:4004:800::200e]:9333".parse().unwrap()
        )); // Google public
        assert!(is_routable(
            &"[2a00:1450:4001:802::200e]:9333".parse().unwrap()
        )); // Google EU
    }

    #[test]
    fn test_session_key_deterministic() {
        let genesis = Hash256::ZERO;
        let na = [1u8; 32];
        let nb = [2u8; 32];
        let dh = [0x42u8; 32];
        let k1 = compute_session_key(&genesis, 4, &na, &nb, &dh);
        let k2 = compute_session_key(&genesis, 4, &na, &nb, &dh);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_session_key_differs_by_nonce() {
        let genesis = Hash256::ZERO;
        let na = [1u8; 32];
        let nb1 = [2u8; 32];
        let nb2 = [3u8; 32];
        let dh = [0x42u8; 32];
        let k1 = compute_session_key(&genesis, 4, &na, &nb1, &dh);
        let k2 = compute_session_key(&genesis, 4, &na, &nb2, &dh);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_session_key_differs_by_genesis() {
        let g1 = Hash256([1u8; 32]);
        let g2 = Hash256([2u8; 32]);
        let na = [0xAA; 32];
        let nb = [0xBB; 32];
        let dh = [0x42u8; 32];
        let k1 = compute_session_key(&g1, 4, &na, &nb, &dh);
        let k2 = compute_session_key(&g2, 4, &na, &nb, &dh);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_hmac_tag_size() {
        assert_eq!(HMAC_TAG_SIZE, 16);
    }
}
