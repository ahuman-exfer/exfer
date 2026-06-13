//! Checksummed address encoding (issue #36).
//!
//! Encoding is bech32m (BIP-350) over the raw 32-byte address hash. There is
//! no witness-version byte: a Phase 1 script IS the 32-byte pubkey hash, so
//! the payload is exactly `Hash256::domain_hash(DS_ADDR, pubkey)`.
//!
//! Scope note: this module only adds the codec and a parser that accepts both
//! the checksummed form and legacy 64-hex. Display/emission everywhere stays
//! 64-hex in this phase — no `hex::encode` call site changes until the
//! Phase 2 emit flip (blocked on a pending API decision).
//!
//! String rules (BIP-350): lowercase is canonical; all-uppercase is accepted
//! (QR alphanumeric mode); mixed case is rejected. The payload must decode to
//! exactly 32 bytes with zero padding bits, so every payload has exactly one
//! valid lowercase encoding per network.

use std::fmt;
use std::sync::LazyLock;

use bech32::primitives::decode::{CheckedHrpstring, CheckedHrpstringError};
use bech32::{Bech32, Bech32m, Fe32, Hrp};

use super::hash::Hash256;

// ── Human-readable parts ──
//
// FINAL per the PR #38 format sign-off: bech32m IS the exfer address
// format, and xf / xft / xfd are FINAL. Defined once here so a different
// choice later is a one-line change.

pub const HRP_MAINNET: &str = "xf";
pub const HRP_TESTNET: &str = "xft";
pub const HRP_DEVNET: &str = "xfd";

/// Devnet genesis id, the runtime marker for devnet mode (issues #29/#32).
/// Cached because `current_network()` may sit on a per-request parse path.
static DEVNET_GENESIS_ID: LazyLock<Hash256> =
    LazyLock::new(|| crate::genesis::devnet_genesis_block().header.block_id());

// ── Network ──

/// The network an address belongs to, as carried by its HRP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
    Devnet,
}

impl Network {
    /// The bech32m human-readable part for this network.
    pub fn hrp(self) -> &'static str {
        match self {
            Network::Mainnet => HRP_MAINNET,
            Network::Testnet => HRP_TESTNET,
            Network::Devnet => HRP_DEVNET,
        }
    }

    /// Map a (lowercase) HRP back to its network. `None` for any HRP outside
    /// the whitelist (e.g. "bc", "cosmos") — callers report those generically
    /// rather than guessing at foreign ecosystems.
    pub fn from_hrp(hrp: &str) -> Option<Network> {
        match hrp {
            HRP_MAINNET => Some(Network::Mainnet),
            HRP_TESTNET => Some(Network::Testnet),
            HRP_DEVNET => Some(Network::Devnet),
            _ => None,
        }
    }

    /// Lowercase human-readable name, for error messages.
    pub fn name(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Devnet => "devnet",
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The network this process is on, derived from the two EXISTING identity
/// mechanisms — no new global:
///
/// - Devnet is a runtime mode, not a build: `exfer devnet` (and the signer's
///   verified-devnet path) routes through `types::enter_devnet`, which binds
///   the process signature domain to the devnet genesis id (issues #29/#32).
///   A signature domain equal to that id is therefore the definitive devnet
///   marker.
/// - Otherwise the compile-time `testnet` cargo feature decides testnet vs
///   mainnet, exactly as it does for genesis difficulty.
pub fn current_network() -> Network {
    if crate::genesis::signature_domain() == *DEVNET_GENESIS_ID {
        return Network::Devnet;
    }
    if cfg!(feature = "testnet") {
        Network::Testnet
    } else {
        Network::Mainnet
    }
}

// ── Errors ──

/// Why an address string failed to parse. Messages match the RPC error tone
/// ("Address must be 32 bytes (64 hex chars), got {}").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddressParseError {
    /// bech32m checksum verification failed.
    BadChecksum,
    /// The string carries a valid bech32 (non-m) checksum over a whitelisted
    /// HRP. Distinct from `BadChecksum` because it points at the actual
    /// mistake (wrong checksum algorithm, e.g. a BIP-173 encoder).
    WrongChecksumVariant,
    /// Both upper- and lowercase characters present (BIP-350 forbids this;
    /// note legacy hex addresses are exempt — `hex::decode` accepts mixed
    /// case and that behavior is preserved bit-for-bit).
    MixedCase,
    /// A valid address for a different whitelisted network.
    WrongNetwork { found: Network, expected: Network },
    /// bech32m payload decoded to a byte length other than 32.
    BadPayloadLength(usize),
    /// Hex candidate (all hex digits) with a character count other than 64.
    BadHexLength(usize),
    /// Checksum-valid bech32m with non-zero padding bits in the final data
    /// character. Rejected so each payload has exactly one valid encoding.
    BadPadding,
    /// Anything else: unknown HRP, bad charset, no separator, not hex.
    UnknownFormat,
}

impl fmt::Display for AddressParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressParseError::BadChecksum => write!(f, "Invalid address checksum"),
            AddressParseError::WrongChecksumVariant => {
                write!(f, "Address uses the bech32 checksum; expected bech32m")
            }
            AddressParseError::MixedCase => {
                write!(f, "Mixed-case address; use all lowercase or all uppercase")
            }
            AddressParseError::WrongNetwork { found, expected } => {
                write!(f, "{} address not valid on this {} node", found, expected)
            }
            AddressParseError::BadPayloadLength(got) => {
                write!(f, "Address payload must be 32 bytes, got {}", got)
            }
            AddressParseError::BadHexLength(got) => {
                write!(
                    f,
                    "Address must be 32 bytes (64 hex chars), got {} hex chars",
                    got
                )
            }
            AddressParseError::BadPadding => {
                write!(f, "Address has non-zero bech32m padding bits")
            }
            AddressParseError::UnknownFormat => {
                write!(
                    f,
                    "Unrecognized address format (expected bech32m or 64 hex chars)"
                )
            }
        }
    }
}

impl std::error::Error for AddressParseError {}

// ── Encoding ──

/// Encode a 32-byte address hash as a lowercase bech32m string for `network`.
pub fn encode(bytes: &[u8; 32], network: Network) -> String {
    let hrp = Hrp::parse(network.hrp()).expect("whitelisted HRP constants are valid");
    // Infallible for a 32-byte payload: 2-3 char HRP + separator + 52 data
    // chars + 6 checksum chars is far below the bech32m code length limit.
    bech32::encode::<Bech32m>(hrp, bytes).expect("32-byte payload fits the bech32m code length")
}

// ── Parsing ──

/// Parse an address in EITHER form accepted on this node:
///
/// - bech32m for the node's own `network` (lowercase or all-uppercase), or
/// - legacy 64-hex (preserved bit-for-bit: `hex::decode` semantics, so mixed
///   case hex stays accepted exactly as every RPC handler accepts it today).
///
/// Dispatch is structural: a whitelisted-HRP prefix ("xf1"/"xft1"/"xfd1",
/// case-insensitive) routes to the strict bech32m decoder, exactly 64 hex
/// digits route to legacy hex, anything else is an error. The two routes
/// cannot collide: hex strings never contain 'x'.
pub fn parse_any(s: &str, network: Network) -> Result<[u8; 32], AddressParseError> {
    if let Some(found) = match_hrp_prefix(s) {
        return decode_bech32m(s, found, network);
    }

    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        if s.len() != 64 {
            return Err(AddressParseError::BadHexLength(s.len()));
        }
        // 64 hex digits always decode to exactly 32 bytes; keep the failure
        // arm anyway so no user input can reach a panic.
        return match hex::decode(s) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(&bytes);
                Ok(out)
            }
            _ => Err(AddressParseError::UnknownFormat),
        };
    }

    Err(AddressParseError::UnknownFormat)
}

/// If `s` starts with a whitelisted HRP plus the '1' separator
/// (case-insensitive), return that network.
fn match_hrp_prefix(s: &str) -> Option<Network> {
    let lower = s.to_ascii_lowercase();
    for network in [Network::Mainnet, Network::Testnet, Network::Devnet] {
        // HRPs are distinct before the separator ("xf1..." vs "xft1..."), so
        // at most one prefix matches.
        if lower.len() > network.hrp().len()
            && lower.as_bytes()[network.hrp().len()] == b'1'
            && lower.starts_with(network.hrp())
        {
            return Some(network);
        }
    }
    None
}

/// Strict bech32m decode of a whitelisted-HRP string: exact checksum
/// algorithm, single case, 32-byte payload, zero padding bits, and the HRP
/// must match the node's own network.
fn decode_bech32m(
    s: &str,
    found: Network,
    expected: Network,
) -> Result<[u8; 32], AddressParseError> {
    let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
    if has_upper && has_lower {
        return Err(AddressParseError::MixedCase);
    }

    let checked = match CheckedHrpstring::new::<Bech32m>(s) {
        Ok(checked) => checked,
        Err(CheckedHrpstringError::Checksum(_)) => {
            // Distinguish "valid bech32, wrong algorithm" from a plain bad
            // checksum: one extra checksum pass, only on the failure path.
            return if CheckedHrpstring::new::<Bech32>(s).is_ok() {
                Err(AddressParseError::WrongChecksumVariant)
            } else {
                Err(AddressParseError::BadChecksum)
            };
        }
        // Charset / separator / HRP parse errors. The prefix matched a
        // whitelisted HRP, so these are malformed data characters.
        Err(_) => return Err(AddressParseError::UnknownFormat),
    };

    // Defensive re-check against the decoder's own HRP view; the dispatch
    // prefix match already pinned `found`.
    match Network::from_hrp(&checked.hrp().to_lowercase()) {
        Some(network) if network == found => {}
        _ => return Err(AddressParseError::UnknownFormat),
    }
    if found != expected {
        return Err(AddressParseError::WrongNetwork { found, expected });
    }

    let bytes: Vec<u8> = checked.byte_iter().collect();
    if bytes.len() != 32 {
        return Err(AddressParseError::BadPayloadLength(bytes.len()));
    }

    // 32 bytes implies exactly 52 data characters (floor(52*5/8) == 32), so
    // the final character carries 4 padding bits. BIP-350 requires them to
    // be zero; enforcing it keeps the encoding canonical (otherwise every
    // payload would have 16 checksum-valid spellings).
    let data = checked.data_part_ascii_no_checksum();
    let last = match data.last() {
        Some(&b) => match Fe32::from_char(char::from(b)) {
            Ok(fe) => fe,
            Err(_) => return Err(AddressParseError::UnknownFormat),
        },
        None => return Err(AddressParseError::UnknownFormat),
    };
    if last.to_u8() & 0x0f != 0 {
        return Err(AddressParseError::BadPadding);
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DS_ADDR;
    use bech32::primitives::iter::{ByteIterExt, Fe32IterExt};

    const NETWORKS: [Network; 3] = [Network::Mainnet, Network::Testnet, Network::Devnet];

    /// An asymmetric payload (catches byte-order / off-by-one mistakes that
    /// all-zero / all-ff payloads cannot).
    fn asym_payload() -> [u8; 32] {
        let mut p = [0u8; 32];
        for (i, b) in p.iter_mut().enumerate() {
            *b = i as u8;
        }
        p
    }

    /// Re-encode `payload` for `hrp_str` with the given checksum algorithm,
    /// optionally bumping the final data character's low (padding) bit.
    fn encode_with<Ck: bech32::Checksum>(
        hrp_str: &str,
        payload: &[u8],
        bump_padding: bool,
    ) -> String {
        let hrp = Hrp::parse(hrp_str).expect("valid test hrp");
        let mut fes: Vec<Fe32> = payload.iter().copied().bytes_to_fes().collect();
        if bump_padding {
            let last = fes.last_mut().expect("non-empty payload");
            *last = Fe32::try_from(last.to_u8() | 0x01).expect("0..32 is a valid Fe32");
        }
        fes.iter()
            .copied()
            .with_checksum::<Ck>(&hrp)
            .chars()
            .collect()
    }

    #[test]
    fn test_round_trip_all_networks() {
        for network in NETWORKS {
            for payload in [[0u8; 32], [0xffu8; 32], asym_payload()] {
                let s = encode(&payload, network);
                assert!(s.starts_with(&format!("{}1", network.hrp())), "{}", s);
                assert_eq!(s, s.to_ascii_lowercase(), "canonical form is lowercase");
                assert_eq!(parse_any(&s, network), Ok(payload));
            }
        }
    }

    #[test]
    fn test_round_trip_derived_address() {
        // A real Phase 1 address: domain-separated hash of a fixed pubkey,
        // exactly what TxOutput::pubkey_hash_from_key computes.
        let mut pubkey = [0u8; 32];
        for (i, b) in pubkey.iter_mut().enumerate() {
            *b = (i as u8) + 1;
        }
        let payload = Hash256::domain_hash(DS_ADDR, &pubkey).0;
        for network in NETWORKS {
            let s = encode(&payload, network);
            assert_eq!(parse_any(&s, network), Ok(payload));
        }
    }

    #[test]
    fn test_uppercase_accepted_mixed_case_rejected() {
        let payload = asym_payload();
        for network in NETWORKS {
            let s = encode(&payload, network);
            assert_eq!(parse_any(&s.to_ascii_uppercase(), network), Ok(payload));

            // Flip exactly one character to uppercase: mixed case.
            let mut mixed = s.clone().into_bytes();
            let i = mixed.len() - 1;
            mixed[i] = mixed[i].to_ascii_uppercase();
            let mixed = String::from_utf8(mixed).expect("ascii");
            assert_ne!(mixed, s, "last char must be a letter for this test");
            assert_eq!(
                parse_any(&mixed, network),
                Err(AddressParseError::MixedCase)
            );
        }
    }

    #[test]
    fn test_single_substitution_detected() {
        let s = encode(&asym_payload(), Network::Mainnet);
        let data_start = HRP_MAINNET.len() + 1;
        // First data char, a middle char, and the final checksum char.
        for idx in [data_start, data_start + 26, s.len() - 1] {
            let mut bytes = s.clone().into_bytes();
            bytes[idx] = if bytes[idx] == b'q' { b'p' } else { b'q' };
            let mutated = String::from_utf8(bytes).expect("ascii");
            assert_ne!(mutated, s);
            assert_eq!(
                parse_any(&mutated, Network::Mainnet),
                Err(AddressParseError::BadChecksum),
                "substitution at index {} must fail the checksum",
                idx
            );
        }
    }

    #[test]
    fn test_adjacent_transposition_detected() {
        // BCH property: any 2-character substitution is detected, and a
        // transposition of two distinct adjacent chars is exactly that.
        for payload in [[0x5au8; 32], asym_payload(), [0xffu8; 32]] {
            let s = encode(&payload, Network::Mainnet);
            let bytes = s.as_bytes();
            let data_start = HRP_MAINNET.len() + 1;
            let mut transposed_any = false;
            for i in data_start..s.len() - 1 {
                if bytes[i] != bytes[i + 1] {
                    let mut t = bytes.to_vec();
                    t.swap(i, i + 1);
                    let t = String::from_utf8(t).expect("ascii");
                    assert!(
                        parse_any(&t, Network::Mainnet).is_err(),
                        "transposition at {} must be detected: {}",
                        i,
                        t
                    );
                    transposed_any = true;
                }
            }
            assert!(transposed_any, "payload produced no distinct adjacent pair");
        }
    }

    #[test]
    fn test_bech32_non_m_rejected_distinctly() {
        let payload = asym_payload();
        for network in NETWORKS {
            let s = encode_with::<Bech32>(network.hrp(), &payload, false);
            assert_eq!(
                parse_any(&s, network),
                Err(AddressParseError::WrongChecksumVariant)
            );
        }
    }

    #[test]
    fn test_wrong_network_carries_found_network() {
        let payload = asym_payload();
        let testnet_addr = encode(&payload, Network::Testnet);
        let err = parse_any(&testnet_addr, Network::Mainnet).expect_err("wrong network");
        assert_eq!(
            err,
            AddressParseError::WrongNetwork {
                found: Network::Testnet,
                expected: Network::Mainnet,
            }
        );
        assert_eq!(
            err.to_string(),
            "testnet address not valid on this mainnet node"
        );

        let mainnet_addr = encode(&payload, Network::Mainnet);
        for node in [Network::Testnet, Network::Devnet] {
            assert_eq!(
                parse_any(&mainnet_addr, node),
                Err(AddressParseError::WrongNetwork {
                    found: Network::Mainnet,
                    expected: node,
                })
            );
        }
        let devnet_addr = encode(&payload, Network::Devnet);
        assert_eq!(
            parse_any(&devnet_addr, Network::Mainnet),
            Err(AddressParseError::WrongNetwork {
                found: Network::Devnet,
                expected: Network::Mainnet,
            })
        );
    }

    #[test]
    fn test_unknown_hrp_is_generic_error() {
        let payload = asym_payload();
        for hrp in ["bc", "cosmos", "xfx"] {
            let s = encode_with::<Bech32m>(hrp, &payload, false);
            assert_eq!(
                parse_any(&s, Network::Mainnet),
                Err(AddressParseError::UnknownFormat),
                "unknown hrp {} must stay generic",
                hrp
            );
        }
    }

    #[test]
    fn test_payload_length_strict() {
        for (len, got) in [(31usize, 31usize), (33, 33)] {
            let payload = vec![0xabu8; len];
            let s = encode_with::<Bech32m>(HRP_MAINNET, &payload, false);
            assert_eq!(
                parse_any(&s, Network::Mainnet),
                Err(AddressParseError::BadPayloadLength(got))
            );
        }
    }

    #[test]
    fn test_nonzero_padding_rejected() {
        let s = encode_with::<Bech32m>(HRP_MAINNET, &asym_payload(), true);
        assert_eq!(
            parse_any(&s, Network::Mainnet),
            Err(AddressParseError::BadPadding)
        );
    }

    #[test]
    fn test_malformed_strings() {
        for s in [
            "",
            "xf",
            "xfqqqqqqqq", // no separator
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            assert_eq!(
                parse_any(s, Network::Mainnet),
                Err(AddressParseError::UnknownFormat)
            );
        }
        // Bad charset character inside an otherwise well-formed string.
        let s = encode(&asym_payload(), Network::Mainnet);
        let mut bytes = s.into_bytes();
        let mid = bytes.len() / 2;
        bytes[mid] = b'b'; // 'b' is not in the bech32 charset
        let s = String::from_utf8(bytes).expect("ascii");
        assert_eq!(
            parse_any(&s, Network::Mainnet),
            Err(AddressParseError::UnknownFormat)
        );
    }

    #[test]
    fn test_legacy_hex_accepted_bit_for_bit() {
        let payload = asym_payload();
        let lower = hex::encode(payload);
        let upper = lower.to_ascii_uppercase();
        // hex::decode accepts mixed case; parse_any must preserve that.
        let mut mixed = String::new();
        for (i, c) in lower.chars().enumerate() {
            if i % 2 == 0 {
                mixed.extend(c.to_uppercase());
            } else {
                mixed.push(c);
            }
        }
        for (s, network) in [
            (lower.as_str(), Network::Mainnet),
            (upper.as_str(), Network::Mainnet),
            (mixed.as_str(), Network::Testnet),
            (lower.as_str(), Network::Devnet),
        ] {
            assert_eq!(
                parse_any(s, network),
                Ok(payload),
                "hex form {} must parse",
                s
            );
            assert_eq!(
                hex::decode(s).expect("valid hex"),
                payload.to_vec(),
                "parse_any hex semantics must match hex::decode"
            );
        }
        // Hex containing '1' must not be mistaken for a bech32 string.
        let ones = "1".repeat(64);
        assert_eq!(parse_any(&ones, Network::Mainnet), Ok([0x11u8; 32]));
    }

    #[test]
    fn test_legacy_hex_length_strict() {
        for len in [63usize, 65] {
            let s = "a".repeat(len);
            assert_eq!(
                parse_any(&s, Network::Mainnet),
                Err(AddressParseError::BadHexLength(len))
            );
        }
        let mut s = "a".repeat(63);
        s.push('g'); // not a hex digit
        assert_eq!(
            parse_any(&s, Network::Mainnet),
            Err(AddressParseError::UnknownFormat)
        );
    }

    #[test]
    fn test_bip350_official_vector_sanity() {
        // Library sanity subset from BIP-350. Network-independent: these are
        // checked against the raw bech32m decoder, not parse_any.
        for valid in [
            "A1LQFN3A",
            "a1lqfn3a",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
            "?1v759aa",
        ] {
            assert!(
                CheckedHrpstring::new::<Bech32m>(valid).is_ok(),
                "BIP-350 valid vector rejected: {}",
                valid
            );
        }
        for invalid in [
            "qyrz8wqd2c9m",  // no separator
            "1qyrz8wqd2c9m", // empty HRP
            "y1b0jsk6g",     // invalid data character
            "M1VUXWEZ",      // checksum calculated with uppercase HRP
            "in1muywd",      // too-short checksum
            "mm1crxm3i",     // invalid character in checksum
        ] {
            assert!(
                CheckedHrpstring::new::<Bech32m>(invalid).is_err(),
                "BIP-350 invalid vector accepted: {}",
                invalid
            );
        }
    }

    #[test]
    fn test_hrp_constants_and_mapping() {
        assert_eq!(Network::Mainnet.hrp(), HRP_MAINNET);
        assert_eq!(Network::Testnet.hrp(), HRP_TESTNET);
        assert_eq!(Network::Devnet.hrp(), HRP_DEVNET);
        for network in NETWORKS {
            assert_eq!(Network::from_hrp(network.hrp()), Some(network));
        }
        assert_eq!(Network::from_hrp("bc"), None);
        assert_eq!(Network::from_hrp("XF"), None, "from_hrp expects lowercase");
    }

    #[test]
    fn test_current_network_without_devnet_bind() {
        // No lib unit test binds the process signature domain, so this
        // process is never devnet here. The devnet branch is exercised in
        // tests/address_vectors.rs (own process, binds via enter_devnet).
        let expected = if cfg!(feature = "testnet") {
            Network::Testnet
        } else {
            Network::Mainnet
        };
        assert_eq!(current_network(), expected);
    }

    #[test]
    fn test_error_display_messages() {
        assert_eq!(
            AddressParseError::BadChecksum.to_string(),
            "Invalid address checksum"
        );
        assert_eq!(
            AddressParseError::BadPayloadLength(31).to_string(),
            "Address payload must be 32 bytes, got 31"
        );
        assert_eq!(
            AddressParseError::BadHexLength(63).to_string(),
            "Address must be 32 bytes (64 hex chars), got 63 hex chars"
        );
    }
}
