//! Deterministic generator for the canonical address-codec test vectors
//! (issue #36): writes tests/vectors/address_vectors.json.
//!
//! These vectors are the shared cross-ecosystem fixture (walletd, indexer,
//! mobile, py all assert against the same file), so generation must be fully
//! deterministic: fixed payloads, no randomness, no timestamps. Re-running
//! the generator must produce a byte-identical file.
//!
//! Every vector is self-checked against the in-tree codec before the file is
//! written; a mismatch aborts without writing.
//!
//! Gated behind the dev-harness feature like the other manual harness bins:
//!     cargo run --features dev-harness --bin gen_address_vectors

use bech32::primitives::decode::CheckedHrpstring;
use bech32::primitives::iter::{ByteIterExt, Fe32IterExt};
use bech32::{Bech32, Bech32m, Fe32, Hrp};
use serde_json::{json, Value};

use exfer::types::address::{self, AddressParseError, Network};
use exfer::types::{Hash256, DS_ADDR};

const OUT_PATH: &str = "tests/vectors/address_vectors.json";

// ── Fixed payloads ──

fn zero_payload() -> [u8; 32] {
    [0u8; 32]
}

fn ones_payload() -> [u8; 32] {
    [0xffu8; 32]
}

/// Asymmetric pattern: bytes 0x00..0x1f. Catches byte-order / off-by-one
/// mistakes that the symmetric payloads cannot.
fn asym_payload() -> [u8; 32] {
    let mut p = [0u8; 32];
    for (i, b) in p.iter_mut().enumerate() {
        *b = i as u8;
    }
    p
}

/// A real Phase 1 address: domain-separated hash of a fixed 32-byte pubkey
/// (bytes 0x01..0x20), exactly what TxOutput::pubkey_hash_from_key computes.
fn derived_payload() -> [u8; 32] {
    let mut pubkey = [0u8; 32];
    for (i, b) in pubkey.iter_mut().enumerate() {
        *b = (i as u8) + 1;
    }
    Hash256::domain_hash(DS_ADDR, &pubkey).0
}

// ── Encoding helpers ──

/// Encode `payload` for `hrp_str` with the given checksum algorithm,
/// optionally bumping the final data character's low (padding) bit.
fn encode_with<Ck: bech32::Checksum>(hrp_str: &str, payload: &[u8], bump_padding: bool) -> String {
    let hrp = Hrp::parse(hrp_str).expect("valid hrp");
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

/// Replace the character at `idx` with 'q' (or 'p' if it already is 'q').
fn substitute(s: &str, idx: usize) -> String {
    let mut bytes = s.as_bytes().to_vec();
    bytes[idx] = if bytes[idx] == b'q' { b'p' } else { b'q' };
    String::from_utf8(bytes).expect("ascii")
}

/// Swap the first pair of distinct adjacent characters in the data part.
fn transpose(s: &str, data_start: usize) -> String {
    let mut bytes = s.as_bytes().to_vec();
    for i in data_start..bytes.len() - 1 {
        if bytes[i] != bytes[i + 1] {
            bytes.swap(i, i + 1);
            return String::from_utf8(bytes).expect("ascii");
        }
    }
    panic!("no distinct adjacent pair in {}", s);
}

// ── Vector construction ──

fn network_str(network: Network) -> &'static str {
    network.name()
}

fn ok_vector(id: &str, desc: &str, input: String, network: Network, payload: [u8; 32]) -> Value {
    json!({
        "id": id,
        "desc": desc,
        "input": input,
        "network": network_str(network),
        "expect": "ok",
        "error_class": Value::Null,
        "payload_hex": hex::encode(payload),
        "canonical": address::encode(&payload, network),
    })
}

fn err_vector(id: &str, desc: &str, input: String, network: Network, error_class: &str) -> Value {
    json!({
        "id": id,
        "desc": desc,
        "input": input,
        "network": network_str(network),
        "expect": "err",
        "error_class": error_class,
        "payload_hex": Value::Null,
        "canonical": Value::Null,
    })
}

/// BIP-350 official vectors: network-independent library checks (network
/// "any"), asserted against the raw bech32m decoder rather than parse_any.
fn bip350_vector(id: &str, desc: &str, input: &str, valid: bool) -> Value {
    json!({
        "id": id,
        "desc": desc,
        "input": input,
        "network": "any",
        "expect": if valid { "ok" } else { "err" },
        "error_class": Value::Null,
        "payload_hex": Value::Null,
        "canonical": Value::Null,
    })
}

fn build_vectors() -> Vec<Value> {
    let mut v = Vec::new();

    let networks = [Network::Mainnet, Network::Testnet, Network::Devnet];
    let payloads: [(&str, &str, [u8; 32]); 4] = [
        ("zero", "all-zero payload", zero_payload()),
        ("ones", "all-0xff payload", ones_payload()),
        ("asym", "asymmetric payload 0x00..0x1f", asym_payload()),
        (
            "derived",
            "domain_hash(EXFER-ADDR, pubkey 0x01..0x20), a real Phase 1 address",
            derived_payload(),
        ),
    ];

    // Valid round-trips per network.
    for network in networks {
        for (name, desc, payload) in &payloads {
            v.push(ok_vector(
                &format!("ok_{}_{}", network.name(), name),
                &format!("{} round-trip: {}", network.name(), desc),
                address::encode(payload, network),
                network,
                *payload,
            ));
        }
    }

    // Full-uppercase accepted (QR alphanumeric mode).
    for network in [Network::Mainnet, Network::Testnet] {
        let payload = asym_payload();
        v.push(ok_vector(
            &format!("ok_upper_{}", network.name()),
            "all-uppercase form is accepted; canonical stays lowercase",
            address::encode(&payload, network).to_ascii_uppercase(),
            network,
            payload,
        ));
    }

    // Mixed case rejected.
    let canon = address::encode(&asym_payload(), Network::Mainnet);
    let mut last_upper = canon.clone().into_bytes();
    let i = last_upper.len() - 1;
    last_upper[i] = last_upper[i].to_ascii_uppercase();
    v.push(err_vector(
        "err_mixed_case_last_char",
        "single uppercased character in an otherwise lowercase address",
        String::from_utf8(last_upper).expect("ascii"),
        Network::Mainnet,
        "mixed_case",
    ));
    let mut first_upper = canon.clone().into_bytes();
    first_upper[0] = first_upper[0].to_ascii_uppercase();
    v.push(err_vector(
        "err_mixed_case_hrp_char",
        "uppercased HRP character with lowercase remainder",
        String::from_utf8(first_upper).expect("ascii"),
        Network::Mainnet,
        "mixed_case",
    ));

    // Single-character substitutions: first data char, middle, last checksum char.
    let data_start = Network::Mainnet.hrp().len() + 1;
    for (pos_name, idx) in [
        ("first_data", data_start),
        ("middle", data_start + 26),
        ("last_checksum", canon.len() - 1),
    ] {
        v.push(err_vector(
            &format!("err_substitution_{}", pos_name),
            &format!("single-character substitution at the {} position", pos_name),
            substitute(&canon, idx),
            Network::Mainnet,
            "bad_checksum",
        ));
    }

    // Adjacent transposition.
    v.push(err_vector(
        "err_transposition",
        "first distinct adjacent character pair in the data part swapped",
        transpose(&canon, data_start),
        Network::Mainnet,
        "bad_checksum",
    ));

    // bech32 (non-m) checksum over a whitelisted HRP.
    for network in [Network::Mainnet, Network::Testnet] {
        v.push(err_vector(
            &format!("err_bech32_not_m_{}", network.name()),
            "same payload and HRP but bech32 (BIP-173) checksum instead of bech32m",
            encode_with::<Bech32>(network.hrp(), &asym_payload(), false),
            network,
            "wrong_checksum_variant",
        ));
    }

    // Cross-network: valid address for one whitelisted network parsed on another.
    for (found, node) in [
        (Network::Testnet, Network::Mainnet),
        (Network::Devnet, Network::Mainnet),
        (Network::Mainnet, Network::Testnet),
        (Network::Mainnet, Network::Devnet),
    ] {
        v.push(err_vector(
            &format!("err_wrong_network_{}_on_{}", found.name(), node.name()),
            &format!("{} address parsed on a {} node", found.name(), node.name()),
            address::encode(&asym_payload(), found),
            node,
            "wrong_network",
        ));
    }

    // Unknown (non-whitelisted) HRPs stay a generic error.
    for hrp in ["bc", "cosmos"] {
        v.push(err_vector(
            &format!("err_unknown_hrp_{}", hrp),
            &format!("checksum-valid bech32m under foreign HRP {}", hrp),
            encode_with::<Bech32m>(hrp, &asym_payload(), false),
            Network::Mainnet,
            "unknown_format",
        ));
    }

    // Checksum-valid payloads of the wrong byte length.
    for len in [31usize, 33] {
        v.push(err_vector(
            &format!("err_payload_{}_bytes", len),
            &format!("checksum-valid bech32m carrying a {}-byte payload", len),
            encode_with::<Bech32m>(Network::Mainnet.hrp(), &vec![0xabu8; len], false),
            Network::Mainnet,
            "bad_payload_length",
        ));
    }

    // Checksum-valid but non-zero padding bits (non-canonical encoding).
    v.push(err_vector(
        "err_nonzero_padding",
        "checksum recomputed over a final data character with non-zero padding bits",
        encode_with::<Bech32m>(Network::Mainnet.hrp(), &asym_payload(), true),
        Network::Mainnet,
        "bad_padding",
    ));

    // Malformed strings.
    v.push(err_vector(
        "err_empty",
        "empty string",
        String::new(),
        Network::Mainnet,
        "unknown_format",
    ));
    v.push(err_vector(
        "err_no_separator",
        "bech32 charset characters but no separator",
        "xfqqqqqqqq".to_string(),
        Network::Mainnet,
        "unknown_format",
    ));
    let mut bad_charset = canon.clone().into_bytes();
    let mid = bad_charset.len() / 2;
    bad_charset[mid] = b'b'; // 'b' is excluded from the bech32 charset
    v.push(err_vector(
        "err_bad_charset_char",
        "character outside the bech32 charset in the data part",
        String::from_utf8(bad_charset).expect("ascii"),
        Network::Mainnet,
        "unknown_format",
    ));

    // Legacy hex fallback: accepted forms.
    let asym_hex = hex::encode(asym_payload());
    v.push(ok_vector(
        "ok_hex_lower",
        "legacy 64-hex, lowercase",
        asym_hex.clone(),
        Network::Mainnet,
        asym_payload(),
    ));
    v.push(ok_vector(
        "ok_hex_upper",
        "legacy 64-hex, uppercase (hex::decode semantics)",
        asym_hex.to_ascii_uppercase(),
        Network::Mainnet,
        asym_payload(),
    ));
    let mixed_hex: String = asym_hex
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect();
    v.push(ok_vector(
        "ok_hex_mixed_case",
        "legacy 64-hex, mixed case stays accepted bit-for-bit (hex::decode semantics)",
        mixed_hex,
        Network::Testnet,
        asym_payload(),
    ));
    v.push(ok_vector(
        "ok_hex_contains_separator_char",
        "64-hex consisting of '1' characters must route to hex, not bech32",
        "1".repeat(64),
        Network::Mainnet,
        [0x11u8; 32],
    ));

    // Legacy hex fallback: rejected forms.
    for len in [63usize, 65] {
        v.push(err_vector(
            &format!("err_hex_{}_chars", len),
            &format!("{} hex chars (must be exactly 64)", len),
            "a".repeat(len),
            Network::Mainnet,
            "bad_hex_length",
        ));
    }
    let mut with_g = "a".repeat(63);
    with_g.push('g');
    v.push(err_vector(
        "err_hex_invalid_digit",
        "64 chars but one is 'g', not a hex digit",
        with_g,
        Network::Mainnet,
        "unknown_format",
    ));
    v.push(err_vector(
        "err_hex_0x_prefix",
        "0x-prefixed hex is not accepted",
        format!("0x{}", asym_hex),
        Network::Mainnet,
        "unknown_format",
    ));

    // BIP-350 official vector sanity subset (library check, network "any").
    for (id, input) in [
        ("bip350_valid_upper_empty_data", "A1LQFN3A"),
        ("bip350_valid_lower_empty_data", "a1lqfn3a"),
        (
            "bip350_valid_abcdef",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
        ),
        (
            "bip350_valid_split",
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
        ),
        ("bip350_valid_punct_hrp", "?1v759aa"),
    ] {
        v.push(bip350_vector(
            id,
            "BIP-350 official valid bech32m string",
            input,
            true,
        ));
    }
    for (id, desc, input) in [
        (
            "bip350_invalid_no_separator",
            "no separator character",
            "qyrz8wqd2c9m",
        ),
        ("bip350_invalid_empty_hrp", "empty HRP", "1qyrz8wqd2c9m"),
        (
            "bip350_invalid_data_char",
            "invalid data character",
            "y1b0jsk6g",
        ),
        (
            "bip350_invalid_upper_hrp_checksum",
            "checksum calculated with uppercase HRP",
            "M1VUXWEZ",
        ),
        (
            "bip350_invalid_short_checksum",
            "too-short checksum",
            "in1muywd",
        ),
        (
            "bip350_invalid_checksum_char",
            "invalid character in checksum",
            "mm1crxm3i",
        ),
    ] {
        v.push(bip350_vector(id, desc, input, false));
    }

    v
}

// ── Self-check ──

fn error_class(e: &AddressParseError) -> &'static str {
    match e {
        AddressParseError::BadChecksum => "bad_checksum",
        AddressParseError::WrongChecksumVariant => "wrong_checksum_variant",
        AddressParseError::MixedCase => "mixed_case",
        AddressParseError::WrongNetwork { .. } => "wrong_network",
        AddressParseError::BadPayloadLength(_) => "bad_payload_length",
        AddressParseError::BadHexLength(_) => "bad_hex_length",
        AddressParseError::BadPadding => "bad_padding",
        AddressParseError::UnknownFormat => "unknown_format",
    }
}

fn parse_network(s: &str) -> Network {
    match s {
        "mainnet" => Network::Mainnet,
        "testnet" => Network::Testnet,
        "devnet" => Network::Devnet,
        other => panic!("unknown network in vector: {}", other),
    }
}

/// Assert one vector against the in-tree codec. Returns an error description
/// on mismatch (the generator refuses to write a fixture the codec disagrees
/// with).
fn check_vector(vector: &Value) -> Result<(), String> {
    let id = vector["id"].as_str().expect("id");
    let input = vector["input"].as_str().expect("input");
    let network = vector["network"].as_str().expect("network");
    let expect_ok = vector["expect"].as_str().expect("expect") == "ok";

    if network == "any" {
        // Raw library check (BIP-350 official vectors).
        let ok = CheckedHrpstring::new::<Bech32m>(input).is_ok();
        if ok != expect_ok {
            return Err(format!(
                "{}: library decode ok={} expected ok={}",
                id, ok, expect_ok
            ));
        }
        return Ok(());
    }

    let node = parse_network(network);
    match exfer::types::address::parse_any(input, node) {
        Ok(payload) => {
            if !expect_ok {
                return Err(format!("{}: parsed ok but vector expects err", id));
            }
            let want = vector["payload_hex"].as_str().expect("payload_hex");
            if hex::encode(payload) != want {
                return Err(format!("{}: payload mismatch", id));
            }
            let canonical = vector["canonical"].as_str().expect("canonical");
            if address::encode(&payload, node) != canonical {
                return Err(format!("{}: canonical mismatch", id));
            }
        }
        Err(e) => {
            if expect_ok {
                return Err(format!("{}: expected ok, got {:?}", id, e));
            }
            let want = vector["error_class"].as_str().expect("error_class");
            if error_class(&e) != want {
                return Err(format!(
                    "{}: error class mismatch: got {} want {}",
                    id,
                    error_class(&e),
                    want
                ));
            }
        }
    }
    Ok(())
}

fn main() {
    let vectors = build_vectors();

    let mut failures = 0;
    for vector in &vectors {
        if let Err(msg) = check_vector(vector) {
            eprintln!("self-check failed: {}", msg);
            failures += 1;
        }
    }
    if failures > 0 {
        eprintln!(
            "{} self-check failure(s); not writing {}",
            failures, OUT_PATH
        );
        std::process::exit(1);
    }

    let doc = json!({
        "description": "Canonical exfer address-codec test vectors (issue #36). \
            Encoding is bech32m (BIP-350) over the raw 32-byte address hash, no \
            witness version byte. HRPs are provisional pending founder sign-off. \
            Entries with network=any are BIP-350 official vectors asserted against \
            the raw bech32m decoder; all others run through parse_any(input, network). \
            Generated deterministically by gen_address_vectors; do not edit by hand.",
        "hrp": {
            "mainnet": Network::Mainnet.hrp(),
            "testnet": Network::Testnet.hrp(),
            "devnet": Network::Devnet.hrp(),
        },
        "vectors": vectors,
    });

    std::fs::create_dir_all("tests/vectors").expect("create tests/vectors");
    let mut out = serde_json::to_string_pretty(&doc).expect("serialize vectors");
    out.push('\n');
    std::fs::write(OUT_PATH, &out).expect("write vectors file");

    println!(
        "wrote {} ({} vectors)",
        OUT_PATH,
        doc["vectors"].as_array().expect("array").len()
    );
}
