//! Asserts every canonical address-codec vector (issue #36) against the
//! in-tree codec. The fixture tests/vectors/address_vectors.json is the
//! shared cross-ecosystem file; regenerate it with
//!     cargo run --features dev-harness --bin gen_address_vectors
//! and this test must stay green without edits.

use bech32::primitives::decode::CheckedHrpstring;
use bech32::Bech32m;
use exfer::types::address::{self, AddressParseError, Network};

const VECTORS_JSON: &str = include_str!("vectors/address_vectors.json");

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
        other => panic!("unknown network in vector file: {}", other),
    }
}

#[test]
fn all_vectors_hold_against_codec() {
    let doc: serde_json::Value = serde_json::from_str(VECTORS_JSON).expect("valid vectors JSON");

    // The fixture must carry the same provisional HRPs the codec compiles
    // with; a silent HRP change would otherwise leave stale vectors green.
    assert_eq!(doc["hrp"]["mainnet"], Network::Mainnet.hrp());
    assert_eq!(doc["hrp"]["testnet"], Network::Testnet.hrp());
    assert_eq!(doc["hrp"]["devnet"], Network::Devnet.hrp());

    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(
        vectors.len() >= 50,
        "vector fixture suspiciously small: {} entries",
        vectors.len()
    );

    let mut checked = 0usize;
    for vector in vectors {
        let id = vector["id"].as_str().expect("id");
        let input = vector["input"].as_str().expect("input");
        let network = vector["network"].as_str().expect("network");
        let expect_ok = match vector["expect"].as_str().expect("expect") {
            "ok" => true,
            "err" => false,
            other => panic!("{}: bad expect value {}", id, other),
        };

        if network == "any" {
            // BIP-350 official vectors: raw bech32m library check.
            let ok = CheckedHrpstring::new::<Bech32m>(input).is_ok();
            assert_eq!(ok, expect_ok, "{}: raw bech32m decode of {:?}", id, input);
            checked += 1;
            continue;
        }

        let node = parse_network(network);
        match address::parse_any(input, node) {
            Ok(payload) => {
                assert!(expect_ok, "{}: parsed ok but vector expects err", id);
                let want = vector["payload_hex"].as_str().expect("payload_hex");
                assert_eq!(hex::encode(payload), want, "{}: payload mismatch", id);

                // Canonical form re-encodes losslessly and re-parses.
                let canonical = vector["canonical"].as_str().expect("canonical");
                assert_eq!(
                    address::encode(&payload, node),
                    canonical,
                    "{}: canonical encoding mismatch",
                    id
                );
                assert_eq!(
                    address::parse_any(canonical, node),
                    Ok(payload),
                    "{}: canonical form must re-parse",
                    id
                );
            }
            Err(e) => {
                assert!(!expect_ok, "{}: expected ok, got {:?} ({})", id, e, e);
                let want = vector["error_class"].as_str().expect("error_class");
                assert_eq!(error_class(&e), want, "{}: error class mismatch", id);
            }
        }
        checked += 1;
    }
    assert_eq!(checked, vectors.len());
}

/// Devnet is a runtime mode: `types::enter_devnet` binds the devnet genesis
/// id as the process signature domain (issues #29/#32), and current_network
/// keys off that bind. Lives here rather than in the lib unit tests because
/// the bind is process-global and set-once; this integration binary owns its
/// process.
#[test]
fn current_network_reports_devnet_after_enter_devnet() {
    exfer::types::enter_devnet().expect("first and only bind in this process");
    assert_eq!(address::current_network(), Network::Devnet);
}
