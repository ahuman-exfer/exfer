//! CLI handling of `wallet send --datum <hex>` (issue #37).
//!
//! The datum argument is decoded and bounded in the CLI handler BEFORE any
//! RPC or UTXO work: bad hex and oversized datums fail with a clean error so
//! consensus is never handed a transaction it will reject. A valid datum
//! must not change the RPC sequence of a send.
//!
//! Same harness as tests/address_cli_parse.rs: each case spawns the real
//! binary against a mock node that reports the build's canonical genesis id,
//! so flows that get past the argument checks proceed to the first
//! post-parse RPC (`get_address_utxos`), which the mock refuses — no flow
//! can accidentally complete a spend.

mod sig_domain_common;

use sig_domain_common::MockNode;
use std::path::PathBuf;
use std::process::Command;

fn exfer_bin() -> &'static str {
    env!("CARGO_BIN_EXE_exfer")
}

/// Generate an unencrypted wallet file; returns its path.
fn make_wallet(dir: &std::path::Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    let out = Command::new(exfer_bin())
        .args(["wallet", "generate", "--no-encrypt", "--json", "--output"])
        .arg(&path)
        .output()
        .expect("spawn wallet generate");
    assert!(out.status.success(), "wallet generate failed: {:?}", out);
    path
}

/// Mock node reporting the canonical genesis id, so the domain check passes
/// and the run reaches the post-parse RPCs.
fn canonical_mock() -> MockNode {
    MockNode::serve(serde_json::json!({
        "height": 9,
        "block_id": hex::encode([0x33; 32]),
        "genesis_block_id": hex::encode(exfer::genesis::GENESIS_BLOCK_ID.as_bytes()),
    }))
}

struct RunOutcome {
    stderr: String,
    methods_seen: Vec<String>,
}

fn run_against_mock(args: &[&str]) -> RunOutcome {
    let mock = canonical_mock();
    let mut full: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    for a in &mut full {
        if a == "RPC_URL" {
            *a = mock.url.clone();
        }
    }
    let out = Command::new(exfer_bin())
        .args(&full)
        .output()
        .expect("spawn exfer binary");
    // Every flow here ends in an error (rejected datum, or the mock
    // refusing the first post-parse RPC) — never a completed spend.
    assert!(
        !out.status.success(),
        "no flow may complete against the method-refusing mock\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    RunOutcome {
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        methods_seen: mock.methods_seen(),
    }
}

#[test]
fn wallet_send_datum_bad_hex_fails_before_any_rpc() {
    let dir = tempfile::tempdir().expect("tempdir");
    let w = make_wallet(dir.path(), "w.key");
    let ws = w.to_str().unwrap();
    let dest_hex = hex::encode([0x61u8; 32]);

    let run = run_against_mock(&[
        "wallet", "send", "--wallet", ws, "--to", &dest_hex, "--amount", "1000", "--datum",
        "not-hex", "--rpc", "RPC_URL",
    ]);
    assert!(
        run.stderr.contains("invalid datum hex"),
        "bad hex must fail with the clean datum error; stderr:\n{}",
        run.stderr
    );
    assert!(
        run.methods_seen.is_empty(),
        "bad --datum hex must fail before ANY RPC; saw {:?}",
        run.methods_seen
    );
}

#[test]
fn wallet_send_datum_empty_fails_before_any_rpc() {
    let dir = tempfile::tempdir().expect("tempdir");
    let w = make_wallet(dir.path(), "w.key");
    let ws = w.to_str().unwrap();
    let dest_hex = hex::encode([0x61u8; 32]);

    // "" decodes to zero bytes — a distinct wire form (present, empty datum)
    // nobody means from a CLI flag; reject rather than attach it silently.
    let run = run_against_mock(&[
        "wallet", "send", "--wallet", ws, "--to", &dest_hex, "--amount", "1000", "--datum", "",
        "--rpc", "RPC_URL",
    ]);
    assert!(
        run.stderr.contains("datum is empty"),
        "empty --datum must fail with the empty-datum error; stderr:\n{}",
        run.stderr
    );
    assert!(
        run.methods_seen.is_empty(),
        "empty --datum must fail before ANY RPC; saw {:?}",
        run.methods_seen
    );
}

#[test]
fn wallet_send_datum_oversize_fails_before_any_rpc() {
    let dir = tempfile::tempdir().expect("tempdir");
    let w = make_wallet(dir.path(), "w.key");
    let ws = w.to_str().unwrap();
    let dest_hex = hex::encode([0x61u8; 32]);

    // 8194 hex chars = 4097 bytes = MAX_DATUM_SIZE + 1.
    let oversize = "ab".repeat(exfer::types::MAX_DATUM_SIZE + 1);
    let run = run_against_mock(&[
        "wallet", "send", "--wallet", ws, "--to", &dest_hex, "--amount", "1000", "--datum",
        &oversize, "--rpc", "RPC_URL",
    ]);
    let expected = format!(
        "datum is {} bytes, exceeds MAX_DATUM_SIZE {}",
        exfer::types::MAX_DATUM_SIZE + 1,
        exfer::types::MAX_DATUM_SIZE
    );
    assert!(
        run.stderr.contains(&expected),
        "expected `{}` in stderr:\n{}",
        expected,
        run.stderr
    );
    assert!(
        run.methods_seen.is_empty(),
        "oversized --datum must fail before ANY RPC; saw {:?}",
        run.methods_seen
    );
}

#[test]
fn wallet_send_valid_datum_drives_same_rpc_sequence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let w = make_wallet(dir.path(), "w.key");
    let ws = w.to_str().unwrap();
    let dest_hex = hex::encode([0x61u8; 32]);

    // Baseline: no datum. Flow reaches the UTXO fetch, which the mock refuses.
    let plain = run_against_mock(&[
        "wallet", "send", "--wallet", ws, "--to", &dest_hex, "--amount", "1000", "--rpc", "RPC_URL",
    ]);
    assert!(
        plain.methods_seen.iter().any(|m| m == "get_address_utxos"),
        "plain send must reach the UTXO fetch; saw {:?}\nstderr:\n{}",
        plain.methods_seen,
        plain.stderr
    );

    // Valid datum: identical RPC progress to the plain send.
    let datum_hex = hex::encode(b"arbitrary-test-payload");
    let with_datum = run_against_mock(&[
        "wallet", "send", "--wallet", ws, "--to", &dest_hex, "--amount", "1000", "--datum",
        &datum_hex, "--rpc", "RPC_URL",
    ]);
    assert!(
        !with_datum.stderr.contains("datum"),
        "valid --datum must not trip the datum checks; stderr:\n{}",
        with_datum.stderr
    );
    assert_eq!(
        with_datum.methods_seen, plain.methods_seen,
        "valid --datum must drive the same RPC sequence as a plain send"
    );
}
