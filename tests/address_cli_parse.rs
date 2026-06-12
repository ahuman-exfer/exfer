//! CLI acceptance of checksummed addresses (issue #36, parse side).
//!
//! Address-string arguments (`wallet send --to`, the covenant spend `--to`
//! destinations) must accept legacy 64-hex AND bech32m for the node's own
//! network, with wrong-network bech32m rejected by the specific codec error.
//! Emission stays hex in this phase, so nothing here inspects output formats.
//!
//! Each case spawns the real binary against a mock node that reports the
//! build's canonical genesis id, so the signature-domain check PASSES and
//! the run proceeds to the address parse. "Accepted" is then proven
//! structurally: the flow advances to its first post-parse RPC
//! (`get_address_utxos` for send, `get_transaction` for spends), which the
//! mock refuses — so no flow can accidentally complete a spend.

mod sig_domain_common;

use exfer::types::address::{encode, Network};
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

/// The network the spawned binary resolves after binding the canonical
/// genesis: never devnet, so the compile-time feature decides. The test
/// crate builds with the same features as the binary.
fn own_network() -> Network {
    if cfg!(feature = "testnet") {
        Network::Testnet
    } else {
        Network::Mainnet
    }
}

/// Mock node reporting the canonical genesis id, so the domain check passes
/// and the run reaches the address parse.
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
    // Every flow here ends in an error (rejected address, or the mock
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
fn wallet_send_accepts_hex_and_bech32m_rejects_wrong_network() {
    let dir = tempfile::tempdir().expect("tempdir");
    let w = make_wallet(dir.path(), "w.key");
    let ws = w.to_str().unwrap();

    let dest_bytes = [0x61u8; 32];
    let dest_hex = hex::encode(dest_bytes);
    let dest_b32 = encode(&dest_bytes, own_network());
    let dest_foreign = encode(&dest_bytes, Network::Devnet);

    let send = |to: &str| {
        run_against_mock(&[
            "wallet", "send", "--wallet", ws, "--to", to, "--amount", "1000", "--rpc", "RPC_URL",
        ])
    };

    // Legacy hex baseline: parse passes, flow reaches get_address_utxos.
    let hex_run = send(&dest_hex);
    assert!(
        hex_run
            .methods_seen
            .iter()
            .any(|m| m == "get_address_utxos"),
        "hex --to must reach the UTXO fetch; saw {:?}\nstderr:\n{}",
        hex_run.methods_seen,
        hex_run.stderr
    );

    // bech32m for the node's own network: identical progress to the hex run.
    let b32_run = send(&dest_b32);
    assert!(
        !b32_run.stderr.contains("invalid recipient"),
        "own-network bech32m must parse; stderr:\n{}",
        b32_run.stderr
    );
    assert_eq!(
        b32_run.methods_seen, hex_run.methods_seen,
        "bech32m --to must drive the same RPC sequence as hex"
    );

    // Wrong-network bech32m: rejected with the specific codec message,
    // after the domain check but before any further RPC.
    let foreign_run = send(&dest_foreign);
    let expected = format!(
        "invalid recipient: devnet address not valid on this {} node",
        own_network()
    );
    assert!(
        foreign_run.stderr.contains(&expected),
        "expected `{}` in stderr:\n{}",
        expected,
        foreign_run.stderr
    );
    assert!(
        foreign_run
            .methods_seen
            .iter()
            .all(|m| m == "get_block_height"),
        "wrong-network --to must stop before any post-parse RPC; saw {:?}",
        foreign_run.methods_seen
    );
}

#[test]
fn multisig_spend_destination_accepts_bech32m_rejects_wrong_network() {
    let dir = tempfile::tempdir().expect("tempdir");
    let w1 = make_wallet(dir.path(), "w1.key");
    let w2 = make_wallet(dir.path(), "w2.key");
    let w1s = w1.to_str().unwrap();
    let w2s = w2.to_str().unwrap();

    let txid = hex::encode([0x44u8; 32]);
    let dest_bytes = [0x62u8; 32];
    let dest_b32 = encode(&dest_bytes, own_network());
    let dest_foreign = encode(&dest_bytes, Network::Devnet);

    let spend = |to: &str| {
        run_against_mock(&[
            "script",
            "multisig2of2-spend",
            "--wallet",
            w1s,
            "--wallet2",
            w2s,
            "--tx-id",
            &txid,
            "--to",
            to,
            "--rpc",
            "RPC_URL",
        ])
    };

    // Own-network bech32m destination: parse passes, flow reaches the
    // authenticated lock-tx lookup.
    let b32_run = spend(&dest_b32);
    assert!(
        !b32_run.stderr.contains("invalid to"),
        "own-network bech32m must parse; stderr:\n{}",
        b32_run.stderr
    );
    assert!(
        b32_run.methods_seen.iter().any(|m| m == "get_transaction"),
        "bech32m --to must reach the lock-tx fetch; saw {:?}\nstderr:\n{}",
        b32_run.methods_seen,
        b32_run.stderr
    );

    // Wrong-network destination: the specific codec error, no post-parse RPC.
    let foreign_run = spend(&dest_foreign);
    let expected = format!(
        "invalid to: devnet address not valid on this {} node",
        own_network()
    );
    assert!(
        foreign_run.stderr.contains(&expected),
        "expected `{}` in stderr:\n{}",
        expected,
        foreign_run.stderr
    );
    assert!(
        foreign_run
            .methods_seen
            .iter()
            .all(|m| m == "get_block_height"),
        "wrong-network --to must stop before any post-parse RPC; saw {:?}",
        foreign_run.methods_seen
    );
}
