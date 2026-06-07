//! Per-subcommand signature-domain coverage (issue #32).
//!
//! Every CLI signing surface — `wallet send --rpc` plus all 18 script
//! subcommands (locks via `fetch_utxos_select` + `sign_p2pkh`; spends via
//! `fetch_lock_tx_output`/`authenticated_output_lookup` +
//! `sign_tx_with_wallet`; HtlcClaim/HtlcReclaim signing INLINE — the two
//! surfaces the #30 attempt missed) — must refuse a node that reports a
//! foreign genesis id, BEFORE any post-check RPC and before any signing.
//!
//! Each case spawns the real binary against a mock node reporting a foreign
//! genesis id and asserts: nonzero exit, the trust-rule error on stderr, and
//! that the mock saw ONLY `get_block_height` — no `get_address_utxos`, no
//! `get_transaction`, no `send_raw_transaction`. Spawning makes this
//! structural: a future subcommand that signs without routing through the
//! shared pre-sign helpers will reach a disabled mock method or submit, and
//! its case here will fail.

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

/// Run one signing subcommand against a foreign-genesis mock node and assert
/// the trust rule fired first.
fn assert_refuses_foreign_domain(label: &str, args: &[&str]) {
    let mock = MockNode::serve(serde_json::json!({
        "height": 9,
        "block_id": hex::encode([0x33; 32]),
        "genesis_block_id": hex::encode([0xCD; 32]),
    }));
    let mut full: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    // Substitute the placeholder RPC url.
    for a in &mut full {
        if a == "RPC_URL" {
            *a = mock.url.clone();
        }
    }
    let out = Command::new(exfer_bin())
        .args(&full)
        .output()
        .unwrap_or_else(|e| panic!("{label}: spawn failed: {e}"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "{label}: must exit nonzero against a foreign-genesis node\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        stderr
    );
    assert!(
        stderr.contains("refusing to sign in a foreign signature domain"),
        "{label}: stderr must carry the trust-rule error, got:\n{stderr}"
    );
    let seen = mock.methods_seen();
    assert!(
        seen.iter().all(|m| m == "get_block_height"),
        "{label}: only get_block_height may be called before the domain check; saw {:?}",
        seen
    );
    assert!(
        !seen.is_empty(),
        "{label}: the domain check must actually have queried the node"
    );
}

#[test]
fn every_signing_subcommand_refuses_a_foreign_genesis_node() {
    let dir = tempfile::tempdir().expect("tempdir");
    let w1 = make_wallet(dir.path(), "w1.key");
    let w2 = make_wallet(dir.path(), "w2.key");
    let w1s = w1.to_str().unwrap();
    let w2s = w2.to_str().unwrap();

    let h = |b: u8| hex::encode([b; 32]); // distinct 32-byte hex args
    let txid = h(0x44);
    let pk_a = h(0x51);
    let pk_b = h(0x52);
    let pk_c = h(0x53);
    let dest = h(0x61);

    // wallet send --rpc (Wallet::build_transaction surface)
    assert_refuses_foreign_domain(
        "wallet send",
        &["wallet", "send", "--wallet", w1s, "--to", &dest, "--amount", "1000", "--rpc", "RPC_URL"],
    );

    // Locks: fetch_utxos_select → sign_p2pkh surface
    assert_refuses_foreign_domain(
        "htlc-lock",
        &["script", "htlc-lock", "--wallet", w1s, "--receiver", &pk_b, "--hash-lock", &h(0x70), "--timeout", "100", "--amount", "1000", "--rpc", "RPC_URL"],
    );
    assert_refuses_foreign_domain(
        "multisig2of2-lock",
        &["script", "multisig2of2-lock", "--wallet", w1s, "--pubkey-b", &pk_b, "--amount", "1000", "--rpc", "RPC_URL"],
    );
    assert_refuses_foreign_domain(
        "multisig1of2-lock",
        &["script", "multisig1of2-lock", "--wallet", w1s, "--pubkey-b", &pk_b, "--amount", "1000", "--rpc", "RPC_URL"],
    );
    assert_refuses_foreign_domain(
        "multisig2of3-lock",
        &["script", "multisig2of3-lock", "--wallet", w1s, "--pubkey-b", &pk_b, "--pubkey-c", &pk_c, "--amount", "1000", "--rpc", "RPC_URL"],
    );
    assert_refuses_foreign_domain(
        "vault-lock",
        &["script", "vault-lock", "--wallet", w1s, "--recovery-pubkey", &pk_b, "--locktime", "100", "--amount", "1000", "--rpc", "RPC_URL"],
    );
    assert_refuses_foreign_domain(
        "escrow-lock",
        &["script", "escrow-lock", "--wallet", w1s, "--party-b", &pk_b, "--arbiter", &pk_c, "--timeout", "100", "--amount", "1000", "--rpc", "RPC_URL"],
    );
    assert_refuses_foreign_domain(
        "delegation-lock",
        &["script", "delegation-lock", "--wallet", w1s, "--delegate", &pk_b, "--expiry", "100", "--amount", "1000", "--rpc", "RPC_URL"],
    );

    // Inline signers (the surfaces #30 missed): authenticated_output_lookup
    // is their first node contact and carries the domain check.
    assert_refuses_foreign_domain(
        "htlc-claim",
        &["script", "htlc-claim", "--wallet", w1s, "--tx-id", &txid, "--preimage", "aabbcc", "--sender", &pk_a, "--timeout", "100", "--rpc", "RPC_URL"],
    );
    assert_refuses_foreign_domain(
        "htlc-reclaim",
        &["script", "htlc-reclaim", "--wallet", w1s, "--tx-id", &txid, "--receiver", &pk_b, "--hash-lock", &h(0x70), "--timeout", "5", "--rpc", "RPC_URL"],
    );

    // Spends: fetch_lock_tx_output → sign_tx_with_wallet surface
    assert_refuses_foreign_domain(
        "multisig2of2-spend",
        &["script", "multisig2of2-spend", "--wallet", w1s, "--wallet2", w2s, "--tx-id", &txid, "--to", &dest, "--rpc", "RPC_URL"],
    );
    assert_refuses_foreign_domain(
        "multisig1of2-spend",
        &["script", "multisig1of2-spend", "--wallet", w1s, "--tx-id", &txid, "--other-pubkey", &pk_b, "--path", "a", "--rpc", "RPC_URL"],
    );
    assert_refuses_foreign_domain(
        "multisig2of3-spend",
        &["script", "multisig2of3-spend", "--wallet", w1s, "--wallet2", w2s, "--tx-id", &txid, "--to", &dest, "--pubkey-a", &pk_a, "--pubkey-b", &pk_b, "--pubkey-c", &pk_c, "--path", "ab", "--rpc", "RPC_URL"],
    );
    assert_refuses_foreign_domain(
        "vault-spend",
        &["script", "vault-spend", "--wallet", w1s, "--tx-id", &txid, "--recovery-pubkey", &pk_b, "--locktime", "5", "--rpc", "RPC_URL"],
    );
    assert_refuses_foreign_domain(
        "vault-recover",
        &["script", "vault-recover", "--wallet", w1s, "--tx-id", &txid, "--primary-pubkey", &pk_b, "--locktime", "100", "--rpc", "RPC_URL"],
    );
    assert_refuses_foreign_domain(
        "escrow-release",
        &["script", "escrow-release", "--wallet", w1s, "--wallet2", w2s, "--tx-id", &txid, "--to", &dest, "--party-a", &pk_a, "--party-b", &pk_b, "--arbiter", &pk_c, "--timeout", "100", "--rpc", "RPC_URL"],
    );
    assert_refuses_foreign_domain(
        "escrow-arbitrate",
        &["script", "escrow-arbitrate", "--wallet", w1s, "--tx-id", &txid, "--to", &dest, "--party-a", &pk_a, "--party-b", &pk_b, "--timeout", "100", "--rpc", "RPC_URL"],
    );
    assert_refuses_foreign_domain(
        "escrow-reclaim",
        &["script", "escrow-reclaim", "--wallet", w1s, "--tx-id", &txid, "--party-b", &pk_b, "--arbiter", &pk_c, "--timeout", "5", "--rpc", "RPC_URL"],
    );
    assert_refuses_foreign_domain(
        "delegation-owner-spend",
        &["script", "delegation-owner-spend", "--wallet", w1s, "--tx-id", &txid, "--delegate", &pk_b, "--expiry", "100", "--rpc", "RPC_URL"],
    );
    assert_refuses_foreign_domain(
        "delegation-delegate-spend",
        &["script", "delegation-delegate-spend", "--wallet", w1s, "--tx-id", &txid, "--owner", &pk_b, "--expiry", "100", "--rpc", "RPC_URL"],
    );
}

/// The named opt-in path: `--expect-genesis <id>` matching the node's
/// reported id gets PAST the domain check (and then fails at the disabled
/// mock method — proving the flow proceeded, not that it spent).
#[test]
fn expect_genesis_flag_admits_the_named_chain() {
    let dir = tempfile::tempdir().expect("tempdir");
    let w1 = make_wallet(dir.path(), "w1.key");
    let foreign = hex::encode([0xCD; 32]);

    let mock = MockNode::serve(serde_json::json!({
        "height": 9,
        "block_id": hex::encode([0x33; 32]),
        "genesis_block_id": foreign,
    }));
    let out = Command::new(exfer_bin())
        .args([
            "script", "htlc-claim",
            "--wallet", w1.to_str().unwrap(),
            "--tx-id", &hex::encode([0x44; 32]),
            "--preimage", "aabbcc",
            "--sender", &hex::encode([0x51; 32]),
            "--timeout", "100",
            "--expect-genesis", &foreign,
            "--rpc", &mock.url,
        ])
        .output()
        .expect("spawn htlc-claim");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("refusing to sign in a foreign signature domain"),
        "named expectation must admit the named chain, got:\n{stderr}"
    );
    let seen = mock.methods_seen();
    assert!(
        seen.contains(&"get_transaction".to_string()),
        "flow must proceed past the domain check to the output lookup; saw {:?}",
        seen
    );
    // Hygiene: all binds happened in spawned child processes — this test
    // process itself must remain unbound.
    assert!(!exfer::genesis::signature_domain_is_bound());
}
