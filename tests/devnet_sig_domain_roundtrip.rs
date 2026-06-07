//! Devnet signature-domain round-trip over real RPC (issue #32).
//!
//! Spawns a REAL `exfer devnet` node process and drives the real binary
//! against its JSON-RPC:
//!  1. RPC contract: `get_block_height.genesis_block_id` is the devnet
//!     genesis id (node.genesis_id, the handshake identity) — never the tip.
//!  2. Trust rule against a real node: `wallet send` WITHOUT
//!     `--expect-genesis` is refused (devnet id != compiled canonical id).
//!  3. Round-trip: `wallet send --expect-genesis devnet` binds the devnet
//!     domain in the CLI process and the spend verifies on the devnet node.
//!  4. Replay rejection: the SAME spend signed in the canonical domain (this
//!     test process, which never binds) is rejected by the devnet node —
//!     the separation issue #32 exists to enforce.
//!
//! PROCESS ISOLATION: the binds happen inside the spawned CLI processes;
//! this test process itself never calls bind, which assertion 4 depends on
//! and the final hygiene check pins. Requires `--features testnet` (devnet
//! genesis nonce=0 only passes trivial difficulty).

#![cfg(feature = "testnet")]

use exfer::types::hash::Hash256;
use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn exfer_bin() -> &'static str {
    env!("CARGO_BIN_EXE_exfer")
}

/// Kill-on-drop guard for the devnet node process.
struct DevnetNode {
    child: Child,
    pub rpc: String,
    pub datadir: std::path::PathBuf,
}

impl Drop for DevnetNode {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn spawn_devnet(dir: &std::path::Path) -> DevnetNode {
    spawn_devnet_on(&dir.join("devnet-data"), None)
}

/// Spawn a devnet node on an explicit datadir (so a restart can reopen the
/// same chain), optionally capturing stderr to a file for boot-log assertions.
fn spawn_devnet_on(datadir: &std::path::Path, stderr_path: Option<&std::path::Path>) -> DevnetNode {
    let rpc_port = free_port();
    let p2p_port = free_port();
    let stderr = match stderr_path {
        Some(p) => Stdio::from(std::fs::File::create(p).expect("create stderr log")),
        None => Stdio::null(),
    };
    let child = Command::new(exfer_bin())
        .args(["devnet", "--datadir"])
        .arg(datadir)
        .args(["--rpc-bind", &format!("127.0.0.1:{rpc_port}")])
        .args(["--bind", &format!("127.0.0.1:{p2p_port}")])
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()
        .expect("spawn exfer devnet");
    DevnetNode {
        child,
        rpc: format!("http://127.0.0.1:{rpc_port}"),
        datadir: datadir.to_path_buf(),
    }
}

fn rpc(url: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
    exfer::rpc::rpc_call(url, method, params)
}

/// Wait until the devnet RPC is up and the chain has spendable height.
fn wait_for_height(node: &DevnetNode, min_height: u64, timeout: Duration) -> serde_json::Value {
    let start = Instant::now();
    loop {
        if let Ok(r) = rpc(&node.rpc, "get_block_height", serde_json::json!({})) {
            if r.get("height").and_then(|h| h.as_u64()).unwrap_or(0) >= min_height {
                return r;
            }
        }
        assert!(
            start.elapsed() < timeout,
            "devnet did not reach height {min_height} within {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[test]
fn devnet_domain_roundtrip_and_canonical_replay_rejection() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = spawn_devnet(tmp.path());

    // Spendable coinbase: maturity 1, so height 3 gives margin.
    let tip = wait_for_height(&node, 3, Duration::from_secs(180));

    // ── 1. RPC contract ────────────────────────────────────────────────
    let devnet_id = exfer::genesis::devnet_genesis_block().header.block_id();
    let reported = tip
        .get("genesis_block_id")
        .and_then(|v| v.as_str())
        .expect("get_block_height must report genesis_block_id");
    assert_eq!(
        reported,
        hex::encode(devnet_id.as_bytes()),
        "genesis_block_id must be node.genesis_id (the handshake identity)"
    );
    assert_ne!(
        reported,
        tip.get("block_id").and_then(|v| v.as_str()).unwrap(),
        "genesis_block_id must not be tip-derived (height > 0 here)"
    );

    let wallet_key = node.datadir.join("devnet-wallet.key");
    assert!(wallet_key.exists(), "devnet auto-creates its mining wallet");
    let dest = hex::encode([0x61; 32]);

    // ── 2. Trust rule against the real node: no --expect-genesis ───────
    let out = Command::new(exfer_bin())
        .args(["wallet", "send", "--wallet"])
        .arg(&wallet_key)
        .args(["--to", &dest, "--amount", "1000", "--rpc", &node.rpc])
        .output()
        .expect("spawn wallet send");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && stderr.contains("refusing to sign in a foreign signature domain"),
        "unnamed devnet must be refused; status={:?} stderr:\n{stderr}",
        out.status
    );

    // ── 3. Round-trip: --expect-genesis devnet → spend verifies ────────
    let out = Command::new(exfer_bin())
        .args(["wallet", "send", "--wallet"])
        .arg(&wallet_key)
        .args([
            "--to", &dest,
            "--amount", "1000",
            "--rpc", &node.rpc,
            "--expect-genesis", "devnet",
            "--json",
        ])
        .output()
        .expect("spawn wallet send --expect-genesis devnet");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "devnet-domain spend must be accepted; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // tracing emits its legacy-wallet WARN on stdout ahead of the JSON —
    // parse from the first brace.
    let json_start = stdout.find('{').expect("wallet send --json must print JSON");
    let sent: serde_json::Value =
        serde_json::from_str(stdout[json_start..].trim()).expect("wallet send --json output");
    assert_eq!(sent.get("submitted"), Some(&serde_json::json!(true)));
    let sent_tx_id = sent.get("tx_id").and_then(|v| v.as_str()).unwrap().to_string();

    // The node ACCEPTED it into its mempool/chain — confirm it is queryable.
    let start = Instant::now();
    loop {
        if rpc(
            &node.rpc,
            "get_transaction",
            serde_json::json!({"hash": sent_tx_id}),
        )
        .is_ok()
        {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "devnet-domain spend was not mined/queryable within 60s"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    // Let the spend settle into a block before re-reading the UTXO set, so
    // step 4 cannot pick the outpoint step 3 already consumed (which would
    // fail as a double-spend instead of the signature rejection under test).
    let settled = rpc(&node.rpc, "get_block_height", serde_json::json!({}))
        .unwrap()
        .get("height")
        .and_then(|h| h.as_u64())
        .unwrap();
    let tip_after = wait_for_height(&node, settled + 2, Duration::from_secs(120));
    let tip_after_h = tip_after.get("height").and_then(|h| h.as_u64()).unwrap();

    // ── 4. Canonical-domain replay is rejected by the devnet node ──────
    // Sign the same shape of spend in THIS process, which never binds: its
    // sig_message uses the compiled canonical (testnet) genesis id. The
    // devnet node must reject the signature — this is the cross-chain
    // replay that the signature-domain separation exists to prevent.
    let w = exfer::wallet::Wallet::load(&wallet_key, None).expect("load devnet wallet");
    let addr_hex = w.address().to_string();
    let utxos = rpc(
        &node.rpc,
        "get_address_utxos",
        serde_json::json!({"address": addr_hex}),
    )
    .expect("get_address_utxos");
    let entry = utxos
        .get("utxos")
        .and_then(|u| u.as_array())
        .and_then(|u| {
            u.iter().find(|e| {
                // A clearly mature, unspent coinbase big enough for value+fee.
                e.get("value").and_then(|v| v.as_u64()).unwrap_or(0) > 1_000_000
                    && e.get("height").and_then(|h| h.as_u64()).unwrap_or(u64::MAX)
                        <= tip_after_h.saturating_sub(2)
            })
        })
        .expect("devnet wallet has a spendable coinbase")
        .clone();
    let prev_tx_id = {
        let b = hex::decode(entry.get("tx_id").and_then(|v| v.as_str()).unwrap()).unwrap();
        let mut a = [0u8; 32];
        a.copy_from_slice(&b);
        Hash256(a)
    };
    let value = entry.get("value").and_then(|v| v.as_u64()).unwrap();

    let mut tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id,
            output_index: entry.get("output_index").and_then(|v| v.as_u64()).unwrap() as u32,
        }],
        outputs: vec![TxOutput {
            value: value - 200_000, // generous fee, well above min
            script: vec![0x61; 32],
            datum: None,
            datum_hash: None,
        }],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };
    assert!(
        !exfer::genesis::signature_domain_is_bound(),
        "this test process must be signing in the canonical fallback domain"
    );
    let sig_msg = tx.sig_message().unwrap(); // canonical domain
    use ed25519_dalek::Signer;
    let sig = w.signing_key_for_cli().sign(&sig_msg);
    let witness_bytes = [w.pubkey().as_slice(), sig.to_bytes().as_slice()].concat();
    for wit in &mut tx.witnesses {
        wit.witness = witness_bytes.clone();
    }
    let tx_hex = hex::encode(tx.serialize().unwrap());
    let res = rpc(
        &node.rpc,
        "send_raw_transaction",
        serde_json::json!({"tx_hex": tx_hex}),
    );
    match res {
        // Exact-variant match: the rejection must be the Ed25519 signature
        // check failing (validation.rs SignatureInvalid), not an incidental
        // double-spend / maturity / fee rejection that would let this test
        // pass without proving the domains are separated.
        Err(e) => assert!(
            e.contains("SignatureInvalid"),
            "rejection must be SignatureInvalid (the domain separation), got: {e}"
        ),
        Ok(v) => panic!(
            "devnet node accepted a canonical-domain signature — the \
             signature domains are NOT separated: {v}"
        ),
    }

    // ── 5. Restart-replay: bind-before-replay regression guard (#32) ───
    // The stored chain now holds a confirmed spend signed in the DEVNET
    // domain (step 3). On restart the node must enter_devnet() — bind the
    // devnet signature domain — BEFORE open_chain replays history; the
    // ordering (main.rs: enter_devnet in the `if devnet` gate, ahead of
    // open_chain) is otherwise correct by inspection only. If the bind moved
    // below open_chain, replay would re-verify those stored signatures in the
    // CANONICAL domain and fail with SignatureInvalid, wedging the boot. Kill
    // the node, reopen the SAME datadir, and assert the replay holds.
    let height_before = rpc(&node.rpc, "get_block_height", serde_json::json!({}))
        .unwrap()
        .get("height")
        .and_then(|h| h.as_u64())
        .unwrap();
    let datadir = node.datadir.clone();
    drop(node); // kill the first node and release the datadir lock

    let restart_log = tmp.path().join("restart.stderr");
    let node2 = spawn_devnet_on(&datadir, Some(&restart_log));
    // If replay verified the stored devnet-domain signatures in the canonical
    // domain, the boot wedges and never reaches the prior height — this waits
    // out to a clear timeout rather than hanging forever.
    let tip2 = wait_for_height(&node2, height_before, Duration::from_secs(120));
    assert_eq!(
        tip2.get("genesis_block_id").and_then(|v| v.as_str()).unwrap(),
        hex::encode(devnet_id.as_bytes()),
        "restarted devnet node must still report the devnet genesis id"
    );
    // The confirmed spend survived replay — history intact, not rolled back.
    rpc(
        &node2.rpc,
        "get_transaction",
        serde_json::json!({"hash": sent_tx_id}),
    )
    .expect("the devnet-domain spend must survive restart replay");
    // And no replay-time signature rejection appears in the boot log.
    let log = std::fs::read_to_string(&restart_log).unwrap_or_default();
    assert!(
        !log.contains("SignatureInvalid"),
        "restart replay must not reject stored devnet-domain signatures:\n{log}"
    );

    // Hygiene: nothing in this process ever bound the domain.
    assert!(!exfer::genesis::signature_domain_is_bound());
}
