---
name: exfer
version: 1.0.0
description: >
  Exfer is a permissionless proof-of-work blockchain for autonomous machine-to-machine
  commerce. It combines Argon2id memory-hard mining, an extended UTXO model, and Exfer
  Script — a total functional combinator language — for transaction conditions.
keywords:
  - payment
  - transfer
  - settlement
  - trustless
  - machine-to-machine
  - cryptocurrency
  - wallet
  - hash lock
  - escrow
  - atomic
  - blockchain
  - proof-of-work
author: Exfer Contributors
license: MIT
repository: https://github.com/ahuman-exfer/exfer
---

# Exfer: A Peer-to-Peer Settlement Protocol for Autonomous Machines

Exfer is a permissionless proof-of-work blockchain for autonomous machine-to-machine commerce. It combines Argon2id memory-hard mining, an extended UTXO model, and Exfer Script — a total functional combinator language — for transaction conditions.

The protocol is the minimum infrastructure that turns independent agents into an economy.

All scripts terminate. Costs are statically computable before execution. The UTXO model eliminates global state and reentrancy. An autonomous agent can construct a transaction, compute its exact cost, and know with certainty that it will validate — without simulating execution, competing in a fee auction, or reasoning about concurrent state changes. There is no gas estimation. There is no mempool priority auction.

## Network

```bash
# Choose any available RPC endpoint:
RPC="http://82.221.100.201:9334"
# RPC="http://89.127.232.155:9334"
# RPC="http://80.78.31.82:9334"
```

The binary includes default seed nodes. No configuration needed. To add additional peers: `--peers ip:port`.

Genesis block ID: `d7b6805c8fd793703db88102b5aed2600af510b79e3cb340ca72c1f762d1e051`

## Units

- 1 EXFER = 100,000,000 exfers (base unit)
- The `--amount` and `--fee` flags accept both formats:
  - Human-readable: `--amount "10 EXFER"`, `--fee "0.5 EXFER"`
  - Base units: `--amount 1000000000`
- Minimum output: 200 exfers (dust threshold)
- Default fee: 100,000 exfers (0.001 EXFER)

---

## 1. Install

### Download pre-built binary (recommended)

```bash
# Linux x86_64
curl -LO https://github.com/ahuman-exfer/exfer/releases/latest/download/exfer-linux-x86_64
chmod +x exfer-linux-x86_64
mv exfer-linux-x86_64 exfer

# macOS Apple Silicon
curl -LO https://github.com/ahuman-exfer/exfer/releases/latest/download/exfer-macos-arm64
chmod +x exfer-macos-arm64
mv exfer-macos-arm64 exfer
```

### Build from source

```bash
git clone https://github.com/ahuman-exfer/exfer.git
cd exfer
cargo build --release
# Binary: target/release/exfer
```

### Verify

```bash
./target/release/exfer --help
```

Expected output:
```
Exfer blockchain node

Usage: exfer <COMMAND>

Commands:
  node    Run a full node
  mine    Run the miner
  wallet  Wallet operations
  script  Script operations (HTLC, covenants)
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

---

## 2. Create a Wallet

Generate a new Ed25519 keypair encrypted with a passphrase:

```bash
exfer wallet generate --output ~/my-wallet.key --json
```

Output (JSON):
```json
{
  "address": "8d896d64864f53214acb49aeb44a09a03d5bb23d19a417a6ce7b0da65c7bd750",
  "file": "~/my-wallet.key",
  "pubkey": "fcbd5a818501cd5439ebe8c0c5ff244c0f1475333e226b7f998e6eb80552c69d"
}
```

Copy the `.key` file to a second location as backup. It is encrypted and safe to store anywhere.

The **address** is a 32-byte pubkey hash used to receive payments. The **pubkey** is used for mining payouts (via `--miner-pubkey`). The private key stays encrypted in the `.key` file.

### View wallet info

```bash
exfer wallet info --wallet ~/my-wallet.key --json
```

---

## 3. Check Balance

Query a remote node via JSON-RPC (no local database needed):

```bash
exfer wallet balance \
  --wallet ~/my-wallet.key \
  --rpc $RPC \
  --json
```

Output:
```json
{
  "address": "8d896d64864f53214acb49aeb44a09a03d5bb23d19a417a6ce7b0da65c7bd750",
  "balance": 7368884920683,
  "source": "rpc",
  "rpc_url": "http://82.221.100.201:9334"
}
```

`balance` is in exfers (base units) — divide by 100,000,000 for EXFER. This balance = 73,688.85 EXFER.

### Check balance by address (RPC directly)

```bash
curl -s -X POST $RPC \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "get_balance",
    "params": {"address": "8d896d64864f53214acb49aeb44a09a03d5bb23d19a417a6ce7b0da65c7bd750"},
    "id": 1
  }'
```

---

## 4. Send a Payment

Send exfers to a recipient address via a remote node:

```bash
exfer wallet send \
  --wallet ~/my-wallet.key \
  --to 8d896d64864f53214acb49aeb44a09a03d5bb23d19a417a6ce7b0da65c7bd750 \
  --amount "10 EXFER" \
  --fee "0.001 EXFER" \
  --rpc $RPC \
  --json
```

- `--to`: recipient address (64 hex chars)
- `--amount`: amount in exfers or "10 EXFER" (both accepted)
- `--fee`: transaction fee (default: 0.001 EXFER)
- `--rpc`: remote node RPC URL (fetches UTXOs and submits the signed transaction)

Output:
```json
{
  "tx_id": "fb8a634fcce6cfc124de86fa0a4b3e6130a1e6bfda68a34dc4f30ec7a2a2b68c",
  "size": 227,
  "tip_height": 5553,
  "submitted": true,
  "rpc_url": "http://82.221.100.201:9334",
  "rpc_result": {"tx_id": "fb8a634fcce6cfc124de86fa0a4b3e6130a1e6bfda68a34dc4f30ec7a2a2b68c"}
}
```

The transaction is signed locally (private key never leaves your machine) and submitted via RPC.

### Wait for confirmation

Poll `get_transaction` with the tx_id until `block_height` appears:

```bash
TX_ID="fb8a634fcce6cfc124de86fa0a4b3e6130a1e6bfda68a34dc4f30ec7a2a2b68c"
for i in $(seq 1 60); do
  RESULT=$(curl -s -X POST $RPC \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"get_transaction\",\"params\":{\"hash\":\"$TX_ID\"},\"id\":1}")
  if echo "$RESULT" | grep -q '"block_height"'; then
    echo "Confirmed: $RESULT"
    break
  fi
  if [ "$i" -eq 60 ]; then
    echo "ERROR: transaction not confirmed after 10 minutes"
    exit 1
  fi
  echo "Pending... ($i/60)"
  sleep 10
done
```

---

## 5. Check Transaction Status

```bash
curl -s -X POST $RPC \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "get_transaction",
    "params": {"hash": "fb8a634fcce6cfc124de86fa0a4b3e6130a1e6bfda68a34dc4f30ec7a2a2b68c"},
    "id": 1
  }'
```

Response:
```json
{
  "jsonrpc": "2.0",
  "result": {
    "tx_id": "fb8a634f...",
    "tx_hex": "01000200...",
    "in_mempool": false,
    "block_hash": "169c02f4...",
    "block_height": 5556
  },
  "id": 1
}
```

- `in_mempool: true` — pending confirmation
- `in_mempool: false` with `block_height` — confirmed in that block

---

## 6. Check Block Height

```bash
curl -s -X POST $RPC \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "get_block_height", "params": {}, "id": 1}'
```

---

## 7. HTLC (Hash-Locked Payment)

An HTLC locks funds so a recipient can claim them by revealing a preimage, or the sender reclaims after a timeout. This is the foundation of trustless atomic swaps and machine-to-machine escrow.

### End-to-end workflow

Two agents, A (sender) and B (receiver):

```bash
# ── Agent B: generate preimage, share hash with Agent A ──
PREIMAGE=$(openssl rand -hex 32)
HASH_LOCK=$(echo -n "$PREIMAGE" | xxd -r -p | shasum -a 256 | cut -d' ' -f1)
echo "Share this hash with Agent A: $HASH_LOCK"
# Agent B keeps $PREIMAGE secret until ready to claim

# ── Agent A: lock funds using the hash from Agent B ──
# Get current height to set timeout
HEIGHT=$(curl -s -X POST $RPC \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"get_block_height","params":{},"id":1}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['height'])")
TIMEOUT=$((HEIGHT + 500))

exfer script htlc-lock \
  --wallet ~/agent-a.key \
  --receiver <AGENT_B_PUBKEY> \
  --hash-lock $HASH_LOCK \
  --timeout $TIMEOUT \
  --amount "10 EXFER" \
  --rpc $RPC \
  --json
# Output includes tx_id — share this with Agent B

# ── Wait for lock tx to confirm ──
TX_ID="<tx_id from above>"
for i in $(seq 1 60); do
  RESULT=$(curl -s -X POST $RPC \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"get_transaction\",\"params\":{\"hash\":\"$TX_ID\"},\"id\":1}")
  if echo "$RESULT" | grep -q '"block_height"'; then echo "Lock confirmed"; break; fi
  if [ "$i" -eq 60 ]; then echo "ERROR: transaction not confirmed after 10 minutes"; exit 1; fi
  sleep 10
done

# ── Agent B: claim by revealing the preimage ──
exfer script htlc-claim \
  --wallet ~/agent-b.key \
  --tx-id $TX_ID \
  --preimage $PREIMAGE \
  --sender <AGENT_A_PUBKEY> \
  --timeout $TIMEOUT \
  --rpc $RPC \
  --json

# ── If Agent B does NOT claim before timeout: Agent A reclaims ──
exfer script htlc-reclaim \
  --wallet ~/agent-a.key \
  --tx-id $TX_ID \
  --receiver <AGENT_B_PUBKEY> \
  --hash-lock $HASH_LOCK \
  --timeout $TIMEOUT \
  --rpc $RPC \
  --json
# This will fail if current height <= timeout (funds still locked)
```

### Command reference

#### htlc-lock (sender locks funds)

```bash
exfer script htlc-lock \
  --wallet ~/my-wallet.key \
  --receiver <RECEIVER_PUBKEY_HEX> \
  --hash-lock <SHA256_HASH_HEX> \
  --timeout <BLOCK_HEIGHT> \
  --amount "10 EXFER" \
  --rpc $RPC \
  --json
```

Output:
```json
{
  "tx_id": "2d3fca9d2cb04de879d0235fab7a279de9bfc7dcbe2d857807416974c648c1f4",
  "htlc_output_index": 0,
  "amount": 1000000000,
  "hash_lock": "2fb68185eeaf951e40aafaf2cdc7007710b9d69bc7663e53c581c9408b0c09e9",
  "timeout": 24630,
  "submitted": true
}
```

#### htlc-claim (receiver reveals preimage)

```bash
exfer script htlc-claim \
  --wallet ~/receiver-wallet.key \
  --tx-id <LOCK_TX_ID> \
  --preimage <PREIMAGE_HEX> \
  --sender <SENDER_PUBKEY_HEX> \
  --timeout <TIMEOUT_HEIGHT> \
  --rpc $RPC \
  --json
```

Output:
```json
{
  "tx_id": "3d7a1a0625af2815e3f18a08db2eff22ca9fe9e5dda33c228d969ce13d6e8a7c",
  "claimed_from": "2d3fca9d2cb04de879d0235fab7a279de9bfc7dcbe2d857807416974c648c1f4",
  "amount": 999900000,
  "fee": 100000,
  "submitted": true
}
```

#### htlc-reclaim (sender reclaims after timeout)

```bash
exfer script htlc-reclaim \
  --wallet ~/my-wallet.key \
  --tx-id <LOCK_TX_ID> \
  --receiver <RECEIVER_PUBKEY_HEX> \
  --hash-lock <HASH_LOCK_HEX> \
  --timeout <TIMEOUT_HEIGHT> \
  --rpc $RPC \
  --json
```

Output:
```json
{
  "tx_id": "b84f8f799dc405eb2c5fe5980e2f1c43b71c15331cc8d035c5a62e8ec8ad0baa",
  "reclaimed_from": "933886c612c9de9f4093fb8aa3852f75f4557da2b5987d76e50fde128511f922",
  "amount": 999900000,
  "fee": 100000,
  "submitted": true
}
```

The command checks that the current block height exceeds the timeout before submitting.

### Poll for confirmation (after any transaction)

```bash
TX_ID="<tx_id>"
for i in $(seq 1 60); do
  RESULT=$(curl -s -X POST $RPC \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"get_transaction\",\"params\":{\"hash\":\"$TX_ID\"},\"id\":1}")
  if echo "$RESULT" | grep -q '"block_height"'; then
    echo "Confirmed: $RESULT"
    break
  fi
  if [ "$i" -eq 60 ]; then
    echo "ERROR: transaction not confirmed after 10 minutes"
    exit 1
  fi
  echo "Pending... ($i/60)"
  sleep 10
done
```

---

## 8. Start Mining

Generate a wallet first if you don't have one (see Section 2):
```bash
exfer wallet generate --output ~/exfer-wallet.key --json
# Use the "pubkey" field from the output as --miner-pubkey below
```

### Mining with pubkey only (recommended — no private key on server)

```bash
exfer mine \
  --datadir ~/.exfer \
  --miner-pubkey <YOUR_PUBKEY_HEX> \
  --rpc-bind 127.0.0.1:9334 \
  --repair-perms
```

- `--miner-pubkey`: your wallet's public key (from `exfer wallet info --json`). Coinbase rewards are paid to this key's address. The private key is NOT needed on the mining server.
- Current block reward: ~100 EXFER per block. Reward decreases over time (half-life ~2 years).
- Default seed nodes are built in — no `--peers` needed.
- `--rpc-bind`: optional JSON-RPC endpoint (use `127.0.0.1` for local-only access). **RPC has no authentication** — do not bind to `0.0.0.0` on untrusted networks without a reverse proxy.
- `--repair-perms`: auto-fix node identity key permissions
- `--verify-all`: verify PoW for all blocks during startup replay (slow, use only if database integrity is suspect). Also disables assume-valid.
- `--no-assume-valid`: disable assume-valid optimization — verify Argon2id PoW for all blocks during IBD, even below the hardcoded checkpoint height (130,000). By default, blocks at or below this checkpoint skip PoW verification during initial sync to speed up IBD. All other validation (transactions, signatures, UTXO accounting, state roots) is always performed.

### Run in background

**Linux:**
```bash
nohup ./target/release/exfer mine \
  --datadir ~/.exfer \
  --miner-pubkey <YOUR_PUBKEY_HEX> \
  --rpc-bind 127.0.0.1:9334 \
  --repair-perms \
  > ~/exfer.log 2>&1 &
```

**macOS:**
```bash
cat > ~/Library/LaunchAgents/org.exfer.miner.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>org.exfer.miner</string>
  <key>ProgramArguments</key>
  <array>
    <string>$(which exfer || echo ./target/release/exfer)</string>
    <string>mine</string>
    <string>--datadir</string><string>$HOME/.exfer</string>
    <string>--miner-pubkey</string><string>YOUR_PUBKEY_HEX</string>
    <string>--repair-perms</string>
  </array>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/tmp/exfer.log</string>
  <key>StandardErrorPath</key><string>/tmp/exfer.log</string>
</dict>
</plist>
EOF
launchctl load ~/Library/LaunchAgents/org.exfer.miner.plist
```

Check status: `curl -s http://127.0.0.1:9334 -d '{"jsonrpc":"2.0","id":1,"method":"get_block_height","params":{}}'`

### Run a non-mining full node

```bash
exfer node \
  --datadir ~/.exfer \
  --rpc-bind 127.0.0.1:9334 \
  --repair-perms
```

---

## RPC Methods

All methods use JSON-RPC 2.0 over HTTP POST.

| Method | Params | Description |
|--------|--------|-------------|
| `get_block_height` | `{}` | Current tip height and block ID |
| `get_balance` | `{"address": "hex"}` | Spendable balance for an address |
| `get_address_utxos` | `{"address": "hex"}` | List of spendable UTXOs for an address (max 1,000) |
| `get_block` | `{"height": u64}` or `{"hash": "hex"}` | Block info including transaction list |
| `get_transaction` | `{"hash": "hex"}` | Transaction details, mempool status, block height |
| `send_raw_transaction` | `{"tx_hex": "hex"}` | Submit a serialized signed transaction |

---

## Available Covenant Patterns

| Pattern | CLI | Description |
|---------|-----|-------------|
| HTLC | `exfer script htlc-lock`, `htlc-claim`, `htlc-reclaim` | Hash time-locked contract (atomic swaps) |
| Multisig 2-of-2 | — | Both parties must sign |
| Multisig 1-of-2 | — | Either party can sign |
| Multisig 2-of-3 | — | Any 2 of 3 parties |
| Vault | — | Timelock + recovery key |
| Escrow | — | Mutual / arbiter / timeout (3-path) |
| Delegation | — | Owner + time-limited delegate |

HTLC is available via CLI (`exfer script htlc-lock`, `htlc-claim`, `htlc-reclaim`). Other patterns are supported by the protocol. CLI commands for additional patterns are planned.

---

## Protocol Constants

| Constant | Value |
|----------|-------|
| Block time target | 10 seconds |
| Difficulty retarget | Every 4,320 blocks |
| Initial block reward | 100 EXFER |
| Reward half-life | 6,307,200 blocks (~2 years) |
| Minimum reward | 1 EXFER |
| Coinbase maturity | 360 blocks |
| Max block size | 4 MiB |
| Max transaction size | 1 MiB |
| Dust threshold | 200 exfers |
| PoW algorithm | Argon2id (m=64MiB, t=2, p=1) |
| P2P port | 9333 |
| RPC port | 9334 (optional) |
