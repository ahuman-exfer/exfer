# Security Model & Known Tradeoffs

## Replay PoW Verification

**Behavior:** On startup, the node replays all stored blocks to rebuild the UTXO set.
Historical blocks (older than RETARGET_WINDOW / 4,320 blocks) skip Argon2id PoW
verification by default. Only recent blocks are PoW-verified.

**Rationale:** Argon2id is deliberately slow (~250ms per block). Full PoW verification
of 80k+ blocks would add ~5 hours to every restart. The data was validated on first
receipt — replay trusts local storage integrity.

**Mitigation:** If the database is suspected of corruption or tampering, start the node
with `--verify-all` to re-validate PoW for every block during replay:

```
exfer mine --verify-all [other flags...]
exfer node --verify-all [other flags...]
```

Wallet replay always uses the partial PoW strategy (no `--verify-all` flag).

## RPC Authentication

**Behavior:** The JSON-RPC server has no authentication. Any client that can reach the
RPC port can query balances, submit transactions, and read chain state.

**Default:** RPC binds to `127.0.0.1` (localhost only). Remote access requires
explicitly setting `--rpc-bind 0.0.0.0:9334`, which prints a warning at startup.

**Recommendation:** For public-facing nodes, use a reverse proxy (nginx, caddy) with
authentication in front of the RPC port. Do not bind RPC to `0.0.0.0` on untrusted
networks without access control.

**RPC attack surface:** An unauthenticated remote RPC allows:
- Balance/UTXO queries (privacy leak, not fund theft)
- Transaction submission (can fill mempool, but standard rate limits apply: 60 tx/min)
- Block/header queries (read-only)

It does NOT allow: key extraction, direct fund movement, node configuration changes,
or peer management. Authentication is planned as a post-launch feature.

## Transaction Budget Burn

**Behavior:** A malicious transaction can consume up to MAX_TX_SCRIPT_BUDGET (20M steps)
of validation work per transaction. At the consensus rate limit of 60 tx/min per peer and
200 tx/min globally, this bounds the maximum validation CPU cost but does not eliminate it.

**Rationale:** Script evaluation is metered by a per-input budget (MAX_SCRIPT_STEPS = 4M)
and a per-transaction budget (MAX_TX_SCRIPT_BUDGET = 20M). The minimum fee formula
(`ceil(tx_cost / 100)`) ensures that high-cost scripts pay proportionally higher fees.
However, an attacker willing to pay fees can still force miners to spend CPU on
validation.

**Mitigation:**
- Per-peer rate limits (MAX_TXS_PER_MIN = 60) bound per-connection throughput
- Global rate limit (MAX_GLOBAL_TXS_PER_MIN = 200) caps aggregate validation load
- Mempool capacity (8,192 tx) bounds memory usage
- Fee market: high-cost transactions pay higher fees, making sustained attacks expensive
- Post-launch: configurable validation budget and priority fee thresholds

## UTXO Scan Performance

**Behavior:** Balance and UTXO queries use a secondary index (script → outpoints) for
O(k) lookups where k is the number of UTXOs for the queried address. This avoids
full-table scans. Results are capped at 1,000 UTXOs per query.

**Limitation:** The UTXO scan semaphore limits concurrency to one scan at a time. Under
heavy RPC load, queries may queue behind each other. Block processing (which requires a
write lock on the UTXO set) is not blocked by read-only scans.

**Mitigation:** For high-throughput RPC use cases, run a dedicated query node behind a
load balancer. The node's RPC is designed for operational use, not as a high-throughput
block explorer API.
