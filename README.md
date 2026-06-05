# Exfer

Peer-to-peer settlement for autonomous machines.

## For Agents

Install and initialize in one command:

```bash
exfer init --passphrase-env EXFER_PASS --mine --json
```

Full agent interface: [SKILL.md](SKILL.md)

## For Developers

Build from source:

```bash
cargo build --release
```

### Local devnet (one command)

Spin up an isolated single-node chain — instant blocks, no networking,
spendable coinbase after one block, JSON-RPC + SSE on. Ideal for
development, CI, and demos. Build with the `testnet` feature for trivial
difficulty; the `devnet` subcommand lowers coinbase maturity to one block at
runtime (the networked `node`/`mine` commands keep the canonical maturity):

```bash
cargo run --features testnet --bin exfer -- devnet
# → mines instantly to an auto-created wallet (coins land there),
#   RPC + SSE on http://127.0.0.1:9334
```

Then point any client (CLI, walletd, the MCP server) at
`http://127.0.0.1:9334` and you have a funded local chain in seconds.

Run:

```bash
# Generate a wallet
./target/release/exfer wallet generate --output wallet.key --json

# Start mining
./target/release/exfer mine --datadir ~/.exfer --miner-pubkey <YOUR_PUBKEY> --repair-perms
```

## Documentation

- [EXFER.md](EXFER.md) — protocol specification
- [SECURITY.md](SECURITY.md) — security considerations

## License

MIT
