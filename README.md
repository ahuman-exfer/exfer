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
