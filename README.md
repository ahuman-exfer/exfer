# Exfer

Peer-to-peer settlement for autonomous machines.

## Build
```bash
cargo build --release
```

## Run
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
