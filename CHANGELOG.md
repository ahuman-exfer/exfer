# Changelog

All notable changes to the Exfer node/wallet are tracked here. The public
release tag (`--version` output, binary artifact names) is independent of
`Cargo.toml`'s internal library version.

## [1.4.2] — 2026-04-16 — Security

**Security:** wallet no longer trusts RPC-reported UTXO values. Upgrade
strongly recommended for any wallet that queries remote RPC endpoints.

### Fix 1 — Wallet RPC trust (HIGH)
All wallet spend paths — the normal `exfer send` flow, every covenant
spender (multisig, vault, escrow, delegation), and HTLC claim/reclaim —
now route UTXO lookups through a single authenticated helper
(`wallet::auth::authenticated_output_lookup`). The helper:

- Fetches the funding transaction via `get_transaction`.
- Deserializes locally under a strict parse (reject trailing bytes after a
  valid transaction — closes the valid-prefix-plus-garbage attack).
- Requires the computed `tx_id` of the deserialized transaction to equal
  the requested txid.
- Requires the output at the caller-supplied index to byte-equal a
  locally-reconstructed `expected_script` (wallet-script for normal spend,
  covenant-script for covenant spend, HTLC locked-script — built from
  the CLI-provided `timeout` — for HTLC flows).

The `value` and `script` fields of `get_address_utxos` JSON responses are
deleted from the spend path. With this change, a malicious RPC cannot
cause the wallet to sign against a phantom output or understate the value
being spent (which pre-1.4.2 became unintended miner fee).

Additionally fixed during Fix 1:

- `HtlcClaim` previously discarded its CLI `timeout` parameter entirely
  (`timeout: _timeout`) and never reconstructed the HTLC locked script.
  It now uses the CLI timeout and verifies the on-chain script against
  the local reconstruction.
- `HtlcReclaim` reconstructed the HTLC program but bound it to `_program`
  (unused). It now feeds that reconstruction into the authenticated
  lookup as `expected_script`.

**Residual trust (unchanged from prior releases).** A malicious RPC can
still omit UTXOs (availability), return already-spent outpoints (wallet
discovers at broadcast), lie about tip height / confirmation depth (UX),
and lie about coinbase maturity. These are availability / UX issues, not
theft. Closing them fully requires SPV-style inclusion proofs against a
locally-maintained header chain, which is future work.

### Fix 2 — RPC response body cap (LOW)
The client-side JSON-RPC reader previously called `read_to_end` on the
socket, allocating up to whatever the peer sent. A malicious endpoint
could stream a multi-GB response and OOM the client. The reader now:

- Parses HTTP headers incrementally (capped at 64 KiB).
- Requires a `Content-Length` header (rejects responses without one).
- Rejects declared `Content-Length > 8 MiB` before reading the body.
- Enforces the 8 MiB cap during the read itself, so an endpoint that
  under-declares `Content-Length` cannot stream more than declared.

### Fix 3 — Peer in-flight buffer budget (MEDIUM)
The peer transport reads each frame payload into memory before HMAC
verification. With `MAX_INBOUND_PEERS = 256` and payloads up to 4 MiB,
distinct peers could force ~1 GiB of unverified in-flight buffer. Small
miners on low-RAM VPS instances OOM'd.

A two-layer budget now gates every pre-verification payload allocation:
a node-wide cap of **128 MiB** across all peers plus a **per-peer cap of
16 MiB**. Each frame reserves `2 · payload_len + 5` bytes (the honest
peak — both the payload buffer and the full-frame reconstruction buffer
are resident simultaneously at HMAC verification time). Reservations
are RAII and release bytes back to both counters whether the frame
passes HMAC, fails HMAC, or errors out in deserialization. When either
cap would be exceeded the current frame is rejected and the peer is
shed with a diagnostic log line.

The per-peer cap of 16 MiB = 2× `MAX_BLOCK_SIZE` preserves the original
design intent ("one block-sized frame with room for the reader to begin
the next") under honest accounting. Prior to first expert re-review of
v1.4.2 this cap was encoded as 8 MiB under accounting that counted only
the payload buffer — actual peak memory was already ~16 MiB. The cap
literal now matches the real peak; no operator-visible change, just
honest bookkeeping.

### Other
- CLI `exfer --version` now reports `1.4.2`.
- `Cargo.toml` `version` field unchanged at `0.1.0` (internal library
  semver is separate from public release tag).

### Notes on scope
The `src/bin/*_test.rs` developer test binaries still read RPC `value`
fields when signing transactions. They are not the user-facing wallet CLI
(which is `src/main.rs` / the `exfer` binary) and assume a trusted local
RPC. Migrating them to the authenticated helper is deliberately deferred
— they are not in end-user wallet scope.

### Expert re-review
The wallet changes in Fix 1 are the ones that must be right. This diff is
being routed to a human expert reviewer before binaries are cut.
