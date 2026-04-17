# exfer 1.4.2 — release notes (draft)

v1.4.2 hardens the wallet against malicious RPC endpoints. Previously,
wallet spend paths read UTXO values from RPC responses without verifying
them against the funding transaction. A malicious RPC could understate
values, causing the wallet to build transactions that sign away the
difference as miner fees. Wallets now verify every spent UTXO by fetching
and authenticating the funding transaction locally. HTLC claim and reclaim
flows now verify locked scripts locally against the CLI-provided timeout.
The RPC client enforces a response body size cap. The peer transport
enforces a global in-flight buffer budget.

Wallet users spending against non-local RPC endpoints should upgrade
before their next spend. Users spending against a local, trusted node are
unaffected in terms of funds safety, though the upgrade is still
recommended as a defence-in-depth measure against local endpoint
compromise.

## What changed

- **Wallet** — every spend path (normal send, multisig/vault/escrow/
  delegation covenants, HTLC claim/reclaim) fetches the funding
  transaction via RPC, re-derives its hash locally, and verifies the
  output script byte-for-byte against a locally-reconstructed expected
  script before signing. `value` and `script` fields from
  `get_address_utxos` JSON responses are no longer read.
- **RPC client** — requires `Content-Length` on every response, caps body
  size at 8 MiB, enforces the cap during the body read as well as on the
  declared header.
- **Peer transport** — bounds pre-HMAC-verification payload buffering at
  128 MiB node-wide and 8 MiB per peer. Exceeding either cap sheds the
  offending peer with a diagnostic log line.

## Who should upgrade

- Anyone using `exfer` to spend against a non-local RPC endpoint (including
  any HTLC or covenant spend): upgrade before your next transaction.
- Node operators: upgrade at your convenience. The peer-budget change
  reduces memory pressure under adversarial inbound load; nodes that
  have not seen OOMs work fine pre-upgrade.

## Compatibility

- No protocol changes. Nodes running 1.4.2 interoperate with earlier
  versions on the wire.
- No consensus changes.
- No wallet file format changes.
- JSON-RPC server interface is unchanged.

## Verification

Binary artifacts will carry standard SHA-256 checksums and Ed25519
signatures from the release key. The expert-reviewed diff for the wallet
changes is available in the repository under the `v1.4.2` tag.
