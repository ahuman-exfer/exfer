// Prevent accidental release builds with testnet consensus parameters.
// Override with: --features allow-testnet-release
#[cfg(all(
    feature = "testnet",
    not(debug_assertions),
    not(feature = "allow-testnet-release")
))]
compile_error!(
    "testnet feature must not be used in release builds. \
     This produces a binary with trivial difficulty and no genesis PoW check. \
     Use debug builds for testnet, or add --features allow-testnet-release to override."
);

// Second guard: even with allow-testnet-release, release builds require
// EXFER_TESTNET_OVERRIDE=1 env var at build time. This prevents accidental
// CI/CD misconfiguration from shipping testnet binaries.
#[cfg(testnet_override_missing)]
compile_error!(
    "allow-testnet-release in release mode requires EXFER_TESTNET_OVERRIDE=1 env var. \
     This prevents accidental CI/CD misconfiguration from shipping testnet binaries."
);

pub mod chain;
pub mod consensus;
pub mod covenants;
pub mod genesis;
pub mod mempool;
pub mod miner;
pub mod network;
pub mod rpc;
pub mod script;
pub mod types;
pub mod wallet;
