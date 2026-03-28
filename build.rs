fn main() {
    // Register the custom cfg so unexpected_cfgs lint doesn't fire.
    println!("cargo:rustc-check-cfg=cfg(testnet_override_missing)");

    // Force Cargo to re-run this build script when the override env var changes.
    println!("cargo:rerun-if-env-changed=EXFER_TESTNET_OVERRIDE");

    let is_testnet = std::env::var("CARGO_FEATURE_TESTNET").is_ok();
    let is_override = std::env::var("CARGO_FEATURE_ALLOW_TESTNET_RELEASE").is_ok();
    let profile = std::env::var("PROFILE").unwrap_or_default();

    if is_testnet
        && is_override
        && profile == "release"
        && std::env::var("EXFER_TESTNET_OVERRIDE").as_deref() != Ok("1")
    {
        println!("cargo:rustc-cfg=testnet_override_missing");
    }
}
