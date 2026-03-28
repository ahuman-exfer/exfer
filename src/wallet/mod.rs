#[allow(clippy::module_inception)]
pub mod wallet;
#[allow(unused_imports)]
pub use wallet::WalletError;
pub use wallet::{is_encrypted_wallet, prompt_passphrase, prompt_passphrase_confirm, Wallet};
