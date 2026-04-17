#[allow(clippy::module_inception)]
pub mod wallet;
pub mod auth;
#[allow(unused_imports)]
pub use wallet::WalletError;
pub use wallet::{is_encrypted_wallet, prompt_passphrase, prompt_passphrase_confirm, Wallet};
#[allow(unused_imports)]
pub use auth::{authenticate_tx_hex, authenticated_output_lookup, AuthError};
