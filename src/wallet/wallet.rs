use crate::chain::state::UtxoSet;
use crate::types::hash::Hash256;
use crate::types::transaction::{OutPoint, Transaction, TxInput, TxOutput, TxWitness};
use crate::types::COINBASE_MATURITY;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;
use std::path::Path;

/// Magic bytes identifying an encrypted wallet file.
const WALLET_MAGIC: &[u8; 4] = b"EXFK";
/// Current encrypted wallet format version.
const WALLET_VERSION: u8 = 1;
/// Argon2id salt length.
const SALT_LEN: usize = 16;
/// AES-256-GCM nonce length.
const NONCE_LEN: usize = 12;
/// Plaintext key length.
const KEY_LEN: usize = 32;
/// Ciphertext length (32-byte key + 16-byte GCM tag).
const CIPHERTEXT_LEN: usize = KEY_LEN + 16;
/// Total encrypted file size: magic(4) + version(1) + salt(16) + nonce(12) + ciphertext(48) = 81.
const ENCRYPTED_FILE_LEN: usize = 4 + 1 + SALT_LEN + NONCE_LEN + CIPHERTEXT_LEN;

/// A simple wallet: manages a single Ed25519 keypair.
///
/// Keys are encrypted at rest using Argon2id + AES-256-GCM unless
/// `--no-encrypt` is passed (which stores the raw 32-byte secret key
/// and prints a warning).
pub struct Wallet {
    signing_key: SigningKey,
}

impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wallet")
            .field("pubkey", &hex::encode(self.pubkey()))
            .finish()
    }
}

impl Wallet {
    /// Generate a new wallet with a random keypair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Wallet { signing_key }
    }

    /// Derive a 32-byte AES key from a passphrase using Argon2id.
    /// Hardened for key-at-rest: m=262144 KiB (256 MiB), t=3, p=1.
    /// Higher than PoW parameters to resist offline brute-force against
    /// weak/medium passphrases (wallet decryption is infrequent so latency
    /// of ~1-2s is acceptable).
    fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], WalletError> {
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(262_144, 3, 1, Some(32))
                .map_err(|e| WalletError::Crypto(format!("argon2 params: {}", e)))?,
        );
        let mut derived = [0u8; 32];
        argon2
            .hash_password_into(passphrase, salt, &mut derived)
            .map_err(|e| WalletError::Crypto(format!("argon2 derive: {}", e)))?;
        Ok(derived)
    }

    /// Save the wallet's secret key encrypted with `passphrase`.
    ///
    /// File format (81 bytes):
    /// - `EXFK` magic (4 bytes)
    /// - version u8 (1 byte)
    /// - Argon2id salt (16 bytes)
    /// - AES-256-GCM nonce (12 bytes)
    /// - ciphertext (48 bytes = 32-byte key + 16-byte GCM tag)
    pub fn save_encrypted(&self, path: &Path, passphrase: &[u8]) -> Result<(), WalletError> {
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);

        let aes_key = Self::derive_key(passphrase, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&aes_key)
            .map_err(|e| WalletError::Crypto(format!("aes init: {}", e)))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, self.signing_key.to_bytes().as_slice())
            .map_err(|e| WalletError::Crypto(format!("aes encrypt: {}", e)))?;

        let mut buf = Vec::with_capacity(ENCRYPTED_FILE_LEN);
        buf.extend_from_slice(WALLET_MAGIC);
        buf.push(WALLET_VERSION);
        buf.extend_from_slice(&salt);
        buf.extend_from_slice(&nonce_bytes);
        buf.extend_from_slice(&ciphertext);

        atomic_write(path, &buf, 0o600)
    }

    /// Load an encrypted wallet, decrypting with `passphrase`.
    pub fn load_encrypted(path: &Path, passphrase: &[u8]) -> Result<Self, WalletError> {
        check_file_permissions(path)?;

        let bytes = fs::read(path).map_err(|e| WalletError::Io(e.to_string()))?;
        if bytes.len() != ENCRYPTED_FILE_LEN {
            return Err(WalletError::InvalidKeyFile);
        }
        if &bytes[0..4] != WALLET_MAGIC {
            return Err(WalletError::InvalidKeyFile);
        }
        if bytes[4] != WALLET_VERSION {
            return Err(WalletError::UnsupportedVersion(bytes[4]));
        }

        let salt = &bytes[5..5 + SALT_LEN];
        let nonce_bytes = &bytes[5 + SALT_LEN..5 + SALT_LEN + NONCE_LEN];
        let ciphertext = &bytes[5 + SALT_LEN + NONCE_LEN..];

        let aes_key = Self::derive_key(passphrase, salt)?;
        let cipher = Aes256Gcm::new_from_slice(&aes_key)
            .map_err(|e| WalletError::Crypto(format!("aes init: {}", e)))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| WalletError::DecryptionFailed)?;

        if plaintext.len() != KEY_LEN {
            return Err(WalletError::InvalidKeyFile);
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&plaintext);
        let signing_key = SigningKey::from_bytes(&key_bytes);

        Ok(Wallet { signing_key })
    }

    /// Load a wallet, auto-detecting format (encrypted vs plaintext).
    pub fn load(path: &Path, passphrase: Option<&[u8]>) -> Result<Self, WalletError> {
        check_file_permissions(path)?;

        let bytes = fs::read(path).map_err(|e| WalletError::Io(e.to_string()))?;

        if bytes.len() >= 4 && &bytes[0..4] == WALLET_MAGIC {
            // Encrypted format
            let passphrase = passphrase.ok_or(WalletError::PassphraseRequired)?;
            drop(bytes); // re-read inside load_encrypted
            return Self::load_encrypted(path, passphrase);
        }

        // Legacy plaintext format (32 raw bytes)
        if bytes.len() != 32 {
            return Err(WalletError::InvalidKeyFile);
        }
        tracing::warn!(
            "Wallet {:?} uses legacy unencrypted format. \
             Re-save with a passphrase to encrypt.",
            path
        );
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        Ok(Wallet { signing_key })
    }

    /// Save the wallet's secret key as raw 32 bytes (unencrypted).
    ///
    /// Only used when `--no-encrypt` is passed. Callers should print a warning.
    pub fn save_unencrypted(&self, path: &Path) -> Result<(), WalletError> {
        atomic_write(path, &self.signing_key.to_bytes(), 0o600)
    }

    /// Get the public key.
    pub fn pubkey(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Get the signing key reference (for CLI script commands that need to sign).
    pub fn signing_key_for_cli(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Get the address (pubkey hash).
    pub fn address(&self) -> Hash256 {
        TxOutput::pubkey_hash_from_key(&self.pubkey())
    }

    /// Compute wallet balance from the UTXO set.
    /// Excludes immature coinbase outputs (those created fewer than COINBASE_MATURITY blocks ago).
    pub fn balance(&self, utxo_set: &UtxoSet, current_height: u64) -> u64 {
        let addr = self.address();
        let mut total = 0u64;
        for (_, entry) in utxo_set.iter() {
            if entry.output.script == addr.as_bytes().as_slice() {
                if entry.is_coinbase
                    && current_height.saturating_sub(entry.height) < COINBASE_MATURITY
                {
                    continue;
                }
                total = total.saturating_add(entry.output.value);
            }
        }
        total
    }

    /// List UTXOs belonging to this wallet.
    /// Excludes immature coinbase outputs (those created fewer than COINBASE_MATURITY blocks ago).
    pub fn list_utxos(&self, utxo_set: &UtxoSet, current_height: u64) -> Vec<(OutPoint, u64)> {
        let addr = self.address();
        let mut utxos = Vec::new();
        for (outpoint, entry) in utxo_set.iter() {
            if entry.output.script == addr.as_bytes().as_slice() {
                if entry.is_coinbase
                    && current_height.saturating_sub(entry.height) < COINBASE_MATURITY
                {
                    continue;
                }
                utxos.push((*outpoint, entry.output.value));
            }
        }
        utxos
    }

    /// Build and sign a transaction to send `amount` exfers to `recipient_pubkey_hash`.
    /// Returns the signed transaction, or an error if insufficient funds.
    /// Rejects recipient amounts below DUST_THRESHOLD; folds sub-dust change into fee.
    /// Excludes immature coinbase outputs from coin selection.
    pub fn build_transaction(
        &self,
        recipient: Hash256,
        amount: u64,
        fee: u64,
        utxo_set: &UtxoSet,
        current_height: u64,
    ) -> Result<Transaction, WalletError> {
        use crate::types::DUST_THRESHOLD;

        // Reject sub-dust recipient amount — consensus will reject the tx anyway
        if amount < DUST_THRESHOLD {
            return Err(WalletError::DustOutput(amount));
        }

        let needed = amount
            .checked_add(fee)
            .ok_or(WalletError::InsufficientFunds)?;

        // Collect UTXOs until we have enough
        let my_utxos = self.list_utxos(utxo_set, current_height);
        let mut selected = Vec::new();
        let mut total_selected = 0u64;

        for (outpoint, value) in &my_utxos {
            selected.push((*outpoint, *value));
            total_selected = total_selected.saturating_add(*value);
            if total_selected >= needed {
                break;
            }
        }

        if total_selected < needed {
            return Err(WalletError::InsufficientFunds);
        }

        // Build inputs
        let inputs: Vec<TxInput> = selected
            .iter()
            .map(|(outpoint, _)| TxInput {
                prev_tx_id: outpoint.tx_id,
                output_index: outpoint.output_index,
            })
            .collect();

        // Build outputs
        let mut outputs = vec![TxOutput {
            value: amount,
            script: recipient.0.to_vec(),
            datum: None,
            datum_hash: None,
        }];

        // Change output — fold sub-dust change into fee to avoid consensus rejection
        let change = total_selected - needed;
        if change >= DUST_THRESHOLD {
            outputs.push(TxOutput::new_p2pkh(change, &self.pubkey()));
        }

        // Build witnesses (placeholder for now to compute signing bytes)
        let witnesses: Vec<TxWitness> = inputs
            .iter()
            .map(|_| TxWitness {
                witness: vec![0u8; 96],
                redeemer: None,
            })
            .collect();

        let mut tx = Transaction {
            inputs,
            outputs,
            witnesses,
        };

        // Sign: compute sig_message and create proper witnesses
        let sig_msg = tx
            .sig_message()
            .map_err(|e| WalletError::Serialization(format!("{}", e)))?;
        let signature = self.signing_key.sign(&sig_msg);

        for witness in &mut tx.witnesses {
            let mut witness_data = Vec::with_capacity(96);
            witness_data.extend_from_slice(&self.pubkey());
            witness_data.extend_from_slice(&signature.to_bytes());
            witness.witness = witness_data;
        }

        // Enforce consensus minimum fee — reject before broadcast to avoid
        // constructing transactions that nodes will always reject.
        // Use effective fee (inputs - outputs), not user-provided fee,
        // because sub-dust change is folded into fees.
        let effective_fee = total_selected - tx.outputs.iter().map(|o| o.value).sum::<u64>();
        let required_min = crate::consensus::cost::min_fee(&tx).ok_or(WalletError::TxTooLarge)?;
        if effective_fee < required_min {
            return Err(WalletError::FeeTooLow {
                provided: effective_fee,
                required: required_min,
            });
        }

        // Reject transactions that exceed MAX_TX_SIZE — nodes will reject them.
        let tx_size = tx
            .serialized_size()
            .map_err(|e| WalletError::Serialization(format!("{}", e)))?;
        if tx_size > crate::types::MAX_TX_SIZE {
            return Err(WalletError::TxTooLarge);
        }

        Ok(tx)
    }
}

/// Write data to a file atomically: write to a temp file in the same
/// directory, fsync, then rename over the target. A crash at any point
/// leaves either the old file intact or the fully-written new file —
/// never a truncated/partial write.
fn atomic_write(path: &Path, data: &[u8], _mode: u32) -> Result<(), WalletError> {
    use std::io::Write;

    let parent = path
        .parent()
        .ok_or_else(|| WalletError::Io("wallet path has no parent directory".to_string()))?;

    // Build a temp path in the same directory (same filesystem) so rename is atomic.
    // Use PID + a random suffix to avoid collisions.
    let tmp_name = format!(
        ".wallet_tmp_{}_{}",
        std::process::id(),
        rand::random::<u32>()
    );
    let tmp_path = parent.join(tmp_name);

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(_mode);
    }

    let result = (|| {
        let mut file = opts
            .open(&tmp_path)
            .map_err(|e| WalletError::Io(e.to_string()))?;
        file.write_all(data)
            .map_err(|e| WalletError::Io(e.to_string()))?;
        file.sync_all()
            .map_err(|e| WalletError::Io(e.to_string()))?;
        drop(file);

        fs::rename(&tmp_path, path).map_err(|e| WalletError::Io(e.to_string()))?;

        // Fsync the parent directory so the new directory entry is durable.
        // Windows does not support opening a directory as a file for fsync.
        #[cfg(unix)]
        {
            let dir = fs::File::open(parent).map_err(|e| WalletError::Io(e.to_string()))?;
            dir.sync_all().map_err(|e| WalletError::Io(e.to_string()))?;
        }

        Ok(())
    })();

    if result.is_err() {
        // Clean up temp file on failure
        let _ = fs::remove_file(&tmp_path);
    }

    result
}

/// Check file permissions on Unix (reject group/world readable).
fn check_file_permissions(path: &Path) -> Result<(), WalletError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(path).map_err(|e| WalletError::Io(e.to_string()))?;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(WalletError::InsecurePermissions(mode & 0o777));
        }
    }
    let _ = path; // suppress unused warning on non-unix
    Ok(())
}

/// Prompt for a passphrase from the terminal (no echo).
///
/// Returns the passphrase bytes, or an error if stdin is not a terminal.
pub fn prompt_passphrase(prompt: &str) -> Result<Vec<u8>, WalletError> {
    eprint!("{}", prompt);
    let pass = rpassword::read_password()
        .map_err(|e| WalletError::Io(format!("failed to read passphrase: {}", e)))?;
    Ok(pass.into_bytes())
}

/// Prompt for passphrase with confirmation (for wallet creation).
pub fn prompt_passphrase_confirm() -> Result<Vec<u8>, WalletError> {
    let pass1 = prompt_passphrase("Enter passphrase: ")?;
    let pass2 = prompt_passphrase("Confirm passphrase: ")?;
    if pass1 != pass2 {
        return Err(WalletError::PassphraseMismatch);
    }
    if pass1.is_empty() {
        return Err(WalletError::EmptyPassphrase);
    }
    Ok(pass1)
}

/// Detect whether a wallet file is encrypted (starts with EXFK magic).
/// Checks file permissions before reading — rejects insecure files early
/// rather than reading key material with world-readable permissions.
pub fn is_encrypted_wallet(path: &Path) -> bool {
    if check_file_permissions(path).is_err() {
        return false; // caller will get the real error from Wallet::load
    }
    fs::read(path)
        .map(|b| b.len() >= 4 && &b[0..4] == WALLET_MAGIC)
        .unwrap_or(false)
}

#[derive(Debug)]
pub enum WalletError {
    Io(String),
    InvalidKeyFile,
    UnsupportedVersion(u8),
    InsecurePermissions(u32),
    InsufficientFunds,
    DustOutput(u64),
    FeeTooLow { provided: u64, required: u64 },
    TxTooLarge,
    Serialization(String),
    Crypto(String),
    DecryptionFailed,
    PassphraseRequired,
    PassphraseMismatch,
    EmptyPassphrase,
}

impl std::fmt::Display for WalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletError::Io(e) => write!(f, "I/O error: {}", e),
            WalletError::InvalidKeyFile => {
                write!(f, "invalid key file (not a recognized wallet format)")
            }
            WalletError::UnsupportedVersion(v) => write!(f, "unsupported wallet version: {}", v),
            WalletError::InsecurePermissions(mode) => write!(
                f,
                "key file has insecure permissions: {:o} (expected 0600)",
                mode
            ),
            WalletError::InsufficientFunds => write!(f, "insufficient funds"),
            WalletError::DustOutput(v) => write!(f, "output value {} below dust threshold", v),
            WalletError::FeeTooLow { provided, required } => {
                write!(f, "fee {} below consensus minimum {}", provided, required)
            }
            WalletError::TxTooLarge => {
                write!(f, "transaction exceeds MAX_TX_SIZE or cost overflows")
            }
            WalletError::Serialization(e) => write!(f, "transaction serialization failed: {}", e),
            WalletError::Crypto(e) => write!(f, "cryptographic error: {}", e),
            WalletError::DecryptionFailed => write!(f, "decryption failed (wrong passphrase?)"),
            WalletError::PassphraseRequired => {
                write!(f, "wallet is encrypted; passphrase required")
            }
            WalletError::PassphraseMismatch => write!(f, "passphrases do not match"),
            WalletError::EmptyPassphrase => write!(f, "passphrase must not be empty"),
        }
    }
}

impl std::error::Error for WalletError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::state::UtxoEntry;
    use ed25519_dalek::VerifyingKey;

    #[test]
    fn test_generate_wallet() {
        let w1 = Wallet::generate();
        let w2 = Wallet::generate();
        assert_ne!(w1.pubkey(), w2.pubkey());
    }

    #[test]
    fn test_address_deterministic() {
        let w = Wallet::generate();
        assert_eq!(w.address(), w.address());
    }

    #[test]
    fn test_balance() {
        let w = Wallet::generate();
        let mut utxo_set = UtxoSet::new();

        let outpoint = OutPoint::new(Hash256::sha256(b"tx1"), 0);
        utxo_set
            .insert(
                outpoint,
                UtxoEntry {
                    output: TxOutput::new_p2pkh(500_000_000, &w.pubkey()),
                    height: 0,
                    is_coinbase: false,
                },
            )
            .expect("insert test UTXO");

        assert_eq!(w.balance(&utxo_set, 1000), 500_000_000);
    }

    #[test]
    fn test_build_and_sign_transaction() {
        let w = Wallet::generate();
        let mut utxo_set = UtxoSet::new();

        let outpoint = OutPoint::new(Hash256::sha256(b"tx1"), 0);
        utxo_set
            .insert(
                outpoint,
                UtxoEntry {
                    output: TxOutput::new_p2pkh(1_000_000_000, &w.pubkey()),
                    height: 0,
                    is_coinbase: false,
                },
            )
            .expect("insert test UTXO");

        let recipient = Hash256::sha256(b"recipient_addr");
        let tx = w
            .build_transaction(recipient, 500_000_000, 10_000, &utxo_set, 1000)
            .unwrap();

        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 2); // payment + change
        assert_eq!(tx.outputs[0].value, 500_000_000);
        assert_eq!(tx.outputs[1].value, 1_000_000_000 - 500_000_000 - 10_000);
        assert_eq!(tx.witnesses.len(), 1);

        // Verify signature
        let sig_msg = tx.sig_message().unwrap();
        let pubkey_bytes: [u8; 32] = tx.witnesses[0].witness[0..32].try_into().unwrap();
        let sig_bytes: [u8; 64] = tx.witnesses[0].witness[32..96].try_into().unwrap();
        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        use ed25519_dalek::Verifier;
        assert!(verifying_key.verify(&sig_msg, &sig).is_ok());
    }

    #[test]
    fn test_insufficient_funds() {
        let w = Wallet::generate();
        let utxo_set = UtxoSet::new();

        let recipient = Hash256::ZERO;
        match w.build_transaction(recipient, 1000, 10, &utxo_set, 1000) {
            Err(WalletError::InsufficientFunds) => {}
            other => panic!("expected InsufficientFunds, got {:?}", other),
        }
    }

    #[test]
    fn test_save_and_load_encrypted() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let path = tmpdir.path().join("wallet.key");
        let passphrase = b"test-passphrase-123";

        let w1 = Wallet::generate();
        w1.save_encrypted(&path, passphrase).unwrap();

        // Verify file size matches encrypted format
        let file_bytes = fs::read(&path).unwrap();
        assert_eq!(file_bytes.len(), ENCRYPTED_FILE_LEN);
        assert_eq!(&file_bytes[0..4], WALLET_MAGIC);
        assert_eq!(file_bytes[4], WALLET_VERSION);

        // Load and verify key matches
        let w2 = Wallet::load_encrypted(&path, passphrase).unwrap();
        assert_eq!(w1.pubkey(), w2.pubkey());
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let path = tmpdir.path().join("wallet.key");

        let w1 = Wallet::generate();
        w1.save_encrypted(&path, b"correct-pass").unwrap();

        match Wallet::load_encrypted(&path, b"wrong-pass") {
            Err(WalletError::DecryptionFailed) => {}
            other => panic!("expected DecryptionFailed, got {:?}", other),
        }
    }

    #[test]
    fn test_save_and_load_unencrypted() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let path = tmpdir.path().join("wallet.key");

        let w1 = Wallet::generate();
        w1.save_unencrypted(&path).unwrap();

        // Legacy load with no passphrase
        let w2 = Wallet::load(&path, None).unwrap();
        assert_eq!(w1.pubkey(), w2.pubkey());
    }

    #[test]
    fn test_auto_detect_encrypted() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let path = tmpdir.path().join("wallet.key");
        let passphrase = b"auto-detect-pass";

        let w1 = Wallet::generate();
        w1.save_encrypted(&path, passphrase).unwrap();

        // Auto-detect should require passphrase
        match Wallet::load(&path, None) {
            Err(WalletError::PassphraseRequired) => {}
            other => panic!("expected PassphraseRequired, got {:?}", other),
        }

        // Auto-detect with passphrase
        let w2 = Wallet::load(&path, Some(passphrase)).unwrap();
        assert_eq!(w1.pubkey(), w2.pubkey());
    }

    #[test]
    fn test_is_encrypted_wallet() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let enc_path = tmpdir.path().join("encrypted.key");
        let plain_path = tmpdir.path().join("plain.key");

        let w = Wallet::generate();
        w.save_encrypted(&enc_path, b"pass").unwrap();
        w.save_unencrypted(&plain_path).unwrap();

        assert!(is_encrypted_wallet(&enc_path));
        assert!(!is_encrypted_wallet(&plain_path));
    }
}
