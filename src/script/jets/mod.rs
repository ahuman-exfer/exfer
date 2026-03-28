//! Jet registry and dispatch for native-speed operations.
//!
//! Each jet has a type signature, cost, and native implementation.

pub mod arithmetic;
pub mod bytes;
pub mod context;
pub mod crypto;
pub mod introspection;
pub mod list;

use super::types::Type;
use super::value::Value;
use context::ScriptContext;

/// Jet evaluation errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JetError {
    /// Type mismatch in jet input.
    TypeMismatch(String),
    /// Arithmetic overflow or underflow.
    Overflow(String),
    /// Division by zero.
    DivisionByZero,
    /// Index out of bounds.
    OutOfBounds(String),
    /// Jet ID reserved but not yet implemented.
    NotImplemented(String),
}

impl std::fmt::Display for JetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for JetError {}

/// Identifies a native jet implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum JetId {
    // Crypto
    Sha256 = 0x0001,
    Ed25519Verify = 0x0002,
    SchnorrVerify = 0x0003,
    MerkleVerify = 0x0004,

    // Arithmetic 64-bit
    Add64 = 0x0100,
    Sub64 = 0x0101,
    Mul64 = 0x0102,
    Div64 = 0x0103,
    Mod64 = 0x0104,
    Eq64 = 0x0105,
    Lt64 = 0x0106,
    Gt64 = 0x0107,

    // Arithmetic 256-bit
    Add256 = 0x0200,
    Sub256 = 0x0201,
    Mul256 = 0x0202,
    Div256 = 0x0203,
    Mod256 = 0x0204,
    Eq256 = 0x0205,
    Lt256 = 0x0206,
    Gt256 = 0x0207,

    // Byte ops
    Cat = 0x0300,
    Slice = 0x0301,
    Len = 0x0302,
    EqBytes = 0x0303,
    EqHash = 0x0304,

    // Introspection
    TxInputs = 0x0400,
    TxOutputs = 0x0401,
    TxValue = 0x0402,
    TxScriptHash = 0x0403,
    TxInputCount = 0x0404,
    TxOutputCount = 0x0405,
    SelfIndex = 0x0406,
    BlockHeight = 0x0407,
    TxSigHash = 0x0408,

    // List ops
    ListLen = 0x0500,
    ListAt = 0x0501,
    ListSum = 0x0502,
    ListAll = 0x0503,
    ListAny = 0x0504,
    ListFind = 0x0505,
}

impl JetId {
    /// Convert a u32 to a JetId.
    pub fn from_u32(id: u32) -> Option<JetId> {
        match id {
            0x0001 => Some(JetId::Sha256),
            0x0002 => Some(JetId::Ed25519Verify),
            0x0003 => Some(JetId::SchnorrVerify),
            0x0004 => Some(JetId::MerkleVerify),
            0x0100 => Some(JetId::Add64),
            0x0101 => Some(JetId::Sub64),
            0x0102 => Some(JetId::Mul64),
            0x0103 => Some(JetId::Div64),
            0x0104 => Some(JetId::Mod64),
            0x0105 => Some(JetId::Eq64),
            0x0106 => Some(JetId::Lt64),
            0x0107 => Some(JetId::Gt64),
            0x0200 => Some(JetId::Add256),
            0x0201 => Some(JetId::Sub256),
            0x0202 => Some(JetId::Mul256),
            0x0203 => Some(JetId::Div256),
            0x0204 => Some(JetId::Mod256),
            0x0205 => Some(JetId::Eq256),
            0x0206 => Some(JetId::Lt256),
            0x0207 => Some(JetId::Gt256),
            0x0300 => Some(JetId::Cat),
            0x0301 => Some(JetId::Slice),
            0x0302 => Some(JetId::Len),
            0x0303 => Some(JetId::EqBytes),
            0x0304 => Some(JetId::EqHash),
            0x0400 => Some(JetId::TxInputs),
            0x0401 => Some(JetId::TxOutputs),
            0x0402 => Some(JetId::TxValue),
            0x0403 => Some(JetId::TxScriptHash),
            0x0404 => Some(JetId::TxInputCount),
            0x0405 => Some(JetId::TxOutputCount),
            0x0406 => Some(JetId::SelfIndex),
            0x0407 => Some(JetId::BlockHeight),
            0x0408 => Some(JetId::TxSigHash),
            0x0500 => Some(JetId::ListLen),
            0x0501 => Some(JetId::ListAt),
            0x0502 => Some(JetId::ListSum),
            0x0503 => Some(JetId::ListAll),
            0x0504 => Some(JetId::ListAny),
            0x0505 => Some(JetId::ListFind),
            _ => None,
        }
    }

    /// Return the (input_type, output_type) for this jet.
    pub fn jet_type(&self) -> (Type, Type) {
        match self {
            JetId::Sha256 => (Type::bytes(), Type::hash256()),
            JetId::Ed25519Verify => (
                Type::Product(
                    Box::new(Type::bytes()),
                    Box::new(Type::Product(
                        Box::new(Type::bytes()),
                        Box::new(Type::bytes()),
                    )),
                ),
                Type::bool_type(),
            ),
            JetId::SchnorrVerify => (
                Type::Product(
                    Box::new(Type::bytes()),
                    Box::new(Type::Product(
                        Box::new(Type::bytes()),
                        Box::new(Type::bytes()),
                    )),
                ),
                Type::bool_type(),
            ),
            JetId::MerkleVerify => (
                Type::Product(
                    Box::new(Type::hash256()),
                    Box::new(Type::Product(
                        Box::new(Type::hash256()),
                        Box::new(Type::bytes()),
                    )),
                ),
                Type::bool_type(),
            ),
            JetId::Add64 | JetId::Sub64 | JetId::Mul64 | JetId::Div64 | JetId::Mod64 => (
                Type::Product(Box::new(Type::u64_type()), Box::new(Type::u64_type())),
                Type::u64_type(),
            ),
            JetId::Eq64 | JetId::Lt64 | JetId::Gt64 => (
                Type::Product(Box::new(Type::u64_type()), Box::new(Type::u64_type())),
                Type::bool_type(),
            ),
            JetId::Add256 | JetId::Sub256 | JetId::Mul256 | JetId::Div256 | JetId::Mod256 => (
                Type::Product(Box::new(Type::u256_type()), Box::new(Type::u256_type())),
                Type::u256_type(),
            ),
            JetId::Eq256 | JetId::Lt256 | JetId::Gt256 => (
                Type::Product(Box::new(Type::u256_type()), Box::new(Type::u256_type())),
                Type::bool_type(),
            ),
            JetId::Cat => (
                Type::Product(Box::new(Type::bytes()), Box::new(Type::bytes())),
                Type::bytes(),
            ),
            JetId::Slice => (
                Type::Product(
                    Box::new(Type::bytes()),
                    Box::new(Type::Product(
                        Box::new(Type::u64_type()),
                        Box::new(Type::u64_type()),
                    )),
                ),
                Type::bytes(),
            ),
            JetId::Len => (Type::bytes(), Type::u64_type()),
            JetId::EqBytes => (
                Type::Product(Box::new(Type::bytes()), Box::new(Type::bytes())),
                Type::bool_type(),
            ),
            JetId::EqHash => (
                Type::Product(Box::new(Type::hash256()), Box::new(Type::hash256())),
                Type::bool_type(),
            ),
            JetId::TxInputs => {
                // Each input: Pair(prev_tx_id: Hash, Pair(output_index: U64, Pair(value: U64, script_hash: Hash)))
                let input_type = Type::Product(
                    Box::new(Type::hash256()),
                    Box::new(Type::Product(
                        Box::new(Type::u64_type()),
                        Box::new(Type::Product(
                            Box::new(Type::u64_type()),
                            Box::new(Type::hash256()),
                        )),
                    )),
                );
                (Type::Unit, Type::List(Box::new(input_type)))
            }
            JetId::TxOutputs => {
                // Each output: Pair(value: U64, Pair(script_hash: Hash, datum_hash: Option(Hash)))
                let output_type = Type::Product(
                    Box::new(Type::u64_type()),
                    Box::new(Type::Product(
                        Box::new(Type::hash256()),
                        Box::new(Type::option(Type::hash256())),
                    )),
                );
                (Type::Unit, Type::List(Box::new(output_type)))
            }
            JetId::TxValue => (Type::u64_type(), Type::u64_type()),
            JetId::TxScriptHash => (Type::u64_type(), Type::hash256()),
            JetId::TxInputCount | JetId::TxOutputCount => (Type::Unit, Type::u64_type()),
            JetId::SelfIndex => (Type::Unit, Type::u64_type()),
            JetId::BlockHeight => (Type::Unit, Type::u64_type()),
            JetId::TxSigHash => (Type::Unit, Type::bytes()),
            JetId::ListLen => (Type::List(Box::new(Type::Unit)), Type::u64_type()),
            JetId::ListAt => (
                Type::Product(
                    Box::new(Type::List(Box::new(Type::Unit))),
                    Box::new(Type::u64_type()),
                ),
                Type::option(Type::Unit),
            ),
            JetId::ListSum => (Type::List(Box::new(Type::u64_type())), Type::u64_type()),
            JetId::ListAll | JetId::ListAny => {
                (Type::List(Box::new(Type::bool_type())), Type::bool_type())
            }
            JetId::ListFind => (
                Type::List(Box::new(Type::bool_type())),
                Type::option(Type::u64_type()),
            ),
        }
    }

    /// Return the static (steps, cells) cost for this jet.
    ///
    /// These values are used by the static cost analyzer to size the execution budget.
    /// For data-dependent jets, they reflect a typical-maximum workload so that most
    /// legitimate scripts fit within budget. At runtime, `runtime_cost` charges the
    /// actual data-proportional cost from the budget.
    pub fn jet_cost(&self) -> (u64, u64) {
        match self {
            JetId::Sha256 => (1_000, 1),
            JetId::Ed25519Verify | JetId::SchnorrVerify => (5_000, 1),
            // 32_000 steps covers proofs up to 63 siblings (2^63-leaf trees).
            JetId::MerkleVerify => (32_000, 1),
            JetId::Add64
            | JetId::Sub64
            | JetId::Mul64
            | JetId::Div64
            | JetId::Mod64
            | JetId::Eq64
            | JetId::Lt64
            | JetId::Gt64 => (10, 1),
            JetId::Add256
            | JetId::Sub256
            | JetId::Mul256
            | JetId::Div256
            | JetId::Mod256
            | JetId::Eq256
            | JetId::Lt256
            | JetId::Gt256 => (50, 1),
            JetId::Cat | JetId::Slice => (100, 1),
            JetId::Len => (10, 0),
            JetId::EqBytes | JetId::EqHash => (500, 0),
            JetId::TxInputs | JetId::TxOutputs => (1_000, 0),
            JetId::TxValue | JetId::TxScriptHash => (10, 0),
            JetId::TxInputCount
            | JetId::TxOutputCount
            | JetId::SelfIndex
            | JetId::BlockHeight
            | JetId::TxSigHash => (5, 0),
            JetId::ListLen => (10, 0),
            JetId::ListAt => (10, 1),
            // 1_000 steps covers lists up to ~990 elements.
            JetId::ListSum | JetId::ListAll | JetId::ListAny | JetId::ListFind => (1_000, 0),
        }
    }

    /// Return the data-proportional runtime step cost for this jet.
    ///
    /// Called during evaluation to charge actual work from the execution budget.
    /// For jets whose work is constant (arithmetic), this equals the static cost.
    /// For data-dependent jets (Merkle, list, byte ops, introspection), cost
    /// scales with actual data size or tx fan-in/fan-out.
    pub fn runtime_cost(&self, input: &Value, context: &context::ScriptContext) -> u64 {
        match self {
            // SHA-256 processes 64-byte blocks; base 500 + 8 per block
            JetId::Sha256 => {
                let len = match input {
                    Value::Bytes(data) => data.len() as u64,
                    _ => 0,
                };
                500u64.saturating_add(len / 64 * 8)
            }
            // MerkleVerify: base 500 + 500 per proof sibling (each = 1 SHA-256)
            JetId::MerkleVerify => {
                let proof_len = match input {
                    Value::Pair(_, rest) => match rest.as_ref() {
                        Value::Pair(_, proof) => match proof.as_ref() {
                            Value::Bytes(data) => data.len() as u64,
                            _ => 0,
                        },
                        _ => 0,
                    },
                    _ => 0,
                };
                500u64.saturating_add((proof_len / 33).saturating_mul(500))
            }
            // List iteration: base 10 + 1 per element
            JetId::ListSum | JetId::ListAll | JetId::ListAny | JetId::ListFind => {
                let len = match input {
                    Value::List(items) => items.len() as u64,
                    _ => 0,
                };
                10u64.saturating_add(len)
            }
            // Hash comparison: fixed 32 bytes = constant cost
            JetId::EqHash => 14, // 10 + 32/8
            // Byte comparison: base 10 + 1 per 8 bytes
            JetId::EqBytes => {
                let max_len = match input {
                    Value::Pair(a, b) => {
                        let la = match a.as_ref() {
                            Value::Bytes(d) => d.len(),
                            Value::Hash(_) => 32,
                            _ => 0,
                        };
                        let lb = match b.as_ref() {
                            Value::Bytes(d) => d.len(),
                            Value::Hash(_) => 32,
                            _ => 0,
                        };
                        std::cmp::max(la, lb) as u64
                    }
                    _ => 0,
                };
                10u64.saturating_add(max_len / 8)
            }
            // Cat: O(n) copy where n = total output length
            JetId::Cat => {
                let total_len = match input {
                    Value::Pair(a, b) => {
                        let la = match a.as_ref() {
                            Value::Bytes(d) => d.len() as u64,
                            _ => 0,
                        };
                        let lb = match b.as_ref() {
                            Value::Bytes(d) => d.len() as u64,
                            _ => 0,
                        };
                        la.saturating_add(lb)
                    }
                    _ => 0,
                };
                10u64.saturating_add(total_len / 8)
            }
            // Slice: O(n) copy where n = source length
            JetId::Slice => {
                let src_len = match input {
                    Value::Pair(a, _) => match a.as_ref() {
                        Value::Bytes(d) => d.len() as u64,
                        _ => 0,
                    },
                    _ => 0,
                };
                10u64.saturating_add(src_len / 8)
            }
            // TxInputs/TxOutputs: iterate + allocate per input/output
            JetId::TxInputs => 10u64.saturating_add(context.tx_inputs.len() as u64 * 10),
            JetId::TxOutputs => 10u64.saturating_add(context.tx_outputs.len() as u64 * 10),
            // TxSigHash: clone cost scales with sig_hash length (can be ~1MB).
            // Base 5 + 1 per 64-byte chunk, matching SHA-256 block granularity.
            JetId::TxSigHash => 5u64.saturating_add(context.sig_hash.len() as u64 / 64),
            // Ed25519Verify: base 5000 + ceil_div(message_bytes, 64) × 8
            JetId::Ed25519Verify => {
                let msg_len = match input {
                    Value::Pair(msg, _) => match msg.as_ref() {
                        Value::Bytes(data) => data.len() as u64,
                        _ => 0,
                    },
                    _ => 0,
                };
                5_000u64.saturating_add(msg_len.div_ceil(64).saturating_mul(8))
            }
            // All other jets: use static cost (constant work)
            _ => {
                let (steps, _) = self.jet_cost();
                steps
            }
        }
    }

    /// Returns true if this jet has a working runtime implementation.
    /// Unimplemented jets (reserved for future use) must not appear in
    /// output scripts — funds would be permanently locked.
    pub fn is_implemented(&self) -> bool {
        !matches!(self, JetId::SchnorrVerify)
    }

    /// Execute a jet on the given input value.
    pub fn eval(&self, input: &Value, context: &ScriptContext) -> Result<Value, JetError> {
        match self {
            // Crypto
            JetId::Sha256 => crypto::jet_sha256(input),
            JetId::Ed25519Verify => crypto::jet_ed25519_verify(input),
            JetId::SchnorrVerify => crypto::jet_schnorr_verify(input),
            JetId::MerkleVerify => crypto::jet_merkle_verify(input),

            // Arithmetic 64-bit
            JetId::Add64 => arithmetic::jet_add64(input),
            JetId::Sub64 => arithmetic::jet_sub64(input),
            JetId::Mul64 => arithmetic::jet_mul64(input),
            JetId::Div64 => arithmetic::jet_div64(input),
            JetId::Mod64 => arithmetic::jet_mod64(input),
            JetId::Eq64 => arithmetic::jet_eq64(input),
            JetId::Lt64 => arithmetic::jet_lt64(input),
            JetId::Gt64 => arithmetic::jet_gt64(input),

            // Arithmetic 256-bit
            JetId::Add256 => arithmetic::jet_add256(input),
            JetId::Sub256 => arithmetic::jet_sub256(input),
            JetId::Mul256 => arithmetic::jet_mul256(input),
            JetId::Div256 => arithmetic::jet_div256(input),
            JetId::Mod256 => arithmetic::jet_mod256(input),
            JetId::Eq256 => arithmetic::jet_eq256(input),
            JetId::Lt256 => arithmetic::jet_lt256(input),
            JetId::Gt256 => arithmetic::jet_gt256(input),

            // Byte ops
            JetId::Cat => bytes::jet_cat(input),
            JetId::Slice => bytes::jet_slice(input),
            JetId::Len => bytes::jet_len(input),
            JetId::EqBytes | JetId::EqHash => bytes::jet_eq_bytes(input),

            // Introspection
            JetId::TxInputs => introspection::jet_tx_inputs(context),
            JetId::TxOutputs => introspection::jet_tx_outputs(context),
            JetId::TxValue => introspection::jet_tx_value(input, context),
            JetId::TxScriptHash => introspection::jet_tx_script_hash(input, context),
            JetId::TxInputCount => introspection::jet_tx_input_count(context),
            JetId::TxOutputCount => introspection::jet_tx_output_count(context),
            JetId::SelfIndex => introspection::jet_self_index(context),
            JetId::BlockHeight => introspection::jet_block_height(context),
            JetId::TxSigHash => introspection::jet_tx_sig_hash(context),

            // List ops
            JetId::ListLen => list::jet_list_len(input),
            JetId::ListAt => list::jet_list_at(input),
            JetId::ListSum => list::jet_list_sum(input),
            JetId::ListAll => list::jet_list_all(input),
            JetId::ListAny => list::jet_list_any(input),
            JetId::ListFind => list::jet_list_find(input),
        }
    }
}
