//! Covenant templates and payment channel patterns.
//!
//! Standard covenant scripts implemented as reusable templates using the
//! ScriptBuilder helper. Each template is a function that takes parameters
//! and returns a well-formed `Program`.

#[allow(unused)]
pub mod builder;
#[allow(unused)]
#[cfg(feature = "channels")]
pub mod channel;
#[allow(unused)]
pub mod delegation;
#[allow(unused)]
pub mod escrow;
#[allow(unused)]
pub mod htlc;
#[allow(unused)]
pub mod multisig;
#[allow(unused)]
pub mod vault;

// Re-export primary types for convenience.
#[allow(unused_imports)]
pub use builder::ScriptBuilder;
#[allow(unused_imports)]
#[cfg(feature = "channels")]
pub use channel::{ChannelState, PaymentChannel};
