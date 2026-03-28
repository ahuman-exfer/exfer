//! Exfer Script — typed total functional scripting language.
//!
//! Programs are DAGs of combinator nodes. The language is first-order:
//! all function references are static (wired at construction time).
//!
//! Public API:
//! - `typecheck`: type-check a program, returning typed nodes
//! - `evaluate`: evaluate a program on an input value
//! - `compute_cost`: compute the static cost of a program
//! - `serialize_program` / `deserialize_program`: binary encoding
//! - `merkle_hash`: compute the Merkle commitment of a program

#[allow(unused)]
pub mod ast;
pub mod cost;
#[allow(unused)]
pub mod eval;
#[allow(unused)]
pub mod jets;
#[allow(unused)]
pub mod serialize;
#[allow(unused)]
pub mod typecheck;
pub mod types;
pub mod value;

// Re-export primary types and functions for convenience.
#[allow(unused_imports)]
pub use ast::{Combinator, NodeId, Program};
#[allow(unused_imports)]
pub use cost::{compute_cost, CostError, ListSizes, ScriptCost};
#[allow(unused_imports)]
pub use eval::{evaluate, evaluate_with_context, Budget, EvalError};
#[allow(unused_imports)]
pub use jets::context::ScriptContext;
#[allow(unused_imports)]
pub use serialize::{deserialize_program, merkle_hash, serialize_program, SerializeError};
#[allow(unused_imports)]
pub use typecheck::{typecheck, types_compatible, TypeError, TypedNode};
pub use types::Type;
pub use value::Value;
