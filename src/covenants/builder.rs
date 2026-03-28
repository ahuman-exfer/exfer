//! Programmatic script construction helpers.
//!
//! ScriptBuilder provides an ergonomic API for constructing Exfer Script
//! programs as combinator DAGs. Nodes are added bottom-up (leaves first,
//! root last). The `build()` method reverses the arena so root is at index 0
//! with children at higher indices, satisfying the DAG invariant.

use crate::script::ast::{Combinator, NodeId, Program};
use crate::script::jets::JetId;
use crate::script::value::Value;
use crate::types::hash::Hash256;

/// Builder for constructing Exfer Script programs.
#[derive(Default)]
pub struct ScriptBuilder {
    nodes: Vec<Combinator>,
}

impl ScriptBuilder {
    pub fn new() -> Self {
        ScriptBuilder { nodes: Vec::new() }
    }

    fn push(&mut self, comb: Combinator) -> NodeId {
        let id = self.nodes.len() as NodeId;
        self.nodes.push(comb);
        id
    }

    // ── Core combinator constructors ──

    pub fn iden(&mut self) -> NodeId {
        self.push(Combinator::Iden)
    }

    pub fn unit(&mut self) -> NodeId {
        self.push(Combinator::Unit)
    }

    pub fn witness(&mut self) -> NodeId {
        self.push(Combinator::Witness)
    }

    pub fn constant(&mut self, v: Value) -> NodeId {
        self.push(Combinator::Const(v))
    }

    pub fn jet(&mut self, jet_id: JetId) -> NodeId {
        self.push(Combinator::Jet(jet_id))
    }

    pub fn comp(&mut self, f: NodeId, g: NodeId) -> NodeId {
        self.push(Combinator::Comp(f, g))
    }

    pub fn pair(&mut self, f: NodeId, g: NodeId) -> NodeId {
        self.push(Combinator::Pair(f, g))
    }

    pub fn take(&mut self, f: NodeId) -> NodeId {
        self.push(Combinator::Take(f))
    }

    pub fn drop_node(&mut self, f: NodeId) -> NodeId {
        self.push(Combinator::Drop(f))
    }

    pub fn injl(&mut self, f: NodeId) -> NodeId {
        self.push(Combinator::InjL(f))
    }

    pub fn injr(&mut self, f: NodeId) -> NodeId {
        self.push(Combinator::InjR(f))
    }

    pub fn case(&mut self, f: NodeId, g: NodeId) -> NodeId {
        self.push(Combinator::Case(f, g))
    }

    pub fn fold(&mut self, f: NodeId, z: NodeId, k: u64) -> NodeId {
        self.push(Combinator::Fold(f, z, k))
    }

    pub fn list_fold(&mut self, f: NodeId, z: NodeId) -> NodeId {
        self.push(Combinator::ListFold(f, z))
    }

    // ── Higher-level helpers ──

    /// Constant false: any input -> Bool(false).
    pub fn const_false(&mut self) -> NodeId {
        self.constant(Value::Bool(false))
    }

    /// Constant true: any input -> Bool(true).
    pub fn const_true(&mut self) -> NodeId {
        self.constant(Value::Bool(true))
    }

    /// Signature check: verifies an Ed25519 signature against the transaction
    /// signing digest (TxSigHash) and the given public key.
    ///
    /// The signing message is obtained from the TxSigHash introspection jet,
    /// NOT from witness data, ensuring signatures are always bound to the
    /// spending transaction. This prevents replay/phishing-style misuse where
    /// an attacker reuses a signature obtained on an unrelated message.
    ///
    /// Witness data must contain:
    /// 1. `Value::Bytes(signature)` - the 64-byte Ed25519 signature
    pub fn sig_check(&mut self, pubkey: &[u8; 32]) -> NodeId {
        // Get the transaction signing digest via TxSigHash jet
        let sig_hash_jet = self.jet(JetId::TxSigHash);
        let u = self.unit();
        let tx_msg = self.comp(u, sig_hash_jet);
        // Ed25519Verify: Product(Bytes(msg), Product(Bytes(pk), Bytes(sig))) -> Bool
        let pk_const = self.constant(Value::Bytes(pubkey.to_vec()));
        let w_sig = self.witness();
        let pk_sig = self.pair(pk_const, w_sig);
        let full_input = self.pair(tx_msg, pk_sig);
        let verify = self.jet(JetId::Ed25519Verify);
        self.comp(full_input, verify)
    }

    /// Hash equality check: reads a preimage from witness, SHA-256 hashes it,
    /// and compares against the expected hash.
    ///
    /// Witness data must contain:
    /// 1. `Value::Bytes(preimage)` - the preimage bytes
    ///
    /// Returns true if SHA-256(preimage) == expected.
    pub fn hash_eq(&mut self, expected: &Hash256) -> NodeId {
        // SHA-256: Bytes -> Hash256
        // EqHash: Pair(Hash256, Hash256) -> Bool
        let w_preimage = self.witness();
        let sha_jet = self.jet(JetId::Sha256);
        let hashed = self.comp(w_preimage, sha_jet);
        let expected_hash = self.constant(Value::Hash(*expected));
        let pair_node = self.pair(hashed, expected_hash);
        let eq_jet = self.jet(JetId::EqHash);
        self.comp(pair_node, eq_jet)
    }

    /// Block height comparison: returns true if current block height > threshold.
    pub fn height_gt(&mut self, height: u64) -> NodeId {
        let bh_jet = self.jet(JetId::BlockHeight);
        let u = self.unit();
        let get_height = self.comp(u, bh_jet);
        let threshold = self.constant(Value::U64(height));
        let pair_heights = self.pair(get_height, threshold);
        let gt_jet = self.jet(JetId::Gt64);
        self.comp(pair_heights, gt_jet)
    }

    /// Block height comparison: returns true if current block height < threshold.
    pub fn height_lt(&mut self, height: u64) -> NodeId {
        let bh_jet = self.jet(JetId::BlockHeight);
        let u = self.unit();
        let get_height = self.comp(u, bh_jet);
        let threshold = self.constant(Value::U64(height));
        let pair_heights = self.pair(get_height, threshold);
        let lt_jet = self.jet(JetId::Lt64);
        self.comp(pair_heights, lt_jet)
    }

    /// Boolean AND: evaluates `a`, short-circuits false if a is false,
    /// otherwise evaluates `b`.
    ///
    /// Both `a` and `b` should produce Bool (Sum(Unit, Unit)) output.
    /// When a returns false (Left), const_false is returned immediately.
    /// When a returns true (Right), b is evaluated on Unit.
    pub fn and(&mut self, a: NodeId, b: NodeId) -> NodeId {
        // comp(a, case(const_false, b))
        let cf = self.const_false();
        let case_node = self.case(cf, b);
        self.comp(a, case_node)
    }

    /// Boolean OR: evaluates `a`, short-circuits true if a is true,
    /// otherwise evaluates `b`.
    ///
    /// Both `a` and `b` should produce Bool (Sum(Unit, Unit)) output.
    /// When a returns false (Left), b is evaluated on Unit.
    /// When a returns true (Right), const_true is returned immediately.
    pub fn or(&mut self, a: NodeId, b: NodeId) -> NodeId {
        // comp(a, case(b, const_true))
        let ct = self.const_true();
        let case_node = self.case(b, ct);
        self.comp(a, case_node)
    }

    /// Build the program. The last-added node becomes the root.
    ///
    /// Reverses the arena so root is at index 0 and children have higher
    /// indices (DAG invariant).
    pub fn build(self) -> Program {
        let n = self.nodes.len();
        assert!(n > 0, "cannot build empty program");

        let remap = |old: NodeId| -> NodeId { (n - 1 - old as usize) as NodeId };

        let mut new_nodes = Vec::with_capacity(n);
        for node in self.nodes.into_iter().rev() {
            new_nodes.push(remap_combinator(node, &remap));
        }

        Program {
            nodes: new_nodes,
            root: 0,
        }
    }
}

/// Remap all NodeId references in a combinator using the given function.
fn remap_combinator(node: Combinator, remap: &dyn Fn(NodeId) -> NodeId) -> Combinator {
    match node {
        Combinator::Comp(f, g) => Combinator::Comp(remap(f), remap(g)),
        Combinator::Pair(f, g) => Combinator::Pair(remap(f), remap(g)),
        Combinator::Take(f) => Combinator::Take(remap(f)),
        Combinator::Drop(f) => Combinator::Drop(remap(f)),
        Combinator::InjL(f) => Combinator::InjL(remap(f)),
        Combinator::InjR(f) => Combinator::InjR(remap(f)),
        Combinator::Case(f, g) => Combinator::Case(remap(f), remap(g)),
        Combinator::Fold(f, z, k) => Combinator::Fold(remap(f), remap(z), k),
        Combinator::ListFold(f, z) => Combinator::ListFold(remap(f), remap(z)),
        // Leaf nodes have no child references
        other => other,
    }
}
