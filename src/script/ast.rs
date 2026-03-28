//! Program AST for Exfer Script.
//!
//! Programs are DAGs (directed acyclic graphs). Nodes are stored in an arena
//! and referenced by NodeId indices. A node may be referenced by multiple parents.

use super::jets::JetId;
use super::value::Value;
use crate::types::hash::Hash256;

/// Index into the program's node arena.
pub type NodeId = u32;

/// A combinator node in the program DAG.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Combinator {
    /// Identity: A -> A
    Iden,
    /// Composition: f then g. Comp(f, g) : A -> C where f: A->B, g: B->C
    Comp(NodeId, NodeId),
    /// Unit: A -> Unit
    Unit,
    /// Pair: evaluate both on same input. Pair(f, g) : A -> Product(B, C)
    Pair(NodeId, NodeId),
    /// Take: project first of product. Take(f) : Product(A, B) -> C where f: A->C
    Take(NodeId),
    /// Drop: project second of product. Drop(f) : Product(A, B) -> C where f: B->C
    Drop(NodeId),
    /// InjL: tag left. InjL(f) : A -> Sum(B, C) where f: A->B
    InjL(NodeId),
    /// InjR: tag right. InjR(f) : A -> Sum(B, C) where f: A->C
    InjR(NodeId),
    /// Case: branch on sum tag. Case(f, g) : Sum(A, B) -> C
    Case(NodeId, NodeId),
    /// Bounded fold: Fold(f, z, k) : Product(Bound(k), A) -> B
    /// z: A->B (initializer), f: Product(A, B)->B (step), k iterations.
    Fold(NodeId, NodeId, u64),
    /// List fold: ListFold(f, z) : Product(List(A), B) -> B
    /// z: B->B (identity on accumulator), f: Product(A, B)->B (step).
    ListFold(NodeId, NodeId),
    /// Native jet implementation.
    Jet(JetId),
    /// Witness hole — filled at evaluation time from witness data.
    Witness,
    /// Pruned branch — Merkle hash of the hidden subtree.
    MerkleHidden(Hash256),
    /// Constant value embedded in the program.
    Const(Value),
}

/// A program: an arena of combinator nodes forming a DAG.
#[derive(Clone, Debug)]
pub struct Program {
    /// Arena of nodes. Children have higher indices than parents.
    pub nodes: Vec<Combinator>,
    /// The root node (always 0 by convention).
    pub root: NodeId,
}

impl Program {
    /// Create a program with a single node as root.
    pub fn single(comb: Combinator) -> Self {
        Program {
            nodes: vec![comb],
            root: 0,
        }
    }

    /// Get the number of nodes in the program.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get a reference to a node by ID.
    pub fn get(&self, id: NodeId) -> Option<&Combinator> {
        self.nodes.get(id as usize)
    }

    /// Get the children of a node (all NodeId references).
    pub fn children(&self, id: NodeId) -> Vec<NodeId> {
        match &self.nodes[id as usize] {
            Combinator::Iden
            | Combinator::Unit
            | Combinator::Witness
            | Combinator::MerkleHidden(_)
            | Combinator::Const(_)
            | Combinator::Jet(_) => vec![],
            Combinator::Take(f)
            | Combinator::Drop(f)
            | Combinator::InjL(f)
            | Combinator::InjR(f) => vec![*f],
            Combinator::Comp(f, g)
            | Combinator::Pair(f, g)
            | Combinator::Case(f, g)
            | Combinator::ListFold(f, g) => vec![*f, *g],
            Combinator::Fold(f, z, _) => vec![*f, *z],
        }
    }

    /// Validate that all NodeId references point to valid nodes,
    /// children have strictly higher indices than their parents (DAG invariant),
    /// and all nodes are reachable from the root (no dead subgraphs).
    pub fn validate_structure(&self) -> Result<(), &'static str> {
        let n = self.nodes.len();
        if n == 0 {
            return Err("empty program");
        }
        if self.root as usize >= n {
            return Err("root index out of bounds");
        }
        // First pass: validate indices and DAG invariant.
        for (i, node) in self.nodes.iter().enumerate() {
            for child in self.children_of(node) {
                if child as usize >= n {
                    return Err("child index out of bounds");
                }
                if child as usize <= i {
                    return Err("child index must be greater than parent (DAG invariant)");
                }
            }
        }
        // Second pass: verify all nodes are reachable from root.
        // Mark reachable nodes via BFS from root. Because children have
        // strictly higher indices than parents, a forward scan suffices.
        let mut reachable = vec![false; n];
        reachable[self.root as usize] = true;
        for i in 0..n {
            if !reachable[i] {
                continue;
            }
            for child in self.children_of(&self.nodes[i]) {
                reachable[child as usize] = true;
            }
        }
        if reachable.iter().any(|&r| !r) {
            return Err("program contains unreachable nodes");
        }
        Ok(())
    }

    /// Compute the maximum evaluation depth of the program DAG.
    ///
    /// This is the longest path from root to any leaf, counting each
    /// combinator traversal as +1 depth. Used to reject scripts that
    /// would exceed MAX_EVAL_DEPTH at spend time.
    pub fn max_depth(&self) -> usize {
        let n = self.nodes.len();
        if n == 0 {
            return 0;
        }
        // depth[i] = depth of subtree rooted at node i
        let mut depth = vec![0usize; n];
        // Process bottom-up (children have higher indices)
        for i in (0..n).rev() {
            let children = self.children(i as NodeId);
            let max_child = children
                .iter()
                .map(|&c| depth[c as usize])
                .max()
                .unwrap_or(0);
            depth[i] = max_child + 1;
        }
        depth[self.root as usize]
    }

    fn children_of(&self, node: &Combinator) -> Vec<NodeId> {
        match node {
            Combinator::Iden
            | Combinator::Unit
            | Combinator::Witness
            | Combinator::MerkleHidden(_)
            | Combinator::Const(_)
            | Combinator::Jet(_) => vec![],
            Combinator::Take(f)
            | Combinator::Drop(f)
            | Combinator::InjL(f)
            | Combinator::InjR(f) => vec![*f],
            Combinator::Comp(f, g)
            | Combinator::Pair(f, g)
            | Combinator::Case(f, g)
            | Combinator::ListFold(f, g) => vec![*f, *g],
            Combinator::Fold(f, z, _) => vec![*f, *z],
        }
    }
}
