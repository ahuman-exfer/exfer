use crate::types::hash::Hash256;
use crate::types::DS_STATE;

/// Depth of the sparse Merkle tree (256-bit keys).
const SMT_DEPTH: usize = 256;

/// Precomputed empty subtree hashes for depths 0..=256.
/// empty_hash[0] = 32 zero bytes (leaf level)
/// empty_hash[d] = SHA-256(empty_hash[d-1] || empty_hash[d-1])
struct EmptyHashes {
    hashes: [[u8; 32]; SMT_DEPTH + 1],
}

impl EmptyHashes {
    fn new() -> Self {
        let mut hashes = [[0u8; 32]; SMT_DEPTH + 1];
        for d in 1..=SMT_DEPTH {
            let mut preimage = [0u8; 64];
            preimage[..32].copy_from_slice(&hashes[d - 1]);
            preimage[32..].copy_from_slice(&hashes[d - 1]);
            hashes[d] = Hash256::sha256(&preimage).0;
        }
        EmptyHashes { hashes }
    }

    fn get(&self, depth: usize) -> &[u8; 32] {
        &self.hashes[depth]
    }
}

fn empty_hashes() -> &'static EmptyHashes {
    use std::sync::OnceLock;
    static INSTANCE: OnceLock<EmptyHashes> = OnceLock::new();
    INSTANCE.get_or_init(EmptyHashes::new)
}

/// The empty root hash (state root of an empty UTXO set).
pub fn empty_root() -> Hash256 {
    Hash256(*empty_hashes().get(SMT_DEPTH))
}

/// Compute the SMT leaf key from a tx_id and output_index.
pub fn leaf_key(tx_id: &Hash256, output_index: u32) -> Hash256 {
    let mut data = Vec::with_capacity(32 + 4);
    data.extend_from_slice(tx_id.as_bytes());
    data.extend_from_slice(&output_index.to_le_bytes());
    Hash256::domain_hash(DS_STATE, &data)
}

/// Compute the SMT leaf value from canonical output bytes and UTXO metadata.
pub fn leaf_value(canonical_output_bytes: &[u8], height: u64, is_coinbase: bool) -> Hash256 {
    let mut data = Vec::with_capacity(canonical_output_bytes.len() + 9);
    data.extend_from_slice(canonical_output_bytes);
    data.extend_from_slice(&height.to_le_bytes());
    data.push(if is_coinbase { 1 } else { 0 });
    Hash256::sha256(&data)
}

/// Extract bit at `bit_index` from a 256-bit key (MSB-first within each byte).
fn get_bit(key: &[u8; 32], bit_index: usize) -> u8 {
    let byte_idx = bit_index / 8;
    let bit_idx = 7 - (bit_index % 8);
    (key[byte_idx] >> bit_idx) & 1
}

// ── Path-compressed SMT ─────────────────────────────────────────────

/// Index into the node arena. 0 = unused/null.
type NodeIdx = u32;
const NULL: NodeIdx = 0;

/// A node in the path-compressed SMT.
///
/// Three kinds:
/// - **Leaf**: stores a 256-bit key and 32-byte value hash.
/// - **Branch**: has a left and right child at a specific bit depth.
/// - **Extension**: skips a range of bits where only one child exists.
///   The subtree hash is derived by folding through empty sibling hashes.
#[derive(Clone, Debug)]
enum SmtNode {
    /// A leaf at full depth (bit_depth == 256).
    Leaf {
        key: [u8; 32],
        value: [u8; 32],
    },
    /// A branch at `bit_depth` where the path diverges.
    Branch {
        bit_depth: u16,
        left: NodeIdx,  // child where bit at bit_depth == 0
        right: NodeIdx, // child where bit at bit_depth == 1
        hash: [u8; 32], // cached subtree hash at this depth
    },
    /// An extension that skips bits [bit_depth .. child_depth).
    /// The child is at child_depth.
    Extension {
        bit_depth: u16,
        child_depth: u16,
        /// The key bits in [bit_depth..child_depth) that this extension matches.
        /// We store a full key prefix — only bits in the range matter.
        prefix_key: [u8; 32],
        child: NodeIdx,
        hash: [u8; 32], // cached subtree hash at bit_depth
    },
}

/// Path-compressed Sparse Merkle Tree.
///
/// Produces identical root hashes to the naive depth-256 implementation:
/// the hash at every logical binary level is the same, but chains of
/// single-child internal nodes are collapsed into extension edges.
///
/// Memory: ~2 nodes per leaf (one leaf + one branch/extension) instead
/// of ~245 nodes per leaf in the uncompressed version.
#[derive(Clone, Debug)]
pub struct SparseMerkleTree {
    arena: Vec<SmtNode>,
    /// Free list of recycled node indices.
    free: Vec<NodeIdx>,
    root: NodeIdx,
    root_hash: Hash256,
    leaf_count: usize,
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        // Index 0 is reserved as NULL sentinel.
        SparseMerkleTree {
            arena: vec![SmtNode::Leaf {
                key: [0; 32],
                value: [0; 32],
            }],
            free: Vec::new(),
            root: NULL,
            root_hash: empty_root(),
            leaf_count: 0,
        }
    }

    fn alloc(&mut self, node: SmtNode) -> NodeIdx {
        if let Some(idx) = self.free.pop() {
            self.arena[idx as usize] = node;
            idx
        } else {
            let idx = self.arena.len() as NodeIdx;
            self.arena.push(node);
            idx
        }
    }

    fn free_node(&mut self, idx: NodeIdx) {
        if idx != NULL {
            self.free.push(idx);
        }
    }

    /// Number of internal + leaf nodes allocated (for diagnostics).
    pub fn node_count(&self) -> usize {
        self.arena.len() - 1 - self.free.len() // -1 for NULL sentinel
    }

    /// Number of leaves.
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    pub fn root(&self) -> Hash256 {
        self.root_hash
    }

    #[allow(dead_code)]
    pub fn contains(&self, key: &Hash256) -> bool {
        self.find_leaf(&key.0).is_some()
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.leaf_count
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.leaf_count == 0
    }

    pub fn insert(&mut self, key: Hash256, value: Hash256) {
        let was_present = self.find_leaf(&key.0).is_some();
        self.root = self.insert_at(self.root, 0, &key.0, &value.0);
        self.root_hash = Hash256(self.subtree_hash(self.root, 0));
        if !was_present {
            self.leaf_count += 1;
        }
    }

    pub fn remove(&mut self, key: &Hash256) {
        if self.find_leaf(&key.0).is_none() {
            return;
        }
        self.root = self.remove_at(self.root, 0, &key.0);
        self.root_hash = Hash256(self.subtree_hash(self.root, 0));
        self.leaf_count -= 1;
    }

    /// Find a leaf by key. Returns Some(value) if present.
    fn find_leaf(&self, key: &[u8; 32]) -> Option<[u8; 32]> {
        let mut idx = self.root;
        loop {
            if idx == NULL {
                return None;
            }
            match &self.arena[idx as usize] {
                SmtNode::Leaf { key: k, value } => {
                    return if k == key { Some(*value) } else { None };
                }
                SmtNode::Branch {
                    bit_depth,
                    left,
                    right,
                    ..
                } => {
                    let bit = get_bit(key, *bit_depth as usize);
                    idx = if bit == 0 { *left } else { *right };
                }
                SmtNode::Extension {
                    bit_depth,
                    child_depth,
                    prefix_key,
                    child,
                    ..
                } => {
                    let bd = *bit_depth as usize;
                    let cd = *child_depth as usize;
                    // Check that the key matches the extension's prefix bits
                    for d in bd..cd {
                        if get_bit(key, d) != get_bit(prefix_key, d) {
                            return None;
                        }
                    }
                    idx = *child;
                }
            }
        }
    }

    /// Insert a leaf into the subtree rooted at `idx` at logical `depth`.
    /// Returns the new root index of this subtree.
    fn insert_at(
        &mut self,
        idx: NodeIdx,
        depth: usize,
        key: &[u8; 32],
        value: &[u8; 32],
    ) -> NodeIdx {
        if idx == NULL {
            // Empty subtree — create a leaf (possibly wrapped in extension if depth < 256)
            let leaf = self.alloc(SmtNode::Leaf {
                key: *key,
                value: *value,
            });
            return self.wrap_in_extension(leaf, depth);
        }

        match self.arena[idx as usize].clone() {
            SmtNode::Leaf {
                key: existing_key,
                value: _existing_value,
            } => {
                if existing_key == *key {
                    // Update existing leaf value
                    self.arena[idx as usize] = SmtNode::Leaf {
                        key: *key,
                        value: *value,
                    };
                    // Rehash upward handled by caller
                    return idx;
                }
                // Split: find the first bit where keys differ
                let leaf_depth = self.logical_depth(idx);
                let diverge = first_different_bit(&existing_key, key, leaf_depth);

                // Create new leaf
                let new_leaf = self.alloc(SmtNode::Leaf {
                    key: *key,
                    value: *value,
                });

                // Create branch at diverge point
                let bit_new = get_bit(key, diverge);
                let (left, right) = if bit_new == 0 {
                    (
                        self.wrap_in_extension(new_leaf, diverge + 1),
                        self.wrap_in_extension(idx, diverge + 1),
                    )
                } else {
                    (
                        self.wrap_in_extension(idx, diverge + 1),
                        self.wrap_in_extension(new_leaf, diverge + 1),
                    )
                };

                let branch_hash = self.compute_branch_hash(left, right, diverge);
                let branch = self.alloc(SmtNode::Branch {
                    bit_depth: diverge as u16,
                    left,
                    right,
                    hash: branch_hash,
                });

                // Wrap branch in extension if diverge > depth
                if diverge > depth {
                    self.alloc(SmtNode::Extension {
                        bit_depth: depth as u16,
                        child_depth: diverge as u16,
                        prefix_key: *key, // any key works, they share bits in [depth..diverge)
                        child: branch,
                        hash: [0; 32], // computed by caller
                    })
                } else {
                    branch
                }
            }
            SmtNode::Branch {
                bit_depth,
                left,
                right,
                ..
            } => {
                let bd = bit_depth as usize;
                let bit = get_bit(key, bd);
                let (new_left, new_right) = if bit == 0 {
                    (self.insert_at(left, bd + 1, key, value), right)
                } else {
                    (left, self.insert_at(right, bd + 1, key, value))
                };
                let h = self.compute_branch_hash(new_left, new_right, bd);
                self.arena[idx as usize] = SmtNode::Branch {
                    bit_depth,
                    left: new_left,
                    right: new_right,
                    hash: h,
                };
                idx
            }
            SmtNode::Extension {
                bit_depth,
                child_depth,
                prefix_key,
                child,
                ..
            } => {
                let bd = bit_depth as usize;
                let cd = child_depth as usize;

                // Check if key matches the extension prefix
                let mut diverge = cd; // assume full match
                for d in bd..cd {
                    if get_bit(key, d) != get_bit(&prefix_key, d) {
                        diverge = d;
                        break;
                    }
                }

                if diverge == cd {
                    // Full match — recurse into child
                    let new_child = self.insert_at(child, cd, key, value);
                    let h = self.fold_hash(
                        self.subtree_hash(new_child, cd),
                        &prefix_key,
                        bd,
                        cd,
                    );
                    self.arena[idx as usize] = SmtNode::Extension {
                        bit_depth,
                        child_depth,
                        prefix_key,
                        child: new_child,
                        hash: h,
                    };
                    idx
                } else {
                    // Partial match — split the extension at diverge
                    let new_leaf = self.alloc(SmtNode::Leaf {
                        key: *key,
                        value: *value,
                    });

                    // Shorten or remove the remaining extension
                    let remaining_child = if diverge + 1 < cd {
                        // Extension from diverge+1 to cd
                        self.alloc(SmtNode::Extension {
                            bit_depth: (diverge + 1) as u16,
                            child_depth,
                            prefix_key,
                            child,
                            hash: self.fold_hash(
                                self.subtree_hash(child, cd),
                                &prefix_key,
                                diverge + 1,
                                cd,
                            ),
                        })
                    } else {
                        child
                    };

                    let bit_new = get_bit(key, diverge);
                    let (left, right) = if bit_new == 0 {
                        (self.wrap_in_extension(new_leaf, diverge + 1), remaining_child)
                    } else {
                        (remaining_child, self.wrap_in_extension(new_leaf, diverge + 1))
                    };

                    let branch_hash = self.compute_branch_hash(left, right, diverge);
                    let branch = self.alloc(SmtNode::Branch {
                        bit_depth: diverge as u16,
                        left,
                        right,
                        hash: branch_hash,
                    });

                    // Wrap in extension if diverge > bd
                    if diverge > bd {
                        let h = self.fold_hash(branch_hash, key, bd, diverge);
                        self.arena[idx as usize] = SmtNode::Extension {
                            bit_depth,
                            child_depth: diverge as u16,
                            prefix_key: *key,
                            child: branch,
                            hash: h,
                        };
                        idx
                    } else {
                        self.free_node(idx);
                        branch
                    }
                }
            }
        }
    }

    /// Remove a leaf from the subtree rooted at `idx`.
    /// Returns the new root index (may be NULL if subtree becomes empty).
    fn remove_at(&mut self, idx: NodeIdx, depth: usize, key: &[u8; 32]) -> NodeIdx {
        if idx == NULL {
            return NULL;
        }

        match self.arena[idx as usize].clone() {
            SmtNode::Leaf { key: k, .. } => {
                if k == *key {
                    self.free_node(idx);
                    NULL
                } else {
                    idx // not our leaf
                }
            }
            SmtNode::Branch {
                bit_depth,
                left,
                right,
                ..
            } => {
                let bd = bit_depth as usize;
                let bit = get_bit(key, bd);
                let (new_left, new_right) = if bit == 0 {
                    (self.remove_at(left, bd + 1, key), right)
                } else {
                    (left, self.remove_at(right, bd + 1, key))
                };

                // If one child became NULL, collapse
                if new_left == NULL && new_right == NULL {
                    self.free_node(idx);
                    return NULL;
                }
                if new_left == NULL {
                    self.free_node(idx);
                    return self.prepend_extension(new_right, depth, bd);
                }
                if new_right == NULL {
                    self.free_node(idx);
                    return self.prepend_extension(new_left, depth, bd);
                }

                let h = self.compute_branch_hash(new_left, new_right, bd);
                self.arena[idx as usize] = SmtNode::Branch {
                    bit_depth,
                    left: new_left,
                    right: new_right,
                    hash: h,
                };
                idx
            }
            SmtNode::Extension {
                bit_depth,
                child_depth,
                prefix_key,
                child,
                ..
            } => {
                let bd = bit_depth as usize;
                let cd = child_depth as usize;
                let new_child = self.remove_at(child, cd, key);
                if new_child == NULL {
                    self.free_node(idx);
                    return NULL;
                }
                // If child collapsed to a single leaf/extension, merge extensions
                let merged = self.try_merge_extension(idx, bd, cd, &prefix_key, new_child);
                merged
            }
        }
    }

    /// Wrap a node in an extension from `target_depth` to the node's logical depth.
    fn wrap_in_extension(&mut self, node_idx: NodeIdx, target_depth: usize) -> NodeIdx {
        let node_depth = self.logical_depth(node_idx);
        if target_depth >= node_depth {
            return node_idx; // no wrapping needed
        }
        let key = self.any_key(node_idx);
        let child_hash = self.subtree_hash(node_idx, node_depth);
        let h = self.fold_hash(child_hash, &key, target_depth, node_depth);
        self.alloc(SmtNode::Extension {
            bit_depth: target_depth as u16,
            child_depth: node_depth as u16,
            prefix_key: key,
            child: node_idx,
            hash: h,
        })
    }

    /// After removing a branch child, prepend an extension from `from_depth`
    /// to the surviving child. Merges with existing extensions.
    fn prepend_extension(
        &mut self,
        child: NodeIdx,
        from_depth: usize,
        _branch_depth: usize,
    ) -> NodeIdx {
        // The surviving child was at branch_depth + 1 (one side of the branch).
        // We need to extend the path from from_depth through the branch bit.
        let child_key = self.any_key(child);
        let child_logical_depth = self.logical_depth(child);

        if let SmtNode::Extension {
            child_depth,
            child: inner_child,
            prefix_key,
            ..
        } = self.arena[child as usize].clone()
        {
            // Merge: extension from from_depth to inner extension's child_depth
            let h = self.fold_hash(
                self.subtree_hash(inner_child, child_depth as usize),
                &prefix_key,
                from_depth,
                child_depth as usize,
            );
            self.arena[child as usize] = SmtNode::Extension {
                bit_depth: from_depth as u16,
                child_depth,
                prefix_key,
                child: inner_child,
                hash: h,
            };
            child
        } else {
            // Create new extension from from_depth to child's logical depth
            if from_depth < child_logical_depth {
                let h = self.fold_hash(
                    self.subtree_hash(child, child_logical_depth),
                    &child_key,
                    from_depth,
                    child_logical_depth,
                );
                self.alloc(SmtNode::Extension {
                    bit_depth: from_depth as u16,
                    child_depth: child_logical_depth as u16,
                    prefix_key: child_key,
                    child,
                    hash: h,
                })
            } else {
                child
            }
        }
    }

    /// Try to merge an extension with its child after removal.
    fn try_merge_extension(
        &mut self,
        ext_idx: NodeIdx,
        ext_bd: usize,
        ext_cd: usize,
        ext_prefix: &[u8; 32],
        new_child: NodeIdx,
    ) -> NodeIdx {
        match &self.arena[new_child as usize] {
            SmtNode::Extension {
                child_depth,
                child: inner,
                prefix_key: inner_prefix,
                ..
            } => {
                // Merge two extensions
                let inner_cd = *child_depth;
                let inner = *inner;
                let inner_prefix = *inner_prefix;
                let h = self.fold_hash(
                    self.subtree_hash(inner, inner_cd as usize),
                    &inner_prefix,
                    ext_bd,
                    inner_cd as usize,
                );
                self.free_node(new_child);
                self.arena[ext_idx as usize] = SmtNode::Extension {
                    bit_depth: ext_bd as u16,
                    child_depth: inner_cd,
                    prefix_key: inner_prefix,
                    child: inner,
                    hash: h,
                };
                ext_idx
            }
            SmtNode::Leaf { key, .. } => {
                // Extension → Leaf: extend to cover the full path
                let leaf_key = *key;
                let h = self.fold_hash(
                    self.subtree_hash(new_child, 256),
                    &leaf_key,
                    ext_bd,
                    256,
                );
                self.arena[ext_idx as usize] = SmtNode::Extension {
                    bit_depth: ext_bd as u16,
                    child_depth: 256,
                    prefix_key: leaf_key,
                    child: new_child,
                    hash: h,
                };
                ext_idx
            }
            SmtNode::Branch { .. } => {
                // Extension → Branch: keep as-is, just update hash
                let h = self.fold_hash(
                    self.subtree_hash(new_child, ext_cd),
                    ext_prefix,
                    ext_bd,
                    ext_cd,
                );
                self.arena[ext_idx as usize] = SmtNode::Extension {
                    bit_depth: ext_bd as u16,
                    child_depth: ext_cd as u16,
                    prefix_key: *ext_prefix,
                    child: new_child,
                    hash: h,
                };
                ext_idx
            }
        }
    }

    /// Get the logical bit-depth where a node sits in the tree.
    fn logical_depth(&self, idx: NodeIdx) -> usize {
        if idx == NULL {
            return 0;
        }
        match &self.arena[idx as usize] {
            SmtNode::Leaf { .. } => 256,
            SmtNode::Branch { bit_depth, .. } => *bit_depth as usize,
            SmtNode::Extension { bit_depth, .. } => *bit_depth as usize,
        }
    }

    /// Get any key reachable from this node (for prefix extraction).
    fn any_key(&self, idx: NodeIdx) -> [u8; 32] {
        if idx == NULL {
            return [0; 32];
        }
        match &self.arena[idx as usize] {
            SmtNode::Leaf { key, .. } => *key,
            SmtNode::Branch { left, right, .. } => {
                if *left != NULL {
                    self.any_key(*left)
                } else {
                    self.any_key(*right)
                }
            }
            SmtNode::Extension {
                prefix_key: _prefix_key, child, ..
            } => self.any_key(*child),
        }
    }

    /// Compute the subtree hash at a given logical depth.
    /// For NULL nodes, returns the empty hash at that depth.
    fn subtree_hash(&self, idx: NodeIdx, at_depth: usize) -> [u8; 32] {
        if idx == NULL {
            return *empty_hashes().get(SMT_DEPTH - at_depth);
        }
        match &self.arena[idx as usize] {
            SmtNode::Leaf { value, .. } => *value,
            SmtNode::Branch { hash, .. } => *hash,
            SmtNode::Extension { hash, .. } => *hash,
        }
    }

    /// Compute the hash for a branch node at `bit_depth` given left and right children.
    fn compute_branch_hash(&self, left: NodeIdx, right: NodeIdx, bit_depth: usize) -> [u8; 32] {
        let left_hash = self.subtree_hash(left, bit_depth + 1);
        let right_hash = self.subtree_hash(right, bit_depth + 1);
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(&left_hash);
        preimage[32..].copy_from_slice(&right_hash);
        Hash256::sha256(&preimage).0
    }

    /// Fold a child hash upward through empty siblings from `from_depth` to `to_depth`.
    /// This is the hash computation for an extension edge: at each skipped level,
    /// the sibling is the empty subtree, and we compute SHA256(left || right).
    fn fold_hash(
        &self,
        child_hash: [u8; 32],
        key: &[u8; 32],
        from_depth: usize,
        to_depth: usize,
    ) -> [u8; 32] {
        let eh = empty_hashes();
        let mut h = child_hash;
        // Walk from to_depth-1 down to from_depth (same order as original update_path)
        for d in (from_depth..to_depth).rev() {
            let bit = get_bit(key, d);
            let empty_sibling = *eh.get(SMT_DEPTH - d - 1);
            let (left, right) = if bit == 0 {
                (h, empty_sibling)
            } else {
                (empty_sibling, h)
            };
            let mut preimage = [0u8; 64];
            preimage[..32].copy_from_slice(&left);
            preimage[32..].copy_from_slice(&right);
            h = Hash256::sha256(&preimage).0;
        }
        h
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Find the first bit position where two keys differ, starting from `from`.
fn first_different_bit(a: &[u8; 32], b: &[u8; 32], from: usize) -> usize {
    for d in from..SMT_DEPTH {
        if get_bit(a, d) != get_bit(b, d) {
            return d;
        }
    }
    SMT_DEPTH // identical (shouldn't happen for distinct keys)
}

/// Batch-compute the SMT root from a set of sorted leaves (used only in tests
/// to verify that incremental updates produce identical results).
#[cfg(test)]
fn compute_root_recursive(
    leaves: &[([u8; 32], [u8; 32])],
    depth: usize,
    bit_index: usize,
) -> Hash256 {
    if leaves.is_empty() {
        return Hash256(*empty_hashes().get(depth));
    }

    if depth == 0 {
        return Hash256(leaves[0].1);
    }

    let split_point = leaves.partition_point(|leaf| {
        let byte_idx = bit_index / 8;
        let bit_idx = 7 - (bit_index % 8);
        (leaf.0[byte_idx] >> bit_idx) & 1 == 0
    });

    let left_leaves = &leaves[..split_point];
    let right_leaves = &leaves[split_point..];

    let left_hash = compute_root_recursive(left_leaves, depth - 1, bit_index + 1);
    let right_hash = compute_root_recursive(right_leaves, depth - 1, bit_index + 1);

    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(left_hash.as_bytes());
    preimage[32..].copy_from_slice(right_hash.as_bytes());
    Hash256::sha256(&preimage)
}

/// Batch-compute root from a leaf map (test helper).
#[cfg(test)]
fn batch_root(leaves: &std::collections::HashMap<[u8; 32], [u8; 32]>) -> Hash256 {
    if leaves.is_empty() {
        return empty_root();
    }
    let mut sorted: Vec<([u8; 32], [u8; 32])> = leaves.iter().map(|(k, v)| (*k, *v)).collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    compute_root_recursive(&sorted, SMT_DEPTH, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_empty_root_deterministic() {
        let root1 = empty_root();
        let root2 = empty_root();
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_empty_root_not_zero() {
        let root = empty_root();
        assert_ne!(root, Hash256::ZERO);
    }

    #[test]
    fn test_empty_smt_root() {
        let smt = SparseMerkleTree::new();
        assert_eq!(smt.root(), empty_root());
    }

    #[test]
    fn test_single_leaf() {
        let mut smt = SparseMerkleTree::new();
        let key = Hash256::sha256(b"key1");
        let value = Hash256::sha256(b"value1");
        smt.insert(key, value);

        let root = smt.root();
        assert_ne!(root, empty_root());
    }

    #[test]
    fn test_insert_remove() {
        let mut smt = SparseMerkleTree::new();
        let key = Hash256::sha256(b"key1");
        let value = Hash256::sha256(b"value1");

        let empty = smt.root();
        smt.insert(key, value);
        assert_ne!(smt.root(), empty);

        smt.remove(&key);
        assert_eq!(smt.root(), empty);
    }

    #[test]
    fn test_two_leaves_order_independent() {
        let key1 = Hash256::sha256(b"key1");
        let val1 = Hash256::sha256(b"val1");
        let key2 = Hash256::sha256(b"key2");
        let val2 = Hash256::sha256(b"val2");

        let mut smt1 = SparseMerkleTree::new();
        smt1.insert(key1, val1);
        smt1.insert(key2, val2);

        let mut smt2 = SparseMerkleTree::new();
        smt2.insert(key2, val2);
        smt2.insert(key1, val1);

        assert_eq!(smt1.root(), smt2.root());
    }

    #[test]
    fn test_different_values_different_roots() {
        let key = Hash256::sha256(b"key");
        let val1 = Hash256::sha256(b"val1");
        let val2 = Hash256::sha256(b"val2");

        let mut smt1 = SparseMerkleTree::new();
        smt1.insert(key, val1);

        let mut smt2 = SparseMerkleTree::new();
        smt2.insert(key, val2);

        assert_ne!(smt1.root(), smt2.root());
    }

    #[test]
    fn test_leaf_key_deterministic() {
        let tx_id = Hash256::sha256(b"tx");
        let k1 = leaf_key(&tx_id, 0);
        let k2 = leaf_key(&tx_id, 0);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_leaf_key_different_indices() {
        let tx_id = Hash256::sha256(b"tx");
        let k0 = leaf_key(&tx_id, 0);
        let k1 = leaf_key(&tx_id, 1);
        assert_ne!(k0, k1);
    }

    #[test]
    fn test_leaf_value_deterministic() {
        let data = b"output bytes";
        let v1 = leaf_value(data, 100, false);
        let v2 = leaf_value(data, 100, false);
        assert_eq!(v1, v2);
    }

    /// Verify that incremental root matches batch-computed root for N leaves.
    #[test]
    fn test_incremental_matches_batch() {
        let mut smt = SparseMerkleTree::new();
        let mut leaf_map: HashMap<[u8; 32], [u8; 32]> = HashMap::new();

        // Insert 50 leaves and verify after each insertion
        for i in 0..50u32 {
            let key = Hash256::sha256(&i.to_le_bytes());
            let value = Hash256::sha256(&(i + 1000).to_le_bytes());
            smt.insert(key, value);
            leaf_map.insert(key.0, value.0);

            let incremental = smt.root();
            let batch = batch_root(&leaf_map);
            assert_eq!(incremental, batch, "mismatch after inserting leaf {}", i);
        }

        // Remove half and verify after each removal
        for i in 0..25u32 {
            let key = Hash256::sha256(&i.to_le_bytes());
            smt.remove(&key);
            leaf_map.remove(&key.0);

            let incremental = smt.root();
            let batch = batch_root(&leaf_map);
            assert_eq!(incremental, batch, "mismatch after removing leaf {}", i);
        }

        // Remove all remaining and verify empty root
        for i in 25..50u32 {
            let key = Hash256::sha256(&i.to_le_bytes());
            smt.remove(&key);
        }
        assert_eq!(smt.root(), empty_root());
    }

    /// Verify insert-remove-reinsert cycle produces correct root.
    #[test]
    fn test_reinsert_after_remove() {
        let mut smt = SparseMerkleTree::new();
        let key = Hash256::sha256(b"reinsert_key");
        let val1 = Hash256::sha256(b"val_a");
        let val2 = Hash256::sha256(b"val_b");

        smt.insert(key, val1);
        let root_a = smt.root();

        smt.remove(&key);
        assert_eq!(smt.root(), empty_root());

        smt.insert(key, val2);
        let root_b = smt.root();
        assert_ne!(root_a, root_b);
        assert_ne!(root_b, empty_root());

        smt.remove(&key);
        smt.insert(key, val1);
        assert_eq!(smt.root(), root_a);
    }

    #[test]
    fn test_node_count_compressed() {
        let mut smt = SparseMerkleTree::new();
        for i in 0..100u32 {
            let key = Hash256::sha256(&i.to_le_bytes());
            let value = Hash256::sha256(&(i + 1000).to_le_bytes());
            smt.insert(key, value);
        }
        // Path-compressed: should be roughly 2-3× leaf count, not 245×
        let nc = smt.node_count();
        assert!(
            nc < 500,
            "node count should be ~2-3x leaf count (100), got {}",
            nc
        );
    }

    #[test]
    fn test_get_bit() {
        let mut key = [0u8; 32];
        key[0] = 0b10110000;
        assert_eq!(get_bit(&key, 0), 1);
        assert_eq!(get_bit(&key, 1), 0);
        assert_eq!(get_bit(&key, 2), 1);
        assert_eq!(get_bit(&key, 3), 1);
        assert_eq!(get_bit(&key, 4), 0);
    }

    /// Stress test: 1000 inserts + removes, verify root matches batch at each step.
    #[test]
    fn test_stress_insert_remove() {
        let mut smt = SparseMerkleTree::new();
        let mut leaf_map: HashMap<[u8; 32], [u8; 32]> = HashMap::new();

        for i in 0..200u32 {
            let key = Hash256::sha256(&i.to_le_bytes());
            let value = Hash256::sha256(&(i + 5000).to_le_bytes());
            smt.insert(key, value);
            leaf_map.insert(key.0, value.0);
        }
        assert_eq!(smt.root(), batch_root(&leaf_map));

        for i in 0..100u32 {
            let key = Hash256::sha256(&i.to_le_bytes());
            smt.remove(&key);
            leaf_map.remove(&key.0);
        }
        assert_eq!(smt.root(), batch_root(&leaf_map));

        for i in 200..300u32 {
            let key = Hash256::sha256(&i.to_le_bytes());
            let value = Hash256::sha256(&(i + 9000).to_le_bytes());
            smt.insert(key, value);
            leaf_map.insert(key.0, value.0);
        }
        assert_eq!(smt.root(), batch_root(&leaf_map));
    }
}
