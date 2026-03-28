use crate::consensus::difficulty::{add_work, work_from_target};
use crate::types::hash::Hash256;

/// Represents a chain tip for comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainTip {
    pub block_id: Hash256,
    pub height: u64,
    pub cumulative_work: [u8; 32],
}

impl ChainTip {
    /// Create a new chain tip, computing cumulative work by adding this block's
    /// work to the parent's cumulative work.
    pub fn new(
        block_id: Hash256,
        height: u64,
        difficulty_target: &Hash256,
        parent_work: &[u8; 32],
    ) -> Self {
        let block_work = work_from_target(difficulty_target);
        let cumulative_work = add_work(parent_work, &block_work);
        ChainTip {
            block_id,
            height,
            cumulative_work,
        }
    }

    /// Genesis chain tip.
    pub fn genesis(block_id: Hash256, difficulty_target: &Hash256) -> Self {
        let cumulative_work = work_from_target(difficulty_target);
        ChainTip {
            block_id,
            height: 0,
            cumulative_work,
        }
    }
}

/// Compare two chain tips. Returns true if `candidate` is preferred over `current`.
///
/// Fork choice rules:
/// 1. Prefer higher cumulative work.
/// 2. If equal work, prefer greater height.
/// 3. If equal work and equal height, keep the current tip (no reorg).
pub fn is_better_chain(candidate: &ChainTip, current: &ChainTip) -> bool {
    match candidate.cumulative_work.cmp(&current.cumulative_work) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => match candidate.height.cmp(&current.height) {
            std::cmp::Ordering::Greater => true,
            // Equal work + equal (or lesser) height: keep current tip
            _ => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_higher_work_wins() {
        let tip_a = ChainTip {
            block_id: Hash256([0xFF; 32]),
            height: 100,
            cumulative_work: {
                let mut w = [0u8; 32];
                w[31] = 200;
                w
            },
        };
        let tip_b = ChainTip {
            block_id: Hash256([0x00; 32]),
            height: 100,
            cumulative_work: {
                let mut w = [0u8; 32];
                w[31] = 100;
                w
            },
        };
        assert!(is_better_chain(&tip_a, &tip_b));
        assert!(!is_better_chain(&tip_b, &tip_a));
    }

    #[test]
    fn test_equal_work_higher_height_wins() {
        let work = {
            let mut w = [0u8; 32];
            w[31] = 100;
            w
        };
        let tip_a = ChainTip {
            block_id: Hash256([0xFF; 32]),
            height: 200,
            cumulative_work: work,
        };
        let tip_b = ChainTip {
            block_id: Hash256([0x00; 32]),
            height: 100,
            cumulative_work: work,
        };
        assert!(is_better_chain(&tip_a, &tip_b));
    }

    #[test]
    fn test_equal_work_equal_height_keeps_current() {
        let work = {
            let mut w = [0u8; 32];
            w[31] = 100;
            w
        };
        let tip_a = ChainTip {
            block_id: Hash256([0x01; 32]),
            height: 100,
            cumulative_work: work,
        };
        let tip_b = ChainTip {
            block_id: Hash256([0x02; 32]),
            height: 100,
            cumulative_work: work,
        };
        // Neither should be preferred — keep current tip
        assert!(!is_better_chain(&tip_a, &tip_b));
        assert!(!is_better_chain(&tip_b, &tip_a));
    }
}
