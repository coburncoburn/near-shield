use crate::poseidon::{poseidon2, Field};
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};

/// Incremental Merkle tree using the "filled subtree" technique:
/// stores O(depth) state and amortizes inserts to O(depth) Poseidon hashes.
///
/// Internally we keep:
///   - `filled_subtrees[level]` = the latest hash of a fully-filled left subtree
///     at that level. Used as the "left sibling" for future inserts on the
///     right side of that level.
///   - `zeros[level]` = the hash of a depth-`level` subtree of zero leaves.
///   - `current_root` = the current Merkle root (cached, recomputed on insert).
#[derive(BorshDeserialize, BorshSerialize)]
#[borsh(crate = "near_sdk::borsh")]
pub struct IncrementalMerkleTree {
    depth: u8,
    next_index: u64,
    filled_subtrees: Vec<[u8; 32]>,
    zeros: Vec<[u8; 32]>,
    current_root: [u8; 32],
}

impl IncrementalMerkleTree {
    pub fn new(_prefix: &[u8], depth: u8) -> Self {
        assert!(depth > 0 && depth <= 32, "depth must be in 1..=32");
        let mut zeros = Vec::with_capacity(depth as usize + 1);
        let mut z = Field::zero();
        zeros.push(z.to_bytes_be());
        for _ in 0..depth {
            z = poseidon2(z, z);
            zeros.push(z.to_bytes_be());
        }
        let filled_subtrees: Vec<[u8; 32]> = zeros[..depth as usize].to_vec();
        let current_root = zeros[depth as usize];
        Self {
            depth,
            next_index: 0,
            filled_subtrees,
            zeros,
            current_root,
        }
    }

    pub fn capacity(&self) -> u64 {
        1u64 << self.depth
    }

    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    pub fn root(&self) -> Field {
        Field::from_be_bytes(&self.current_root)
    }

    pub fn empty_root_for_depth(&self, depth: u8) -> Field {
        Field::from_be_bytes(&self.zeros[depth as usize])
    }

    /// Inserts a leaf and returns its leaf index.
    pub fn insert(&mut self, leaf: Field) -> u64 {
        assert!(self.next_index < self.capacity(), "tree full");
        let index = self.next_index;
        let mut current = leaf;
        let mut current_index = index;
        for level in 0..self.depth as usize {
            let is_right = current_index & 1 == 1;
            if is_right {
                let left = Field::from_be_bytes(&self.filled_subtrees[level]);
                current = poseidon2(left, current);
            } else {
                self.filled_subtrees[level] = current.to_bytes_be();
                let right = Field::from_be_bytes(&self.zeros[level]);
                current = poseidon2(current, right);
            }
            current_index >>= 1;
        }
        self.current_root = current.to_bytes_be();
        self.next_index += 1;
        index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_root_equals_full_zero_subtree() {
        let t = IncrementalMerkleTree::new(b"t", 4);
        assert_eq!(t.root(), t.empty_root_for_depth(4));
    }

    #[test]
    fn root_changes_after_insert() {
        let mut t = IncrementalMerkleTree::new(b"t", 4);
        let r0 = t.root();
        t.insert(Field::from_u64(123));
        let r1 = t.root();
        assert_ne!(r0, r1);
    }

    #[test]
    fn two_inserts_produce_distinct_roots() {
        let mut t = IncrementalMerkleTree::new(b"t", 4);
        t.insert(Field::from_u64(1));
        let r1 = t.root();
        t.insert(Field::from_u64(2));
        let r2 = t.root();
        assert_ne!(r1, r2);
    }

    #[test]
    fn leaf_indices_are_sequential() {
        let mut t = IncrementalMerkleTree::new(b"t", 4);
        assert_eq!(t.insert(Field::from_u64(10)), 0);
        assert_eq!(t.insert(Field::from_u64(20)), 1);
        assert_eq!(t.insert(Field::from_u64(30)), 2);
    }

    #[test]
    fn insert_matches_naive_recomputation_for_small_tree() {
        // Build a depth-2 tree (capacity 4) and verify the root against a
        // naive recomputation.
        let mut t = IncrementalMerkleTree::new(b"t", 2);
        let leaves = [
            Field::from_u64(1),
            Field::from_u64(2),
            Field::from_u64(3),
            Field::from_u64(4),
        ];
        for l in leaves {
            t.insert(l);
        }
        let h01 = poseidon2(leaves[0], leaves[1]);
        let h23 = poseidon2(leaves[2], leaves[3]);
        let root = poseidon2(h01, h23);
        assert_eq!(t.root(), root);
    }

    #[test]
    fn partial_fill_root_matches_zero_padded_recomputation() {
        // Depth 2 tree with only the first two leaves filled. The remaining
        // two should be treated as zeros.
        let mut t = IncrementalMerkleTree::new(b"t", 2);
        let l0 = Field::from_u64(7);
        let l1 = Field::from_u64(8);
        t.insert(l0);
        t.insert(l1);
        let h01 = poseidon2(l0, l1);
        let z = Field::zero();
        let h_zz = poseidon2(z, z);
        let root = poseidon2(h01, h_zz);
        assert_eq!(t.root(), root);
    }

    #[test]
    #[should_panic(expected = "tree full")]
    fn full_tree_panics_on_insert() {
        let mut t = IncrementalMerkleTree::new(b"t", 2);
        for i in 0..4 {
            t.insert(Field::from_u64(i));
        }
        t.insert(Field::from_u64(99));
    }
}
