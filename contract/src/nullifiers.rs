use crate::poseidon::Field;
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::store::LookupSet;

#[derive(BorshDeserialize, BorshSerialize)]
#[borsh(crate = "near_sdk::borsh")]
pub struct NullifierSet {
    set: LookupSet<[u8; 32]>,
}

impl NullifierSet {
    pub fn new(prefix: &[u8]) -> Self {
        Self {
            set: LookupSet::new(prefix.to_vec()),
        }
    }
    pub fn contains(&self, n: &Field) -> bool {
        self.set.contains(&n.to_bytes_be())
    }
    /// Returns true if this nullifier was newly inserted (i.e. not previously spent).
    pub fn insert(&mut self, n: Field) -> bool {
        self.set.insert(n.to_bytes_be())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_set_does_not_contain_any_nullifier() {
        let set = NullifierSet::new(b"n");
        assert!(!set.contains(&Field::from_u64(42)));
    }

    #[test]
    fn inserting_marks_as_spent() {
        let mut set = NullifierSet::new(b"n");
        let n = Field::from_u64(42);
        assert!(set.insert(n));
        assert!(set.contains(&n));
    }

    #[test]
    fn double_insert_returns_false() {
        let mut set = NullifierSet::new(b"n");
        let n = Field::from_u64(42);
        assert!(set.insert(n));
        assert!(!set.insert(n));
    }

    #[test]
    fn distinct_nullifiers_tracked_separately() {
        let mut set = NullifierSet::new(b"n");
        set.insert(Field::from_u64(1));
        set.insert(Field::from_u64(2));
        assert!(set.contains(&Field::from_u64(1)));
        assert!(set.contains(&Field::from_u64(2)));
        assert!(!set.contains(&Field::from_u64(3)));
    }
}
