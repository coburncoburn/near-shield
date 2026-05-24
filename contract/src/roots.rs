use crate::poseidon::Field;
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};

/// Rolling window of the last N Merkle roots. Allows clients to build proofs
/// against a slightly stale root without losing if other transactions land in
/// the meantime.
#[derive(BorshDeserialize, BorshSerialize)]
#[borsh(crate = "near_sdk::borsh")]
pub struct RootsWindow {
    capacity: u32,
    head: u32,
    len: u32,
    roots: Vec<[u8; 32]>,
}

impl RootsWindow {
    pub fn new(_prefix: &[u8], capacity: u32) -> Self {
        assert!(capacity > 0, "capacity must be > 0");
        Self {
            capacity,
            head: 0,
            len: 0,
            roots: Vec::with_capacity(capacity as usize),
        }
    }

    pub fn push(&mut self, root: Field) {
        let bytes = root.to_bytes_be();
        if self.len < self.capacity {
            self.roots.push(bytes);
            self.len += 1;
            self.head = (self.head + 1) % self.capacity;
        } else {
            self.roots[self.head as usize] = bytes;
            self.head = (self.head + 1) % self.capacity;
        }
    }

    pub fn contains(&self, root: &Field) -> bool {
        let bytes = root.to_bytes_be();
        self.roots.iter().any(|r| *r == bytes)
    }

    pub fn len(&self) -> u32 {
        self.len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_window_contains_nothing() {
        let w = RootsWindow::new(b"r", 3);
        assert!(!w.contains(&Field::from_u64(1)));
        assert_eq!(w.len(), 0);
    }

    #[test]
    fn push_makes_root_recent() {
        let mut w = RootsWindow::new(b"r", 3);
        w.push(Field::from_u64(1));
        assert!(w.contains(&Field::from_u64(1)));
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn rotates_after_capacity() {
        let mut w = RootsWindow::new(b"r", 2);
        w.push(Field::from_u64(1));
        w.push(Field::from_u64(2));
        w.push(Field::from_u64(3));
        assert!(!w.contains(&Field::from_u64(1)), "oldest root evicted");
        assert!(w.contains(&Field::from_u64(2)));
        assert!(w.contains(&Field::from_u64(3)));
        assert_eq!(w.len(), 2);
    }

    #[test]
    fn many_pushes_keep_len_at_capacity() {
        let mut w = RootsWindow::new(b"r", 4);
        for i in 0..100 {
            w.push(Field::from_u64(i));
        }
        assert_eq!(w.len(), 4);
        // Last 4 pushed are 96..=99
        for i in 96..100 {
            assert!(w.contains(&Field::from_u64(i)));
        }
        for i in 0..96 {
            assert!(!w.contains(&Field::from_u64(i)));
        }
    }
}
