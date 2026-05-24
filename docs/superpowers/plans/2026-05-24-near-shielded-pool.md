# NEAR Shielded USDC Pool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the v0 shielded USDC pool on NEAR per `docs/superpowers/specs/2026-05-24-near-shielded-pool-design.md`.

**Architecture:** Monorepo with three top-level workspaces — `circuits/` (Noir), `contract/` (Rust near-sdk), `sdk/` (TypeScript pnpm workspace containing core, sdk, auditor, relayer, cli). Crypto primitives shared between Rust and TS via parallel implementations with cross-language test vectors.

**Tech Stack:** Noir (Aztec bb backend), Rust + near-sdk, TypeScript, pnpm workspaces, near-workspaces-rs for contract tests, vitest for TS tests.

---

## File Structure

```
hip4/
├── Cargo.toml                              # workspace root
├── pnpm-workspace.yaml                     # TS workspace root
├── circuits/
│   ├── deposit/{src/main.nr, Nargo.toml}
│   ├── transfer/{src/main.nr, Nargo.toml}
│   ├── withdraw/{src/main.nr, Nargo.toml}
│   └── shared/src/lib.nr                   # Poseidon, encryption helpers
├── contract/
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs                          # entry, near_bindgen
│   │   ├── state.rs                        # Contract struct
│   │   ├── merkle.rs                       # IncrementalTree
│   │   ├── nullifiers.rs                   # spent-set wrapper
│   │   ├── roots.rs                        # rolling root window
│   │   ├── verifier.rs                     # zk verifier wrapper
│   │   ├── poseidon.rs                     # field hash
│   │   ├── ft.rs                           # USDC FT integration
│   │   ├── deposit.rs                      # method
│   │   ├── transfer.rs                     # method
│   │   ├── withdraw.rs                     # method
│   │   └── events.rs                       # log emission
│   └── tests/                              # near-workspaces integration tests
├── sdk/
│   ├── package.json
│   ├── packages/
│   │   ├── core/                           # primitives, scanning, prover bridge
│   │   ├── sdk/                            # high-level Wallet API
│   │   ├── auditor/                        # decryption + indexer
│   │   ├── relayer/                        # reference HTTP service
│   │   └── cli/                            # interactive CLI
│   └── test-vectors/                       # JSON vectors shared with Rust tests
└── docs/
```

---

## Phase 1 — Repo scaffolding

### Task 1: Initialize workspace roots

**Files:**
- Create: `Cargo.toml`
- Create: `pnpm-workspace.yaml`
- Create: `.gitignore`
- Create: `README.md`

- [ ] **Step 1: Create Cargo workspace root**

```toml
# Cargo.toml
[workspace]
resolver = "2"
members = ["contract"]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MIT OR Apache-2.0"

[workspace.dependencies]
near-sdk = "5.5"
near-workspaces = "0.15"
anyhow = "1"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
borsh = "1"
```

- [ ] **Step 2: Create pnpm workspace**

```yaml
# pnpm-workspace.yaml
packages:
  - "sdk/packages/*"
```

- [ ] **Step 3: Create .gitignore**

```
target/
node_modules/
dist/
*.log
.DS_Store
.env
.env.local
.aztec/
```

- [ ] **Step 4: Create README.md**

```markdown
# NEAR Shielded USDC Pool

Privacy-preserving USDC pool on NEAR with per-user auditor view keys.
See `docs/superpowers/specs/2026-05-24-near-shielded-pool-design.md`.

## Layout
- `circuits/` — Noir zk circuits
- `contract/` — NEAR Rust contract
- `sdk/` — TypeScript SDK, relayer, auditor indexer, CLI
```

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml pnpm-workspace.yaml .gitignore README.md
git commit -m "chore: initialize workspace roots"
```

---

## Phase 2 — Contract crate skeleton + core primitives

### Task 2: Contract crate scaffolding

**Files:**
- Create: `contract/Cargo.toml`
- Create: `contract/src/lib.rs`

- [ ] **Step 1: Write contract/Cargo.toml**

```toml
[package]
name = "shielded-pool"
version.workspace = true
edition.workspace = true
license.workspace = true

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
near-sdk = { workspace = true }
borsh = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }

[dev-dependencies]
near-workspaces = { workspace = true }
tokio = { workspace = true }
anyhow = { workspace = true }
```

- [ ] **Step 2: Write minimal lib.rs**

```rust
// contract/src/lib.rs
use near_sdk::near;

mod merkle;
mod nullifiers;
mod poseidon;
mod roots;

#[near(contract_state)]
#[derive(Default)]
pub struct Contract {}

#[near]
impl Contract {
    #[init]
    pub fn new() -> Self {
        Self {}
    }
}
```

- [ ] **Step 3: Verify it builds**

Run: `cargo build -p shielded-pool`
Expected: clean build, no warnings about missing items (modules are empty stubs — create empty files in next task).

- [ ] **Step 4: Create empty module files**

Touch `contract/src/{merkle,nullifiers,poseidon,roots}.rs` as empty files.

- [ ] **Step 5: Commit**

```bash
git add contract/
git commit -m "feat(contract): scaffold contract crate"
```

### Task 3: Field type and Poseidon hash (Rust)

**Files:**
- Modify: `contract/src/poseidon.rs`
- Modify: `contract/Cargo.toml` (add `light-poseidon`)

The contract needs Poseidon hashing matching the Noir circuits exactly. Use the `light-poseidon` crate (BN254, same as Noir default).

- [ ] **Step 1: Add dependency**

In `contract/Cargo.toml` under `[dependencies]` add:
```toml
light-poseidon = "0.2"
ark-bn254 = "0.5"
ark-ff = "0.5"
```

- [ ] **Step 2: Write failing test**

```rust
// contract/src/poseidon.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_two_known_vector() {
        // Vector: poseidon([1, 2]) over BN254 produces a known field element.
        // Source: matches Noir std::hash::poseidon::bn254::hash_2([1,2]).
        let a = Field::from_u64(1);
        let b = Field::from_u64(2);
        let h = poseidon2(a, b);
        assert_eq!(
            h.to_hex(),
            "0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a"
        );
    }
}
```

- [ ] **Step 3: Run test, expect fail**

Run: `cargo test -p shielded-pool poseidon::tests::hash_two_known_vector`
Expected: FAIL — `Field` and `poseidon2` not defined.

- [ ] **Step 4: Implement Field and poseidon2/poseidon4**

```rust
// contract/src/poseidon.rs
use ark_bn254::Fr;
use ark_ff::{PrimeField, BigInteger};
use light_poseidon::{Poseidon, PoseidonHasher};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field(pub Fr);

impl Field {
    pub fn from_u64(x: u64) -> Self { Field(Fr::from(x)) }
    pub fn from_bytes_le(b: &[u8]) -> Self { Field(Fr::from_le_bytes_mod_order(b)) }
    pub fn to_bytes_be(&self) -> [u8; 32] {
        let bi = self.0.into_bigint();
        let mut out = [0u8; 32];
        let bytes = bi.to_bytes_be();
        out[32 - bytes.len()..].copy_from_slice(&bytes);
        out
    }
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_bytes_be()))
    }
    pub fn zero() -> Self { Field(Fr::from(0u64)) }
}

pub fn poseidon2(a: Field, b: Field) -> Field {
    let mut h = Poseidon::<Fr>::new_circom(2).expect("poseidon-2 init");
    Field(h.hash(&[a.0, b.0]).expect("poseidon-2 hash"))
}

pub fn poseidon4(a: Field, b: Field, c: Field, d: Field) -> Field {
    let mut h = Poseidon::<Fr>::new_circom(4).expect("poseidon-4 init");
    Field(h.hash(&[a.0, b.0, c.0, d.0]).expect("poseidon-4 hash"))
}
```

Add `hex = "0.4"` to dependencies.

- [ ] **Step 5: Run test, expect pass**

Run: `cargo test -p shielded-pool poseidon::tests::hash_two_known_vector`
Expected: PASS.

If the expected hex differs (because `light-poseidon`'s `new_circom` may use slightly different params), capture the *actual* output, verify against Noir's `std::hash::poseidon::bn254::hash_2([1,2])` reference (cross-check during circuit phase), and update the assertion. The point of this test is locking the Rust↔Noir compatibility surface — both sides must produce the same value or the whole scheme breaks.

- [ ] **Step 6: Commit**

```bash
git add contract/src/poseidon.rs contract/Cargo.toml
git commit -m "feat(contract): poseidon-2 and poseidon-4 over BN254"
```

### Task 4: Nullifier set wrapper

**Files:**
- Modify: `contract/src/nullifiers.rs`
- Modify: `contract/src/lib.rs`

- [ ] **Step 1: Write failing test**

```rust
// contract/src/nullifiers.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon::Field;

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
}
```

- [ ] **Step 2: Run, expect fail**

Run: `cargo test -p shielded-pool nullifiers::tests`
Expected: FAIL — `NullifierSet` not defined.

- [ ] **Step 3: Implement**

```rust
// contract/src/nullifiers.rs
use near_sdk::store::LookupSet;
use crate::poseidon::Field;

#[derive(near_sdk::borsh::BorshDeserialize, near_sdk::borsh::BorshSerialize)]
#[borsh(crate = "near_sdk::borsh")]
pub struct NullifierSet {
    set: LookupSet<[u8; 32]>,
}

impl NullifierSet {
    pub fn new(prefix: &[u8]) -> Self {
        Self { set: LookupSet::new(prefix.to_vec()) }
    }
    pub fn contains(&self, n: &Field) -> bool {
        self.set.contains(&n.to_bytes_be())
    }
    pub fn insert(&mut self, n: Field) -> bool {
        self.set.insert(n.to_bytes_be())
    }
}
```

Note: `LookupSet` works inside `cargo test` for `near-sdk` 5.x as a thin wrapper — confirm at test time.

- [ ] **Step 4: Run, expect pass**

Run: `cargo test -p shielded-pool nullifiers::tests`
Expected: PASS for all three tests.

- [ ] **Step 5: Wire module + commit**

In `contract/src/lib.rs` keep `mod nullifiers;` (already added in Task 2).

```bash
git add contract/src/nullifiers.rs
git commit -m "feat(contract): NullifierSet wrapper over LookupSet"
```

### Task 5: Rolling roots window

**Files:**
- Modify: `contract/src/roots.rs`

- [ ] **Step 1: Write failing tests**

```rust
// contract/src/roots.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon::Field;

    #[test]
    fn empty_window_contains_nothing() {
        let w = RootsWindow::new(b"r", 3);
        assert!(!w.contains(&Field::from_u64(1)));
    }

    #[test]
    fn push_makes_root_recent() {
        let mut w = RootsWindow::new(b"r", 3);
        w.push(Field::from_u64(1));
        assert!(w.contains(&Field::from_u64(1)));
    }

    #[test]
    fn rotates_after_capacity() {
        let mut w = RootsWindow::new(b"r", 2);
        w.push(Field::from_u64(1));
        w.push(Field::from_u64(2));
        w.push(Field::from_u64(3));
        assert!(!w.contains(&Field::from_u64(1)));
        assert!(w.contains(&Field::from_u64(2)));
        assert!(w.contains(&Field::from_u64(3)));
    }
}
```

- [ ] **Step 2: Run, expect fail**

Run: `cargo test -p shielded-pool roots::tests`
Expected: FAIL.

- [ ] **Step 3: Implement**

```rust
// contract/src/roots.rs
use near_sdk::store::Vector;
use crate::poseidon::Field;

#[derive(near_sdk::borsh::BorshDeserialize, near_sdk::borsh::BorshSerialize)]
#[borsh(crate = "near_sdk::borsh")]
pub struct RootsWindow {
    roots: Vector<[u8; 32]>,
    capacity: u32,
    head: u32,
    len: u32,
}

impl RootsWindow {
    pub fn new(prefix: &[u8], capacity: u32) -> Self {
        Self {
            roots: Vector::new(prefix.to_vec()),
            capacity,
            head: 0,
            len: 0,
        }
    }

    pub fn push(&mut self, root: Field) {
        let bytes = root.to_bytes_be();
        if self.len < self.capacity {
            self.roots.push(bytes);
            self.len += 1;
            self.head = (self.head + 1) % self.capacity;
        } else {
            let idx = self.head;
            // Vector::replace exists in near-sdk 5
            if let Some(slot) = self.roots.get_mut(idx) {
                *slot = bytes;
            }
            self.head = (self.head + 1) % self.capacity;
        }
    }

    pub fn contains(&self, root: &Field) -> bool {
        let bytes = root.to_bytes_be();
        for i in 0..self.len {
            if self.roots.get(i).map_or(false, |r| *r == bytes) {
                return true;
            }
        }
        false
    }
}
```

- [ ] **Step 4: Run, expect pass**

Run: `cargo test -p shielded-pool roots::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add contract/src/roots.rs
git commit -m "feat(contract): rolling Merkle root window"
```

### Task 6: Incremental Merkle tree

**Files:**
- Modify: `contract/src/merkle.rs`

- [ ] **Step 1: Write failing tests**

```rust
// contract/src/merkle.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon::Field;

    #[test]
    fn empty_tree_root_is_zero_subtree_hash() {
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
    fn full_tree_panics_on_insert() {
        let mut t = IncrementalMerkleTree::new(b"t", 2); // capacity 4
        for i in 0..4 { t.insert(Field::from_u64(i)); }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            t.insert(Field::from_u64(99));
        }));
        assert!(result.is_err());
    }
}
```

- [ ] **Step 2: Run, expect fail**

Run: `cargo test -p shielded-pool merkle::tests`
Expected: FAIL.

- [ ] **Step 3: Implement incremental Merkle**

```rust
// contract/src/merkle.rs
use near_sdk::store::Vector;
use crate::poseidon::{Field, poseidon2};

/// Incremental Merkle tree using cached "filled subtree" optimization.
/// Stores O(depth) state, not O(2^depth).
#[derive(near_sdk::borsh::BorshDeserialize, near_sdk::borsh::BorshSerialize)]
#[borsh(crate = "near_sdk::borsh")]
pub struct IncrementalMerkleTree {
    depth: u8,
    next_index: u64,
    filled_subtrees: Vector<[u8; 32]>, // length == depth
    zeros: Vector<[u8; 32]>,           // precomputed empty-subtree hashes by level
}

impl IncrementalMerkleTree {
    pub fn new(prefix: &[u8], depth: u8) -> Self {
        let mut filled = Vector::new([prefix, b"_f"].concat());
        let mut zeros = Vector::new([prefix, b"_z"].concat());

        let mut z = Field::zero();
        for _ in 0..depth {
            let bytes = z.to_bytes_be();
            zeros.push(bytes);
            filled.push(bytes);
            z = poseidon2(z, z);
        }
        let root_zero = z.to_bytes_be();
        // store root-level zero at index `depth` for convenience
        zeros.push(root_zero);

        Self { depth, next_index: 0, filled_subtrees: filled, zeros }
    }

    pub fn capacity(&self) -> u64 { 1u64 << self.depth }

    pub fn empty_root_for_depth(&self, depth: u8) -> Field {
        Field::from_bytes_le(&{
            let mut v = self.zeros.get(depth as u32).unwrap().clone();
            v.reverse();
            v
        })
    }

    pub fn insert(&mut self, leaf: Field) -> u64 {
        assert!(self.next_index < self.capacity(), "tree full");
        let index = self.next_index;
        let mut current = leaf;
        let mut current_index = index;
        for level in 0..self.depth as u32 {
            let is_right = current_index & 1 == 1;
            let sibling = if is_right {
                Field::from_be_bytes(&self.filled_subtrees.get(level).unwrap().clone())
            } else {
                let z = self.zeros.get(level).unwrap().clone();
                self.filled_subtrees.replace(level, current.to_bytes_be());
                Field::from_be_bytes(&z)
            };
            current = if is_right { poseidon2(sibling, current) } else { poseidon2(current, sibling) };
            current_index >>= 1;
        }
        self.next_index += 1;
        index
    }

    pub fn root(&self) -> Field {
        // recompute from filled_subtrees + zeros at current next_index
        if self.next_index == 0 {
            return self.empty_root_for_depth(self.depth);
        }
        let mut current = Field::zero();
        let mut idx = self.next_index - 1;
        let mut current_is_filled_path = true;
        for level in 0..self.depth as u32 {
            if current_is_filled_path {
                current = Field::from_be_bytes(&self.filled_subtrees.get(level).unwrap().clone());
                current_is_filled_path = false;
            } else {
                let is_right = idx & 1 == 1;
                let sibling = if is_right {
                    Field::from_be_bytes(&self.filled_subtrees.get(level).unwrap().clone())
                } else {
                    Field::from_be_bytes(&self.zeros.get(level).unwrap().clone())
                };
                current = if is_right { poseidon2(sibling, current) } else { poseidon2(current, sibling) };
            }
            idx >>= 1;
        }
        current
    }
}

impl Field {
    pub fn from_be_bytes(b: &[u8]) -> Self {
        use ark_ff::PrimeField;
        Field(ark_bn254::Fr::from_be_bytes_mod_order(b))
    }
}
```

Add `Vector::replace` usage — `near-sdk` 5 supports it.

- [ ] **Step 4: Run, expect pass**

Run: `cargo test -p shielded-pool merkle::tests`
Expected: PASS.

If the incremental-root reconstruction has bugs, the `root_changes_after_insert` test will catch it. Iterate until green.

- [ ] **Step 5: Commit**

```bash
git add contract/src/merkle.rs
git commit -m "feat(contract): incremental Merkle tree with poseidon2 hashing"
```

---

## Phase 3 — Verifier integration and contract methods

### Task 7: Verifier trait + mock implementation

**Files:**
- Modify: `contract/src/verifier.rs`
- Modify: `contract/src/lib.rs`

- [ ] **Step 1: Write failing tests**

```rust
// contract/src/verifier.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_verifier_accepts_known_proof() {
        let v = MockVerifier::default();
        assert!(v.verify(&[1, 2, 3], &[Field::from_u64(1)]));
    }

    #[test]
    fn mock_verifier_rejects_empty_proof() {
        let v = MockVerifier::default();
        assert!(!v.verify(&[], &[Field::from_u64(1)]));
    }
}
```

- [ ] **Step 2: Run, expect fail**

Run: `cargo test -p shielded-pool verifier::tests`
Expected: FAIL.

- [ ] **Step 3: Implement trait + mock**

```rust
// contract/src/verifier.rs
use crate::poseidon::Field;

pub trait Verifier {
    fn verify(&self, proof: &[u8], public_inputs: &[Field]) -> bool;
}

#[derive(Default)]
pub struct MockVerifier;

impl Verifier for MockVerifier {
    fn verify(&self, proof: &[u8], _public_inputs: &[Field]) -> bool {
        !proof.is_empty()
    }
}

/// Real verifier wraps Aztec's barretenberg verifier compiled to WASM.
/// Lives behind a Cargo feature `bb-verifier` so unit tests compile fast.
#[cfg(feature = "bb-verifier")]
pub mod bb {
    use super::*;
    pub struct BbVerifier { pub vk: Vec<u8> }
    impl Verifier for BbVerifier {
        fn verify(&self, _proof: &[u8], _pi: &[Field]) -> bool {
            unimplemented!("integrate barretenberg verifier in Task 22")
        }
    }
}
```

- [ ] **Step 4: Run, expect pass**

Run: `cargo test -p shielded-pool verifier::tests`
Expected: PASS.

- [ ] **Step 5: Wire module**

Add `mod verifier;` to `contract/src/lib.rs`.

- [ ] **Step 6: Commit**

```bash
git add contract/src/verifier.rs contract/src/lib.rs
git commit -m "feat(contract): Verifier trait + MockVerifier for tests"
```

### Task 8: Contract state struct + init

**Files:**
- Modify: `contract/src/lib.rs`

- [ ] **Step 1: Replace lib.rs with full Contract definition**

```rust
// contract/src/lib.rs
use near_sdk::{near, AccountId, PanicOnDefault};
use near_sdk::store::Vector;

mod merkle;
mod nullifiers;
mod poseidon;
mod roots;
mod verifier;
mod events;
mod ft;
mod deposit;
mod transfer;
mod withdraw;

use merkle::IncrementalMerkleTree;
use nullifiers::NullifierSet;
use roots::RootsWindow;

pub const TREE_DEPTH: u8 = 20;
pub const ROOTS_WINDOW: u32 = 30;

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    pub owner: AccountId,
    pub usdc_token: AccountId,
    pub tree: IncrementalMerkleTree,
    pub recent_roots: RootsWindow,
    pub nullifiers: NullifierSet,
    pub vk_deposit: Vec<u8>,
    pub vk_transfer: Vec<u8>,
    pub vk_withdraw: Vec<u8>,
}

#[near]
impl Contract {
    #[init]
    pub fn new(
        owner: AccountId,
        usdc_token: AccountId,
        vk_deposit: Vec<u8>,
        vk_transfer: Vec<u8>,
        vk_withdraw: Vec<u8>,
    ) -> Self {
        Self {
            owner,
            usdc_token,
            tree: IncrementalMerkleTree::new(b"m", TREE_DEPTH),
            recent_roots: RootsWindow::new(b"r", ROOTS_WINDOW),
            nullifiers: NullifierSet::new(b"n"),
            vk_deposit,
            vk_transfer,
            vk_withdraw,
        }
    }

    pub fn owner(&self) -> AccountId { self.owner.clone() }
    pub fn usdc_token(&self) -> AccountId { self.usdc_token.clone() }
    pub fn merkle_root(&self) -> String { self.tree.root().to_hex() }
}
```

- [ ] **Step 2: Touch event/ft/method modules as empty**

Create empty `contract/src/{events,ft,deposit,transfer,withdraw}.rs`.

- [ ] **Step 3: Verify build**

Run: `cargo build -p shielded-pool`
Expected: clean build.

- [ ] **Step 4: Commit**

```bash
git add contract/src/
git commit -m "feat(contract): Contract state struct and init"
```

### Task 9: Deposit method (unit-tested with MockVerifier)

**Files:**
- Modify: `contract/src/deposit.rs`
- Modify: `contract/src/events.rs`

- [ ] **Step 1: Write deposit event**

```rust
// contract/src/events.rs
use near_sdk::serde::Serialize;
use near_sdk::serde_json::json;

pub fn emit_deposit(commitment: &str, leaf_index: u64, view_ct: &str, note_ct: &str) {
    near_sdk::env::log_str(&json!({
        "standard": "shielded-pool",
        "event": "deposit",
        "data": {
            "commitment": commitment,
            "leaf_index": leaf_index,
            "view_ct": view_ct,
            "note_ct": note_ct,
        }
    }).to_string());
}

pub fn emit_transfer(roots: &str, nullifiers: [&str; 2], commitments: [&str; 2], leaf_indices: [u64; 2], view_cts: [&str; 2], note_cts: [&str; 2]) {
    near_sdk::env::log_str(&json!({
        "standard": "shielded-pool",
        "event": "transfer",
        "data": {
            "merkle_root": roots,
            "nullifiers": nullifiers,
            "commitments": commitments,
            "leaf_indices": leaf_indices,
            "view_cts": view_cts,
            "note_cts": note_cts,
        }
    }).to_string());
}

pub fn emit_withdraw(nullifier: &str, recipient: &str, amount: u128, relayer: &str, fee: u128, view_ct: &str) {
    near_sdk::env::log_str(&json!({
        "standard": "shielded-pool",
        "event": "withdraw",
        "data": {
            "nullifier": nullifier,
            "recipient": recipient,
            "amount": amount.to_string(),
            "relayer": relayer,
            "relayer_fee": fee.to_string(),
            "view_ct": view_ct,
        }
    }).to_string());
}
```

- [ ] **Step 2: Write failing test for deposit**

```rust
// contract/src/deposit.rs
#[cfg(test)]
mod tests {
    use crate::Contract;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use near_sdk::{AccountId, NearToken};

    fn alice() -> AccountId { "alice.near".parse().unwrap() }
    fn usdc() -> AccountId { "usdc.near".parse().unwrap() }
    fn owner() -> AccountId { "owner.near".parse().unwrap() }

    fn setup() -> Contract {
        let mut ctx = VMContextBuilder::new();
        ctx.predecessor_account_id(alice()).attached_deposit(NearToken::from_yoctonear(1));
        testing_env!(ctx.build());
        Contract::new(owner(), usdc(), vec![1,2,3], vec![1,2,3], vec![1,2,3])
    }

    #[test]
    fn deposit_with_valid_mock_proof_inserts_into_tree() {
        let mut c = setup();
        let pre_root = c.merkle_root();
        c.deposit(
            "0x01".repeat(32),                       // commitment hex
            100_000_000.into(),                      // 100 USDC (6 decimals)
            "0x02".repeat(32),                       // auditor_pubkey
            "viewct".into(),
            "notect".into(),
            vec![1,2,3],                             // proof bytes
        );
        assert_ne!(c.merkle_root(), pre_root);
    }

    #[test]
    #[should_panic(expected = "invalid proof")]
    fn deposit_with_empty_proof_rejects() {
        let mut c = setup();
        c.deposit(
            "0x01".repeat(32),
            100_000_000.into(),
            "0x02".repeat(32),
            "viewct".into(),
            "notect".into(),
            vec![],
        );
    }
}
```

- [ ] **Step 3: Implement deposit method**

```rust
// contract/src/deposit.rs
use near_sdk::{near, json_types::U128};
use crate::{Contract, poseidon::Field, verifier::{Verifier, MockVerifier}, events};

#[near]
impl Contract {
    /// In v0 unit tests we use MockVerifier; integration tests on a sandbox
    /// will deploy with real verifier keys.
    pub fn deposit(
        &mut self,
        commitment: String,
        amount: U128,
        auditor_pubkey: String,
        view_ct: String,
        note_ct: String,
        proof: Vec<u8>,
    ) {
        let commitment_field = parse_hex32(&commitment).expect("bad commitment hex");
        let auditor_field = parse_hex32(&auditor_pubkey).expect("bad auditor hex");

        let pi = vec![
            commitment_field,
            Field::from_u128(amount.0),
            auditor_field,
            hash_bytes_to_field(view_ct.as_bytes()),
        ];

        let verifier = MockVerifier::default();
        assert!(verifier.verify(&proof, &pi), "invalid proof");

        let leaf_index = self.tree.insert(commitment_field);
        self.recent_roots.push(self.tree.root());
        events::emit_deposit(&commitment, leaf_index, &view_ct, &note_ct);

        // Real implementation also triggers ft_transfer_call from predecessor to self.
        // Deferred to Task 12 (FT integration).
    }
}

fn parse_hex32(s: &str) -> Option<Field> {
    let s = s.trim_start_matches("0x");
    if s.len() != 64 { return None; }
    let bytes = hex::decode(s).ok()?;
    Some(Field::from_be_bytes(&bytes))
}

fn hash_bytes_to_field(b: &[u8]) -> Field {
    use light_poseidon::{Poseidon, PoseidonHasher};
    // Chunk-and-hash; for unit tests we just hash the first 31 bytes as a field.
    Field::from_bytes_le(&b.iter().take(31).copied().collect::<Vec<_>>())
}

impl Field {
    pub fn from_u128(x: u128) -> Self {
        Field(ark_bn254::Fr::from(x))
    }
}
```

- [ ] **Step 4: Run, expect pass**

Run: `cargo test -p shielded-pool deposit::tests`
Expected: both tests PASS.

- [ ] **Step 5: Commit**

```bash
git add contract/src/deposit.rs contract/src/events.rs
git commit -m "feat(contract): deposit method with MockVerifier"
```

### Task 10: Transfer method

(Pattern mirrors Task 9 closely. Use the spec's transfer public inputs. Tests must cover: valid mock proof inserts both commitments and marks both nullifiers spent; stale root rejected; double-spend rejected.)

**Files:**
- Modify: `contract/src/transfer.rs`

- [ ] **Step 1: Write failing tests**

```rust
// contract/src/transfer.rs
#[cfg(test)]
mod tests {
    use crate::Contract;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use near_sdk::AccountId;

    fn setup() -> Contract {
        let ctx = VMContextBuilder::new();
        testing_env!(ctx.build());
        Contract::new(
            "owner.near".parse().unwrap(),
            "usdc.near".parse().unwrap(),
            vec![1,2,3], vec![1,2,3], vec![1,2,3],
        )
    }

    #[test]
    fn transfer_with_valid_mock_proof_succeeds() {
        let mut c = setup();
        // Seed a root so the merkle_root pre-check passes
        // (in real flow this comes from prior deposits)
        c.recent_roots.push(crate::poseidon::Field::from_u64(7));
        let merkle_root = "0x".to_string() + &"00".repeat(31) + "07";

        c.transfer(
            merkle_root.clone(),
            ["0xaa".repeat(32), "0xbb".repeat(32)],
            ["0xcc".repeat(32), "0xdd".repeat(32)],
            "0xee".repeat(32),
            "0xff".repeat(32),
            ["v1".into(), "v2".into()],
            ["n1".into(), "n2".into()],
            vec![1,2,3],
        );

        let n_aa = crate::poseidon::Field::from_be_bytes(&[0xaa; 32]);
        assert!(c.nullifiers.contains(&n_aa));
    }

    #[test]
    #[should_panic(expected = "stale root")]
    fn transfer_with_unknown_root_rejects() {
        let mut c = setup();
        c.transfer(
            "0x".to_string() + &"99".repeat(32),
            ["0xaa".repeat(32), "0xbb".repeat(32)],
            ["0xcc".repeat(32), "0xdd".repeat(32)],
            "0xee".repeat(32),
            "0xff".repeat(32),
            ["v1".into(), "v2".into()],
            ["n1".into(), "n2".into()],
            vec![1,2,3],
        );
    }

    #[test]
    #[should_panic(expected = "double spend")]
    fn transfer_double_spend_rejects() {
        let mut c = setup();
        c.recent_roots.push(crate::poseidon::Field::from_u64(7));
        let root = "0x".to_string() + &"00".repeat(31) + "07";

        c.transfer(
            root.clone(),
            ["0xaa".repeat(32), "0xbb".repeat(32)],
            ["0xcc".repeat(32), "0xdd".repeat(32)],
            "0xee".repeat(32),
            "0xff".repeat(32),
            ["v1".into(), "v2".into()],
            ["n1".into(), "n2".into()],
            vec![1,2,3],
        );
        // Reuse nullifier 0xaa with a new (fresh-looking) root push
        c.recent_roots.push(crate::poseidon::Field::from_u64(8));
        c.transfer(
            "0x".to_string() + &"00".repeat(31) + "08",
            ["0xaa".repeat(32), "0xb2".repeat(32)],
            ["0xc2".repeat(32), "0xd2".repeat(32)],
            "0xee".repeat(32),
            "0xff".repeat(32),
            ["v1".into(), "v2".into()],
            ["n1".into(), "n2".into()],
            vec![1,2,3],
        );
    }
}
```

- [ ] **Step 2: Run, expect fail**

Run: `cargo test -p shielded-pool transfer::tests`
Expected: FAIL — `transfer` method not defined.

- [ ] **Step 3: Implement transfer**

```rust
// contract/src/transfer.rs
use near_sdk::near;
use crate::{Contract, deposit::{parse_hex32, hash_bytes_to_field}, verifier::{Verifier, MockVerifier}, events};

#[near]
impl Contract {
    pub fn transfer(
        &mut self,
        merkle_root: String,
        nullifiers: [String; 2],
        commitments: [String; 2],
        auditor_pubkey: String,
        recipient_auditor_pubkey: String,
        view_cts: [String; 2],
        note_cts: [String; 2],
        proof: Vec<u8>,
    ) {
        let root = parse_hex32(&merkle_root).expect("bad root hex");
        assert!(self.recent_roots.contains(&root), "stale root");

        let n0 = parse_hex32(&nullifiers[0]).expect("bad n0");
        let n1 = parse_hex32(&nullifiers[1]).expect("bad n1");
        assert!(!self.nullifiers.contains(&n0), "double spend");
        assert!(!self.nullifiers.contains(&n1), "double spend");
        assert_ne!(n0, n1, "nullifiers must differ");

        let c0 = parse_hex32(&commitments[0]).expect("bad c0");
        let c1 = parse_hex32(&commitments[1]).expect("bad c1");
        let ap = parse_hex32(&auditor_pubkey).expect("bad ap");
        let rap = parse_hex32(&recipient_auditor_pubkey).expect("bad rap");

        let pi = vec![
            root,
            n0, n1,
            c0, c1,
            ap, rap,
            hash_bytes_to_field(view_cts[0].as_bytes()),
            hash_bytes_to_field(view_cts[1].as_bytes()),
        ];
        let verifier = MockVerifier::default();
        assert!(verifier.verify(&proof, &pi), "invalid proof");

        self.nullifiers.insert(n0);
        self.nullifiers.insert(n1);
        let li0 = self.tree.insert(c0);
        let li1 = self.tree.insert(c1);
        self.recent_roots.push(self.tree.root());

        events::emit_transfer(
            &merkle_root,
            [&nullifiers[0], &nullifiers[1]],
            [&commitments[0], &commitments[1]],
            [li0, li1],
            [&view_cts[0], &view_cts[1]],
            [&note_cts[0], &note_cts[1]],
        );
    }
}
```

Make `parse_hex32` and `hash_bytes_to_field` `pub(crate)` in `deposit.rs`.

- [ ] **Step 4: Run, expect pass**

Run: `cargo test -p shielded-pool transfer::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add contract/src/transfer.rs contract/src/deposit.rs
git commit -m "feat(contract): transfer method with root/nullifier checks"
```

### Task 11: Withdraw method (with relayer split)

**Files:**
- Modify: `contract/src/withdraw.rs`

Same TDD shape as Task 10. Public inputs include `recipient`, `amount`, `relayer`, `relayer_fee`. Tests cover: valid proof marks nullifier spent and emits event; relayer-fee greater than amount panics; double-spend rejected.

- [ ] **Step 1: Write failing tests**

```rust
// contract/src/withdraw.rs
#[cfg(test)]
mod tests {
    use crate::Contract;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn setup() -> Contract {
        testing_env!(VMContextBuilder::new().build());
        Contract::new(
            "owner.near".parse().unwrap(),
            "usdc.near".parse().unwrap(),
            vec![1,2,3], vec![1,2,3], vec![1,2,3],
        )
    }

    #[test]
    fn withdraw_with_valid_mock_proof_marks_spent() {
        let mut c = setup();
        c.recent_roots.push(crate::poseidon::Field::from_u64(7));
        let root = "0x".to_string() + &"00".repeat(31) + "07";
        c.withdraw(
            root,
            "0xab".repeat(32),
            "bob.near".parse().unwrap(),
            100_000_000u128.into(),
            "0xcd".repeat(32),
            "viewct".into(),
            "relayer.near".parse().unwrap(),
            500_000u128.into(),
            vec![1,2,3],
        );
        let n = crate::poseidon::Field::from_be_bytes(&[0xab; 32]);
        assert!(c.nullifiers.contains(&n));
    }

    #[test]
    #[should_panic(expected = "fee exceeds amount")]
    fn withdraw_fee_too_high_rejects() {
        let mut c = setup();
        c.recent_roots.push(crate::poseidon::Field::from_u64(7));
        let root = "0x".to_string() + &"00".repeat(31) + "07";
        c.withdraw(
            root,
            "0xab".repeat(32),
            "bob.near".parse().unwrap(),
            100u128.into(),
            "0xcd".repeat(32),
            "viewct".into(),
            "relayer.near".parse().unwrap(),
            200u128.into(),
            vec![1,2,3],
        );
    }
}
```

- [ ] **Step 2: Run, expect fail**

Run: `cargo test -p shielded-pool withdraw::tests`
Expected: FAIL.

- [ ] **Step 3: Implement withdraw**

```rust
// contract/src/withdraw.rs
use near_sdk::{near, AccountId, json_types::U128};
use crate::{Contract, deposit::{parse_hex32, hash_bytes_to_field}, verifier::{Verifier, MockVerifier}, events, poseidon::Field};

#[near]
impl Contract {
    pub fn withdraw(
        &mut self,
        merkle_root: String,
        nullifier: String,
        recipient: AccountId,
        amount: U128,
        auditor_pubkey: String,
        view_ct: String,
        relayer: AccountId,
        relayer_fee: U128,
        proof: Vec<u8>,
    ) {
        assert!(relayer_fee.0 <= amount.0, "fee exceeds amount");

        let root = parse_hex32(&merkle_root).expect("bad root hex");
        assert!(self.recent_roots.contains(&root), "stale root");

        let n = parse_hex32(&nullifier).expect("bad nullifier hex");
        assert!(!self.nullifiers.contains(&n), "double spend");

        let ap = parse_hex32(&auditor_pubkey).expect("bad ap");

        let pi = vec![
            root,
            n,
            hash_bytes_to_field(recipient.as_bytes()),
            Field::from_u128(amount.0),
            hash_bytes_to_field(relayer.as_bytes()),
            Field::from_u128(relayer_fee.0),
            ap,
            hash_bytes_to_field(view_ct.as_bytes()),
        ];
        assert!(MockVerifier::default().verify(&proof, &pi), "invalid proof");

        self.nullifiers.insert(n);
        events::emit_withdraw(
            &nullifier, recipient.as_str(), amount.0, relayer.as_str(), relayer_fee.0, &view_ct,
        );

        // Real implementation transfers (amount - fee) to recipient and fee to relayer
        // via the USDC FT contract — deferred to Task 12.
    }
}
```

- [ ] **Step 4: Run, expect pass**

Run: `cargo test -p shielded-pool withdraw::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add contract/src/withdraw.rs
git commit -m "feat(contract): withdraw method with relayer fee split"
```

### Task 12: USDC FT integration

**Files:**
- Modify: `contract/src/ft.rs`
- Modify: `contract/src/deposit.rs` (call `ft_transfer_call` flow)
- Modify: `contract/src/withdraw.rs` (call `ft_transfer` for payouts)

Deposit uses NEP-141 `ft_on_transfer` (the *user* calls USDC's `ft_transfer_call` targeting the pool with `msg = deposit_payload`). The pool implements `ft_on_transfer` to parse the payload and run the deposit logic. Withdraw uses `ft_transfer` cross-contract calls to recipient and relayer.

Sub-steps (write each as its own checkbox in execution):
- [ ] **Step 1:** Define `DepositMsg` struct (commitment, amount, auditor_pubkey, view_ct, note_ct, proof) — JSON serializable.
- [ ] **Step 2:** Implement `ft_on_transfer` on Contract; assert predecessor == `usdc_token`; parse msg; run deposit logic; return zero unused tokens.
- [ ] **Step 3:** Refactor `deposit` method body into private `do_deposit(&mut self, msg: DepositMsg)`; called both by `ft_on_transfer` and by unit tests.
- [ ] **Step 4:** In `withdraw`, after marking nullifier spent, issue two `Promise::new(self.usdc_token.clone()).function_call("ft_transfer", ...)` — one to recipient, one to relayer.
- [ ] **Step 5:** Write integration test (uses `near-workspaces`) that deploys the pool + a stub FT, has Alice deposit, Bob withdraw, asserts FT balances.

(Each sub-step gets its own TDD cycle. Total: ~8 commits.)

---

## Phase 4 — TypeScript SDK foundation

### Task 13: pnpm workspace + core package skeleton

**Files:**
- Create: `sdk/packages/core/package.json`
- Create: `sdk/packages/core/tsconfig.json`
- Create: `sdk/packages/core/src/index.ts`
- Create: `sdk/packages/core/src/index.test.ts`

- [ ] **Step 1: Initialize core package**

```json
// sdk/packages/core/package.json
{
  "name": "@shielded-near/core",
  "version": "0.1.0",
  "type": "module",
  "main": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "scripts": {
    "build": "tsc",
    "test": "vitest run"
  },
  "dependencies": {
    "@noble/curves": "^1.6.0",
    "@noble/ciphers": "^1.0.0",
    "@noble/hashes": "^1.5.0"
  },
  "devDependencies": {
    "typescript": "^5.5.0",
    "vitest": "^2.1.0",
    "@types/node": "^22.0.0"
  }
}
```

```json
// sdk/packages/core/tsconfig.json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "declaration": true,
    "outDir": "dist"
  },
  "include": ["src"]
}
```

- [ ] **Step 2: Failing smoke test**

```ts
// sdk/packages/core/src/index.test.ts
import { describe, it, expect } from "vitest";
import { VERSION } from "./index";

describe("core", () => {
  it("exposes a version constant", () => {
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
```

```ts
// sdk/packages/core/src/index.ts
export const VERSION = "0.1.0";
```

Run: `cd sdk/packages/core && pnpm install && pnpm test`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add sdk/
git commit -m "feat(sdk): core package skeleton with vitest"
```

### Task 14: Field type and Poseidon (TypeScript)

Mirror Rust Field/poseidon. Use `circomlibjs` or hand-rolled poseidon-bn254 from `@noble/curves` field ops. Critical: must match Rust output bit-for-bit on a shared test vector.

**Files:**
- Create: `sdk/packages/core/src/field.ts`
- Create: `sdk/packages/core/src/poseidon.ts`
- Create: `sdk/packages/core/src/poseidon.test.ts`
- Create: `sdk/test-vectors/poseidon.json`

- [ ] **Step 1:** Add `circomlibjs` to core deps.
- [ ] **Step 2:** Write `poseidon.test.ts` consuming `test-vectors/poseidon.json` — three vectors covering poseidon2 and poseidon4.
- [ ] **Step 3:** Implement `Field` (256-bit, BN254 modular reduction) and `poseidon2`, `poseidon4`.
- [ ] **Step 4:** Run vitest, all green.
- [ ] **Step 5:** Add a *Rust* test in `contract/tests/cross_lang_poseidon.rs` that loads the same JSON and asserts byte equality.
- [ ] **Step 6:** Commit `feat(sdk): Field + Poseidon matching Rust contract`.

### Task 15: Hybrid X25519 + ChaCha20-Poly1305 encryption

Mirrors what circuits will enforce. Test vectors shared with circuit-side test fixtures.

**Files:**
- Create: `sdk/packages/core/src/encrypt.ts`
- Create: `sdk/packages/core/src/encrypt.test.ts`

- [ ] **Step 1:** Define payload struct `{ action, sender, recipient, amount, memo, timestamp }`.
- [ ] **Step 2:** Failing test: encrypt-then-decrypt roundtrip; wrong key fails; tamper detection.
- [ ] **Step 3:** Implement using `@noble/curves/ed25519` (x25519) + `@noble/ciphers/chacha`.
- [ ] **Step 4:** Run tests, green.
- [ ] **Step 5:** Commit.

### Task 16: Note model + keys

- [ ] **Step 1:** Define `Note { amount, ownerPubkey, auditorPubkey, blinding }` TS type.
- [ ] **Step 2:** Failing test: `commitNote(note)` matches a known vector (cross-check Rust).
- [ ] **Step 3:** Implement using `poseidon4`.
- [ ] **Step 4:** Test `deriveSpendingKey(seed)`, `deriveViewingKey(seed)`, `ownerPubkeyFrom(sk)`.
- [ ] **Step 5:** Test `computeNullifier(sk, commitment, leafIndex)` matches known vector.
- [ ] **Step 6:** Commit.

### Task 17: Note scanner

- [ ] **Step 1:** Failing test: given a viewing key and a list of `note_ct`s with one addressed to that vk, returns exactly that note.
- [ ] **Step 2:** Implement trial-decrypt loop.
- [ ] **Step 3:** Test idempotency across re-scans.
- [ ] **Step 4:** Commit.

---

## Phase 5 — Noir circuits

### Task 18: Repository scaffolding for Noir

**Files:**
- Create: `circuits/shared/Nargo.toml`
- Create: `circuits/shared/src/lib.nr`
- Create: `circuits/deposit/Nargo.toml`
- Create: `circuits/deposit/src/main.nr`
- Create: `circuits/transfer/Nargo.toml`
- Create: `circuits/transfer/src/main.nr`
- Create: `circuits/withdraw/Nargo.toml`
- Create: `circuits/withdraw/src/main.nr`

- [ ] **Step 1:** Add a `noirup`/`nargo` install note to README; pin Noir version in each `Nargo.toml` (`compiler_version = ">=0.40"`).
- [ ] **Step 2:** Implement `shared/src/lib.nr` with `Note`, `commit_note(note)`, `nullifier_of(sk, commitment, leaf_index)`, encryption helpers.
- [ ] **Step 3:** `nargo check` in each package — passes.
- [ ] **Step 4:** Commit.

### Task 19: `deposit.nr`

Public inputs: `commitment, amount, auditor_pubkey, view_ct_hash`. Witness: `note, view_ct_ephemeral_sk`.

- [ ] **Step 1:** Write circuit body asserting `commitment == commit_note(note)` and `note.amount == amount` and `note.auditor_pubkey == auditor_pubkey` and `view_ct_hash == hash_encrypt(note, auditor_pubkey, ephemeral_sk)`.
- [ ] **Step 2:** Add `#[test]` cases proving honest witness; assert dishonest witness fails (e.g., wrong amount).
- [ ] **Step 3:** `nargo test`.
- [ ] **Step 4:** Generate verifier key (`nargo compile && nargo write_vk`); commit VK to `contract/src/vk/deposit.vk` (binary asset).
- [ ] **Step 5:** Commit.

### Task 20: `transfer.nr`

Constraints per spec Section 3. 2-in/2-out. Auditor binding on both inputs and outputs.

- [ ] **Step 1:** Implement.
- [ ] **Step 2:** Tests: value-conservation, double-spend prevention by sk binding, auditor laundering rejected, recipient-auditor binding on outputs.
- [ ] **Step 3:** `nargo test`.
- [ ] **Step 4:** Generate VK, commit.
- [ ] **Step 5:** Commit code + VK.

### Task 21: `withdraw.nr`

Whole-note withdraw. Public inputs include `recipient`, `amount`, `relayer`, `relayer_fee`.

- [ ] **Step 1:** Implement.
- [ ] **Step 2:** Tests: honest withdrawal proves; wrong-amount fails; wrong-relayer fails.
- [ ] **Step 3:** `nargo test`.
- [ ] **Step 4:** Generate VK, commit.
- [ ] **Step 5:** Commit.

### Task 22: Real verifier integration in contract

Compile barretenberg's verifier to a WASM blob deployable inside the NEAR contract. Aztec ships `bb_wasm` which can verify Honk/UltraPlonk proofs.

- [ ] **Step 1:** Add Cargo feature `bb-verifier`; pull in `barretenberg-wasm` (or bind to the C++ verifier via WAVM-compatible bindings — research during task).
- [ ] **Step 2:** Implement `BbVerifier::verify` parsing VK from the contract's stored bytes, parsing the proof, calling the verifier function.
- [ ] **Step 3:** Replace `MockVerifier::default()` in `deposit/transfer/withdraw` with a dispatch on a `Verifier` trait object resolved per-method from the contract's stored VKs.
- [ ] **Step 4:** Integration test (`near-workspaces`) that proves and verifies one real deposit.
- [ ] **Step 5:** Measure gas; document in README.
- [ ] **Step 6:** Commit.

---

## Phase 6 — High-level SDK + relayer + auditor

### Task 23: `@shielded-near/sdk` — Wallet API

- [ ] **Step 1:** Test: `Wallet.from(seed).deposit({ amount, auditorPubkey })` produces a NEAR tx + proof.
- [ ] **Step 2:** Implement using core primitives + Noir prover bridge (`bb.js` WASM).
- [ ] **Step 3:** Tests for `transfer`, `withdraw` happy paths.
- [ ] **Step 4:** Commit.

### Task 24: `@shielded-near/relayer` — HTTP service

- [ ] **Step 1:** Express/Fastify server with `GET /quote`, `POST /submit`.
- [ ] **Step 2:** Test: given a valid proof matching the quote, submits; tampered proof rejected on-chain.
- [ ] **Step 3:** Dockerfile + README run instructions.
- [ ] **Step 4:** Commit.

### Task 25: `@shielded-near/auditor` — indexer + SDK + CLI

- [ ] **Step 1:** Indexer that polls NEAR logs, trial-decrypts `view_ct`s, writes to SQLite (use `better-sqlite3`).
- [ ] **Step 2:** Query API: `getTransactionsForUser(ownerPubkey)`, `getAllTransactions()`, `verifyDisclosure(view_ct, expected)`.
- [ ] **Step 3:** CLI commands: `auditor scan`, `auditor query --user <pubkey>`, `auditor verify <view_ct> --expect <json>`.
- [ ] **Step 4:** Integration test against local sandbox + contract.
- [ ] **Step 5:** Commit.

### Task 26: `@shielded-near/cli` — interactive end-user CLI

- [ ] **Step 1:** Commands: `init`, `deposit`, `transfer`, `withdraw`, `balance`, `scan`.
- [ ] **Step 2:** Snapshot tests on rendered output.
- [ ] **Step 3:** End-to-end test: `cli deposit && cli transfer && cli withdraw` against sandbox.
- [ ] **Step 4:** Commit.

---

## Phase 7 — End-to-end integration

### Task 27: Canonical end-to-end test

The headline test from the spec: "Alice deposits 100, transfers 60 to Bob, Bob withdraws 60 to a fresh address, each auditor sees only their user's side."

- [ ] **Step 1:** Standup script that boots `near-sandbox`, deploys USDC stub + pool, funds Alice.
- [ ] **Step 2:** Test driver in TypeScript drives the SDK through the full sequence.
- [ ] **Step 3:** Auditor A and Auditor B indexers verify their views.
- [ ] **Step 4:** Asserts: final balances correct, both auditors see only their user's actions, no on-chain link between Alice's deposit and Bob's withdrawal beyond what's mediated by view ciphertexts.
- [ ] **Step 5:** Commit.

### Task 28: CI

- [ ] **Step 1:** GitHub Actions workflow: `cargo test`, `pnpm -r test`, `nargo test`.
- [ ] **Step 2:** Cache `target/`, `node_modules/`, `.aztec/`.
- [ ] **Step 3:** Performance assertion job (proving time + gas) gated to manual trigger.
- [ ] **Step 4:** Commit.

### Task 29: README, docs, demo script

- [ ] **Step 1:** Top-level README with architecture diagram, install steps, quickstart.
- [ ] **Step 2:** `docs/auditor-onboarding.md` walking through auditor setup.
- [ ] **Step 3:** `docs/relayer-operator.md` walking through running a relayer.
- [ ] **Step 4:** Demo script (`scripts/demo.sh`) running the canonical e2e against a fresh sandbox.
- [ ] **Step 5:** Commit.

---

## Out of scope (do not implement in v0)

Mirror the spec's non-goals. Reject scope creep.
