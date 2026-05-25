// Shielded pool -- shared circuit primitives.
//
// Hashing is aligned with the Rust contract (`light-poseidon::new_circom`) and
// TypeScript SDK (`poseidon-lite`): BN254 Poseidon with Circom-compatible
// parameters. The helpers are named by arity, not by Poseidon2-the-permutation.

use poseidon::poseidon::bn254;

/// Merkle tree depth. MUST equal `contract::TREE_DEPTH` (currently 20).
/// Changing this requires regenerating verifier keys + reconfiguring the
/// contract. Set lower in development to keep proving times tractable for
/// circuit unit tests.
pub global MERKLE_DEPTH: u32 = 4;

pub struct Note {
    pub amount: Field,
    pub owner_pubkey: Field,
    pub auditor_pubkey: Field,
    pub blinding: Field,
}

pub fn commit_note(note: Note) -> Field {
    poseidon4(
        note.amount,
        note.owner_pubkey,
        note.auditor_pubkey,
        note.blinding,
    )
}

pub fn nullifier_of(spending_key: Field, commitment: Field, leaf_index: Field) -> Field {
    poseidon2(
        spending_key,
        poseidon2(commitment, leaf_index),
    )
}

pub fn owner_pubkey_of(spending_key: Field) -> Field {
    poseidon2(spending_key, 0)
}

pub fn poseidon2(a: Field, b: Field) -> Field {
    bn254::hash_2([a, b])
}

pub fn poseidon4(a: Field, b: Field, c: Field, d: Field) -> Field {
    bn254::hash_4([a, b, c, d])
}

/// Verifies a Merkle inclusion proof: that `leaf` is at `leaf_index` in a tree
/// whose root is `root`. `path` carries the sibling at each level (from leaf
/// to root). At each level, the bit `leaf_index & 1` selects whether the
/// current value is the left (0) or right (1) child.
pub fn verify_merkle_proof<let DEPTH: u32>(
    root: Field,
    leaf: Field,
    leaf_index: Field,
    path: [Field; DEPTH],
) {
    let mut current = leaf;
    let bits = leaf_index.to_le_bits::<DEPTH>();
    for level in 0..DEPTH {
        let sibling = path[level];
        let bit = bits[level];
        // bit == 0: current is left, sibling is right
        // bit == 1: current is right, sibling is left
        let (l, r) = if bit {
            (sibling, current)
        } else {
            (current, sibling)
        };
        current = poseidon2(l, r);
    }
    assert(current == root);
}

#[test]
fn commit_note_is_deterministic() {
    let note = Note { amount: 1, owner_pubkey: 2, auditor_pubkey: 3, blinding: 4 };
    let note2 = Note { amount: 1, owner_pubkey: 2, auditor_pubkey: 3, blinding: 4 };
    assert(commit_note(note) == commit_note(note2));
}

#[test]
fn poseidon2_matches_cross_language_vector() {
    assert(
        poseidon2(1, 2) == 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
    );
}

#[test]
fn poseidon4_matches_cross_language_vector() {
    assert(
        poseidon4(1, 2, 3, 4) == 0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465
    );
}

#[test]
fn commit_note_changes_with_every_field() {
    let base = Note { amount: 1, owner_pubkey: 1, auditor_pubkey: 1, blinding: 1 };
    let c0 = commit_note(base);
    let c_amt = commit_note(Note { amount: 2, owner_pubkey: 1, auditor_pubkey: 1, blinding: 1 });
    let c_own = commit_note(Note { amount: 1, owner_pubkey: 2, auditor_pubkey: 1, blinding: 1 });
    let c_aud = commit_note(Note { amount: 1, owner_pubkey: 1, auditor_pubkey: 2, blinding: 1 });
    let c_bld = commit_note(Note { amount: 1, owner_pubkey: 1, auditor_pubkey: 1, blinding: 2 });
    assert(c_amt != c0);
    assert(c_own != c0);
    assert(c_aud != c0);
    assert(c_bld != c0);
}

#[test]
fn nullifier_is_deterministic() {
    let sk: Field = 99;
    let c: Field = 123;
    let i: Field = 7;
    assert(nullifier_of(sk, c, i) == nullifier_of(sk, c, i));
}

#[test]
fn nullifier_sensitive_to_inputs() {
    assert(nullifier_of(99, 123, 7) != nullifier_of(99, 123, 8));
    assert(nullifier_of(99, 123, 7) != nullifier_of(100, 123, 7));
    assert(nullifier_of(99, 123, 7) != nullifier_of(99, 124, 7));
}

#[test]
fn merkle_proof_verifies_depth_2_leaf_0() {
    // Tree with leaves [10, 20, 30, 40] (only first two real, last two zero
    // doesn't apply here -- this test uses all four). Sibling at level 0 for
    // leaf_index=0 is leaves[1]; sibling at level 1 is hash(leaves[2..4]).
    let l0: Field = 10;
    let l1: Field = 20;
    let l2: Field = 30;
    let l3: Field = 40;
    let h01 = poseidon2(l0, l1);
    let h23 = poseidon2(l2, l3);
    let root = poseidon2(h01, h23);
    let path: [Field; 2] = [l1, h23];
    verify_merkle_proof(root, l0, 0, path);
}

#[test]
fn merkle_proof_verifies_depth_2_leaf_3() {
    let l0: Field = 10;
    let l1: Field = 20;
    let l2: Field = 30;
    let l3: Field = 40;
    let h01 = poseidon2(l0, l1);
    let h23 = poseidon2(l2, l3);
    let root = poseidon2(h01, h23);
    // leaf_index = 3 = 0b11; sibling at level 0 is l2, at level 1 is h01.
    let path: [Field; 2] = [l2, h01];
    verify_merkle_proof(root, l3, 3, path);
}

#[test(should_fail)]
fn merkle_proof_with_wrong_sibling_fails() {
    let l0: Field = 10;
    let l1: Field = 20;
    let l2: Field = 30;
    let l3: Field = 40;
    let h01 = poseidon2(l0, l1);
    let h23 = poseidon2(l2, l3);
    let root = poseidon2(h01, h23);
    let bad_path: [Field; 2] = [l2, h23]; // wrong: level-0 sibling should be l1
    verify_merkle_proof(root, l0, 0, bad_path);
}
