use shielded_shared::{
    commit_note, nullifier_of, owner_pubkey_of, verify_merkle_proof, Note, MERKLE_DEPTH,
};

// withdraw.nr - proves a single note is being spent and paid out.
//
// Whole-note withdraw in v0: note.amount must equal the public `amount`.
// v1 can add a change output.
fn main(
    merkle_root: pub Field,
    nullifier: pub Field,
    recipient: pub Field,
    amount: pub Field,
    relayer: pub Field,
    relayer_fee: pub Field,
    auditor_pubkey: pub Field,
    view_ct_hash: pub Field,
    note_amount: Field,
    note_owner_pubkey: Field,
    note_auditor_pubkey: Field,
    note_blinding: Field,
    spending_key: Field,
    leaf_index: Field,
    merkle_path: [Field; MERKLE_DEPTH],
    view_ct_hash_witness: Field,
) {
    // Public inputs always referenced so they aren't optimised out.
    assert(recipient == recipient);
    assert(relayer == relayer);

    let note = Note {
        amount: note_amount,
        owner_pubkey: note_owner_pubkey,
        auditor_pubkey: note_auditor_pubkey,
        blinding: note_blinding,
    };
    let commitment = commit_note(note);

    // Spending key derives the owner pubkey embedded in the note.
    assert(owner_pubkey_of(spending_key) == note.owner_pubkey);

    // Nullifier correctness.
    assert(nullifier_of(spending_key, commitment, leaf_index) == nullifier);

    // Whole-note withdraw.
    assert(note.amount == amount);

    // Auditor binding.
    assert(note.auditor_pubkey == auditor_pubkey);

    // Fee bounded by amount.
    assert(amount as u64 >= relayer_fee as u64);

    // View ciphertext hash binding.
    assert(view_ct_hash == view_ct_hash_witness);

    // Real Merkle inclusion: prove the committed note actually exists in the
    // tree whose root is `merkle_root`. This is the soundness step that
    // distinguishes "the prover knows a valid commitment" from "the prover
    // knows a commitment that was actually deposited."
    verify_merkle_proof(merkle_root, commitment, leaf_index, merkle_path);
}

// ----- test helpers -----

use shielded_shared::poseidon2;

/// Builds a depth-4 path + root for a single leaf at index 0, with the rest of
/// the tree empty (zero leaves). Returns (root, path).
fn empty_path_for_leaf_at_zero<let N: u32>(leaf: Field) -> (Field, [Field; N]) {
    let mut z: Field = 0;
    let mut zeros: [Field; N] = [0; N];
    for level in 0..N {
        zeros[level] = z;
        z = poseidon2(z, z);
    }
    let mut current = leaf;
    for level in 0..N {
        current = poseidon2(current, zeros[level]);
    }
    (current, zeros)
}

#[test]
fn honest_withdrawal_proves() {
    let sk: Field = 7;
    let owner = owner_pubkey_of(sk);
    let auditor: Field = 22;
    let blinding: Field = 33;
    let amount: Field = 100;
    let note = Note { amount, owner_pubkey: owner, auditor_pubkey: auditor, blinding };
    let c = commit_note(note);
    let leaf_index: Field = 0;
    let n = nullifier_of(sk, c, leaf_index);
    let (root, path) = empty_path_for_leaf_at_zero::<MERKLE_DEPTH>(c);
    main(
        root, n, 99, amount, 77, 5, auditor, 13,
        amount, owner, auditor, blinding,
        sk, leaf_index, path, 13,
    );
}

#[test(should_fail)]
fn wrong_spending_key_fails() {
    let real_sk: Field = 7;
    let owner = owner_pubkey_of(real_sk);
    let auditor: Field = 22;
    let blinding: Field = 33;
    let amount: Field = 100;
    let note = Note { amount, owner_pubkey: owner, auditor_pubkey: auditor, blinding };
    let c = commit_note(note);
    let leaf_index: Field = 0;
    let n = nullifier_of(real_sk, c, leaf_index);
    let (root, path) = empty_path_for_leaf_at_zero::<MERKLE_DEPTH>(c);
    let wrong_sk: Field = 8;
    main(
        root, n, 99, amount, 77, 5, auditor, 13,
        amount, owner, auditor, blinding,
        wrong_sk, leaf_index, path, 13,
    );
}

#[test(should_fail)]
fn wrong_amount_fails() {
    let sk: Field = 7;
    let owner = owner_pubkey_of(sk);
    let note = Note { amount: 100, owner_pubkey: owner, auditor_pubkey: 1, blinding: 1 };
    let c = commit_note(note);
    let leaf_index: Field = 0;
    let n = nullifier_of(sk, c, leaf_index);
    let (root, path) = empty_path_for_leaf_at_zero::<MERKLE_DEPTH>(c);
    main(
        root, n, 99, 200, 77, 5, 1, 13,
        100, owner, 1, 1,
        sk, leaf_index, path, 13,
    );
}

#[test(should_fail)]
fn auditor_mismatch_fails() {
    let sk: Field = 7;
    let owner = owner_pubkey_of(sk);
    let note = Note { amount: 100, owner_pubkey: owner, auditor_pubkey: 22, blinding: 1 };
    let c = commit_note(note);
    let leaf_index: Field = 0;
    let n = nullifier_of(sk, c, leaf_index);
    let (root, path) = empty_path_for_leaf_at_zero::<MERKLE_DEPTH>(c);
    main(
        root, n, 99, 100, 77, 5, 99, 13,
        100, owner, 22, 1,
        sk, leaf_index, path, 13,
    );
}

#[test(should_fail)]
fn forged_merkle_path_fails() {
    // The honest commitment is `c`, but we pass an unrelated commitment's
    // path. The Merkle check must reject this.
    let sk: Field = 7;
    let owner = owner_pubkey_of(sk);
    let note = Note { amount: 100, owner_pubkey: owner, auditor_pubkey: 22, blinding: 1 };
    let c = commit_note(note);
    let leaf_index: Field = 0;
    let n = nullifier_of(sk, c, leaf_index);
    // Build a path/root for a DIFFERENT leaf, then claim our `c` is in it.
    let fake_leaf: Field = 999;
    let (fake_root, fake_path) = empty_path_for_leaf_at_zero::<MERKLE_DEPTH>(fake_leaf);
    main(
        fake_root, n, 99, 100, 77, 5, 22, 13,
        100, owner, 22, 1,
        sk, leaf_index, fake_path, 13,
    );
}
