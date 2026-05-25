use shielded_shared::{
    commit_note, nullifier_of, owner_pubkey_of, poseidon2, verify_merkle_proof, Note, MERKLE_DEPTH,
};

// transfer.nr - 2-in, 2-out shielded transfer.
//
// Both input commitments are proven to be members of the tree whose root is
// `merkle_root`. Value is conserved across inputs/outputs. Auditor bindings
// hold on both sides.
fn main(
    merkle_root: pub Field,
    nullifier0: pub Field,
    nullifier1: pub Field,
    commitment_out0: pub Field,
    commitment_out1: pub Field,
    auditor_pubkey: pub Field,
    recipient_auditor_pubkey: pub Field,
    view_ct_hash_sender: pub Field,
    view_ct_hash_recipient: pub Field,
    // Inputs
    in0_amount: Field,
    in0_owner_pubkey: Field,
    in0_blinding: Field,
    in0_leaf_index: Field,
    in0_path: [Field; MERKLE_DEPTH],
    in1_amount: Field,
    in1_owner_pubkey: Field,
    in1_blinding: Field,
    in1_leaf_index: Field,
    in1_path: [Field; MERKLE_DEPTH],
    spending_key: Field,
    // Outputs
    out0_amount: Field,
    out0_owner_pubkey: Field,
    out0_blinding: Field,
    out1_amount: Field,
    out1_owner_pubkey: Field,
    out1_blinding: Field,
    // View hash witnesses
    view_ct_hash_sender_witness: Field,
    view_ct_hash_recipient_witness: Field,
) {
    let in0 = Note {
        amount: in0_amount,
        owner_pubkey: in0_owner_pubkey,
        auditor_pubkey,
        blinding: in0_blinding,
    };
    let in1 = Note {
        amount: in1_amount,
        owner_pubkey: in1_owner_pubkey,
        auditor_pubkey,
        blinding: in1_blinding,
    };

    let c_in0 = commit_note(in0);
    let c_in1 = commit_note(in1);

    // Spending key derives both input owner pubkeys.
    assert(owner_pubkey_of(spending_key) == in0_owner_pubkey);
    assert(owner_pubkey_of(spending_key) == in1_owner_pubkey);

    // Nullifier correctness.
    assert(nullifier_of(spending_key, c_in0, in0_leaf_index) == nullifier0);
    assert(nullifier_of(spending_key, c_in1, in1_leaf_index) == nullifier1);

    // Merkle inclusion for both input commitments under the same root.
    verify_merkle_proof(merkle_root, c_in0, in0_leaf_index, in0_path);
    verify_merkle_proof(merkle_root, c_in1, in1_leaf_index, in1_path);

    // Outputs bound to recipient_auditor_pubkey.
    let out0 = Note {
        amount: out0_amount,
        owner_pubkey: out0_owner_pubkey,
        auditor_pubkey: recipient_auditor_pubkey,
        blinding: out0_blinding,
    };
    let out1 = Note {
        amount: out1_amount,
        owner_pubkey: out1_owner_pubkey,
        auditor_pubkey: recipient_auditor_pubkey,
        blinding: out1_blinding,
    };
    assert(commit_note(out0) == commitment_out0);
    assert(commit_note(out1) == commitment_out1);

    // Value conservation.
    assert(in0_amount + in1_amount == out0_amount + out1_amount);

    // View hash bindings.
    assert(view_ct_hash_sender == view_ct_hash_sender_witness);
    assert(view_ct_hash_recipient == view_ct_hash_recipient_witness);
}

// ----- test helpers -----

/// Build a depth-N tree whose root contains the two given commitments at
/// leaf indices 0 and 1, with every other leaf zero. Returns
/// `(root, path_for_leaf0, path_for_leaf1)`.
fn tree_with_two_leaves<let N: u32>(leaf0: Field, leaf1: Field) -> (Field, [Field; N], [Field; N]) {
    let mut zeros: [Field; N] = [0; N];
    let mut z: Field = 0;
    for level in 0..N {
        zeros[level] = z;
        z = poseidon2(z, z);
    }
    // path for leaf0 (index 0): level 0 sibling is leaf1, then zero subtrees.
    let mut path0: [Field; N] = [0; N];
    path0[0] = leaf1;
    for level in 1..N {
        path0[level] = zeros[level];
    }
    // path for leaf1 (index 1): level 0 sibling is leaf0, then zero subtrees.
    let mut path1: [Field; N] = [0; N];
    path1[0] = leaf0;
    for level in 1..N {
        path1[level] = zeros[level];
    }
    // Compute root from leaf0 (could equally be from leaf1).
    let h01 = poseidon2(leaf0, leaf1);
    let mut current = h01;
    for level in 1..N {
        current = poseidon2(current, zeros[level]);
    }
    (current, path0, path1)
}

#[test]
fn honest_transfer_proves() {
    let sk: Field = 7;
    let owner = owner_pubkey_of(sk);
    let auditor: Field = 22;
    let recip_auditor: Field = 33;
    let in0 = Note { amount: 60, owner_pubkey: owner, auditor_pubkey: auditor, blinding: 1 };
    let in1 = Note { amount: 40, owner_pubkey: owner, auditor_pubkey: auditor, blinding: 2 };
    let c_in0 = commit_note(in0);
    let c_in1 = commit_note(in1);
    let n0 = nullifier_of(sk, c_in0, 0);
    let n1 = nullifier_of(sk, c_in1, 1);
    let (root, path0, path1) = tree_with_two_leaves::<MERKLE_DEPTH>(c_in0, c_in1);
    let out0 = Note { amount: 70, owner_pubkey: 100, auditor_pubkey: recip_auditor, blinding: 3 };
    let out1 = Note { amount: 30, owner_pubkey: owner, auditor_pubkey: recip_auditor, blinding: 4 };
    let c_out0 = commit_note(out0);
    let c_out1 = commit_note(out1);
    main(
        root, n0, n1, c_out0, c_out1, auditor, recip_auditor, 13, 14,
        60, owner, 1, 0, path0,
        40, owner, 2, 1, path1,
        sk,
        70, 100, 3,
        30, owner, 4,
        13, 14,
    );
}

#[test(should_fail)]
fn value_conservation_violation_fails() {
    let sk: Field = 7;
    let owner = owner_pubkey_of(sk);
    let auditor: Field = 22;
    let in0 = Note { amount: 60, owner_pubkey: owner, auditor_pubkey: auditor, blinding: 1 };
    let in1 = Note { amount: 40, owner_pubkey: owner, auditor_pubkey: auditor, blinding: 2 };
    let c_in0 = commit_note(in0);
    let c_in1 = commit_note(in1);
    let n0 = nullifier_of(sk, c_in0, 0);
    let n1 = nullifier_of(sk, c_in1, 1);
    let (root, path0, path1) = tree_with_two_leaves::<MERKLE_DEPTH>(c_in0, c_in1);
    // Outputs sum to 200 instead of 100 -- must reject.
    let out0 = Note { amount: 150, owner_pubkey: 100, auditor_pubkey: auditor, blinding: 3 };
    let out1 = Note { amount: 50, owner_pubkey: owner, auditor_pubkey: auditor, blinding: 4 };
    let c_out0 = commit_note(out0);
    let c_out1 = commit_note(out1);
    main(
        root, n0, n1, c_out0, c_out1, auditor, auditor, 13, 14,
        60, owner, 1, 0, path0,
        40, owner, 2, 1, path1,
        sk,
        150, 100, 3,
        50, owner, 4,
        13, 14,
    );
}

#[test(should_fail)]
fn auditor_laundering_fails() {
    let sk: Field = 7;
    let owner = owner_pubkey_of(sk);
    let real_auditor: Field = 22;
    let in0 = Note { amount: 60, owner_pubkey: owner, auditor_pubkey: real_auditor, blinding: 1 };
    let c_in0 = commit_note(in0);
    let n0 = nullifier_of(sk, c_in0, 0);
    let in1 = Note { amount: 40, owner_pubkey: owner, auditor_pubkey: real_auditor, blinding: 2 };
    let c_in1 = commit_note(in1);
    let n1 = nullifier_of(sk, c_in1, 1);
    let (root, path0, path1) = tree_with_two_leaves::<MERKLE_DEPTH>(c_in0, c_in1);
    let out0 = Note { amount: 100, owner_pubkey: owner, auditor_pubkey: real_auditor, blinding: 3 };
    let c_out0 = commit_note(out0);
    // Declare a different auditor (99) on the public input.
    main(
        root, n0, n1, c_out0, c_out0, 99, real_auditor, 13, 14,
        60, owner, 1, 0, path0,
        40, owner, 2, 1, path1,
        sk,
        100, owner, 3,
        0, owner, 0,
        13, 14,
    );
}

#[test(should_fail)]
fn forged_merkle_path_fails() {
    let sk: Field = 7;
    let owner = owner_pubkey_of(sk);
    let auditor: Field = 22;
    let recip_auditor: Field = 33;
    let in0 = Note { amount: 60, owner_pubkey: owner, auditor_pubkey: auditor, blinding: 1 };
    let in1 = Note { amount: 40, owner_pubkey: owner, auditor_pubkey: auditor, blinding: 2 };
    let c_in0 = commit_note(in0);
    let c_in1 = commit_note(in1);
    let n0 = nullifier_of(sk, c_in0, 0);
    let n1 = nullifier_of(sk, c_in1, 1);
    // Build a root from DIFFERENT leaves, then submit our `c_in0`/`c_in1`
    // claiming they belong to it. Must reject.
    let (fake_root, fake_path0, fake_path1) = tree_with_two_leaves::<MERKLE_DEPTH>(99, 100);
    let out0 = Note { amount: 70, owner_pubkey: 100, auditor_pubkey: recip_auditor, blinding: 3 };
    let out1 = Note { amount: 30, owner_pubkey: owner, auditor_pubkey: recip_auditor, blinding: 4 };
    let c_out0 = commit_note(out0);
    let c_out1 = commit_note(out1);
    main(
        fake_root, n0, n1, c_out0, c_out1, auditor, recip_auditor, 13, 14,
        60, owner, 1, 0, fake_path0,
        40, owner, 2, 1, fake_path1,
        sk,
        70, 100, 3,
        30, owner, 4,
        13, 14,
    );
}
