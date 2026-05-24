use shielded_shared::{commit_note, nullifier_of, owner_pubkey_of, Note};

// transfer.nr - 2-in, 2-out shielded transfer.
//
// Constraints:
//   - Each input nullifier is correctly derived from sk + input commitment + leaf_index.
//   - Spending key derives each input's owner pubkey.
//   - Output commitments are well-formed.
//   - Value conservation: sum(inputs) == sum(outputs).
//   - Auditor binding on inputs: each input note's auditor matches public auditor_pubkey.
//   - Auditor binding on outputs: each output note's auditor matches public recipient_auditor_pubkey.
//   - Both view_ct hashes are bound to witness.
//
// Merkle inclusion proofs are deferred to v0.1 (same caveat as withdraw.nr).
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
    in1_amount: Field,
    in1_owner_pubkey: Field,
    in1_blinding: Field,
    in1_leaf_index: Field,
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
    merkle_root_witness: Field,
) {
    // Build input notes (both bound to the public auditor_pubkey).
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

    // Merkle root.
    assert(merkle_root == merkle_root_witness);
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
    let out0 = Note { amount: 70, owner_pubkey: 100, auditor_pubkey: recip_auditor, blinding: 3 };
    let out1 = Note { amount: 30, owner_pubkey: owner, auditor_pubkey: recip_auditor, blinding: 4 };
    let c_out0 = commit_note(out0);
    let c_out1 = commit_note(out1);
    main(
        42, n0, n1, c_out0, c_out1, auditor, recip_auditor, 13, 14,
        60, owner, 1, 0,
        40, owner, 2, 1,
        sk,
        70, 100, 3,
        30, owner, 4,
        13, 14, 42,
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
    // Outputs sum to 200 instead of 100 -- must reject.
    let out0 = Note { amount: 150, owner_pubkey: 100, auditor_pubkey: auditor, blinding: 3 };
    let out1 = Note { amount: 50, owner_pubkey: owner, auditor_pubkey: auditor, blinding: 4 };
    let c_out0 = commit_note(out0);
    let c_out1 = commit_note(out1);
    main(
        42, n0, n1, c_out0, c_out1, auditor, auditor, 13, 14,
        60, owner, 1, 0,
        40, owner, 2, 1,
        sk,
        150, 100, 3,
        50, owner, 4,
        13, 14, 42,
    );
}

#[test(should_fail)]
fn auditor_laundering_fails() {
    // Input notes carry auditor 22, but caller declares auditor 99 on the
    // public input. The auditor binding via the in0/in1 Note struct (which
    // reads auditor_pubkey from the public input) means the prover ends up
    // producing a different commitment than expected -- fails the commit check.
    let sk: Field = 7;
    let owner = owner_pubkey_of(sk);
    let real_auditor: Field = 22;
    let in0 = Note { amount: 60, owner_pubkey: owner, auditor_pubkey: real_auditor, blinding: 1 };
    let c_in0 = commit_note(in0);
    let n0 = nullifier_of(sk, c_in0, 0);
    let in1 = Note { amount: 40, owner_pubkey: owner, auditor_pubkey: real_auditor, blinding: 2 };
    let c_in1 = commit_note(in1);
    let n1 = nullifier_of(sk, c_in1, 1);
    let out0 = Note { amount: 100, owner_pubkey: owner, auditor_pubkey: real_auditor, blinding: 3 };
    let c_out0 = commit_note(out0);
    // Declare a different auditor in public input; nullifier check will fail
    // because the prover-side commitment used real_auditor while the in-circuit
    // commitment computation will use the lied auditor (99).
    main(
        42, n0, n1, c_out0, c_out0, 99, real_auditor, 13, 14,
        60, owner, 1, 0,
        40, owner, 2, 1,
        sk,
        100, owner, 3,
        0, owner, 0,
        13, 14, 42,
    );
}
