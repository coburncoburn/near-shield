use shielded_shared::{commit_note, Note};

// deposit.nr - proves a new note commitment is well-formed.
//
// Public inputs (visible on chain):
//   commitment     - the new note's commitment
//   amount         - cleartext deposit amount (deposits are not anonymous in amount)
//   auditor_pubkey - the depositor's chosen auditor
//   view_ct_hash   - hash of the auditor disclosure ciphertext
//
// Witness (private to the prover):
//   note         - full Note (amount, owner_pubkey, auditor_pubkey, blinding)
//   view_ct_hash_witness - the view_ct_hash recomputed inside the circuit
//                           (binds the ciphertext to the witness; in v0 the
//                           sponge over the ciphertext bytes is computed
//                           off-circuit and asserted equal).
fn main(
    commitment: pub Field,
    amount: pub Field,
    auditor_pubkey: pub Field,
    view_ct_hash: pub Field,
    owner_pubkey: Field,
    blinding: Field,
    view_ct_hash_witness: Field,
) {
    let note = Note { amount, owner_pubkey, auditor_pubkey, blinding };
    assert(commit_note(note) == commitment);
    assert(view_ct_hash == view_ct_hash_witness);
}

#[test]
fn honest_witness_proves() {
    let owner = 11;
    let auditor = 22;
    let blinding = 33;
    let amount = 100;
    let note = Note {
        amount,
        owner_pubkey: owner,
        auditor_pubkey: auditor,
        blinding,
    };
    let c = commit_note(note);
    main(c, amount, auditor, 7, owner, blinding, 7);
}

#[test(should_fail)]
fn wrong_amount_in_witness_fails() {
    let note = Note { amount: 100, owner_pubkey: 1, auditor_pubkey: 1, blinding: 1 };
    let c = commit_note(note);
    // Public amount says 100 but witness amount in commitment computation is also 100;
    // dishonest case: claim a different amount in the public input.
    main(c, 200, 1, 7, 1, 1, 7);
}

#[test(should_fail)]
fn wrong_auditor_in_public_input_fails() {
    let note = Note { amount: 100, owner_pubkey: 1, auditor_pubkey: 22, blinding: 1 };
    let c = commit_note(note);
    main(c, 100, 99, 7, 1, 1, 7);
}

#[test(should_fail)]
fn mismatched_view_ct_hash_fails() {
    let note = Note { amount: 100, owner_pubkey: 1, auditor_pubkey: 1, blinding: 1 };
    let c = commit_note(note);
    main(c, 100, 1, 7, 1, 1, 8);
}
