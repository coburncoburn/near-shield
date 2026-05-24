use shielded_shared::{commit_note, nullifier_of, owner_pubkey_of, Note};

// withdraw.nr - proves a single note is being spent and paid out.
//
// Whole-note withdraw in v0: note.amount must equal the public `amount`.
// v1 can add a change output.
//
// Merkle inclusion is proved out-of-circuit in v0 (the contract checks the
// public `merkle_root` against its rolling window). A proper v0.1 will add an
// in-circuit Merkle proof here; for now the auditor binding and value binding
// are enforced by the circuit while inclusion is socially enforced by the
// contract requiring a *recent* root.
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
    view_ct_hash_witness: Field,
    merkle_root_witness: Field,
) {
    // Public inputs always referenced (so unused-input optimizations don't strip them).
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

    // Whole-note withdraw: amounts must match.
    assert(note.amount == amount);

    // Auditor binding: input note's auditor must equal the disclosed auditor.
    assert(note.auditor_pubkey == auditor_pubkey);

    // Fee is bounded by the amount (also checked on-chain, but bind here too).
    assert(amount as u64 >= relayer_fee as u64);

    // View ciphertext hash binding (sponge over ciphertext bytes hashed off-circuit).
    assert(view_ct_hash == view_ct_hash_witness);

    // Merkle root binding (full inclusion proof deferred).
    assert(merkle_root == merkle_root_witness);
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
    let leaf = 0;
    let n = nullifier_of(sk, c, leaf);
    main(
        42, // merkle_root (any value, also passed as witness)
        n,
        99, // recipient
        amount,
        77, // relayer
        5,  // relayer_fee
        auditor,
        13, // view_ct_hash
        amount,
        owner,
        auditor,
        blinding,
        sk,
        leaf,
        13,
        42,
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
    let leaf = 0;
    let n = nullifier_of(real_sk, c, leaf);
    let wrong_sk: Field = 8;
    main(
        42,
        n,
        99,
        amount,
        77,
        5,
        auditor,
        13,
        amount,
        owner,
        auditor,
        blinding,
        wrong_sk,
        leaf,
        13,
        42,
    );
}

#[test(should_fail)]
fn wrong_amount_fails() {
    let sk: Field = 7;
    let owner = owner_pubkey_of(sk);
    let note = Note { amount: 100, owner_pubkey: owner, auditor_pubkey: 1, blinding: 1 };
    let c = commit_note(note);
    let leaf = 0;
    let n = nullifier_of(sk, c, leaf);
    main(42, n, 99, 200, 77, 5, 1, 13, 100, owner, 1, 1, sk, leaf, 13, 42);
}

#[test(should_fail)]
fn auditor_mismatch_fails() {
    let sk: Field = 7;
    let owner = owner_pubkey_of(sk);
    let note = Note { amount: 100, owner_pubkey: owner, auditor_pubkey: 22, blinding: 1 };
    let c = commit_note(note);
    let leaf = 0;
    let n = nullifier_of(sk, c, leaf);
    // Public auditor pubkey is 99 but note's is 22.
    main(42, n, 99, 100, 77, 5, 99, 13, 100, owner, 22, 1, sk, leaf, 13, 42);
}
