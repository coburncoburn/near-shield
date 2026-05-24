// Shielded pool -- shared circuit primitives.
//
// IMPORTANT: This implementation uses Noir stdlib's Pedersen hash for
// commitments and nullifiers. The Rust contract and TypeScript SDK currently
// use Poseidon2 via light-poseidon (circom params). Aligning the hash function
// across all three layers is a known unfinished task (referenced in the spec's
// "open questions deferred to plan phase" -- the alignment work converges on a
// single Poseidon2 implementation in a follow-up commit). The structure of the
// circuits below is correct; only the specific hash invocation must converge.

pub struct Note {
    pub amount: Field,
    pub owner_pubkey: Field,
    pub auditor_pubkey: Field,
    pub blinding: Field,
}

pub fn commit_note(note: Note) -> Field {
    std::hash::pedersen_hash([
        note.amount,
        note.owner_pubkey,
        note.auditor_pubkey,
        note.blinding,
    ])
}

pub fn nullifier_of(spending_key: Field, commitment: Field, leaf_index: Field) -> Field {
    std::hash::pedersen_hash([
        spending_key,
        std::hash::pedersen_hash([commitment, leaf_index]),
    ])
}

pub fn owner_pubkey_of(spending_key: Field) -> Field {
    std::hash::pedersen_hash([spending_key, 0])
}

#[test]
fn commit_note_is_deterministic() {
    let note = Note { amount: 1, owner_pubkey: 2, auditor_pubkey: 3, blinding: 4 };
    let note2 = Note { amount: 1, owner_pubkey: 2, auditor_pubkey: 3, blinding: 4 };
    assert(commit_note(note) == commit_note(note2));
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
