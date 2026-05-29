pragma circom 2.1.6;
include "circomlib/circuits/poseidon.circom";

// commit_note = Poseidon([amount, ownerPubkey, auditorPubkey, blinding])
template CommitNote() {
  signal input amount; signal input ownerPubkey; signal input auditorPubkey; signal input blinding;
  signal output out;
  component h = Poseidon(4);
  h.inputs[0] <== amount; h.inputs[1] <== ownerPubkey; h.inputs[2] <== auditorPubkey; h.inputs[3] <== blinding;
  out <== h.out;
}
// owner_pubkey = Poseidon([spendingKey, 0])
template OwnerPubkey() {
  signal input spendingKey; signal output out;
  component h = Poseidon(2); h.inputs[0] <== spendingKey; h.inputs[1] <== 0; out <== h.out;
}
// nullifier = Poseidon([spendingKey, Poseidon([commitment, leafIndex])])
template Nullifier() {
  signal input spendingKey; signal input commitment; signal input leafIndex; signal output out;
  component inner = Poseidon(2); inner.inputs[0] <== commitment; inner.inputs[1] <== leafIndex;
  component outer = Poseidon(2); outer.inputs[0] <== spendingKey; outer.inputs[1] <== inner.out;
  out <== outer.out;
}
