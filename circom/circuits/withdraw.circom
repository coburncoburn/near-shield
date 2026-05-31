pragma circom 2.1.6;
include "lib/commit.circom";
include "lib/merkle.circom";
include "lib/range.circom";
include "circomlib/circuits/bitify.circom";

// Single-note whole-amount withdraw.
// Public inputs (contract order, 8): merkleRoot, nullifier, recipient, amount,
//   relayer, relayerFee, auditorPubkey, viewCtHash.
// recipient & relayer are bound into the proof via squared signals so a relayer
// cannot tamper with them; relayerFee is already bound by the amount>=relayerFee check.
template Withdraw(DEPTH) {
  // public (contract order, 8):
  signal input merkleRoot; signal input nullifier; signal input recipient; signal input amount;
  signal input relayer; signal input relayerFee; signal input auditorPubkey; signal input viewCtHash;
  // private:
  signal input noteAmount; signal input noteOwner; signal input noteAuditor; signal input noteBlinding;
  signal input spendingKey; signal input leafIndex; signal input merklePath[DEPTH]; signal input viewCtHashWitness;

  component c = CommitNote(); c.amount <== noteAmount; c.ownerPubkey <== noteOwner; c.auditorPubkey <== noteAuditor; c.blinding <== noteBlinding;
  component own = OwnerPubkey(); own.spendingKey <== spendingKey; own.out === noteOwner;
  component nf = Nullifier(); nf.spendingKey <== spendingKey; nf.commitment <== c.out; nf.leafIndex <== leafIndex; nf.out === nullifier;

  noteAmount === amount;
  noteAuditor === auditorPubkey;

  component geq = U64Geq(); geq.a <== amount; geq.b <== relayerFee;

  viewCtHash === viewCtHashWitness;

  component idx = Num2Bits(DEPTH); idx.in <== leafIndex;
  component m = MerkleInclusion(DEPTH); m.leaf <== c.out; m.root <== merkleRoot; m.indexBits <== idx.out; m.pathElements <== merklePath;

  // Bind recipient & relayer into the proof (NOT relayerFee — already bound by U64Geq).
  signal recipientSq <== recipient * recipient;
  signal relayerSq <== relayer * relayer;
}
component main { public [merkleRoot, nullifier, recipient, amount, relayer, relayerFee, auditorPubkey, viewCtHash] } = Withdraw(20);
