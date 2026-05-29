// Transfer circuit — 2-in / 2-out shielded transfer for HIP-4.
// Public inputs (9, contract order): merkleRoot, nullifier0, nullifier1,
//   commitmentOut0, commitmentOut1, auditorPubkey, recipientAuditorPubkey,
//   viewCtHashSender, viewCtHashRecipient.
// Auditor split: input notes are committed under auditorPubkey (sender's
//   auditor); output notes are committed under recipientAuditorPubkey.
// Value conservation: in0Amount + in1Amount === out0Amount + out1Amount,
//   with RangeCheck(128) on all four amounts (prevents wraparound-mint).
pragma circom 2.1.6;
include "lib/commit.circom";
include "lib/merkle.circom";
include "lib/range.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

template Transfer(DEPTH) {
  // public (contract order, 9):
  signal input merkleRoot;
  signal input nullifier0; signal input nullifier1;
  signal input commitmentOut0; signal input commitmentOut1;
  signal input auditorPubkey; signal input recipientAuditorPubkey;
  signal input viewCtHashSender; signal input viewCtHashRecipient;
  // private:
  signal input in0Amount; signal input in0Owner; signal input in0Blinding; signal input in0LeafIndex; signal input in0Path[DEPTH];
  signal input in1Amount; signal input in1Owner; signal input in1Blinding; signal input in1LeafIndex; signal input in1Path[DEPTH];
  signal input spendingKey;
  signal input out0Amount; signal input out0Owner; signal input out0Blinding;
  signal input out1Amount; signal input out1Owner; signal input out1Blinding;
  signal input viewCtHashSenderWitness; signal input viewCtHashRecipientWitness;

  component cin0 = CommitNote(); cin0.amount <== in0Amount; cin0.ownerPubkey <== in0Owner; cin0.auditorPubkey <== auditorPubkey; cin0.blinding <== in0Blinding;
  component cin1 = CommitNote(); cin1.amount <== in1Amount; cin1.ownerPubkey <== in1Owner; cin1.auditorPubkey <== auditorPubkey; cin1.blinding <== in1Blinding;

  component own = OwnerPubkey(); own.spendingKey <== spendingKey;
  own.out === in0Owner; own.out === in1Owner;

  component n0 = Nullifier(); n0.spendingKey <== spendingKey; n0.commitment <== cin0.out; n0.leafIndex <== in0LeafIndex; n0.out === nullifier0;
  component n1 = Nullifier(); n1.spendingKey <== spendingKey; n1.commitment <== cin1.out; n1.leafIndex <== in1LeafIndex; n1.out === nullifier1;

  component eqn = IsEqual(); eqn.in[0] <== nullifier0; eqn.in[1] <== nullifier1; eqn.out === 0;

  component idx0 = Num2Bits(DEPTH); idx0.in <== in0LeafIndex;
  component idx1 = Num2Bits(DEPTH); idx1.in <== in1LeafIndex;
  component m0 = MerkleInclusion(DEPTH); m0.leaf <== cin0.out; m0.root <== merkleRoot; m0.indexBits <== idx0.out; m0.pathElements <== in0Path;
  component m1 = MerkleInclusion(DEPTH); m1.leaf <== cin1.out; m1.root <== merkleRoot; m1.indexBits <== idx1.out; m1.pathElements <== in1Path;

  component co0 = CommitNote(); co0.amount <== out0Amount; co0.ownerPubkey <== out0Owner; co0.auditorPubkey <== recipientAuditorPubkey; co0.blinding <== out0Blinding; co0.out === commitmentOut0;
  component co1 = CommitNote(); co1.amount <== out1Amount; co1.ownerPubkey <== out1Owner; co1.auditorPubkey <== recipientAuditorPubkey; co1.blinding <== out1Blinding; co1.out === commitmentOut1;

  component r0 = RangeCheck(128); r0.in <== in0Amount;
  component r1 = RangeCheck(128); r1.in <== in1Amount;
  component r2 = RangeCheck(128); r2.in <== out0Amount;
  component r3 = RangeCheck(128); r3.in <== out1Amount;

  in0Amount + in1Amount === out0Amount + out1Amount;

  viewCtHashSender === viewCtHashSenderWitness;
  viewCtHashRecipient === viewCtHashRecipientWitness;
}
component main { public [merkleRoot, nullifier0, nullifier1, commitmentOut0, commitmentOut1, auditorPubkey, recipientAuditorPubkey, viewCtHashSender, viewCtHashRecipient] } = Transfer(20);
