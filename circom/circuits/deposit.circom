pragma circom 2.1.6;
include "lib/commit.circom";

template Deposit() {
  // public (contract order): commitment, amount, auditorPubkey, viewCtHash
  signal input commitment; signal input amount; signal input auditorPubkey; signal input viewCtHash;
  // private
  signal input ownerPubkey; signal input blinding; signal input viewCtHashWitness;

  component c = CommitNote();
  c.amount <== amount; c.ownerPubkey <== ownerPubkey; c.auditorPubkey <== auditorPubkey; c.blinding <== blinding;
  c.out === commitment;
  viewCtHash === viewCtHashWitness;
}
component main { public [commitment, amount, auditorPubkey, viewCtHash] } = Deposit();
