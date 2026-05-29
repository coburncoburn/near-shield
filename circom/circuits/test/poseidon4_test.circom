pragma circom 2.1.6;
include "circomlib/circuits/poseidon.circom";
template P4() { signal input in[4]; signal output out;
  component h = Poseidon(4); for (var i=0;i<4;i++){ h.inputs[i] <== in[i]; } out <== h.out; }
component main = P4();
