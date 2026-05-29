pragma circom 2.1.6;
include "circomlib/circuits/poseidon.circom";
template P2() { signal input a; signal input b; signal output out;
  component h = Poseidon(2); h.inputs[0] <== a; h.inputs[1] <== b; out <== h.out; }
component main = P2();
