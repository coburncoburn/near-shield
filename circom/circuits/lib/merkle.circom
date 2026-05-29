pragma circom 2.1.6;
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/switcher.circom";

// Depth-DEPTH inclusion. indexBits are LE bits of leafIndex.
// Switcher: sel==0 -> outL=L,outR=R ; sel==1 -> swapped.
// Matches arkworks: bit==0 keeps current on the left (current=L, sibling=R).
template MerkleInclusion(DEPTH) {
  signal input leaf; signal input root;
  signal input indexBits[DEPTH]; signal input pathElements[DEPTH];
  component sw[DEPTH]; component h[DEPTH];
  signal cur[DEPTH + 1]; cur[0] <== leaf;
  for (var i = 0; i < DEPTH; i++) {
    sw[i] = Switcher();
    sw[i].sel <== indexBits[i]; sw[i].L <== cur[i]; sw[i].R <== pathElements[i];
    h[i] = Poseidon(2); h[i].inputs[0] <== sw[i].outL; h[i].inputs[1] <== sw[i].outR;
    cur[i + 1] <== h[i].out;
  }
  root === cur[DEPTH];
}
