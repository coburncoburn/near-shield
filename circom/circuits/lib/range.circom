pragma circom 2.1.6;
include "circomlib/circuits/bitify.circom";

// Enforce in < 2^n.
template RangeCheck(n) { signal input in; component bits = Num2Bits(n); bits.in <== in; }

// Enforce a >= b as 64-bit unsigned (mirrors arkworks enforce_u64_geq:
// bound a, b, and a-b to 64 bits).
template U64Geq() {
  signal input a; signal input b;
  component ra = Num2Bits(64); ra.in <== a;
  component rb = Num2Bits(64); rb.in <== b;
  component rd = Num2Bits(64); rd.in <== a - b;
}
