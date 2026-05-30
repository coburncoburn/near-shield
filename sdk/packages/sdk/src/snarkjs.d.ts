// snarkjs 0.7.x ships no first-class TypeScript types.
// This minimal ambient declaration silences tsc; typed wrappers are in
// groth16-adapter.ts and snarkjs-prover.ts.
declare module "snarkjs";
