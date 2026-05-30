/**
 * Types and byte-serialisation helpers for snarkjs Groth16 proofs/verification keys.
 *
 * The two conversion functions (`vkJsonToContractBytes`, `snarkjsProofToBytes`) are
 * stubs for now — real encoding logic is introduced in Task 1 of Sub-project B.
 */

/** An affine G1 point: [x, y, z] as decimal strings (projective, z = "1"). */
export type G1 = [string, string, string];

/** An affine G2 point: [[x0,x1],[y0,y1],[z0,z1]] as decimal-string pairs. */
export type G2 = [[string, string], [string, string], [string, string]];

/** snarkjs Groth16 proof, as returned by `groth16.fullProve` / `groth16.prove`. */
export interface SnarkjsProof {
  pi_a: G1;
  pi_b: G2;
  pi_c: G1;
  protocol?: string;
  curve?: string;
}

/** snarkjs verification key, as exported by `snarkjs zkey export verificationKey`. */
export interface SnarkjsVk {
  vk_alpha_1: G1;
  vk_beta_2: G2;
  vk_gamma_2: G2;
  vk_delta_2: G2;
  IC: G1[];
}

/**
 * Encode a snarkjs verification key into the byte format expected by the
 * on-chain groth16 verifier.
 *
 * @throws {Error} Not yet implemented — see Task 1.
 */
export function vkJsonToContractBytes(_vk: SnarkjsVk): Uint8Array {
  throw new Error("not implemented");
}

/**
 * Encode a snarkjs Groth16 proof into the 256-byte wire format consumed by the
 * on-chain verifier (A_g1 || B_g2 || C_g1, EIP-196/197 encoding).
 *
 * @throws {Error} Not yet implemented — see Task 1.
 */
export function snarkjsProofToBytes(_proof: SnarkjsProof): Uint8Array {
  throw new Error("not implemented");
}
