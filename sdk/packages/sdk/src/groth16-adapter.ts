/**
 * Types and byte-serialisation helpers for snarkjs Groth16 proofs/verification keys.
 *
 * Byte layout (EIP-196/197, little-endian field coordinates):
 *   - Field scalar  → 32 bytes LE
 *   - G1 point      → 64 bytes = x_LE(32) ‖ y_LE(32); infinity → 64 zero bytes
 *   - G2 point      → 128 bytes = x.c0(32) ‖ x.c1(32) ‖ y.c0(32) ‖ y.c1(32); infinity → 128 zeros
 *   - Proof         → 256 bytes = A_g1(64) ‖ B_g2(128) ‖ C_g1(64)
 *     NOTE: A is passed un-negated; the on-chain contract negates A itself.
 *   - VK            → alpha_g1(64) ‖ beta_g2(128) ‖ gamma_g2(128) ‖ delta_g2(128) ‖ IC[0..n](64 each)
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
  /** Present in real vk.json exports; unused by the adapter. */
  protocol?: string;
  /** Present in real vk.json exports; unused by the adapter. */
  curve?: string;
  /** Present in real vk.json exports; unused by the adapter. */
  nPublic?: number;
  /** Present in real vk.json exports; unused by the adapter. */
  vk_alphabeta_12?: string[][][];
}

// ──────────────────────────────────────────────────────────────────────────────
// Private encoding helpers
// ──────────────────────────────────────────────────────────────────────────────

const FR = 32; // field element byte length

/** Decode a decimal-string field element into 32 bytes, little-endian. */
function decToLe(dec: string): Uint8Array {
  const v0 = BigInt(dec);
  if (v0 < 0n || v0 >= (1n << 256n))
    throw new RangeError(`decToLe: value out of 32-byte range: ${dec}`);
  let v = v0;
  const out = new Uint8Array(FR);
  for (let i = 0; i < FR; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Encode a snarkjs G1 point to 64 bytes (x_LE ‖ y_LE). Infinity → 64 zeros. */
function encodeG1(p: G1): Uint8Array {
  const o = new Uint8Array(64);
  if (p[2] === "0") return o; // point at infinity
  o.set(decToLe(p[0]), 0);
  o.set(decToLe(p[1]), 32);
  return o;
}

/**
 * Encode a snarkjs G2 point to 128 bytes (x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1). Infinity → 128 zeros.
 *
 * IMPORTANT — Fp2 component order (c0 then c1) is a first-attempt assumption.
 * Its semantic correctness cannot be confirmed until the Task 2 contract
 * `verify_groth16` gate runs against a real proof. If that gate rejects valid
 * proofs, swap the c0 ↔ c1 order in each pair here (offsets 0↔32 and 64↔96).
 */
function encodeG2(p: G2): Uint8Array {
  const o = new Uint8Array(128);
  if (p[2][0] === "0" && p[2][1] === "0") return o; // point at infinity
  o.set(decToLe(p[0][0]),  0);  // x.c0
  o.set(decToLe(p[0][1]), 32);  // x.c1
  o.set(decToLe(p[1][0]), 64);  // y.c0
  o.set(decToLe(p[1][1]), 96);  // y.c1
  return o;
}

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Encode a snarkjs verification key into the byte format expected by the
 * on-chain groth16 verifier.
 *
 * Layout: alpha_g1(64) ‖ beta_g2(128) ‖ gamma_g2(128) ‖ delta_g2(128) ‖ IC[0..n](64 each)
 */
export function vkJsonToContractBytes(vk: SnarkjsVk): Uint8Array {
  const parts = [
    encodeG1(vk.vk_alpha_1),
    encodeG2(vk.vk_beta_2),
    encodeG2(vk.vk_gamma_2),
    encodeG2(vk.vk_delta_2),
    ...vk.IC.map(encodeG1),
  ];
  const total = parts.reduce((a, p) => a + p.length, 0);
  const o = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    o.set(p, off);
    off += p.length;
  }
  return o;
}

/**
 * Encode a snarkjs Groth16 proof into the 256-byte wire format consumed by the
 * on-chain verifier.
 *
 * Layout: A_g1(64) ‖ B_g2(128) ‖ C_g1(64)
 *
 * NOTE: A is passed un-negated. The on-chain contract negates A itself.
 */
export function snarkjsProofToBytes(proof: SnarkjsProof): Uint8Array {
  const o = new Uint8Array(256);
  o.set(encodeG1(proof.pi_a),   0);
  o.set(encodeG2(proof.pi_b),  64);
  o.set(encodeG1(proof.pi_c), 192);
  return o;
}
