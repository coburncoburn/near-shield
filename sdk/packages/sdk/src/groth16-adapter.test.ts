import { describe, it, expect } from "vitest";
import { snarkjsProofToBytes, vkJsonToContractBytes } from "./groth16-adapter.js";
import type { SnarkjsProof, SnarkjsVk } from "./groth16-adapter.js";

// ──────────────────────────────────────────────────────────────────────────────
// Minimal hand-crafted fixtures (affine coords, z = "1" means affine)
// ──────────────────────────────────────────────────────────────────────────────

const PROOF: SnarkjsProof = {
  pi_a: ["1", "2", "1"],                        // G1 affine
  pi_b: [["3", "4"], ["5", "6"], ["1", "0"]],   // G2 affine  (z.c0="1" → not infinity)
  pi_c: ["5", "7", "1"],                        // G1 affine, x="5" for coord check
};

// VK with 2 IC points so we can verify per-IC length contribution
const VK: SnarkjsVk = {
  vk_alpha_1: ["1", "2", "1"],
  vk_beta_2:  [["3", "4"], ["5", "6"], ["1", "0"]],
  vk_gamma_2: [["7", "8"], ["9", "10"], ["1", "0"]],
  vk_delta_2: [["11","12"], ["13","14"], ["1", "0"]],
  IC: [
    ["5", "2", "1"],   // IC[0] — x = "5" for coord check
    ["3", "4", "1"],   // IC[1]
  ],
};

// VK with 1 IC point
const VK_1IC: SnarkjsVk = { ...VK, IC: [["1", "2", "1"]] };

// G1 point at infinity
const PROOF_INF_A: SnarkjsProof = {
  pi_a: ["0", "0", "0"],
  pi_b: PROOF.pi_b,
  pi_c: PROOF.pi_c,
};

// G2 point at infinity
const PROOF_INF_B: SnarkjsProof = {
  pi_a: PROOF.pi_a,
  pi_b: [["0", "0"], ["0", "0"], ["0", "0"]],
  pi_c: PROOF.pi_c,
};

// ──────────────────────────────────────────────────────────────────────────────
// snarkjsProofToBytes
// ──────────────────────────────────────────────────────────────────────────────
describe("snarkjsProofToBytes", () => {
  it("returns exactly 256 bytes", () => {
    expect(snarkjsProofToBytes(PROOF).length).toBe(256);
  });

  it("coordinate '5' serialises to LE-32: first byte 5, rest 0 (C.x at offset 192)", () => {
    // pi_c.x = "5", which maps to bytes [192..224)
    const bytes = snarkjsProofToBytes(PROOF);
    expect(bytes[192]).toBe(5);
    for (let i = 193; i < 224; i++) expect(bytes[i]).toBe(0);
  });

  it("G1 point-at-infinity produces 64 zero bytes at offset 0", () => {
    const bytes = snarkjsProofToBytes(PROOF_INF_A);
    for (let i = 0; i < 64; i++) expect(bytes[i]).toBe(0);
  });

  it("G2 point-at-infinity produces 128 zero bytes at offset 64", () => {
    const bytes = snarkjsProofToBytes(PROOF_INF_B);
    for (let i = 64; i < 192; i++) expect(bytes[i]).toBe(0);
  });

  it("coordinate '1' serialises correctly: byte 0 = 1, rest 0", () => {
    const bytes = snarkjsProofToBytes(PROOF);
    // pi_a.x = "1" at offset 0
    expect(bytes[0]).toBe(1);
    for (let i = 1; i < 32; i++) expect(bytes[i]).toBe(0);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// vkJsonToContractBytes
// ──────────────────────────────────────────────────────────────────────────────
describe("vkJsonToContractBytes", () => {
  it("returns correct length for 2 IC entries: 64 + 128*3 + 64*2 = 576", () => {
    // alpha_g1(64) + beta_g2(128) + gamma_g2(128) + delta_g2(128) + IC[0](64) + IC[1](64)
    expect(vkJsonToContractBytes(VK).length).toBe(64 + 128 * 3 + 64 * 2);
  });

  it("returns correct length for 1 IC entry: 64 + 128*3 + 64*1 = 512", () => {
    expect(vkJsonToContractBytes(VK_1IC).length).toBe(64 + 128 * 3 + 64 * 1);
  });

  it("length formula holds for any IC count", () => {
    for (const n of [0, 1, 2, 5]) {
      const vk: SnarkjsVk = { ...VK, IC: Array(n).fill(["1", "2", "1"]) };
      expect(vkJsonToContractBytes(vk).length).toBe(64 + 128 * 3 + 64 * n);
    }
  });

  it("IC[0].x = '5' serialises LE at offset 64+128*3 = 448", () => {
    // VK.IC[0].x = "5"  →  offset 448, byte 0 = 5, bytes 1..31 = 0
    const bytes = vkJsonToContractBytes(VK);
    expect(bytes[448]).toBe(5);
    for (let i = 449; i < 480; i++) expect(bytes[i]).toBe(0);
  });
});
