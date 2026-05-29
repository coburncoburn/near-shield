import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { load } from "./helpers.js";

const vectors = JSON.parse(
  readFileSync(
    path.resolve(fileURLToPath(import.meta.url), "../../../sdk/test-vectors/poseidon.json"),
    "utf8",
  ),
);
const toBig = (hex: string) => BigInt(hex); // "0x..." parses directly

describe("poseidon parity kill-gate", () => {
  it("circomlib Poseidon(2) matches all locked poseidon2 vectors", async () => {
    const c = await load("test/poseidon2_test.circom");
    for (const v of vectors.poseidon2) {
      const w = await c.calculateWitness({ a: v.inputs[0], b: v.inputs[1] }, true);
      await c.assertOut(w, { out: toBig(v.expected) });
    }
  });

  it("circomlib Poseidon(4) matches all locked poseidon4 vectors", async () => {
    const c = await load("test/poseidon4_test.circom");
    for (const v of vectors.poseidon4) {
      const w = await c.calculateWitness({ in: v.inputs }, true);
      await c.assertOut(w, { out: toBig(v.expected) });
    }
  });
});
