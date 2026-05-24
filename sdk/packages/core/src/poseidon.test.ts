import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { Field } from "./field.js";
import { poseidon2, poseidon4 } from "./poseidon.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectorsPath = resolve(__dirname, "../../../test-vectors/poseidon.json");
const vectors = JSON.parse(readFileSync(vectorsPath, "utf8"));

describe("poseidon cross-language vectors", () => {
  for (const v of vectors.poseidon2) {
    it(`poseidon2(${v.inputs.join(",")}) matches Rust`, () => {
      const [a, b] = v.inputs.map((n: number) => Field.fromU64(n));
      expect(poseidon2(a, b).toHex()).toBe(v.expected);
    });
  }
  for (const v of vectors.poseidon4) {
    it(`poseidon4(${v.inputs.join(",")}) matches Rust`, () => {
      const [a, b, c, d] = v.inputs.map((n: number) => Field.fromU64(n));
      expect(poseidon4(a, b, c, d).toHex()).toBe(v.expected);
    });
  }
});

describe("poseidon properties", () => {
  it("poseidon2 is deterministic", () => {
    const a = Field.fromU64(7);
    const b = Field.fromU64(8);
    expect(poseidon2(a, b).toHex()).toBe(poseidon2(a, b).toHex());
  });

  it("poseidon2 is order-sensitive", () => {
    expect(poseidon2(Field.fromU64(1), Field.fromU64(2)).toHex()).not.toBe(
      poseidon2(Field.fromU64(2), Field.fromU64(1)).toHex()
    );
  });
});
