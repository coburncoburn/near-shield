import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { hashBytesToField } from "./hash_bytes.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectorsPath = resolve(__dirname, "../../../test-vectors/view_ct_hash.json");
const vectors = JSON.parse(readFileSync(vectorsPath, "utf8"));

describe("hashBytesToField cross-language vectors", () => {
  for (const c of vectors.cases) {
    it(`matches Rust for "${c.name}"`, () => {
      const input = Buffer.from(c.input_b64, "base64");
      const out = hashBytesToField(new Uint8Array(input));
      expect(out.toHex()).toBe(c.expected);
    });
  }
});

describe("hashBytesToField properties", () => {
  it("is deterministic", () => {
    const x = new Uint8Array([1, 2, 3, 4, 5]);
    expect(hashBytesToField(x).toHex()).toBe(hashBytesToField(x).toHex());
  });

  it("changes when input bytes change", () => {
    const a = hashBytesToField(new Uint8Array([1, 2, 3]));
    const b = hashBytesToField(new Uint8Array([1, 2, 4]));
    expect(a.toHex()).not.toBe(b.toHex());
  });

  it("handles inputs exactly at chunk boundary (31, 62 bytes)", () => {
    const at31 = new Uint8Array(31).fill(1);
    const at62 = new Uint8Array(62).fill(1);
    expect(hashBytesToField(at31).toHex()).not.toBe(hashBytesToField(at62).toHex());
  });
});
