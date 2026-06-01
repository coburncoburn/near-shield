import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { keccakToField } from "./keccak_to_field.js";

const VECTORS = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("../../../test-vectors/view_ct_keccak.json", import.meta.url)),
    "utf-8"
  )
) as { cases: { name: string; input_hex: string; expected_field_hex: string }[] };

function hexToBytes(h: string): Uint8Array {
  const s = h.startsWith("0x") ? h.slice(2) : h;
  if (s.length === 0) return new Uint8Array(0);
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

describe("keccakToField cross-language vectors", () => {
  for (const c of VECTORS.cases) {
    it(c.name, () => {
      expect(keccakToField(hexToBytes(c.input_hex)).toHex()).toBe(c.expected_field_hex);
    });
  }
});
