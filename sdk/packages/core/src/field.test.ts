import { describe, expect, it } from "vitest";
import { BN254_MODULUS, Field } from "./field.js";

describe("Field", () => {
  it("from_u64 then to_hex matches Rust convention", () => {
    expect(Field.fromU64(1).toHex()).toBe(
      "0x0000000000000000000000000000000000000000000000000000000000000001"
    );
  });

  it("zero has zero hex", () => {
    expect(Field.zero().toHex()).toBe("0x" + "00".repeat(32));
  });

  it("reduces values mod p", () => {
    const big = new Field(BN254_MODULUS + 5n);
    expect(big.value).toBe(5n);
  });

  it("from_hex round-trips to_hex", () => {
    const h = "0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a";
    expect(Field.fromHex(h).toHex()).toBe(h);
  });

  it("equals is value-based", () => {
    expect(Field.fromU64(7).equals(Field.fromU64(7))).toBe(true);
    expect(Field.fromU64(7).equals(Field.fromU64(8))).toBe(false);
  });

  it("rejects malformed hex", () => {
    expect(() => Field.fromHex("0xabcd")).toThrow();
  });
});

describe("Field.fromBytesLe", () => {
  it("empty slice -> 0", () => {
    expect(Field.fromBytesLe(new Uint8Array(0)).equals(Field.zero())).toBe(true);
  });
  it("single byte = value", () => {
    expect(Field.fromBytesLe(new Uint8Array([0x61])).equals(Field.fromU64(0x61n))).toBe(true);
  });
  it("byte order is little-endian: [0x01, 0x02] -> 0x0201", () => {
    expect(Field.fromBytesLe(new Uint8Array([0x01, 0x02])).equals(Field.fromU64(0x0201n))).toBe(true);
  });
  it("31 bytes of 0xff fits without reduction", () => {
    const v = Field.fromBytesLe(new Uint8Array(31).fill(0xff));
    // (1 << 248) - 1
    const expected = (1n << 248n) - 1n;
    expect(v.equals(new Field(expected))).toBe(true);
  });
});
