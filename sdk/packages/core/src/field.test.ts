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
