import { describe, expect, it } from "vitest";
import { Field } from "./field.js";
import { poseidon2, poseidon4 } from "./poseidon.js";
import { commitNote, computeNullifier } from "./note.js";

describe("Note", () => {
  it("commitNote equals poseidon4 of the field tuple", () => {
    const note = {
      amount: 100_000_000n,
      ownerPubkey: Field.fromU64(11),
      auditorPubkey: Field.fromU64(22),
      blinding: Field.fromU64(33),
    };
    const expected = poseidon4(
      new Field(note.amount),
      note.ownerPubkey,
      note.auditorPubkey,
      note.blinding
    );
    expect(commitNote(note).toHex()).toBe(expected.toHex());
  });

  it("commitNote is sensitive to every field", () => {
    const base = {
      amount: 1n,
      ownerPubkey: Field.fromU64(1),
      auditorPubkey: Field.fromU64(1),
      blinding: Field.fromU64(1),
    };
    const c0 = commitNote(base).toHex();
    expect(commitNote({ ...base, amount: 2n }).toHex()).not.toBe(c0);
    expect(commitNote({ ...base, ownerPubkey: Field.fromU64(2) }).toHex()).not.toBe(c0);
    expect(commitNote({ ...base, auditorPubkey: Field.fromU64(2) }).toHex()).not.toBe(c0);
    expect(commitNote({ ...base, blinding: Field.fromU64(2) }).toHex()).not.toBe(c0);
  });

  it("computeNullifier is deterministic", () => {
    const sk = Field.fromU64(99);
    const c = Field.fromU64(123);
    const idx = 7n;
    expect(computeNullifier(sk, c, idx).toHex()).toBe(
      computeNullifier(sk, c, idx).toHex()
    );
  });

  it("computeNullifier is sensitive to leaf index", () => {
    const sk = Field.fromU64(99);
    const c = Field.fromU64(123);
    expect(computeNullifier(sk, c, 7n).toHex()).not.toBe(
      computeNullifier(sk, c, 8n).toHex()
    );
  });

  it("computeNullifier is sensitive to spending key", () => {
    const c = Field.fromU64(123);
    expect(computeNullifier(Field.fromU64(99), c, 7n).toHex()).not.toBe(
      computeNullifier(Field.fromU64(100), c, 7n).toHex()
    );
  });
});
