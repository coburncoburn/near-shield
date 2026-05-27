import { describe, expect, it } from "vitest";
import { generateKeyPair, sealTo } from "./encrypt.js";
import { Field } from "./field.js";
import { encodeNotePayload, scanNotes, type NoteCiphertext } from "./scanner.js";

function makeCt(recipientPub: Uint8Array, note: Parameters<typeof encodeNotePayload>[0], leafIndex: bigint): NoteCiphertext {
  return { leafIndex, sealed: sealTo(recipientPub, encodeNotePayload(note)) };
}

describe("scanner", () => {
  it("returns the note when ciphertext is addressed to viewing key", () => {
    const vk = generateKeyPair();
    const note = {
      amount: 100n,
      ownerPubkey: Field.fromU64(1),
      auditorPubkey: Field.fromU64(2),
      blinding: Field.fromU64(3),
    };
    const cts = [makeCt(vk.publicKey, note, 5n)];
    const found = scanNotes(vk.privateKey, cts);
    expect(found).toHaveLength(1);
    expect(found[0].leafIndex).toBe(5n);
    expect(found[0].note.amount).toBe(100n);
  });

  it("ignores ciphertexts for other recipients", () => {
    const mine = generateKeyPair();
    const other = generateKeyPair();
    const note = {
      amount: 1n,
      ownerPubkey: Field.fromU64(1),
      auditorPubkey: Field.fromU64(1),
      blinding: Field.fromU64(1),
    };
    const cts = [makeCt(other.publicKey, note, 0n)];
    expect(scanNotes(mine.privateKey, cts)).toHaveLength(0);
  });

  it("filters mixed batches and preserves input order", () => {
    const me = generateKeyPair();
    const other = generateKeyPair();
    const n = (amt: bigint) => ({
      amount: amt,
      ownerPubkey: Field.fromU64(1),
      auditorPubkey: Field.fromU64(1),
      blinding: Field.fromU64(amt),
    });
    const cts = [
      makeCt(other.publicKey, n(1n), 0n),
      makeCt(me.publicKey, n(2n), 1n),
      makeCt(other.publicKey, n(3n), 2n),
      makeCt(me.publicKey, n(4n), 3n),
    ];
    const found = scanNotes(me.privateKey, cts);
    expect(found.map((f) => f.note.amount)).toEqual([2n, 4n]);
    expect(found.map((f) => f.leafIndex)).toEqual([1n, 3n]);
  });

  it("skips corrupted ciphertexts silently", () => {
    const me = generateKeyPair();
    const note = {
      amount: 1n,
      ownerPubkey: Field.fromU64(1),
      auditorPubkey: Field.fromU64(1),
      blinding: Field.fromU64(1),
    };
    const ct = makeCt(me.publicKey, note, 0n);
    ct.sealed[60] ^= 0xff;
    expect(scanNotes(me.privateKey, [ct])).toHaveLength(0);
  });

  it("a poisoned ephemeral key in one ciphertext does not abort the batch", () => {
    // An attacker can post a log entry whose ephemeral pubkey is a low-order
    // point; x25519 shared-secret derivation throws on it. The scanner must
    // skip that entry and still recover legitimate notes, or one malicious log
    // halts scanning for everyone.
    const me = generateKeyPair();
    const note = {
      amount: 42n,
      ownerPubkey: Field.fromU64(1),
      auditorPubkey: Field.fromU64(1),
      blinding: Field.fromU64(1),
    };
    const poison: NoteCiphertext = {
      leafIndex: 0n,
      sealed: new Uint8Array(32 + 12 + 16 + 1), // all-zero ephemeral pubkey
    };
    const good = makeCt(me.publicKey, note, 1n);
    const found = scanNotes(me.privateKey, [poison, good]);
    expect(found).toHaveLength(1);
    expect(found[0].note.amount).toBe(42n);
    expect(found[0].leafIndex).toBe(1n);
  });

  it("re-scanning the same ciphertexts is idempotent", () => {
    const me = generateKeyPair();
    const note = {
      amount: 7n,
      ownerPubkey: Field.fromU64(1),
      auditorPubkey: Field.fromU64(1),
      blinding: Field.fromU64(1),
    };
    const cts = [makeCt(me.publicKey, note, 9n)];
    const a = scanNotes(me.privateKey, cts);
    const b = scanNotes(me.privateKey, cts);
    expect(a).toEqual(b);
  });
});
