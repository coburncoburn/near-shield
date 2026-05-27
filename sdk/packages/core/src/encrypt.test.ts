import { describe, expect, it } from "vitest";
import {
  decodeDisclosure,
  encodeDisclosure,
  generateKeyPair,
  openSealed,
  sealTo,
  type ViewDisclosure,
} from "./encrypt.js";

const sample: ViewDisclosure = {
  action: "transfer",
  senderOwnerPubkey: "0x" + "11".repeat(32),
  recipientOwnerPubkey: "0x" + "22".repeat(32),
  amounts: ["100", "60", "40"],
  memo: "invoice #42",
  timestamp: 1716576000,
};

describe("hybrid encryption", () => {
  it("roundtrips a disclosure end-to-end", () => {
    const auditor = generateKeyPair();
    const sealed = sealTo(auditor.publicKey, encodeDisclosure(sample));
    const opened = openSealed(auditor.privateKey, sealed);
    expect(opened).not.toBeNull();
    expect(decodeDisclosure(opened!)).toEqual(sample);
  });

  it("wrong recipient key fails decryption", () => {
    const auditorA = generateKeyPair();
    const auditorB = generateKeyPair();
    const sealed = sealTo(auditorA.publicKey, encodeDisclosure(sample));
    expect(openSealed(auditorB.privateKey, sealed)).toBeNull();
  });

  it("returns null (not throw) on an invalid/low-order ephemeral key", () => {
    // x25519 shared-secret derivation throws on a low-order point (all-zero
    // pubkey). openSealed must catch it and return null so a single poisoned
    // ciphertext can't crash batch scanning/auditing.
    const auditor = generateKeyPair();
    const sealed = new Uint8Array(32 + 12 + 16 + 1); // zeroed ephemeral pubkey
    expect(() => openSealed(auditor.privateKey, sealed)).not.toThrow();
    expect(openSealed(auditor.privateKey, sealed)).toBeNull();
  });

  it("tampered ciphertext fails authentication", () => {
    const auditor = generateKeyPair();
    const sealed = sealTo(auditor.publicKey, encodeDisclosure(sample));
    // Flip a byte inside the ciphertext region (past the ephemeral pub + nonce)
    sealed[60] ^= 0xff;
    expect(openSealed(auditor.privateKey, sealed)).toBeNull();
  });

  it("each seal uses a fresh ephemeral key (ciphertexts differ)", () => {
    const auditor = generateKeyPair();
    const a = sealTo(auditor.publicKey, encodeDisclosure(sample));
    const b = sealTo(auditor.publicKey, encodeDisclosure(sample));
    expect(Array.from(a)).not.toEqual(Array.from(b));
  });

  it("trial-decryption: only the matching auditor recovers", () => {
    const alice = generateKeyPair();
    const bob = generateKeyPair();
    const carol = generateKeyPair();
    const ct = sealTo(bob.publicKey, encodeDisclosure(sample));
    expect(openSealed(alice.privateKey, ct)).toBeNull();
    expect(openSealed(carol.privateKey, ct)).toBeNull();
    expect(openSealed(bob.privateKey, ct)).not.toBeNull();
  });
});
