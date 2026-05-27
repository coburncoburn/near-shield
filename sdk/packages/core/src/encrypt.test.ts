import { describe, expect, it } from "vitest";
import {
  decodeDisclosure,
  encodeDisclosure,
  generateKeyPair,
  openSealed,
  sealTo,
  SEAL_CONTEXT_NOTE,
  SEAL_CONTEXT_VIEW,
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
    const sealed = sealTo(auditor.publicKey, encodeDisclosure(sample), SEAL_CONTEXT_VIEW);
    const opened = openSealed(auditor.privateKey, sealed, SEAL_CONTEXT_VIEW);
    expect(opened).not.toBeNull();
    expect(decodeDisclosure(opened!)).toEqual(sample);
  });

  it("wrong recipient key fails decryption", () => {
    const auditorA = generateKeyPair();
    const auditorB = generateKeyPair();
    const sealed = sealTo(auditorA.publicKey, encodeDisclosure(sample), SEAL_CONTEXT_VIEW);
    expect(openSealed(auditorB.privateKey, sealed, SEAL_CONTEXT_VIEW)).toBeNull();
  });

  it("returns null (not throw) on an invalid/low-order ephemeral key", () => {
    // x25519 shared-secret derivation throws on a low-order point (all-zero
    // pubkey). openSealed must catch it and return null so a single poisoned
    // ciphertext can't crash batch scanning/auditing.
    const auditor = generateKeyPair();
    const sealed = new Uint8Array(32 + 32 + 12 + 16 + 1); // valid length, zeroed ephemeral pubkey
    expect(() => openSealed(auditor.privateKey, sealed, SEAL_CONTEXT_VIEW)).not.toThrow();
    expect(openSealed(auditor.privateKey, sealed, SEAL_CONTEXT_VIEW)).toBeNull();
  });

  it("tampered ciphertext fails authentication", () => {
    const auditor = generateKeyPair();
    const sealed = sealTo(auditor.publicKey, encodeDisclosure(sample), SEAL_CONTEXT_VIEW);
    // Flip a byte in the ciphertext region (past eph(32)+commit(32)+nonce(12)=76).
    sealed[80] ^= 0xff;
    expect(openSealed(auditor.privateKey, sealed, SEAL_CONTEXT_VIEW)).toBeNull();
  });

  it("rejects a tampered key-commitment (committing AEAD)", () => {
    const auditor = generateKeyPair();
    const sealed = sealTo(auditor.publicKey, encodeDisclosure(sample), SEAL_CONTEXT_VIEW);
    // Flip a byte in the key-commitment region (offset 32..63).
    sealed[40] ^= 0xff;
    expect(openSealed(auditor.privateKey, sealed, SEAL_CONTEXT_VIEW)).toBeNull();
  });

  it("each seal uses a fresh ephemeral key (ciphertexts differ)", () => {
    const auditor = generateKeyPair();
    const a = sealTo(auditor.publicKey, encodeDisclosure(sample), SEAL_CONTEXT_VIEW);
    const b = sealTo(auditor.publicKey, encodeDisclosure(sample), SEAL_CONTEXT_VIEW);
    expect(Array.from(a)).not.toEqual(Array.from(b));
  });

  it("trial-decryption: only the matching auditor recovers", () => {
    const alice = generateKeyPair();
    const bob = generateKeyPair();
    const carol = generateKeyPair();
    const ct = sealTo(bob.publicKey, encodeDisclosure(sample), SEAL_CONTEXT_VIEW);
    expect(openSealed(alice.privateKey, ct, SEAL_CONTEXT_VIEW)).toBeNull();
    expect(openSealed(carol.privateKey, ct, SEAL_CONTEXT_VIEW)).toBeNull();
    expect(openSealed(bob.privateKey, ct, SEAL_CONTEXT_VIEW)).not.toBeNull();
  });

  it("domain-separates contexts: a view ciphertext can't be opened as a note", () => {
    // Same key, same bytes — only the context differs. Opening under the wrong
    // context must fail, so a ciphertext sealed for one purpose can't be reused
    // in another even when a key serves multiple roles.
    const kp = generateKeyPair();
    const sealed = sealTo(kp.publicKey, encodeDisclosure(sample), SEAL_CONTEXT_VIEW);
    expect(openSealed(kp.privateKey, sealed, SEAL_CONTEXT_NOTE)).toBeNull();
    expect(openSealed(kp.privateKey, sealed, SEAL_CONTEXT_VIEW)).not.toBeNull();
  });
});
