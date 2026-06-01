import { describe, expect, it } from "vitest";
import {
  encodeDisclosure,
  generateKeyPair,
  sealTo,
  SEAL_CONTEXT_VIEW,
  type ViewDisclosure,
} from "@shielded-near/core";
import { AuditorIndex, type RawEvent } from "./indexer.js";

const ownerAlice = "0x" + "11".repeat(32);
const ownerBob = "0x" + "22".repeat(32);
const ownerCarol = "0x" + "33".repeat(32);

function disclosure(
  action: ViewDisclosure["action"],
  sender: string,
  recipient: string,
  amounts: string[]
): ViewDisclosure {
  return {
    action,
    senderOwnerPubkey: sender,
    recipientOwnerPubkey: recipient,
    amounts,
    memo: "",
    timestamp: 0,
  };
}

function event(
  blockHeight: number,
  txHash: string,
  action: ViewDisclosure["action"],
  cts: Uint8Array[]
): RawEvent {
  return { blockHeight, txHash, action, viewCiphertexts: cts };
}

describe("AuditorIndex", () => {
  it("decrypts ciphertexts addressed to this auditor", () => {
    const auditor = generateKeyPair();
    const idx = new AuditorIndex(auditor.privateKey);
    const d = disclosure("deposit", ownerAlice, ownerAlice, ["100"]);
    const ct = sealTo(auditor.publicKey, encodeDisclosure(d), SEAL_CONTEXT_VIEW);
    expect(idx.ingest([event(1, "tx1", "deposit", [ct])])).toBe(1);
    expect(idx.getAll()).toHaveLength(1);
    expect(idx.getAll()[0].disclosure).toEqual(d);
  });

  it("silently skips ciphertexts for other auditors", () => {
    const mine = generateKeyPair();
    const other = generateKeyPair();
    const idx = new AuditorIndex(mine.privateKey);
    const d = disclosure("deposit", ownerAlice, ownerAlice, ["100"]);
    const ct = sealTo(other.publicKey, encodeDisclosure(d), SEAL_CONTEXT_VIEW);
    expect(idx.ingest([event(1, "tx1", "deposit", [ct])])).toBe(0);
    expect(idx.getAll()).toHaveLength(0);
  });

  it("getForUser returns events where user is sender or recipient", () => {
    const auditor = generateKeyPair();
    const idx = new AuditorIndex(auditor.privateKey);
    const a = disclosure("transfer", ownerAlice, ownerBob, ["60"]);
    const b = disclosure("transfer", ownerBob, ownerCarol, ["40"]);
    const c = disclosure("deposit", ownerCarol, ownerCarol, ["100"]);
    const cts = [a, b, c].map((d) => sealTo(auditor.publicKey, encodeDisclosure(d), SEAL_CONTEXT_VIEW));
    idx.ingest([
      event(1, "tx1", "transfer", [cts[0]]),
      event(2, "tx2", "transfer", [cts[1]]),
      event(3, "tx3", "deposit", [cts[2]]),
    ]);
    expect(idx.getForUser(ownerAlice)).toHaveLength(1);
    expect(idx.getForUser(ownerBob)).toHaveLength(2);
    expect(idx.getForUser(ownerCarol)).toHaveLength(2);
    expect(idx.getForUser("0x" + "ff".repeat(32))).toHaveLength(0);
  });

  it("handles multi-ct events (e.g. transfer with sender + recipient auditor cts)", () => {
    const auditorA = generateKeyPair();
    const auditorB = generateKeyPair();
    const idx = new AuditorIndex(auditorA.privateKey);
    const d = disclosure("transfer", ownerAlice, ownerBob, ["60"]);
    const ctA = sealTo(auditorA.publicKey, encodeDisclosure(d), SEAL_CONTEXT_VIEW);
    const ctB = sealTo(auditorB.publicKey, encodeDisclosure(d), SEAL_CONTEXT_VIEW);
    expect(idx.ingest([event(1, "tx", "transfer", [ctA, ctB])])).toBe(1);
    expect(idx.getAll()).toHaveLength(1);
  });

  it("verifyDisclosure confirms genuine and rejects tampered values", () => {
    const auditor = generateKeyPair();
    const idx = new AuditorIndex(auditor.privateKey);
    const d = disclosure("deposit", ownerAlice, ownerAlice, ["100"]);
    const ct = sealTo(auditor.publicKey, encodeDisclosure(d), SEAL_CONTEXT_VIEW);
    expect(idx.verifyDisclosure(ct, d)).toBe(true);
    const tampered = { ...d, amounts: ["999"] };
    expect(idx.verifyDisclosure(ct, tampered)).toBe(false);
  });

  it("rejects short private keys at construction", () => {
    expect(() => new AuditorIndex(new Uint8Array(16))).toThrow();
  });

  it("ingest is idempotent over repeat batches (appends; caller dedupes by txHash)", () => {
    const auditor = generateKeyPair();
    const idx = new AuditorIndex(auditor.privateKey);
    const d = disclosure("deposit", ownerAlice, ownerAlice, ["100"]);
    const ct = sealTo(auditor.publicKey, encodeDisclosure(d), SEAL_CONTEXT_VIEW);
    idx.ingest([event(1, "tx", "deposit", [ct])]);
    idx.ingest([event(1, "tx", "deposit", [ct])]);
    expect(idx.getAll()).toHaveLength(2);
  });
});
