import { describe, expect, it } from "vitest";
import { Field, generateKeyPair } from "@shielded-near/core";
import { Wallet } from "./wallet.js";
import {
  toDepositArgs,
  toFtTransferCallArgs,
  toTransferArgs,
  toTransferCall,
  toWithdrawArgs,
  toWithdrawCall,
} from "./envelopes.js";

function makeWallet(byte: number): Wallet {
  const seed = new Uint8Array(64).fill(byte);
  return new Wallet({
    seed,
    usdcTokenAccountId: "usdc.near",
    poolAccountId: "pool.near",
  });
}

describe("envelopes - deposit", () => {
  it("toDepositArgs produces NEAR-shape JSON with U128 strings and byte-array proof", () => {
    const w = makeWallet(0xa);
    const auditor = generateKeyPair();
    const tx = w.buildDeposit({ amount: 100n, auditorPubkey: auditor.publicKey });
    const args = toDepositArgs(tx);
    expect(typeof args.commitment).toBe("string");
    expect(args.commitment.startsWith("0x")).toBe(true);
    expect(args.amount).toBe("100");
    expect(typeof args.auditor_pubkey).toBe("string");
    expect(args.view_ct.startsWith("0x")).toBe(true);
    expect(args.note_ct.startsWith("0x")).toBe(true);
    expect(Array.isArray(args.proof)).toBe(true);
    expect(args.proof.every((n) => Number.isInteger(n) && n >= 0 && n <= 255)).toBe(true);
  });

  it("toFtTransferCallArgs wraps deposit args inside ft_transfer_call envelope", () => {
    const w = makeWallet(0xa);
    const auditor = generateKeyPair();
    const tx = w.buildDeposit({ amount: 100n, auditorPubkey: auditor.publicKey });
    const env = toFtTransferCallArgs(tx, "usdc.near", "pool.near");
    expect(env.contractId).toBe("usdc.near");
    expect(env.methodName).toBe("ft_transfer_call");
    expect(env.args.receiver_id).toBe("pool.near");
    expect(env.args.amount).toBe("100");
    expect(env.args.memo).toBeNull();
    expect(env.attachedDeposit).toBe("1");
    const msg = JSON.parse(env.args.msg as string);
    expect(msg.commitment).toBe(tx.publicInputs.commitment);
    expect(msg.amount).toBe("100");
  });

  it("toDepositArgs rejects non-deposit transactions", () => {
    const w = makeWallet(0xa);
    const auditor = generateKeyPair();
    const dep = w.buildDeposit({ amount: 100n, auditorPubkey: auditor.publicKey });
    w.scan(dep.noteCiphertexts.map((sealed, i) => ({ leafIndex: BigInt(i), sealed })));
    const wd = w.buildWithdraw({
      amount: 100n,
      recipientNearAccount: "bob.near",
      relayer: "relayer.near",
      relayerFee: 1n,
    });
    expect(() => toDepositArgs(wd)).toThrow(/expected method=deposit/);
  });
});

describe("envelopes - transfer", () => {
  function preparedAlice(): { alice: Wallet; auditorAPub: Uint8Array } {
    const alice = makeWallet(0xa);
    const auditorA = generateKeyPair();
    const dep0 = alice.buildDeposit({ amount: 40n, auditorPubkey: auditorA.publicKey });
    const dep1 = alice.buildDeposit({ amount: 60n, auditorPubkey: auditorA.publicKey });
    alice.scan([
      ...dep0.noteCiphertexts.map((sealed, i) => ({ leafIndex: BigInt(i), sealed })),
      ...dep1.noteCiphertexts.map((sealed, i) => ({ leafIndex: BigInt(i + 1), sealed })),
    ]);
    return { alice, auditorAPub: auditorA.publicKey };
  }

  it("toTransferArgs maps to contract's [String; 2] shape", () => {
    const { alice } = preparedAlice();
    const bob = makeWallet(0xb);
    const auditorB = generateKeyPair();
    const tx = alice.buildTransfer({
      amount: 60n,
      recipientOwnerPubkey: Field.fromHex(bob.address().ownerPubkey),
      recipientAuditorPubkey: auditorB.publicKey,
      recipientViewingPubkey: new Uint8Array(Buffer.from(bob.address().viewingPubkey, "hex")),
    });
    const args = toTransferArgs(tx);
    expect(args.nullifiers).toHaveLength(2);
    expect(args.commitments).toHaveLength(2);
    expect(args.view_cts).toHaveLength(2);
    expect(args.note_cts).toHaveLength(2);
    expect(args.nullifiers.every((s) => typeof s === "string")).toBe(true);
    expect(args.commitments.every((s) => typeof s === "string")).toBe(true);
  });

  it("toTransferCall wraps the args in a pool function-call envelope", () => {
    const { alice } = preparedAlice();
    const bob = makeWallet(0xb);
    const auditorB = generateKeyPair();
    const tx = alice.buildTransfer({
      amount: 60n,
      recipientOwnerPubkey: Field.fromHex(bob.address().ownerPubkey),
      recipientAuditorPubkey: auditorB.publicKey,
      recipientViewingPubkey: new Uint8Array(Buffer.from(bob.address().viewingPubkey, "hex")),
    });
    const env = toTransferCall(tx, "pool.near");
    expect(env.contractId).toBe("pool.near");
    expect(env.methodName).toBe("transfer");
    expect(env.attachedDeposit).toBe("0");
    // args is opaque to the envelope but should still be present as object
    expect(typeof env.args).toBe("object");
    expect(Array.isArray((env.args as { nullifiers: unknown }).nullifiers)).toBe(true);
  });
});

describe("envelopes - withdraw", () => {
  it("toWithdrawArgs produces correct field names and U128 amount/fee", () => {
    const w = makeWallet(0xa);
    const auditor = generateKeyPair();
    const dep = w.buildDeposit({ amount: 500n, auditorPubkey: auditor.publicKey });
    w.scan(dep.noteCiphertexts.map((sealed, i) => ({ leafIndex: BigInt(i), sealed })));
    const tx = w.buildWithdraw({
      amount: 500n,
      recipientNearAccount: "bob.near",
      relayer: "relayer.near",
      relayerFee: 10n,
    });
    const args = toWithdrawArgs(tx);
    expect(args.nullifier.startsWith("0x")).toBe(true);
    expect(args.recipient).toBe("bob.near");
    expect(args.amount).toBe("500");
    expect(args.relayer).toBe("relayer.near");
    expect(args.relayer_fee).toBe("10");
    expect(args.view_ct.startsWith("0x")).toBe(true);
  });

  it("toWithdrawCall wraps the args in a pool function-call envelope", () => {
    const w = makeWallet(0xa);
    const auditor = generateKeyPair();
    const dep = w.buildDeposit({ amount: 500n, auditorPubkey: auditor.publicKey });
    w.scan(dep.noteCiphertexts.map((sealed, i) => ({ leafIndex: BigInt(i), sealed })));
    const tx = w.buildWithdraw({
      amount: 500n,
      recipientNearAccount: "bob.near",
      relayer: "relayer.near",
      relayerFee: 10n,
    });
    const env = toWithdrawCall(tx, "pool.near");
    expect(env.contractId).toBe("pool.near");
    expect(env.methodName).toBe("withdraw");
  });
});
