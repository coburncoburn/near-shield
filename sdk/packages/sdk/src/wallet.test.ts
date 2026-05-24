import { describe, expect, it } from "vitest";
import { generateKeyPair } from "@shielded-near/core";
import { Wallet, type WalletConfig } from "./wallet.js";

function makeConfig(): WalletConfig {
  const seed = new Uint8Array(64);
  crypto.getRandomValues(seed);
  return {
    seed,
    usdcTokenAccountId: "usdc.near",
    poolAccountId: "pool.near",
  };
}

describe("Wallet", () => {
  it("derives a stable address from the seed", () => {
    const cfg = makeConfig();
    const w1 = new Wallet(cfg);
    const w2 = new Wallet(cfg);
    expect(w1.address().ownerPubkey).toBe(w2.address().ownerPubkey);
    expect(w1.address().viewingPubkey).toBe(w2.address().viewingPubkey);
  });

  it("rejects too-short seeds", () => {
    expect(() => new Wallet({ ...makeConfig(), seed: new Uint8Array(16) })).toThrow();
  });

  it("buildDeposit produces a transaction with auditor view ciphertext", () => {
    const cfg = makeConfig();
    const w = new Wallet(cfg);
    const auditor = generateKeyPair();
    const tx = w.buildDeposit({ amount: 100_000_000n, auditorPubkey: auditor.publicKey });
    expect(tx.method).toBe("deposit");
    expect(tx.viewCiphertexts).toHaveLength(1);
    expect(tx.noteCiphertexts).toHaveLength(1);
    expect(tx.publicInputs.amount).toBe("100000000");
    expect(typeof tx.publicInputs.commitment).toBe("string");
    expect((tx.publicInputs.commitment as string).startsWith("0x")).toBe(true);
  });

  it("buildDeposit's note ciphertext is decryptable by this wallet", () => {
    const cfg = makeConfig();
    const w = new Wallet(cfg);
    const auditor = generateKeyPair();
    const tx = w.buildDeposit({ amount: 100n, auditorPubkey: auditor.publicKey });
    const cts = tx.noteCiphertexts.map((sealed, i) => ({ leafIndex: BigInt(i), sealed }));
    const found = w.scan(cts);
    expect(found).toBe(1);
    expect(w.balance()).toBe(100n);
  });

  it("buildWithdraw refuses when no matching note is held", () => {
    const cfg = makeConfig();
    const w = new Wallet(cfg);
    expect(() =>
      w.buildWithdraw({
        amount: 100n,
        recipientNearAccount: "bob.near",
        relayer: "relayer.near",
        relayerFee: 1n,
      })
    ).toThrow();
  });

  it("buildWithdraw refuses when relayer fee exceeds amount", () => {
    const cfg = makeConfig();
    const w = new Wallet(cfg);
    expect(() =>
      w.buildWithdraw({
        amount: 100n,
        recipientNearAccount: "bob.near",
        relayer: "relayer.near",
        relayerFee: 999n,
      })
    ).toThrow();
  });

  it("buildWithdraw succeeds after a matching deposit is scanned", () => {
    const cfg = makeConfig();
    const w = new Wallet(cfg);
    const auditor = generateKeyPair();
    const dep = w.buildDeposit({ amount: 500n, auditorPubkey: auditor.publicKey });
    w.scan(dep.noteCiphertexts.map((sealed, i) => ({ leafIndex: BigInt(i), sealed })));
    const wd = w.buildWithdraw({
      amount: 500n,
      recipientNearAccount: "bob.near",
      relayer: "relayer.near",
      relayerFee: 10n,
    });
    expect(wd.method).toBe("withdraw");
    expect(wd.publicInputs.amount).toBe("500");
    expect(wd.publicInputs.relayer).toBe("relayer.near");
    expect(wd.publicInputs.relayerFee).toBe("10");
  });
});
