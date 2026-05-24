/**
 * Canonical end-to-end scenario from the spec, run in-process:
 *
 *   1. Alice deposits 100 USDC, choosing Auditor A.
 *   2. Alice transfers a 100 note to Bob (Auditor B).
 *   3. Bob scans the chain, finds the note, withdraws 100 to a fresh NEAR account.
 *   4. Auditor A only sees Alice's side.
 *   5. Auditor B only sees Bob's side.
 *
 * The Rust contract is exercised in its own test suite (in `contract/`). This
 * test integrates the off-chain SDK packages (core scanner, Wallet, AuditorIndex)
 * and verifies they compose correctly. The "chain" is represented as a list of
 * NoteCiphertext entries with assigned leaf indices.
 */

import { describe, expect, it } from "vitest";
import {
  encodeDisclosure,
  generateKeyPair,
  sealTo,
  type NoteCiphertext,
} from "@shielded-near/core";
import { AuditorIndex, type RawEvent } from "../../auditor/src/indexer.js";
import { Wallet } from "./wallet.js";

function makeSeed(byte: number): Uint8Array {
  return new Uint8Array(64).fill(byte);
}

function ctsFromBuilt(builtNoteCts: Uint8Array[], startIdx: bigint): NoteCiphertext[] {
  return builtNoteCts.map((sealed, i) => ({ leafIndex: startIdx + BigInt(i), sealed }));
}

function hex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

describe("canonical e2e", () => {
  it("Alice deposits, Bob receives via scan, both auditors see only their user", () => {
    const alice = new Wallet({
      seed: makeSeed(0xa),
      usdcTokenAccountId: "usdc.near",
      poolAccountId: "pool.near",
    });
    const bob = new Wallet({
      seed: makeSeed(0xb),
      usdcTokenAccountId: "usdc.near",
      poolAccountId: "pool.near",
    });
    const auditorA = generateKeyPair();
    const auditorB = generateKeyPair();
    const indexA = new AuditorIndex(auditorA.privateKey);
    const indexB = new AuditorIndex(auditorB.privateKey);

    // 1) Alice deposits 100
    const deposit = alice.buildDeposit({
      amount: 100n,
      auditorPubkey: auditorA.publicKey,
    });

    const depositEvent: RawEvent = {
      blockHeight: 1,
      txHash: "tx_dep",
      action: "deposit",
      viewCiphertexts: deposit.viewCiphertexts,
    };
    expect(indexA.ingest([depositEvent])).toBe(1);
    expect(indexB.ingest([depositEvent])).toBe(0);

    // Alice scans her own deposit so she knows about the note
    alice.scan(ctsFromBuilt(deposit.noteCiphertexts, 0n));
    expect(alice.balance()).toBe(100n);

    // 2) Alice "transfers" a 100 note to Bob. (Wallet.buildTransfer is part of
    // a later task; here we drive the scanner + auditor pieces directly using
    // primitives, which is what the eventual transfer-builder will compose.)
    const transferDisclosure = {
      action: "transfer" as const,
      senderOwnerPubkey: alice.address().ownerPubkey,
      recipientOwnerPubkey: bob.address().ownerPubkey,
      amounts: ["100"],
      memo: "alice->bob",
      timestamp: 1234,
    };
    const viewCtForA = sealTo(auditorA.publicKey, encodeDisclosure(transferDisclosure));
    const viewCtForB = sealTo(auditorB.publicKey, encodeDisclosure(transferDisclosure));

    // Note ciphertext addressed to Bob's viewing key
    const noteForBob = sealTo(
      bob.viewingKey.publicKey,
      new TextEncoder().encode(
        JSON.stringify({
          amount: "100",
          ownerPubkey: bob.address().ownerPubkey,
          auditorPubkey: "0x" + hex(auditorB.publicKey),
          blinding: "0x" + "11".repeat(32),
        })
      )
    );

    const transferEvent: RawEvent = {
      blockHeight: 2,
      txHash: "tx_xfer",
      action: "transfer",
      viewCiphertexts: [viewCtForA, viewCtForB],
    };
    indexA.ingest([transferEvent]);
    indexB.ingest([transferEvent]);

    // 3) Bob scans and finds the note
    bob.scan([{ leafIndex: 1n, sealed: noteForBob }]);
    expect(bob.balance()).toBe(100n);

    // Bob withdraws to a fresh NEAR account
    const withdraw = bob.buildWithdraw({
      amount: 100n,
      recipientNearAccount: "fresh-bob.near",
      relayer: "relayer.near",
      relayerFee: 1n,
    });
    expect(withdraw.publicInputs.recipient).toBe("fresh-bob.near");

    const withdrawEvent: RawEvent = {
      blockHeight: 3,
      txHash: "tx_wd",
      action: "withdraw",
      viewCiphertexts: withdraw.viewCiphertexts,
    };
    indexA.ingest([withdrawEvent]);
    indexB.ingest([withdrawEvent]);

    // 4 & 5) Each auditor sees only their user's events
    const aRecords = indexA.getAll();
    const aActions = aRecords.map((r) => r.disclosure.action);
    expect(aActions).toContain("deposit");
    expect(aActions).toContain("transfer");

    const bRecords = indexB.getAll();
    const bActions = bRecords.map((r) => r.disclosure.action);
    expect(bActions).toContain("transfer");

    // Isolation: A never sees the withdraw (it was bound to Bob's auditor only).
    const aSawWithdraw = aRecords.some(
      (r) => r.disclosure.action === "withdraw" && r.disclosure.recipientOwnerPubkey === "fresh-bob.near"
    );
    expect(aSawWithdraw).toBe(false);

    // Isolation: B never sees Alice's original deposit.
    const bSawAlicesDeposit = bRecords.some(
      (r) => r.disclosure.action === "deposit" && r.disclosure.senderOwnerPubkey === alice.address().ownerPubkey
    );
    expect(bSawAlicesDeposit).toBe(false);
  });
});
