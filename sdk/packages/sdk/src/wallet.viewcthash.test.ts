import { describe, it, expect } from "vitest";
import { Field, generateKeyPair, keccakToField } from "@shielded-near/core";
import { Wallet } from "./wallet.js";
import { encodeCiphertext } from "./envelopes.js";
import type { Prover, ProveRequest } from "./prover.js";

class CapturingProver {
  public last?: ProveRequest;
  async prove(req: ProveRequest): Promise<Uint8Array> {
    this.last = req;
    return new Uint8Array(256);
  }
}

const utf8 = (s: string) => new TextEncoder().encode(s);

const DEPOSIT_PI_INDEX_VIEW_CT_HASH = 3; // PI order: commitment, amount, auditor, view_ct_hash
const TRANSFER_PI_INDEX_VIEW_CT_HASH_SENDER = 7;    // PI order: merkleRoot, nullifier0, nullifier1, c_recipient, c_change, senderAuditorField, recipientAuditorField, view_ct_hash_sender, view_ct_hash_recipient
const TRANSFER_PI_INDEX_VIEW_CT_HASH_RECIPIENT = 8;
const WITHDRAW_PI_INDEX_VIEW_CT_HASH = 7; // PI order: merkleRoot, nullifier, recipient, amount, relayer, relayer_fee, auditorPubkey, view_ct_hash

describe("view_ct_hash binding", () => {
  it("deposit proves the hash of the encoded ciphertext bytes", async () => {
    const seed = new Uint8Array(64).fill(7);
    const auditorPubkey = new Uint8Array(32).fill(9);
    const prover = new CapturingProver();
    const w = new Wallet({ seed, usdcTokenAccountId: "usdc.test", poolAccountId: "pool.test" });
    const tx = await w.buildDepositProved({ amount: 100n, auditorPubkey }, prover as unknown as Prover);
    const expected = keccakToField(
      new TextEncoder().encode(encodeCiphertext(tx.viewCiphertexts[0]))
    ).toHex();
    expect(prover.last!.publicInputs[DEPOSIT_PI_INDEX_VIEW_CT_HASH]).toBe(expected);
  });

  it("transfer proves the hash of the encoded ciphertext bytes for both sender and recipient view_ct_hash", async () => {
    const seed = new Uint8Array(64).fill(3);
    const auditorA = generateKeyPair();
    const auditorB = generateKeyPair();

    const alice = new Wallet({ seed, usdcTokenAccountId: "usdc.test", poolAccountId: "pool.test" });
    const bob = new Wallet({ seed: new Uint8Array(64).fill(5), usdcTokenAccountId: "usdc.test", poolAccountId: "pool.test" });

    // Scan two deposits so alice has two unspent notes with the same auditor.
    const dep0 = alice.buildDeposit({ amount: 40n, auditorPubkey: auditorA.publicKey });
    const dep1 = alice.buildDeposit({ amount: 60n, auditorPubkey: auditorA.publicKey });
    alice.scan([
      ...dep0.noteCiphertexts.map((sealed, i) => ({ leafIndex: BigInt(i), sealed })),
      ...dep1.noteCiphertexts.map((sealed, i) => ({ leafIndex: BigInt(i + 1), sealed })),
    ]);

    const merklePath = Array.from({ length: 20 }, (_, i) => Field.fromU64(i).toHex());
    const prover = new CapturingProver();
    const tx = await alice.buildTransferProved(
      {
        amount: 60n,
        recipientOwnerPubkey: Field.fromHex(bob.address().ownerPubkey),
        recipientAuditorPubkey: auditorB.publicKey,
        recipientViewingPubkey: new Uint8Array(Buffer.from(bob.address().viewingPubkey, "hex")),
        memo: "test",
      },
      prover as unknown as Prover,
      {
        merkleRoot: Field.fromU64(99).toHex(),
        merklePath0: merklePath,
        merklePath1: merklePath,
      }
    );

    const expectedSender = keccakToField(utf8(encodeCiphertext(tx.viewCiphertexts[0]))).toHex();
    const expectedRecipient = keccakToField(utf8(encodeCiphertext(tx.viewCiphertexts[1]))).toHex();

    expect(prover.last!.publicInputs[TRANSFER_PI_INDEX_VIEW_CT_HASH_SENDER]).toBe(expectedSender);
    expect(prover.last!.publicInputs[TRANSFER_PI_INDEX_VIEW_CT_HASH_RECIPIENT]).toBe(expectedRecipient);
  });

  it("withdraw proves the hash of the encoded ciphertext bytes for view_ct_hash", async () => {
    const seed = new Uint8Array(64).fill(11);
    const auditor = generateKeyPair();

    const w = new Wallet({ seed, usdcTokenAccountId: "usdc.test", poolAccountId: "pool.test" });

    // Scan a deposit so w has an unspent note with the exact withdraw amount.
    const dep = w.buildDeposit({ amount: 500n, auditorPubkey: auditor.publicKey });
    w.scan(dep.noteCiphertexts.map((sealed, i) => ({ leafIndex: BigInt(i), sealed })));

    const merklePath = Array.from({ length: 20 }, (_, i) => Field.fromU64(i).toHex());
    const prover = new CapturingProver();
    const tx = await w.buildWithdrawProved(
      {
        amount: 500n,
        recipientNearAccount: "bob.near",
        relayer: "relayer.near",
        relayerFee: 10n,
        merklePath,
        merkleRoot: Field.fromU64(42).toHex(),
      },
      prover as unknown as Prover
    );

    const expected = keccakToField(utf8(encodeCiphertext(tx.viewCiphertexts[0]))).toHex();
    expect(prover.last!.publicInputs[WITHDRAW_PI_INDEX_VIEW_CT_HASH]).toBe(expected);
  });
});
