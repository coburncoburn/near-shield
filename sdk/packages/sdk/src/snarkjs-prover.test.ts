/**
 * Exact-signal-set tests for proveRequestToCircomInput.
 *
 * For each circuit we build a representative ProveRequest using the WALLET's
 * actual witness key names (copied from buildDepositProved / buildTransferProved
 * / buildWithdrawProved in wallet.ts), then assert that the set of keys in the
 * produced circom input object EXACTLY matches the set of signals declared in
 * the corresponding circom source file.
 *
 * A name mismatch fails at snarkjs.groth16.fullProve (witness generation rejects
 * an unknown/missing signal) BEFORE any proof — so it would NOT be caught by the
 * verify gate. This test is the guard.
 */

import { describe, it, expect } from "vitest";
import { proveRequestToCircomInput } from "./snarkjs-prover.js";
import type { ProveRequest } from "./prover.js";

// Placeholder field hex value used everywhere we don't care about the actual value.
const F = "0x0000000000000000000000000000000000000000000000000000000000000001";

// Merkle path: 20 sibling hashes.
const PATH: string[] = Array.from({ length: 20 }, () => F);

// ---------------------------------------------------------------------------
// Expected signal sets (read from circom/circuits/*.circom)
// ---------------------------------------------------------------------------

const DEPOSIT_SIGNALS = new Set([
  // public (4)
  "commitment",
  "amount",
  "auditorPubkey",
  "viewCtHash",
  // private (3)
  "ownerPubkey",
  "blinding",
  "viewCtHashWitness",
]);

const TRANSFER_SIGNALS = new Set([
  // public (9)
  "merkleRoot",
  "nullifier0",
  "nullifier1",
  "commitmentOut0",
  "commitmentOut1",
  "auditorPubkey",
  "recipientAuditorPubkey",
  "viewCtHashSender",
  "viewCtHashRecipient",
  // private (19)
  "in0Amount",
  "in0Owner",
  "in0Blinding",
  "in0LeafIndex",
  "in0Path",
  "in1Amount",
  "in1Owner",
  "in1Blinding",
  "in1LeafIndex",
  "in1Path",
  "spendingKey",
  "out0Amount",
  "out0Owner",
  "out0Blinding",
  "out1Amount",
  "out1Owner",
  "out1Blinding",
  "viewCtHashSenderWitness",
  "viewCtHashRecipientWitness",
]);

const WITHDRAW_SIGNALS = new Set([
  // public (8)
  "merkleRoot",
  "nullifier",
  "recipient",
  "amount",
  "relayer",
  "relayerFee",
  "auditorPubkey",
  "viewCtHash",
  // private (8)
  "noteAmount",
  "noteOwner",
  "noteAuditor",
  "noteBlinding",
  "spendingKey",
  "leafIndex",
  "merklePath",
  "viewCtHashWitness",
]);

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function keySet(req: ProveRequest): Set<string> {
  return new Set(Object.keys(proveRequestToCircomInput(req)));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("proveRequestToCircomInput — exact signal set", () => {
  it("deposit: produced keys === circom signal set", () => {
    // wallet.ts buildDepositProved witness keys: ownerPubkey, blinding, viewCtHashWitness
    const req: ProveRequest = {
      circuit: "deposit",
      publicInputs: [
        F, // commitment
        F, // amount
        F, // auditorPubkey
        F, // viewCtHash
      ],
      witness: {
        ownerPubkey: F,
        blinding: F,
        viewCtHashWitness: F,
      },
    };
    expect(keySet(req)).toEqual(DEPOSIT_SIGNALS);
  });

  it("transfer: produced keys === circom signal set (renames applied)", () => {
    // wallet.ts buildTransferProved witness keys include OwnerPubkey variants
    // that must be renamed: in0OwnerPubkey→in0Owner, in1OwnerPubkey→in1Owner,
    // out0OwnerPubkey→out0Owner, out1OwnerPubkey→out1Owner.
    const req: ProveRequest = {
      circuit: "transfer",
      publicInputs: [
        F, // merkleRoot
        F, // nullifier0
        F, // nullifier1
        F, // commitmentOut0
        F, // commitmentOut1
        F, // auditorPubkey
        F, // recipientAuditorPubkey
        F, // viewCtHashSender
        F, // viewCtHashRecipient
      ],
      witness: {
        in0Amount: F,
        in0OwnerPubkey: F, // renamed → in0Owner
        in0Blinding: F,
        in0LeafIndex: F,
        in0Path: PATH,
        in1Amount: F,
        in1OwnerPubkey: F, // renamed → in1Owner
        in1Blinding: F,
        in1LeafIndex: F,
        in1Path: PATH,
        spendingKey: F,
        out0Amount: F,
        out0OwnerPubkey: F, // renamed → out0Owner
        out0Blinding: F,
        out1Amount: F,
        out1OwnerPubkey: F, // renamed → out1Owner
        out1Blinding: F,
        viewCtHashSenderWitness: F,
        viewCtHashRecipientWitness: F,
      },
    };
    expect(keySet(req)).toEqual(TRANSFER_SIGNALS);
  });

  it("withdraw: produced keys === circom signal set (renames applied)", () => {
    // wallet.ts buildWithdrawProved witness keys include noteOwnerPubkey and
    // noteAuditorPubkey that must be renamed to noteOwner and noteAuditor.
    const req: ProveRequest = {
      circuit: "withdraw",
      publicInputs: [
        F, // merkleRoot
        F, // nullifier
        F, // recipient
        F, // amount
        F, // relayer
        F, // relayerFee
        F, // auditorPubkey
        F, // viewCtHash
      ],
      witness: {
        noteAmount: F,
        noteOwnerPubkey: F, // renamed → noteOwner
        noteAuditorPubkey: F, // renamed → noteAuditor
        noteBlinding: F,
        spendingKey: F,
        leafIndex: F,
        merklePath: PATH,
        viewCtHashWitness: F,
      },
    };
    expect(keySet(req)).toEqual(WITHDRAW_SIGNALS);
  });
});

describe("proveRequestToCircomInput — value conversion", () => {
  it("converts 0x-hex public inputs to decimal strings", () => {
    const req: ProveRequest = {
      circuit: "deposit",
      publicInputs: [
        "0x000000000000000000000000000000000000000000000000000000000000000a", // 10
        "0x0000000000000000000000000000000000000000000000000000000000000001", // 1
        "0x0000000000000000000000000000000000000000000000000000000000000002", // 2
        "0x0000000000000000000000000000000000000000000000000000000000000003", // 3
      ],
      witness: {
        ownerPubkey: "0x0000000000000000000000000000000000000000000000000000000000000004",
        blinding: "0x0000000000000000000000000000000000000000000000000000000000000005",
        viewCtHashWitness: "0x0000000000000000000000000000000000000000000000000000000000000006",
      },
    };
    const out = proveRequestToCircomInput(req);
    expect(out.commitment).toBe("10");
    expect(out.amount).toBe("1");
    expect(out.ownerPubkey).toBe("4");
    expect(out.blinding).toBe("5");
  });

  it("converts array witness values (merkle path) to decimal string arrays", () => {
    const req: ProveRequest = {
      circuit: "withdraw",
      publicInputs: [F, F, F, F, F, F, F, F],
      witness: {
        noteAmount: F,
        noteOwnerPubkey: F,
        noteAuditorPubkey: F,
        noteBlinding: F,
        spendingKey: F,
        leafIndex: F,
        merklePath: [
          "0x0000000000000000000000000000000000000000000000000000000000000007",
          ...Array.from({ length: 19 }, () => F),
        ],
        viewCtHashWitness: F,
      },
    };
    const out = proveRequestToCircomInput(req);
    expect(Array.isArray(out.merklePath)).toBe(true);
    expect((out.merklePath as string[])[0]).toBe("7");
  });
});

describe("proveRequestToCircomInput — error cases", () => {
  it("throws on unknown circuit", () => {
    const req = { circuit: "unknown", publicInputs: [], witness: {} } as unknown as ProveRequest;
    expect(() => proveRequestToCircomInput(req)).toThrow("unknown circuit");
  });

  it("throws when public inputs count mismatches", () => {
    const req: ProveRequest = {
      circuit: "deposit",
      publicInputs: [F, F], // only 2 instead of 4
      witness: {},
    };
    expect(() => proveRequestToCircomInput(req)).toThrow("expected 4 public inputs, got 2");
  });
});
