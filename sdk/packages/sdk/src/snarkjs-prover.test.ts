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
import { existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { proveRequestToCircomInput, SnarkjsProver } from "./snarkjs-prover.js";
import { nodeArtifactProvider } from "./node-artifacts.js";
import type { ProveRequest } from "./prover.js";
import { Field, commitNote, computeNullifier, poseidon2 } from "@shielded-near/core";
import { MerkleTree } from "@shielded-near/client";

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
    expect(out.viewCtHashWitness).toBe("6");
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

  it("throws when a witness value is an empty string", () => {
    const req: ProveRequest = {
      circuit: "deposit",
      publicInputs: [F, F, F, F],
      witness: {
        ownerPubkey: "",
        blinding: F,
        viewCtHashWitness: F,
      },
    };
    expect(() => proveRequestToCircomInput(req)).toThrow(
      "proveRequestToCircomInput: expected non-empty hex string"
    );
  });

  it("throws when a public input is not a string", () => {
    const req = {
      circuit: "deposit",
      publicInputs: [42, F, F, F], // number instead of hex string
      witness: {
        ownerPubkey: F,
        blinding: F,
        viewCtHashWitness: F,
      },
    } as unknown as ProveRequest;
    expect(() => proveRequestToCircomInput(req)).toThrow(
      "proveRequestToCircomInput: expected non-empty hex string"
    );
  });
});

// ---------------------------------------------------------------------------
// SnarkjsProver in-process proving tests
// ---------------------------------------------------------------------------

const here = dirname(fileURLToPath(import.meta.url));
// sdk/packages/sdk/src/ → repo root is ../../../../
const repoRoot = resolve(here, "..", "..", "..", "..");
const buildDir = resolve(repoRoot, "circom", "build");

/** Convert a bigint field value to a 0x-prefixed 32-byte big-endian hex string. */
function fhex(v: bigint): string {
  return new Field(v).toHex();
}

/** Convert an array of bigint field values to hex strings. */
function fhexArr(arr: bigint[]): string[] {
  return arr.map(fhex);
}

describe(
  "SnarkjsProver (in-process proving)",
  () => {
    const circuits = ["deposit", "transfer", "withdraw"] as const;

    for (const circuit of circuits) {
      const zkeyFile = resolve(buildDir, "keys", `${circuit}_dev.zkey`);
      const keysExist = existsSync(zkeyFile);

      it.skipIf(!keysExist)(
        `${circuit}: fullProve produces 256-byte proof`,
        async () => {
          const prover = new SnarkjsProver(nodeArtifactProvider(buildDir));
          let req: ProveRequest;

          if (circuit === "deposit") {
            const amount = 100n;
            const ownerPubkey = new Field(11n);
            const auditorPubkey = new Field(22n);
            const blinding = new Field(33n);
            const viewCtHash = 7n;
            const commitment = commitNote({ amount, ownerPubkey, auditorPubkey, blinding });
            req = {
              circuit: "deposit",
              publicInputs: [
                fhex(commitment.value),
                fhex(amount),
                fhex(auditorPubkey.value),
                fhex(viewCtHash),
              ],
              witness: {
                ownerPubkey: fhex(ownerPubkey.value),
                blinding: fhex(blinding.value),
                viewCtHashWitness: fhex(viewCtHash),
              },
            };
          } else if (circuit === "transfer") {
            const sk = new Field(7n);
            const owner = poseidon2(sk, new Field(0n));
            const auditor = new Field(22n);
            const recipAuditor = new Field(33n);

            const c_in0 = commitNote({ amount: 60n, ownerPubkey: owner, auditorPubkey: auditor, blinding: new Field(1n) });
            const c_in1 = commitNote({ amount: 40n, ownerPubkey: owner, auditorPubkey: auditor, blinding: new Field(2n) });

            const tree = new MerkleTree();
            tree.append(c_in0);
            tree.append(c_in1);

            const merkleRoot = tree.root();
            const in0Path = tree.pathFor(0n);
            const in1Path = tree.pathFor(1n);

            const nullifier0 = computeNullifier(sk, c_in0, 0n);
            const nullifier1 = computeNullifier(sk, c_in1, 1n);

            const commitmentOut0 = commitNote({ amount: 70n, ownerPubkey: new Field(100n), auditorPubkey: recipAuditor, blinding: new Field(3n) });
            const commitmentOut1 = commitNote({ amount: 30n, ownerPubkey: owner, auditorPubkey: recipAuditor, blinding: new Field(4n) });

            const viewCtHashSender = 13n;
            const viewCtHashRecipient = 14n;

            req = {
              circuit: "transfer",
              publicInputs: [
                fhex(merkleRoot.value),
                fhex(nullifier0.value),
                fhex(nullifier1.value),
                fhex(commitmentOut0.value),
                fhex(commitmentOut1.value),
                fhex(auditor.value),
                fhex(recipAuditor.value),
                fhex(viewCtHashSender),
                fhex(viewCtHashRecipient),
              ],
              witness: {
                in0Amount: fhex(60n),
                in0OwnerPubkey: fhex(owner.value),   // renamed → in0Owner
                in0Blinding: fhex(1n),
                in0LeafIndex: fhex(0n),
                in0Path: fhexArr(in0Path.map((f) => f.value)),
                in1Amount: fhex(40n),
                in1OwnerPubkey: fhex(owner.value),   // renamed → in1Owner
                in1Blinding: fhex(2n),
                in1LeafIndex: fhex(1n),
                in1Path: fhexArr(in1Path.map((f) => f.value)),
                spendingKey: fhex(sk.value),
                out0Amount: fhex(70n),
                out0OwnerPubkey: fhex(100n),          // renamed → out0Owner; different recipient owner (not the sender)
                out0Blinding: fhex(3n),
                out1Amount: fhex(30n),
                out1OwnerPubkey: fhex(owner.value),   // renamed → out1Owner
                out1Blinding: fhex(4n),
                viewCtHashSenderWitness: fhex(viewCtHashSender),
                viewCtHashRecipientWitness: fhex(viewCtHashRecipient),
              },
            };
          } else {
            // withdraw
            const sk = new Field(7n);
            const owner = poseidon2(sk, new Field(0n));
            const auditor = new Field(22n);
            const blinding = new Field(33n);
            const amount = 100n;
            const recipient = 99n;
            const relayer = 77n;
            const relayerFee = 5n;
            const viewCtHash = 13n;

            const commitment = commitNote({ amount, ownerPubkey: owner, auditorPubkey: auditor, blinding });
            const tree = new MerkleTree();
            tree.append(commitment);

            const merkleRoot = tree.root();
            const merklePath = tree.pathFor(0n);
            const nullifier = computeNullifier(sk, commitment, 0n);

            req = {
              circuit: "withdraw",
              publicInputs: [
                fhex(merkleRoot.value),
                fhex(nullifier.value),
                fhex(recipient),
                fhex(amount),
                fhex(relayer),
                fhex(relayerFee),
                fhex(auditor.value),
                fhex(viewCtHash),
              ],
              witness: {
                noteAmount: fhex(amount),
                noteOwnerPubkey: fhex(owner.value),   // renamed → noteOwner
                noteAuditorPubkey: fhex(auditor.value), // renamed → noteAuditor
                noteBlinding: fhex(blinding.value),
                spendingKey: fhex(sk.value),
                leafIndex: fhex(0n),
                merklePath: fhexArr(merklePath.map((f) => f.value)),
                viewCtHashWitness: fhex(viewCtHash),
              },
            };
          }

          const result = await prover.prove(req);
          expect(result.length).toBe(256);
        },
        120_000 // generous timeout — snarkjs fullProve is slow
      );
    }
  }
);
