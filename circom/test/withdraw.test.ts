/**
 * Withdraw circuit equivalence tests.
 * Mirrors tools/prover/src/circuits/withdraw.rs tests:
 *   1. honest withdraw → satisfiable
 *   2. wrong_spending_key → rejected
 *   3. forged_merkle_path → rejected
 *   4. fee_exceeds_amount → rejected
 *   5. leaf_index_above_depth → rejected
 */
import { describe, it, expect, beforeAll } from "vitest";
import { Field, commitNote, computeNullifier, poseidon2 } from "@shielded-near/core";
import { MerkleTree } from "@shielded-near/client";
import { load } from "./helpers.js";

/**
 * Canonical honest withdraw inputs.
 * Exported so future prove-verify tests can import and reuse them.
 * Mirrors withdraw.rs::honest():
 *   sk=7, owner=poseidon2(7,0), auditor=22, blinding=33, amount=100,
 *   recipient=99, relayer=77, relayerFee=5, viewCtHash=13, leafIndex=0.
 */
export function honestWithdrawInput() {
  const sk = new Field(7n);
  const owner = poseidon2(sk, new Field(0n));
  const auditor = new Field(22n);
  const blinding = new Field(33n);
  const amount = 100n;
  const recipient = 99n;
  const relayer = 77n;
  const relayerFee = 5n;
  const viewCtHash = 13n;

  const commitment = commitNote({
    amount,
    ownerPubkey: owner,
    auditorPubkey: auditor,
    blinding,
  });

  const tree = new MerkleTree();
  tree.append(commitment); // index 0

  const merkleRoot = tree.root();
  const merklePath = tree.pathFor(0n);
  const nullifier = computeNullifier(sk, commitment, 0n);

  return {
    // public
    merkleRoot: merkleRoot.value,
    nullifier: nullifier.value,
    recipient,
    amount,
    relayer,
    relayerFee,
    auditorPubkey: auditor.value,
    viewCtHash,
    // private
    noteAmount: amount,
    noteOwner: owner.value,
    noteAuditor: auditor.value,
    noteBlinding: blinding.value,
    spendingKey: sk.value,
    leafIndex: 0n,
    merklePath: merklePath.map((f) => f.value),
    viewCtHashWitness: viewCtHash, // mirrors public viewCtHash — intentional duplication
  };
}

describe("Withdraw circuit", () => {
  // Shared circuit instance — load once for the whole suite.
  let circuit: Awaited<ReturnType<typeof load>>;
  beforeAll(async () => {
    circuit = await load("withdraw.circom");
  });

  it("honest withdraw → satisfiable", async () => {
    const input = honestWithdrawInput();
    const witness = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(witness);
  });

  it("wrong_spending_key → rejected", async () => {
    // sk=8 means OwnerPubkey(8) != noteOwner (which was derived from sk=7),
    // and the nullifier also mismatches — owner check fires first.
    const badInput = {
      ...honestWithdrawInput(),
      spendingKey: 8n,
    };
    await expect(circuit.calculateWitness(badInput, true)).rejects.toThrow();
  });

  it("forged_merkle_path → rejected", async () => {
    // one-leaf fake tree: root differs from honest, so MerkleInclusion rejects
    // Replace merkleRoot + merklePath with those of a tree containing a different note (999).
    const fakeTree = new MerkleTree();
    fakeTree.append(new Field(999n));

    const fakeRoot = fakeTree.root();
    const fakePath = fakeTree.pathFor(0n);

    const badInput = {
      ...honestWithdrawInput(),
      merkleRoot: fakeRoot.value,
      merklePath: fakePath.map((f) => f.value),
    };
    await expect(circuit.calculateWitness(badInput, true)).rejects.toThrow();
  });

  it("fee_exceeds_amount → rejected", async () => {
    // relayerFee=101 > amount=100: U64Geq computes 100-101 = -1 mod p,
    // which doesn't fit 64 bits → Num2Bits(64) rejects.
    const badInput = {
      ...honestWithdrawInput(),
      relayerFee: 101n,
    };
    await expect(circuit.calculateWitness(badInput, true)).rejects.toThrow();
  });

  it("leaf_index_above_depth → rejected", async () => {
    // leafIndex = 2^20: low 20 bits == 0, so merkle inclusion holds (uses leaf 0 path).
    // Recompute nullifier for evil_index so that constraint holds too.
    // Only Num2Bits(20) on leafIndex rejects.
    //
    // Local re-derivation mirrors honestWithdrawInput()'s exact note params
    // (sk=7, auditor=22, blinding=33, amount=100) because the builder doesn't
    // expose the internal commitment — we need it to recompute the nullifier.
    const sk = new Field(7n);
    const owner = poseidon2(sk, new Field(0n));
    const auditor = new Field(22n);
    const blinding = new Field(33n);

    const commitment = commitNote({
      amount: 100n,
      ownerPubkey: owner,
      auditorPubkey: auditor,
      blinding,
    });

    const evilIndex = 1n << 20n; // = 2^20, low 20 bits == 0 (matches leaf 0 path)
    const evilNullifier = computeNullifier(sk, commitment, evilIndex);

    const badInput = {
      ...honestWithdrawInput(),
      leafIndex: evilIndex,
      nullifier: evilNullifier.value,
    };
    await expect(circuit.calculateWitness(badInput, true)).rejects.toThrow();
  });
});
