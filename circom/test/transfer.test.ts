/**
 * Transfer circuit equivalence tests.
 * Mirrors tools/prover/src/circuits/transfer.rs tests:
 *   1. honest transfer → satisfiable
 *   2. value_violation → rejected
 *   3. wraparound_mint → rejected
 *   4. forged_merkle_path → rejected
 *   5. same_input_note → rejected
 *   6. input_leaf_index_above_depth → rejected
 */
import { describe, it, expect, beforeAll } from "vitest";
import { BN254_MODULUS, Field, commitNote, computeNullifier, poseidon2 } from "@shielded-near/core";
import { MerkleTree } from "@shielded-near/client";
import { load } from "./helpers.js";
import { honestTransferInput } from "./fixtures.js";

describe("Transfer circuit", () => {
  // Shared circuit instance — load once for the whole suite.
  let circuit: Awaited<ReturnType<typeof load>>;
  beforeAll(async () => {
    circuit = await load("transfer.circom");
  });

  it("honest transfer → satisfiable", async () => {
    const input = honestTransferInput();
    const witness = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(witness);
  });

  it("value_violation → rejected", async () => {
    // out0Amount=150 breaks conservation (60+40 != 150+30), even with rebuilt commitmentOut0
    const recipAuditor = new Field(33n);
    const badCommitmentOut0 = commitNote({
      amount: 150n,
      ownerPubkey: new Field(100n),
      auditorPubkey: recipAuditor,
      blinding: new Field(3n),
    });
    const badInput = {
      ...honestTransferInput(),
      out0Amount: 150n,
      commitmentOut0: badCommitmentOut0.value,
    };
    await expect(circuit.calculateWitness(badInput, true)).rejects.toThrow();
  });

  it("wraparound_mint → rejected", async () => {
    // huge = (1<<100) * (1<<30) = 1<<130, which is > 2^128 (fails RangeCheck(128))
    // out1 = 100 - huge (mod p), so conservation holds in-field
    const recipAuditor = new Field(33n);
    const sk = new Field(7n);
    const owner = poseidon2(sk, new Field(0n));

    const huge = (1n << 100n) * (1n << 30n); // = 1n << 130n
    const out1 = ((100n - huge) % BN254_MODULUS + BN254_MODULUS) % BN254_MODULUS;

    const badCommitmentOut0 = commitNote({
      amount: huge,
      ownerPubkey: new Field(100n),
      auditorPubkey: recipAuditor,
      blinding: new Field(3n),
    });
    const badCommitmentOut1 = commitNote({
      amount: out1,
      ownerPubkey: owner,
      auditorPubkey: recipAuditor,
      blinding: new Field(4n),
    });

    const badInput = {
      ...honestTransferInput(),
      out0Amount: huge,
      out1Amount: out1,
      commitmentOut0: badCommitmentOut0.value,
      commitmentOut1: badCommitmentOut1.value,
    };
    await expect(circuit.calculateWitness(badInput, true)).rejects.toThrow();
  });

  it("forged_merkle_path → rejected", async () => {
    // Replace merkleRoot + both paths with those of a different tree (leaves 999, 1000)
    const fakeTree = new MerkleTree();
    fakeTree.append(new Field(999n));
    fakeTree.append(new Field(1000n));

    const fakeRoot = fakeTree.root();
    const fakePath0 = fakeTree.pathFor(0n);
    const fakePath1 = fakeTree.pathFor(1n);

    const badInput = {
      ...honestTransferInput(),
      merkleRoot: fakeRoot.value,
      in0Path: fakePath0.map((f) => f.value),
      in1Path: fakePath1.map((f) => f.value),
    };
    await expect(circuit.calculateWitness(badInput, true)).rejects.toThrow();
  });

  it("same_input_note → rejected", async () => {
    // Both inputs are the same note (amount=60, blinding=1) at leaf index 0.
    // nullifier0 == nullifier1 because sk, commitment, and leafIndex are identical.
    // The IsEqual(nullifier0, nullifier1) === 0 constraint fires and rejects the
    // witness; circom_tester's sanityCheck=true (second arg to calculateWitness)
    // is what surfaces that constraint violation as a throw.
    const sk = new Field(7n);
    const owner = poseidon2(sk, new Field(0n));
    const auditor = new Field(22n);
    const recipAuditor = new Field(33n);

    const c_in = commitNote({ amount: 60n, ownerPubkey: owner, auditorPubkey: auditor, blinding: new Field(1n) });

    // Tree holds the same commitment at both leaves; path0 is used for both inputs.
    const tree = new MerkleTree();
    tree.append(c_in); // index 0
    tree.append(c_in); // index 1 (same commitment)
    const path0 = tree.pathFor(0n);

    // Both nullifiers are the same (same sk, same commitment, same index 0).
    const n = computeNullifier(sk, c_in, 0n);

    // Outputs sum to 120 = 60+60 (double-counted total).
    const cout0 = commitNote({ amount: 120n, ownerPubkey: new Field(100n), auditorPubkey: recipAuditor, blinding: new Field(3n) });
    const cout1 = commitNote({ amount: 0n, ownerPubkey: owner, auditorPubkey: recipAuditor, blinding: new Field(4n) });

    const badInput = {
      ...honestTransferInput(),
      merkleRoot: tree.root().value,
      nullifier1: n.value,
      commitmentOut0: cout0.value,
      commitmentOut1: cout1.value,
      in0Path: path0.map((f) => f.value),
      in1Amount: 60n,
      in1Blinding: 1n,
      in1LeafIndex: 0n,
      in1Path: path0.map((f) => f.value),
      out0Amount: 120n,
      out1Amount: 0n,
    };
    await expect(circuit.calculateWitness(badInput, true)).rejects.toThrow();
  });

  it("input_leaf_index_above_depth → rejected", async () => {
    // in0LeafIndex = 2^20: low 20 bits == 0, so merkle inclusion still holds
    // (the tree path for leaf 0 is still valid), and we recompute nullifier0
    // for the evil index so nullifier holds too. Only Num2Bits(20) range check rejects.
    const sk = new Field(7n);
    const owner = poseidon2(sk, new Field(0n));
    const auditor = new Field(22n);

    const c_in0 = commitNote({ amount: 60n, ownerPubkey: owner, auditorPubkey: auditor, blinding: new Field(1n) });
    const evilIndex = 1n << 20n; // = 2^20, low 20 bits == 0 (matches leaf 0 path)

    // Recompute nullifier0 for evil_index so that constraint holds
    const evilNullifier0 = computeNullifier(sk, c_in0, evilIndex);

    const badInput = {
      ...honestTransferInput(),
      in0LeafIndex: evilIndex,
      nullifier0: evilNullifier0.value,
    };
    await expect(circuit.calculateWitness(badInput, true)).rejects.toThrow();
  });
});
