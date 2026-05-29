/**
 * Parity corpus: proves that circom templates in circom/circuits/lib/ compute
 * byte-identical values to the SDK oracle (@shielded-near/core + client).
 */
import { describe, it } from "vitest";
import { Field, commitNote, computeNullifier, poseidon2 } from "@shielded-near/core";
import { MerkleTree } from "@shielded-near/client";
import { load } from "./helpers.js";

// ---------------------------------------------------------------------------
// Deterministic pseudo-random field elements for reproducible test vectors.
// We use simple arithmetic sequences rather than crypto.getRandomValues so
// the test is deterministic without seeding.
// ---------------------------------------------------------------------------
function fakeField(seed: number): Field {
  // Spread across the field by multiplying seed by a large prime.
  return new Field(BigInt(seed) * 6364136223846793005n + 1442695040888963407n);
}

// ---------------------------------------------------------------------------
// 1. CommitNote parity
// ---------------------------------------------------------------------------
describe("CommitNote parity", () => {
  it("matches poseidon4(amount, ownerPubkey, auditorPubkey, blinding) for 5 random tuples", async () => {
    const circuit = await load("test/commit_test.circom");

    const tuples = [
      { amount: 1_000_000n, owner: fakeField(1), auditor: fakeField(2), blinding: fakeField(3) },
      { amount: 500_000n,   owner: fakeField(4), auditor: fakeField(5), blinding: fakeField(6) },
      { amount: 0n,         owner: fakeField(7), auditor: fakeField(8), blinding: fakeField(9) },
      { amount: 999999999n, owner: fakeField(10), auditor: fakeField(11), blinding: fakeField(12) },
      { amount: 1n,         owner: fakeField(13), auditor: fakeField(14), blinding: fakeField(15) },
    ];

    for (const { amount, owner, auditor, blinding } of tuples) {
      const oracleResult = commitNote({
        amount,
        ownerPubkey: owner,
        auditorPubkey: auditor,
        blinding,
      });

      const witness = await circuit.calculateWitness({
        amount: amount,
        ownerPubkey: owner.value,
        auditorPubkey: auditor.value,
        blinding: blinding.value,
      }, true);

      await circuit.checkConstraints(witness);
      await circuit.assertOut(witness, { out: oracleResult.value });
    }
  });
});

// ---------------------------------------------------------------------------
// 2. OwnerPubkey parity
// ---------------------------------------------------------------------------
describe("OwnerPubkey parity", () => {
  it("matches poseidon2(spendingKey, 0) for 5 spending keys", async () => {
    const circuit = await load("test/owner_test.circom");

    const keys = [fakeField(100), fakeField(200), fakeField(300), fakeField(400), fakeField(500)];

    for (const sk of keys) {
      const oracleResult = poseidon2(sk, new Field(0n));

      const witness = await circuit.calculateWitness({
        spendingKey: sk.value,
      }, true);

      await circuit.checkConstraints(witness);
      await circuit.assertOut(witness, { out: oracleResult.value });
    }
  });
});

// ---------------------------------------------------------------------------
// 3. Nullifier parity
// ---------------------------------------------------------------------------
describe("Nullifier parity", () => {
  it("matches computeNullifier(spendingKey, commitment, leafIndex) for 5 cases", async () => {
    const circuit = await load("test/nullifier_test.circom");

    const cases = [
      { sk: fakeField(1000), commitment: fakeField(2000), leafIndex: 0n },
      { sk: fakeField(1001), commitment: fakeField(2001), leafIndex: 1n },
      { sk: fakeField(1002), commitment: fakeField(2002), leafIndex: 7n },
      { sk: fakeField(1003), commitment: fakeField(2003), leafIndex: 100n },
      { sk: fakeField(1004), commitment: fakeField(2004), leafIndex: 1048575n }, // 2^20 - 1 (max depth-20 index)
    ];

    for (const { sk, commitment, leafIndex } of cases) {
      const oracleResult = computeNullifier(sk, commitment, leafIndex);

      const witness = await circuit.calculateWitness({
        spendingKey: sk.value,
        commitment: commitment.value,
        leafIndex: leafIndex,
      }, true);

      await circuit.checkConstraints(witness);
      await circuit.assertOut(witness, { out: oracleResult.value });
    }
  });
});

// ---------------------------------------------------------------------------
// 4. MerkleInclusion parity
// ---------------------------------------------------------------------------
describe("MerkleInclusion parity", () => {
  it("accepts valid inclusion witness for leaves in a populated tree", async () => {
    const circuit = await load("test/merkle_test.circom");

    // Build a tree with several leaves.
    const tree = new MerkleTree();
    const leaves = [fakeField(10), fakeField(20), fakeField(30), fakeField(40), fakeField(50)];
    const indices: bigint[] = [];
    for (const leaf of leaves) {
      const idx = tree.append(leaf);
      indices.push(BigInt(idx));
    }

    const root = tree.root();

    // Test each leaf.
    for (let i = 0; i < leaves.length; i++) {
      const leafIndex = indices[i];
      const leaf = leaves[i];
      const pathElements = tree.pathFor(leafIndex);

      // Decompose leafIndex into 20 LE bits.
      const indexBits: bigint[] = [];
      for (let b = 0; b < 20; b++) {
        indexBits.push((leafIndex >> BigInt(b)) & 1n);
      }

      // calculateWitness will throw if root === cur[DEPTH] is violated.
      const witness = await circuit.calculateWitness({
        leaf: leaf.value,
        root: root.value,
        indexBits,
        pathElements: pathElements.map((f) => f.value),
      }, true);

      await circuit.checkConstraints(witness);
    }
  });
});
