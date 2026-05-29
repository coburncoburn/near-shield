/**
 * Deposit circuit equivalence tests.
 * Mirrors tools/prover/src/circuits/deposit.rs tests:
 *   1. honest deposit → satisfiable
 *   2. wrong amount → rejected
 *   3. view_ct_hash != witness → rejected
 */
import { describe, it, expect, beforeAll } from "vitest";
import { Field, commitNote } from "@shielded-near/core";
import { load } from "./helpers.js";

describe("Deposit circuit", () => {
  // Shared circuit instance — load once for the whole suite.
  let circuit: Awaited<ReturnType<typeof load>>;
  beforeAll(async () => {
    circuit = await load("deposit.circom");
  });

  // Deterministic test vectors (mirrors deposit.rs: amount=100, owner=11, auditor=22, blinding=33).
  const amount = 100n;
  const ownerPubkey = new Field(11n);
  const auditorPubkey = new Field(22n);
  const blinding = new Field(33n);
  const viewCtHash = 7n; // arbitrary hash value

  it("honest deposit → satisfiable", async () => {
    const commitment = commitNote({ amount, ownerPubkey, auditorPubkey, blinding });

    const input = {
      commitment: commitment.value,
      amount,
      auditorPubkey: auditorPubkey.value,
      viewCtHash,
      ownerPubkey: ownerPubkey.value,
      blinding: blinding.value,
      viewCtHashWitness: viewCtHash,
    };

    const witness = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(witness);
  });

  it("wrong amount → rejected", async () => {
    // commitment built for amount=100, but we hand amount=200 to the circuit
    const commitment = commitNote({ amount, ownerPubkey, auditorPubkey, blinding });

    const badInput = {
      commitment: commitment.value,
      amount: 200n,            // mismatch
      auditorPubkey: auditorPubkey.value,
      viewCtHash,
      ownerPubkey: ownerPubkey.value,
      blinding: blinding.value,
      viewCtHashWitness: viewCtHash,
    };

    await expect(circuit.calculateWitness(badInput, true)).rejects.toThrow();
  });

  it("view_ct_hash != witness → rejected", async () => {
    const commitment = commitNote({ amount, ownerPubkey, auditorPubkey, blinding });

    const badInput = {
      commitment: commitment.value,
      amount,
      auditorPubkey: auditorPubkey.value,
      viewCtHash,
      ownerPubkey: ownerPubkey.value,
      blinding: blinding.value,
      viewCtHashWitness: 999n, // mismatch: witness != public viewCtHash
    };

    await expect(circuit.calculateWitness(badInput, true)).rejects.toThrow();
  });
});
