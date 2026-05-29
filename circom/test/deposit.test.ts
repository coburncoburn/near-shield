/**
 * Deposit circuit equivalence tests.
 * Mirrors tools/prover/src/circuits/deposit.rs tests:
 *   1. honest deposit → satisfiable
 *   2. wrong amount → rejected
 *   3. view_ct_hash != witness → rejected
 */
import { describe, it, expect, beforeAll } from "vitest";
import { load } from "./helpers.js";
import { honestDepositInput } from "./fixtures.js";

describe("Deposit circuit", () => {
  // Shared circuit instance — load once for the whole suite.
  let circuit: Awaited<ReturnType<typeof load>>;
  beforeAll(async () => {
    circuit = await load("deposit.circom");
  });

  it("honest deposit → satisfiable", async () => {
    const input = honestDepositInput();
    const witness = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(witness);
  });

  it("wrong amount → rejected", async () => {
    // commitment built for amount=100, but we hand amount=200 to the circuit
    const badInput = {
      ...honestDepositInput(),
      amount: 200n, // mismatch
    };

    await expect(circuit.calculateWitness(badInput, true)).rejects.toThrow();
  });

  it("view_ct_hash != witness → rejected", async () => {
    const badInput = {
      ...honestDepositInput(),
      viewCtHashWitness: 999n, // mismatch: witness != public viewCtHash
    };

    await expect(circuit.calculateWitness(badInput, true)).rejects.toThrow();
  });
});
