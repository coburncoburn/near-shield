import { wasm as wasmTester } from "circom_tester";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

// Minimal typing for circom_tester (ships no .d.ts); keeps signal-name typos
// from silently passing at call sites in later tasks.
export interface CircomTester {
  calculateWitness(input: Record<string, unknown>, sanityCheck?: boolean): Promise<bigint[]>;
  assertOut(witness: bigint[], expected: Record<string, unknown>): Promise<void>;
  checkConstraints(witness: bigint[]): Promise<void>;
}

// circom_tester compiles the circuit (needs `circom` in PATH and -l node_modules).
export async function load(relCircuitPath: string): Promise<CircomTester> {
  return wasmTester(path.join(root, "circuits", relCircuitPath), {
    include: [path.join(root, "node_modules")],
  }) as Promise<CircomTester>;
}
