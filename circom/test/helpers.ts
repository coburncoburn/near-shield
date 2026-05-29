import { wasm as wasmTester } from "circom_tester";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

// circom_tester compiles the circuit (needs `circom` in PATH and -l node_modules).
export async function load(relCircuitPath: string) {
  return wasmTester(path.join(root, "circuits", relCircuitPath), {
    include: [path.join(root, "node_modules")],
  });
}
