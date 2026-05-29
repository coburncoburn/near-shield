/**
 * Task 6: DEV prove→verify roundtrip for all three circuits.
 *
 * Prerequisites: run `bash circom/scripts/dev-setup.sh` first to generate
 * build/keys/<circuit>_dev.zkey and build/keys/<circuit>_vk.json.
 * If keys are absent the tests are SKIPPED (not failed).
 */
import { describe, it, expect } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import * as snarkjs from "snarkjs";

import { honestDepositInput, honestTransferInput, honestWithdrawInput } from "./fixtures.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

function wasmPath(circuit: string) {
  return path.join(root, "build", `${circuit}_js`, `${circuit}.wasm`);
}
function zkeyPath(circuit: string) {
  return path.join(root, "build", "keys", `${circuit}_dev.zkey`);
}
function vkPath(circuit: string) {
  return path.join(root, "build", "keys", `${circuit}_vk.json`);
}

type CircuitName = "deposit" | "transfer" | "withdraw";

const circuits: CircuitName[] = ["deposit", "transfer", "withdraw"];

describe(
  "Groth16 prove→verify roundtrip",
  () => {
    for (const circuit of circuits) {
      const hasKeys = existsSync(zkeyPath(circuit)) && existsSync(vkPath(circuit));

      it(
        `${circuit}: fullProve then verify → true`,
        async () => {
          if (!hasKeys) {
            console.log(
              `SKIP ${circuit}: build/keys/${circuit}_dev.zkey not found. Run circom/scripts/dev-setup.sh first.`
            );
            return;
          }

          const wasm = wasmPath(circuit);
          const zkey = zkeyPath(circuit);
          const vk = JSON.parse(readFileSync(vkPath(circuit), "utf8"));

          let input: Record<string, unknown>;
          if (circuit === "deposit") {
            input = honestDepositInput() as Record<string, unknown>;
          } else if (circuit === "transfer") {
            input = honestTransferInput() as Record<string, unknown>;
          } else {
            input = honestWithdrawInput() as Record<string, unknown>;
          }

          const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey);
          const valid = await snarkjs.groth16.verify(vk, publicSignals, proof);

          expect(valid).toBe(true);
        },
        // fullProve for transfer can take several seconds — use 300s to be safe
        300_000
      );
    }
  }
);
