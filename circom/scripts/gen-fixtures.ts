/**
 * gen-fixtures.ts
 *
 * Generates snarkjs Groth16 fixtures for all three circuits (deposit, transfer,
 * withdraw) and writes them to circom/fixtures/<circuit>/.
 *
 * For each circuit:
 *   proof.json   — raw snarkjs proof object
 *   public.json  — publicSignals array (decimal strings)
 *   vk.json      — exportVerificationKey output
 *   proof.bin    — snarkjsProofToBytes(proof)    [256 bytes]
 *   vk.bin       — vkJsonToContractBytes(vk)
 *   public.bin   — each public signal as 32-byte big-endian field element
 *
 * circom/fixtures/meta.json — { <circuit>: { r1csSha256, nPublic } }
 *
 * Run with:
 *   pnpm --filter @shielded-near/circom exec tsx scripts/gen-fixtures.ts
 */

import * as snarkjs from "snarkjs";
import * as fs from "fs";
import * as crypto from "crypto";
import * as path from "path";
import { fileURLToPath } from "url";
import { vkJsonToContractBytes, snarkjsProofToBytes } from "@shielded-near/sdk";
import {
  honestDepositInput,
  honestTransferInput,
  honestWithdrawInput,
} from "../test/fixtures.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const BUILD = path.join(ROOT, "build");
const FIXTURES = path.join(ROOT, "fixtures");

type CircuitName = "deposit" | "transfer" | "withdraw";

function inputForCircuit(c: CircuitName): Record<string, unknown> {
  switch (c) {
    case "deposit":
      return honestDepositInput() as Record<string, unknown>;
    case "transfer":
      return honestTransferInput() as Record<string, unknown>;
    case "withdraw":
      return honestWithdrawInput() as Record<string, unknown>;
  }
}

/**
 * Convert a public signal (decimal string) to a 32-byte big-endian buffer.
 */
function signalToBe32(dec: string): Uint8Array {
  let v = BigInt(dec);
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

async function main() {
  const circuits: CircuitName[] = ["deposit", "transfer", "withdraw"];
  const meta: Record<string, { r1csSha256: string; nPublic: number }> = {};

  for (const c of circuits) {
    console.log(`\n=== ${c} ===`);

    const wasmPath = path.join(BUILD, `${c}_js`, `${c}.wasm`);
    const zkeyPath = path.join(BUILD, "keys", `${c}_dev.zkey`);
    const r1csPath = path.join(BUILD, `${c}.r1cs`);
    const outDir = path.join(FIXTURES, c);

    fs.mkdirSync(outDir, { recursive: true });

    // Build the honest input
    const input = inputForCircuit(c);

    // Prove
    console.log("  fullProve ...");
    const { proof, publicSignals } = await (snarkjs.groth16 as any).fullProve(
      input,
      wasmPath,
      zkeyPath
    );

    // Export VK
    console.log("  exportVerificationKey ...");
    const vk = await (snarkjs.zKey as any).exportVerificationKey(zkeyPath);

    // Encode to contract bytes
    const vkBin = vkJsonToContractBytes(vk);
    const proofBin = snarkjsProofToBytes(proof);

    // public.bin: concat of each signal as 32-byte BE
    const publicBin = new Uint8Array(publicSignals.length * 32);
    for (let i = 0; i < publicSignals.length; i++) {
      publicBin.set(signalToBe32(publicSignals[i]), i * 32);
    }

    // Write JSON files
    fs.writeFileSync(path.join(outDir, "proof.json"), JSON.stringify(proof, null, 2));
    fs.writeFileSync(path.join(outDir, "public.json"), JSON.stringify(publicSignals, null, 2));
    fs.writeFileSync(path.join(outDir, "vk.json"), JSON.stringify(vk, null, 2));

    // Write binary files
    fs.writeFileSync(path.join(outDir, "proof.bin"), Buffer.from(proofBin));
    fs.writeFileSync(path.join(outDir, "vk.bin"), Buffer.from(vkBin));
    fs.writeFileSync(path.join(outDir, "public.bin"), Buffer.from(publicBin));

    console.log(`  proof.bin: ${proofBin.length} bytes`);
    console.log(`  vk.bin:    ${vkBin.length} bytes  (nPublic=${vk.nPublic})`);
    console.log(`  public.bin: ${publicBin.length} bytes  (${publicSignals.length} signals)`);

    // Compute r1cs sha256
    const r1csBytes = fs.readFileSync(r1csPath);
    const r1csSha256 = crypto.createHash("sha256").update(r1csBytes).digest("hex");

    meta[c] = { r1csSha256, nPublic: vk.nPublic };
  }

  fs.writeFileSync(path.join(FIXTURES, "meta.json"), JSON.stringify(meta, null, 2));
  console.log("\nWrote circom/fixtures/meta.json");
  console.log("Done.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
