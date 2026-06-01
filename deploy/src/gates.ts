import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { vkJsonToContractBytes } from "@shielded-near/sdk";

export type Circuit = "deposit" | "transfer" | "withdraw";
export const VK_LEN: Record<Circuit, number> = { deposit: 768, transfer: 1088, withdraw: 1024 };

// sha256 of the contract VK bytes (vkJsonToContractBytes(<c> DEV vk.json), == sha256(circom/fixtures/<c>/vk.bin)).
// Copied VERBATIM from scripts/check-production-readiness.sh DEV_VK_FINGERPRINTS:
export const DEV_VK_FINGERPRINTS: Record<Circuit, string> = {
  deposit:  "8abe07dc84b83e87f469c02456546cea85ec2797a4006a13af5dd5009697ba4f",
  transfer: "1298e44b0ed0ed6227b1b6753d548359d865005afed77dabadb134c12571f171",
  withdraw: "d72df6c51b91bed8558977fca485c9b1392cccddca285939d17a52d68dd9d4cb",
};

export function vkSha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function assertVkLength(c: Circuit, bytes: Uint8Array): void {
  if (bytes.length !== VK_LEN[c])
    throw new Error(`${c}: VK is ${bytes.length} bytes, expected ${VK_LEN[c]}`);
}

/** Authoritative DEV-key block: fingerprints the ACTUAL bytes to be deployed. */
export function assertNotDevKey(c: Circuit, bytes: Uint8Array): void {
  const fp = vkSha256(bytes);
  if (fp === DEV_VK_FINGERPRINTS[c])
    throw new Error(`${c}: DEV verifying key detected (sha256=${fp}). Deploy ceremony keys, not DEV keys.`);
}

/** Build-check: production groth16-verifier WASM (not mock); size-gated. Throws on failure. */
export function runReadinessCheck(repoRoot: string): void {
  const r = spawnSync("bash", ["scripts/check-production-readiness.sh"], { cwd: repoRoot, encoding: "utf8" });
  if (r.error) throw new Error(`failed to spawn readiness check: ${r.error.message}`);
  if (r.status !== 0)
    throw new Error(`production readiness check failed (exit ${r.status}):\n${r.stdout}\n${r.stderr}`);
}
