import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { vkJsonToContractBytes } from "@shielded-near/sdk";
import { type Circuit, assertVkLength, assertNotDevKey, vkSha256 } from "./gates.js";

export interface InitArgs {
  owner: string;
  usdc_token: string;
  vk_deposit: number[];
  vk_transfer: number[];
  vk_withdraw: number[];
}

export interface AssembleResult {
  initArgs: InitArgs;
  vkSha256: Record<Circuit, string>;
}

const CIRCUITS: Circuit[] = ["deposit", "transfer", "withdraw"];

function readVkJson(vkDir: string, c: Circuit): unknown {
  const nested = join(vkDir, c, "vk.json");
  const flat = join(vkDir, `${c}_vk.json`);
  const p = existsSync(nested) ? nested : flat;
  if (!existsSync(p))
    throw new Error(
      `vk.json not found for ${c} under ${vkDir} (looked at ${nested} and ${flat})`
    );
  return JSON.parse(readFileSync(p, "utf8"));
}

/** Reads the ceremony vk.json per circuit, runs the gates on the ACTUAL deployed bytes, assembles new() args. */
export function assembleInitArgs(
  vkDir: string,
  owner: string,
  usdcToken: string
): AssembleResult {
  const bytes = {} as Record<Circuit, Uint8Array>;
  for (const c of CIRCUITS) {
    const b = vkJsonToContractBytes(readVkJson(vkDir, c) as any);
    assertVkLength(c, b); // length of the bytes actually deployed (Gate #3)
    assertNotDevKey(c, b); // authoritative DEV-key block (Gate #2)
    bytes[c] = b;
  }
  return {
    initArgs: {
      owner,
      usdc_token: usdcToken,
      vk_deposit: Array.from(bytes.deposit),
      vk_transfer: Array.from(bytes.transfer),
      vk_withdraw: Array.from(bytes.withdraw),
    },
    vkSha256: {
      deposit: vkSha256(bytes.deposit),
      transfer: vkSha256(bytes.transfer),
      withdraw: vkSha256(bytes.withdraw),
    },
  };
}
