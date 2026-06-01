import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import type { InitArgs } from "./assemble.js";

export interface EmitInput {
  network: "testnet" | "mainnet";
  account: string;
  wasmPath: string;
  wasmSha256: string;
  initArgs: InitArgs;
  vkSha256: Record<string, string>;
  outDir: string;
}

/** Writes <outDir>/<network>-init-args.json and returns the operator command + summary. Does NOT broadcast. */
export function emitDeployCommand(i: EmitInput): { argsPath: string; command: string; summary: string } {
  mkdirSync(i.outDir, { recursive: true });
  const argsPath = join(i.outDir, `${i.network}-init-args.json`);
  writeFileSync(argsPath, JSON.stringify(i.initArgs));
  const command =
    `near contract deploy ${i.account} use-file ${i.wasmPath} ` +
    `with-init-call new json-args "$(cat ${argsPath})" ` +
    `prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' ` +
    `network-config ${i.network} sign-with-keychain send`;
  const summary =
    `network=${i.network} account=${i.account}\n` +
    `wasm=${i.wasmPath} sha256=${i.wasmSha256}\n` +
    `owner=${i.initArgs.owner} usdc_token=${i.initArgs.usdc_token}\n` +
    `vk sha256: deposit=${i.vkSha256.deposit} transfer=${i.vkSha256.transfer} withdraw=${i.vkSha256.withdraw}`;
  return { argsPath, command, summary };
}
