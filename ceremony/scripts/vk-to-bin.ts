import { readFileSync, writeFileSync } from "node:fs";
import { vkJsonToContractBytes } from "@shielded-near/sdk";
const [, , vkJsonPath, vkBinPath] = process.argv;
if (!vkJsonPath || !vkBinPath) { console.error("usage: vk-to-bin.ts <vk.json> <vk.bin>"); process.exit(1); }
try {
  const vk = JSON.parse(readFileSync(vkJsonPath, "utf8"));
  writeFileSync(vkBinPath, Buffer.from(vkJsonToContractBytes(vk)));
} catch (e) {
  console.error("vk-to-bin:", e instanceof Error ? e.message : String(e));
  process.exit(1);
}
