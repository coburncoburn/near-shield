import { readFileSync, writeFileSync } from "node:fs";
import { vkJsonToContractBytes } from "@shielded-near/sdk";
const [, , vkJsonPath, vkBinPath] = process.argv;
if (!vkJsonPath || !vkBinPath) { console.error("usage: vk-to-bin.ts <vk.json> <vk.bin>"); process.exit(1); }
const vk = JSON.parse(readFileSync(vkJsonPath, "utf8"));
writeFileSync(vkBinPath, Buffer.from(vkJsonToContractBytes(vk)));
