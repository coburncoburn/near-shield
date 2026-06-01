import { readFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";

export interface DeployConfig {
  network: "sandbox" | "testnet" | "mainnet";
  account: string;
  owner: string;
  usdcToken: string;
}

const CONFIG_DIR = resolve(import.meta.dirname, "../config");

export function loadConfig(
  network: "sandbox" | "testnet" | "mainnet",
  overrides?: Partial<DeployConfig>
): DeployConfig {
  const filePath = join(CONFIG_DIR, `${network}.json`);

  let fileValues: Partial<DeployConfig> = {};
  if (existsSync(filePath)) {
    fileValues = JSON.parse(readFileSync(filePath, "utf8")) as Partial<DeployConfig>;
  }

  const merged: DeployConfig = {
    network,
    account: overrides?.account ?? fileValues.account ?? "",
    owner: overrides?.owner ?? fileValues.owner ?? "",
    usdcToken: overrides?.usdcToken ?? fileValues.usdcToken ?? "",
  };

  if (!merged.account) {
    throw new Error(`loadConfig(${network}): "account" is required but missing after merge`);
  }
  if (!merged.owner) {
    throw new Error(`loadConfig(${network}): "owner" is required but missing after merge`);
  }
  if (!merged.usdcToken) {
    throw new Error(
      `loadConfig(${network}): "usdcToken" is required but missing — mainnet value must be runbook-verified`
    );
  }

  return merged;
}
