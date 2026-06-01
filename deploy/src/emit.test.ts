import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect, afterEach } from "vitest";
import { emitDeployCommand } from "./emit.js";
import type { EmitInput } from "./emit.js";

let tmpDir: string | undefined;

afterEach(() => {
  if (tmpDir) {
    rmSync(tmpDir, { recursive: true, force: true });
    tmpDir = undefined;
  }
});

function makeTmpDir(): string {
  tmpDir = mkdtempSync(join(tmpdir(), "emit-test-"));
  return tmpDir;
}

const SAMPLE_INIT_ARGS = {
  owner: "owner.testnet",
  usdc_token: "usdc.testnet",
  vk_deposit: [1, 2, 3],
  vk_transfer: [4, 5, 6],
  vk_withdraw: [7, 8, 9],
};

const SAMPLE_VK_SHA256 = {
  deposit: "aabbcc",
  transfer: "ddeeff",
  withdraw: "112233",
};

function makeInput(network: "testnet" | "mainnet", outDir: string): EmitInput {
  return {
    network,
    account: `shielded.${network}`,
    wasmPath: `/artifacts/shielded.wasm`,
    wasmSha256: "deadbeef",
    initArgs: SAMPLE_INIT_ARGS,
    vkSha256: SAMPLE_VK_SHA256,
    outDir,
  };
}

describe("emitDeployCommand", () => {
  it("returns command containing 'near contract deploy <account> use-file <wasm> with-init-call new json-args' for mainnet", () => {
    const outDir = makeTmpDir();
    const input = makeInput("mainnet", outDir);
    const { command } = emitDeployCommand(input);

    expect(command).toContain(`near contract deploy ${input.account} use-file '${input.wasmPath}'`);
    expect(command).toContain("with-init-call new json-args");
    expect(command).toContain("network-config mainnet");
    expect(command).toContain("300.0 Tgas");
  });

  it("returns command containing 'network-config testnet' for testnet", () => {
    const outDir = makeTmpDir();
    const input = makeInput("testnet", outDir);
    const { command, argsPath } = emitDeployCommand(input);

    expect(command).toContain(`near contract deploy ${input.account} use-file '${input.wasmPath}'`);
    expect(command).toContain("with-init-call new json-args");
    expect(command).toContain("network-config testnet");
    expect(command).toContain(argsPath);
  });

  it("writes <outDir>/<network>-init-args.json that round-trips the initArgs", () => {
    const outDir = makeTmpDir();
    const input = makeInput("mainnet", outDir);
    const { argsPath } = emitDeployCommand(input);

    expect(argsPath).toBe(join(outDir, "mainnet-init-args.json"));
    const parsed = JSON.parse(readFileSync(argsPath, "utf8"));
    expect(parsed.owner).toBe(SAMPLE_INIT_ARGS.owner);
    expect(parsed.usdc_token).toBe(SAMPLE_INIT_ARGS.usdc_token);
    expect(parsed.vk_deposit).toEqual(SAMPLE_INIT_ARGS.vk_deposit);
    expect(parsed.vk_transfer).toEqual(SAMPLE_INIT_ARGS.vk_transfer);
    expect(parsed.vk_withdraw).toEqual(SAMPLE_INIT_ARGS.vk_withdraw);
  });

  it("writes testnet file at <outDir>/testnet-init-args.json", () => {
    const outDir = makeTmpDir();
    const input = makeInput("testnet", outDir);
    const { argsPath } = emitDeployCommand(input);

    expect(argsPath).toBe(join(outDir, "testnet-init-args.json"));
    const parsed = JSON.parse(readFileSync(argsPath, "utf8"));
    expect(parsed.owner).toBe(SAMPLE_INIT_ARGS.owner);
  });

  it("summary contains wasm sha256, all 3 vk sha256s, owner and usdc_token", () => {
    const outDir = makeTmpDir();
    const input = makeInput("mainnet", outDir);
    const { summary } = emitDeployCommand(input);

    expect(summary).toContain("deadbeef"); // wasmSha256
    expect(summary).toContain("aabbcc");   // deposit vk sha256
    expect(summary).toContain("ddeeff");   // transfer vk sha256
    expect(summary).toContain("112233");   // withdraw vk sha256
    expect(summary).toContain("owner.testnet");
    expect(summary).toContain("usdc.testnet");
  });

  it("returns plain strings + an args path, no broadcast", () => {
    // Structural check: emitDeployCommand only writes a file and returns strings.
    // No near-workspaces or RPC calls are made. The test itself makes no network requests.
    const outDir = makeTmpDir();
    const input = makeInput("mainnet", outDir);
    const result = emitDeployCommand(input);
    expect(typeof result.command).toBe("string");
    expect(typeof result.argsPath).toBe("string");
    expect(typeof result.summary).toBe("string");
  });
});
