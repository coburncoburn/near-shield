/**
 * E2E tests for deploy.ts: tests the full pipeline (gates → assemble → sandbox|emit).
 *
 * skipReadiness:true is used throughout so the suite doesn't re-invoke the slow
 * check-production-readiness.sh script — that script is exercised separately in
 * gates.test.ts.  The production CLI (main) refuses --skip-readiness for mainnet/testnet.
 */
import { describe, it, expect } from "vitest";
import { mkdirSync, copyFileSync, existsSync, readFileSync, rmSync } from "node:fs";
import { resolve, join } from "node:path";
import { tmpdir } from "node:os";
import { run, MAINNET_CHECKLIST } from "./deploy.js";

// Repo root: deploy/src → ../.. = repo root
const REPO = resolve(import.meta.dirname, "../..");
const WASM = resolve(REPO, "target/wasm32-unknown-unknown/release/shielded_pool.opt.wasm");
const VK_DIR = resolve(REPO, "ceremony/out");

// Prereqs for sandbox/emit tests that need ceremony VKs and the opt WASM.
const ceremonyPresent = ["deposit", "transfer", "withdraw"].every((c) =>
  existsSync(resolve(VK_DIR, c, "vk.json"))
);
const wasmPresent = existsSync(WASM);
const prereqs = wasmPresent && ceremonyPresent;

// ── Test 1: Sandbox success ───────────────────────────────────────────────────

describe("deploy pipeline — sandbox success", () => {
  it.skipIf(!prereqs)(
    "runs full sandbox deploy + verifies receipt",
    async () => {
      const outDir = resolve(tmpdir(), `deploy-e2e-sandbox-${Date.now()}`);
      mkdirSync(outDir, { recursive: true });
      try {
        const result = await run({
          network: "sandbox",
          vkDir: VK_DIR,
          wasm: WASM,
          repoRoot: REPO,
          owner: "owner.test.near",
          usdcToken: "usdc.test.near",
          // Note: sandbox.json has account=pool.test.near; owner/usdcToken override it.
          skipReadiness: true,
          outDir,
        });

        expect(result.mode).toBe("sandbox");
        if (result.mode !== "sandbox") return; // type-narrow

        // SandboxResult ok + views
        expect(result.sandbox.ok).toBe(true);
        expect(result.sandbox.owner).toBe("owner.test.near");
        expect(result.sandbox.usdcToken).toBe("usdc.test.near");
        expect(result.sandbox.paused).toBe(false);

        // Receipt file written and valid JSON
        expect(existsSync(result.receiptPath)).toBe(true);
        const receipt = JSON.parse(readFileSync(result.receiptPath, "utf8")) as {
          network: string;
          wasmSha256: string;
          vkSha256: Record<string, string>;
          initArgs: { owner: string; usdc_token: string };
          sandbox: { ok: boolean };
        };
        expect(receipt.network).toBe("sandbox");
        expect(receipt.wasmSha256).toMatch(/^[0-9a-f]{64}$/);
        expect(receipt.vkSha256.deposit).toMatch(/^[0-9a-f]{64}$/);
        expect(receipt.vkSha256.transfer).toMatch(/^[0-9a-f]{64}$/);
        expect(receipt.vkSha256.withdraw).toMatch(/^[0-9a-f]{64}$/);
        expect(receipt.initArgs.owner).toBe("owner.test.near");
        expect(receipt.initArgs.usdc_token).toBe("usdc.test.near");
        expect(receipt.sandbox.ok).toBe(true);
      } finally {
        rmSync(outDir, { recursive: true, force: true });
      }
    },
    120_000
  );
});

// ── Test 2: DEV-key abort (committed fixtures — has vk.bin) ──────────────────

describe("deploy pipeline — DEV-key abort (circom/fixtures, has vk.bin)", () => {
  it(
    "rejects with /DEV verifying key detected/ when given fixtures dir",
    async () => {
      // circom/fixtures/<c>/vk.json are DEV keys; vk.bin also present there.
      // The gate fingerprints the BYTES produced by vkJsonToContractBytes, not a
      // vk.bin scan — so the rejection is based on the deployed-bytes fingerprint.
      const fixturesDir = resolve(REPO, "circom/fixtures");
      await expect(
        run({
          network: "sandbox",
          vkDir: fixturesDir,
          wasm: WASM,
          repoRoot: REPO,
          owner: "o.test.near",
          usdcToken: "u.test.near",
          skipReadiness: true,
        })
      ).rejects.toThrow(/DEV verifying key detected/);
    },
    30_000
  );
});

// ── Test 3: DEV-key abort (json-only dir — KEY SECURITY TEST) ────────────────
//
// Build a tmp dir laid out <tmp>/<c>/vk.json by COPYING the json-only DEV keys from
// circom/build/keys/<c>_vk.json (no vk.bin present).  The gate must STILL reject,
// proving it fingerprints the bytes (vkJsonToContractBytes output), not a vk.bin scan.

const buildKeysDir = resolve(REPO, "circom/build/keys");
const jsonOnlyKeysPresent = ["deposit", "transfer", "withdraw"].every((c) =>
  existsSync(join(buildKeysDir, `${c}_vk.json`))
);

describe("deploy pipeline — DEV-key abort (json-only dir, NO vk.bin) [KEY SECURITY TEST]", () => {
  it.skipIf(!jsonOnlyKeysPresent)(
    "rejects with /DEV verifying key detected/ even when no vk.bin is present",
    async () => {
      const tmpDir = resolve(tmpdir(), `deploy-e2e-devkey-jsononly-${Date.now()}`);
      try {
        // Lay out <tmp>/<c>/vk.json (nested layout, no vk.bin)
        for (const c of ["deposit", "transfer", "withdraw"] as const) {
          const circDir = join(tmpDir, c);
          mkdirSync(circDir, { recursive: true });
          copyFileSync(join(buildKeysDir, `${c}_vk.json`), join(circDir, "vk.json"));
          // Explicitly ensure no vk.bin is copied — only the json arrives.
        }

        await expect(
          run({
            network: "sandbox",
            vkDir: tmpDir,
            wasm: WASM,
            repoRoot: REPO,
            owner: "o.test.near",
            usdcToken: "u.test.near",
            skipReadiness: true,
          })
        ).rejects.toThrow(/DEV verifying key detected/);
      } finally {
        rmSync(tmpDir, { recursive: true, force: true });
      }
    },
    30_000
  );
});

// ── Test 4: mainnet emit (confirmed) ─────────────────────────────────────────
//
// Note: skipReadiness:true is used here to keep the test fast.  In real mainnet
// use the CLI refuses --skip-readiness (main() resets it), so the readiness gate
// always runs there.  The e2e focuses on the emit path + argsPath output.

describe("deploy pipeline — mainnet emit (confirmed)", () => {
  it.skipIf(!prereqs)(
    "emits deploy command + writes init-args file + includes gating checklist",
    async () => {
      const outDir = resolve(tmpdir(), `deploy-e2e-mainnet-${Date.now()}`);
      mkdirSync(outDir, { recursive: true });
      try {
        const result = await run({
          network: "mainnet",
          vkDir: VK_DIR,
          wasm: WASM,
          repoRoot: REPO,
          owner: "owner.near",
          usdcToken: "usdc.near",
          // account must come from an override since mainnet.json doesn't exist in this repo.
          account: "pool.near",
          confirmMainnet: true,
          skipReadiness: true, // kept fast in tests; CLI never passes this for mainnet
          outDir,
        });

        expect(result.mode).toBe("emit");
        if (result.mode !== "emit") return; // type-narrow

        // Command contains the expected near-cli-rs subcommands
        expect(result.command).toMatch(/near contract deploy/);
        expect(result.command).toMatch(/network-config mainnet/);

        // argsPath file written
        expect(existsSync(result.argsPath)).toBe(true);
        const args = JSON.parse(readFileSync(result.argsPath, "utf8")) as {
          owner: string;
          usdc_token: string;
          vk_deposit: number[];
          vk_transfer: number[];
          vk_withdraw: number[];
        };
        expect(args.owner).toBe("owner.near");
        expect(args.usdc_token).toBe("usdc.near");
        expect(Array.isArray(args.vk_deposit)).toBe(true);
        expect(args.vk_deposit.length).toBeGreaterThan(0);

        // Gating checklist must be present and contain all required items.
        expect(result.checklist).toBeDefined();
        expect(result.checklist).toContain("external security audit done");
        expect(result.checklist).toContain("real ceremony completed + VKs published");
        expect(result.checklist).toContain("independent circuit soundness review done");
        expect(result.checklist).toContain("canonical mainnet USDC token id verified");
        expect(result.checklist).toContain("owner = ledger/multisig");
        // Checklist must match the canonical exported constant exactly.
        expect(result.checklist).toEqual([...MAINNET_CHECKLIST]);
      } finally {
        rmSync(outDir, { recursive: true, force: true });
      }
    },
    30_000
  );
});

// ── Test 5: mainnet without --confirm-mainnet ─────────────────────────────────

describe("deploy pipeline — mainnet without --confirm-mainnet", () => {
  it.skipIf(!prereqs)(
    "throws asking for --confirm-mainnet",
    async () => {
      // Uses a dummy vkDir/wasm; the mainnet confirmation gate is checked AFTER
      // config+assemble, so we need valid VKs.
      await expect(
        run({
          network: "mainnet",
          vkDir: VK_DIR,
          wasm: WASM,
          repoRoot: REPO,
          owner: "owner.near",
          usdcToken: "usdc.near",
          account: "pool.near",
          confirmMainnet: false,
          skipReadiness: true,
        })
      ).rejects.toThrow(/--confirm-mainnet/);
    },
    30_000
  );
});
