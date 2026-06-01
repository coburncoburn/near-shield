import { describe, it, expect } from "vitest";
import { existsSync } from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { assembleInitArgs } from "./assemble.js";

// deploy/src → ../.. = repo root
const REPO_ROOT = resolve(import.meta.dirname, "../..");

const CEREMONY_OUT = resolve(REPO_ROOT, "ceremony/out");
const DEV_FIXTURES = resolve(REPO_ROOT, "circom/fixtures");

describe("assembleInitArgs — ceremony keys", () => {
  if (!existsSync(CEREMONY_OUT)) {
    it.skip(
      "ceremony/out absent — run bash ceremony/scripts/run-dev-ceremony.sh first",
      () => {}
    );
  } else {
    it("returns correct array lengths and fields for ceremony VKs", () => {
      const result = assembleInitArgs(CEREMONY_OUT, "owner.near", "usdc.near");

      expect(result.initArgs.owner).toBe("owner.near");
      expect(result.initArgs.usdc_token).toBe("usdc.near");

      expect(result.initArgs.vk_deposit).toHaveLength(768);
      expect(result.initArgs.vk_transfer).toHaveLength(1088);
      expect(result.initArgs.vk_withdraw).toHaveLength(1024);

      // vkSha256 returns 64-char hex strings for all three circuits
      expect(result.vkSha256.deposit).toMatch(/^[0-9a-f]{64}$/);
      expect(result.vkSha256.transfer).toMatch(/^[0-9a-f]{64}$/);
      expect(result.vkSha256.withdraw).toMatch(/^[0-9a-f]{64}$/);
    });
  }
});

describe("assembleInitArgs — DEV key detection", () => {
  it("throws for DEV keys (circom/fixtures)", () => {
    expect(() =>
      assembleInitArgs(DEV_FIXTURES, "owner.near", "usdc.near")
    ).toThrow(/DEV verifying key detected/);
  });
});

describe("assembleInitArgs — missing vk.json", () => {
  it("throws an actionable error naming the missing file path", () => {
    const emptyDir = mkdtempSync(tmpdir() + "/assemble-test-");
    expect(() =>
      assembleInitArgs(emptyDir, "owner.near", "usdc.near")
    ).toThrow(/vk\.json not found for deposit/);
  });
});
