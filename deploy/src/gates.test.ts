import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { vkJsonToContractBytes, type SnarkjsVk } from "@shielded-near/sdk";
import {
  assertVkLength,
  assertNotDevKey,
  vkSha256,
  DEV_VK_FINGERPRINTS,
  type Circuit,
} from "./gates.js";

// Repo root: deploy/src → ../../.. = repo root
const REPO_ROOT = resolve(import.meta.dirname, "../..");

function readVk(path: string): SnarkjsVk {
  return JSON.parse(readFileSync(path, "utf8")) as SnarkjsVk;
}

function devVkBytes(c: Circuit): Uint8Array {
  return vkJsonToContractBytes(readVk(resolve(REPO_ROOT, `circom/fixtures/${c}/vk.json`)));
}

// ── Test 1: assertVkLength ────────────────────────────────────────────────────

describe("assertVkLength", () => {
  it("does not throw for deposit DEV vk (768 bytes)", () => {
    const bytes = devVkBytes("deposit");
    expect(() => assertVkLength("deposit", bytes)).not.toThrow();
  });

  it("throws when length is wrong (700 bytes)", () => {
    const short = new Uint8Array(700);
    expect(() => assertVkLength("deposit", short)).toThrow(
      /deposit: VK is 700 bytes, expected 768/
    );
  });
});

// ── Test 2: DEV key refused ───────────────────────────────────────────────────

describe("assertNotDevKey — DEV keys must be refused", () => {
  const circuits: Circuit[] = ["deposit", "transfer", "withdraw"];
  for (const c of circuits) {
    it(`throws for ${c} DEV key`, () => {
      const bytes = devVkBytes(c);
      expect(() => assertNotDevKey(c, bytes)).toThrow(/DEV verifying key detected/);
    });
  }
});

// ── Test 3: Ceremony key passes ───────────────────────────────────────────────

describe("assertNotDevKey — ceremony keys pass", () => {
  const circuits: Circuit[] = ["deposit", "transfer", "withdraw"];
  for (const c of circuits) {
    const ceremonyVkPath = resolve(REPO_ROOT, `ceremony/out/${c}/vk.json`);
    if (!existsSync(ceremonyVkPath)) {
      it.skip(`${c}: ceremony/out/${c}/vk.json absent — run bash ceremony/scripts/run-dev-ceremony.sh first`, () => {});
      continue;
    }
    it(`does not throw for ${c} ceremony key`, () => {
      const bytes = vkJsonToContractBytes(readVk(ceremonyVkPath));
      expect(() => assertNotDevKey(c, bytes)).not.toThrow();
    });
  }
});

// ── Test 4: Denylist sync ─────────────────────────────────────────────────────

describe("DEV_VK_FINGERPRINTS denylist matches committed DEV keys", () => {
  const circuits: Circuit[] = ["deposit", "transfer", "withdraw"];
  for (const c of circuits) {
    it(`${c}: hardcoded fingerprint matches vkJsonToContractBytes(circom/fixtures/${c}/vk.json)`, () => {
      const bytes = devVkBytes(c);
      const actual = vkSha256(bytes);
      expect(actual).toBe(DEV_VK_FINGERPRINTS[c]);
    });
  }
});
