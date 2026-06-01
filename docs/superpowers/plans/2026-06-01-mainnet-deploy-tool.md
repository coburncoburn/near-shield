# Mainnet Deploy Tool Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers-extended-cc:subagent-driven-development (if subagents available) or superpowers-extended-cc:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a TS deploy tool that runs hard safety gates (refuse DEV keys + mock WASM), assembles the contract `new()` init args from ceremony verifying keys, deploys+inits+post-verifies on a near-workspaces sandbox for validation, and EMITS the near-cli-rs command + init JSON for a human operator to broadcast to testnet/mainnet (no signing key in the tool) — plus a DEPLOY-RUNBOOK.

**Architecture:** New `deploy/` pnpm workspace package. Pipeline: **gates (build-check + byte-level DEV-fingerprint + VK length) → assemble init args (reusing `@shielded-near/sdk` `vkJsonToContractBytes`) → execute**. `--network sandbox` deploys via near-workspaces (like the demo) + post-verifies via view calls + writes a receipt; `--network testnet|mainnet` emits the near-cli-rs deploy command + an init-args JSON file (no broadcast). The authoritative DEV-key block fingerprints the actual bytes being deployed (`sha256(vkJsonToContractBytes(vk.json))`), not a `vk.bin` dir scan.

**Tech Stack:** TS + tsx + vitest, near-workspaces ^4.0.0 (sandbox), `@shielded-near/sdk` (`vkJsonToContractBytes`), node:crypto/child_process. The production WASM `target/wasm32-unknown-unknown/release/shielded_pool.opt.wasm`, `scripts/check-production-readiness.sh` (mock-rejection + size + DEV-fingerprint guard), ceremony VKs in `ceremony/out/<c>/vk.json`. Spec: `docs/superpowers/specs/2026-06-01-mainnet-deploy-tool-design.md`.

**Conventions:** @superpowers-extended-cc:test-driven-development + @superpowers-extended-cc:verification-before-completion (paste real output). Contract init: `new(owner: AccountId, usdc_token: AccountId, vk_deposit: Vec<u8>, vk_transfer: Vec<u8>, vk_withdraw: Vec<u8>)`. View methods: `owner()`, `usdc_token()`, `is_paused()`. VK contract-byte lengths: deposit 768, transfer 1088, withdraw 1024. near-workspaces deploy pattern (from `demo/src/run-demo.ts`): `Worker.init()` → `worker.rootAccount` → `root.createSubAccount("pool")` → `acct.deploy(wasm)` → `acct.call(acct, "new", initArgs)` → `acct.view("owner", {})`.

---

### Task 0: Scaffold `deploy/` workspace package

**Files:**
- Create: `deploy/package.json`, `deploy/tsconfig.json`, `deploy/vitest.config.ts`, `deploy/.gitignore`
- Modify: `pnpm-workspace.yaml` (add `deploy`)

- [ ] **Step 1: package.json**
```json
{
  "name": "@shielded-near/deploy",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "sideEffects": false,
  "scripts": { "deploy": "tsx src/deploy.ts", "test": "vitest run" },
  "dependencies": {
    "@shielded-near/sdk": "workspace:*",
    "near-workspaces": "^4.0.0"
  },
  "devDependencies": {
    "@types/node": "^22.0.0", "tsx": "^4.0.0", "typescript": "^5.5.0", "vitest": "^2.1.0"
  }
}
```

- [ ] **Step 2: config + ignore**
`deploy/tsconfig.json` (mirror `sdk/packages/sdk/tsconfig.json` options; `"include": ["src","test"]`). `deploy/vitest.config.ts` with `testTimeout: 120_000, hookTimeout: 120_000` (sandbox is slow). `deploy/.gitignore`: `out/` (receipts + emitted init-args).

- [ ] **Step 3: register + install**
Add `- "deploy"` under `packages:` in `pnpm-workspace.yaml`. Run `pnpm install` from repo root. Verify `pnpm --filter @shielded-near/deploy exec tsc --noEmit` (passes with no src yet — or add an empty `src/index.ts`).

- [ ] **Step 4: Commit**
```bash
git add -f deploy pnpm-workspace.yaml pnpm-lock.yaml
git commit -m "build(deploy): scaffold deploy workspace package"
```

---

### Task 1: Safety gates (`gates.ts`)

**Files:**
- Create: `deploy/src/gates.ts`, `deploy/src/gates.test.ts`

- [ ] **Step 1: Write failing tests** (`gates.test.ts`)
Using `vkJsonToContractBytes` from `@shielded-near/sdk` and the repo's real VK JSONs:
- `assertVkLength`: `vkJsonToContractBytes(circom/fixtures/deposit/vk.json)` → length 768 passes; a truncated array throws.
- `assertNotDevKey`: the bytes of the committed DEV key `circom/fixtures/deposit/vk.json` (→ `vkJsonToContractBytes` → sha256) MUST be in the denylist → `assertNotDevKey` THROWS. The ceremony key `ceremony/out/deposit/vk.json` → NOT in denylist → passes. (Requires `ceremony/out` from the ceremony dry-run; if absent, the test can skip-with-message or the runner runs `bash ceremony/scripts/run-dev-ceremony.sh` first.)
- **Denylist sync test:** for each circuit, `sha256(vkJsonToContractBytes(circom/fixtures/<c>/vk.json))` equals the hardcoded `DEV_VK_FINGERPRINTS[<c>]` (which are copied from `scripts/check-production-readiness.sh`) — so the denylist can't silently drift.

- [ ] **Step 2: Implement `gates.ts`**
```ts
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { vkJsonToContractBytes } from "@shielded-near/sdk";

export type Circuit = "deposit" | "transfer" | "withdraw";
export const VK_LEN: Record<Circuit, number> = { deposit: 768, transfer: 1088, withdraw: 1024 };

// sha256 of vkJsonToContractBytes(<c> DEV vk.json) == sha256(circom/fixtures/<c>/vk.bin).
// COPY these three values verbatim from scripts/check-production-readiness.sh DEV_VK_FINGERPRINTS.
export const DEV_VK_FINGERPRINTS: Record<Circuit, string> = {
  deposit: "<copy from check-production-readiness.sh>",
  transfer: "<copy …>",
  withdraw: "<copy …>",
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
/** Build-check: production groth16-verifier WASM, not mock; size-gated. */
export function runReadinessCheck(repoRoot: string): void {
  const r = spawnSync("bash", ["scripts/check-production-readiness.sh"], { cwd: repoRoot, encoding: "utf8" });
  if (r.status !== 0)
    throw new Error(`production readiness check failed:\n${r.stdout}\n${r.stderr}`);
}
```

- [ ] **Step 3: Run + commit**
`pnpm --filter @shielded-near/deploy exec vitest run gates` → PASS. Commit `deploy/src/gates.ts deploy/src/gates.test.ts` with `feat(deploy): safety gates (build-check + byte-level DEV-fingerprint + VK length)`.

---

### Task 2: Config + init-args assembly (`config.ts`, `assemble.ts`)

**Files:**
- Create: `deploy/src/config.ts`, `deploy/src/assemble.ts`, `deploy/src/config.test.ts`, `deploy/src/assemble.test.ts`
- Create: `deploy/config/sandbox.json` (test/sample config)

- [ ] **Step 1: config.ts** — `DeployConfig = { network: "sandbox"|"testnet"|"mainnet", account: string, owner: string, usdcToken: string }`. `loadConfig(network, overrides)`: read `deploy/config/<network>.json` if present, apply CLI/env overrides; **throw if `usdcToken` is missing/empty** (no default — runbook-verified for mainnet). `deploy/config/sandbox.json` = placeholder values for the sandbox test (account/owner/usdcToken are sandbox-internal, set at runtime, so this file mainly documents shape). Test: missing usdcToken throws; overrides win.

- [ ] **Step 2: assemble.ts**
```ts
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { vkJsonToContractBytes } from "@shielded-near/sdk";
import { type Circuit, assertVkLength, assertNotDevKey } from "./gates.js";

export interface InitArgs { owner: string; usdc_token: string;
  vk_deposit: number[]; vk_transfer: number[]; vk_withdraw: number[]; }
export interface AssembleResult { initArgs: InitArgs; vkSha256: Record<Circuit, string>; }

function readVkJson(vkDir: string, c: Circuit): unknown {
  const nested = join(vkDir, c, "vk.json");
  const flat = join(vkDir, `${c}_vk.json`);
  const p = existsSync(nested) ? nested : flat;
  return JSON.parse(readFileSync(p, "utf8"));
}
/** Reads ceremony vk.json per circuit, runs the gates on the ACTUAL bytes, assembles new() args. */
export function assembleInitArgs(vkDir: string, owner: string, usdcToken: string): AssembleResult {
  const bytes = {} as Record<Circuit, Uint8Array>;
  for (const c of ["deposit","transfer","withdraw"] as Circuit[]) {
    const b = vkJsonToContractBytes(readVkJson(vkDir, c) as any);
    assertVkLength(c, b);     // length of the deployed bytes
    assertNotDevKey(c, b);    // authoritative DEV-key block
    bytes[c] = b;
  }
  const { vkSha256 } = require("./gates.js");
  return {
    initArgs: { owner, usdc_token: usdcToken,
      vk_deposit: Array.from(bytes.deposit), vk_transfer: Array.from(bytes.transfer), vk_withdraw: Array.from(bytes.withdraw) },
    vkSha256: { deposit: vkSha256(bytes.deposit), transfer: vkSha256(bytes.transfer), withdraw: vkSha256(bytes.withdraw) },
  };
}
```
(Use ESM imports for `vkSha256` rather than `require` — adapt to the file's import style.)

- [ ] **Step 3: Tests**
`assemble.test.ts`: `assembleInitArgs("ceremony/out", "owner.near", "usdc.near")` → vk_* arrays of length 768/1088/1024, owner/usdc_token set. Pointed at `circom/fixtures` (DEV) → THROWS (assertNotDevKey). (Skip-if-absent for ceremony/out.)

- [ ] **Step 4: Run + commit**
`vitest run config assemble` → PASS. Commit with `feat(deploy): per-network config + init-args assembly with gates on deployed bytes`.

---

### Task 3: Emit path for testnet/mainnet (`emit.ts`)

**Files:**
- Create: `deploy/src/emit.ts`, `deploy/src/emit.test.ts`

- [ ] **Step 1: emit.ts** — writes the init args to a file and prints the near-cli-rs command + summary.
```ts
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import type { InitArgs } from "./assemble.js";

export interface EmitInput { network: "testnet"|"mainnet"; account: string; wasmPath: string;
  wasmSha256: string; initArgs: InitArgs; vkSha256: Record<string,string>; outDir: string; }

/** Writes <outDir>/<network>-init-args.json and returns the operator command + summary string. */
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
```

- [ ] **Step 2: Tests** — `emitDeployCommand` returns a command containing `near contract deploy <account> use-file <wasm> with-init-call new json-args`, references the written args file, and the args file parses to an InitArgs with the 5 fields + vk arrays of the right lengths. NOTHING is broadcast (pure string/file). Assert `network-config mainnet` appears for mainnet.

- [ ] **Step 3: Run + commit**
`vitest run emit` → PASS. Commit `feat(deploy): emit near-cli-rs deploy command + init-args file for testnet/mainnet`.

---

### Task 4: Sandbox deploy path (`sandbox.ts`)

**Files:**
- Create: `deploy/src/sandbox.ts`, `deploy/src/sandbox.test.ts`

- [ ] **Step 1: sandbox.ts** — near-workspaces deploy + init + post-verify (mirror `demo/src/run-demo.ts`):
```ts
import { Worker } from "near-workspaces";
import type { InitArgs } from "./assemble.js";

export interface SandboxResult { ok: true; owner: string; usdcToken: string; paused: boolean; }
/** Deploys the WASM to a fresh sandbox account, calls new(initArgs), post-verifies views. */
export async function deployToSandbox(wasmPath: string, initArgs: InitArgs): Promise<SandboxResult> {
  const worker = await Worker.init();
  try {
    const pool = await worker.rootAccount.createSubAccount("pool");
    await pool.deploy(wasmPath);
    // 300 Tgas: `new` writes ~2.9 KB of VK bytes to state; the near-workspaces
    // default (~30 Tgas) is too tight. Mirrors demo/src/run-demo.ts's `new` call.
    await pool.call(pool, "new", initArgs, { gas: "300000000000000" });
    const owner = await pool.view<string>("owner", {});
    const usdcToken = await pool.view<string>("usdc_token", {});
    const paused = await pool.view<boolean>("is_paused", {});
    if (owner !== initArgs.owner) throw new Error(`owner view ${owner} != ${initArgs.owner}`);
    if (usdcToken !== initArgs.usdc_token) throw new Error(`usdc_token view ${usdcToken} != ${initArgs.usdc_token}`);
    if (paused !== false) throw new Error(`expected is_paused=false, got ${paused}`);
    return { ok: true, owner, usdcToken, paused };
  } finally { await worker.tearDown(); }
}
```
Note: in the sandbox, `owner`/`usdc_token` must be valid AccountIds that exist or are acceptable to `new` (the contract just stores them; `new` doesn't validate they exist). Use the pool account id for owner and a created/placeholder token account id — confirm `new` accepts arbitrary AccountId strings (it does; it only stores them). If view of a non-account is fine, pass e.g. `pool.accountId` for owner and a `usdc.test.near`-style id.

- [ ] **Step 2: Integration test** (`sandbox.test.ts`) — assemble from `ceremony/out` (owner=`pool.test.near`-style or the created account, usdc=`usdc.test.near`) then `deployToSandbox(POOL_OPT_WASM, initArgs)` → `ok`, views match. Skip-with-message if `ceremony/out` or the opt WASM is absent (document the build steps: `cargo build … --features groth16-verifier` + `check-production-readiness.sh` + `bash ceremony/scripts/run-dev-ceremony.sh`). 120s timeout.

- [ ] **Step 3: Run + commit**
Build prereqs if needed, then `vitest run sandbox` → PASS (deploy+init+views). Paste. Commit `feat(deploy): sandbox deploy+init+post-verify via near-workspaces`.

---

### Task 5: CLI entrypoint (`deploy.ts`) + end-to-end tests

**Files:**
- Create: `deploy/src/deploy.ts`, `deploy/src/deploy.e2e.test.ts`

- [ ] **Step 1: deploy.ts** — parse flags (`--network`, `--vk-dir` [default `ceremony/out`], `--wasm` [default the opt WASM path], `--confirm-mainnet`, config overrides). Pipeline:
  1. `runReadinessCheck(repoRoot)` (skip only if `--skip-readiness` for sandbox dev iteration — but default ON; for mainnet ALWAYS on).
  2. `loadConfig(network, overrides)`.
  3. `assembleInitArgs(vkDir, cfg.owner, cfg.usdcToken)` (this runs the per-circuit length + DEV-fingerprint gates on the deployed bytes).
  4. compute `wasmSha256`.
  5. network branch: `sandbox` → `deployToSandbox` + write receipt to `deploy/out/sandbox-receipt.json`; `testnet|mainnet` → `emitDeployCommand` + print command + summary; for `mainnet` require `--confirm-mainnet` and print the gating checklist (ceremony done, soundness review done, audit done, USDC id verified).

- [ ] **Step 2: e2e tests** (`deploy.e2e.test.ts`) — drive the CLI's exported `run(opts)` function (export the pipeline as a function, with `main()` parsing argv):
  - **sandbox success:** `run({network:"sandbox", vkDir:"ceremony/out", wasm:OPT_WASM, owner, usdcToken})` → deploys + views match + receipt written. (skip-if-absent prereqs.)
  - **DEV-key abort (committed vk.bin dir):** `run({…, vkDir:"circom/fixtures", …})` → THROWS (assertNotDevKey on the deployed bytes). 
  - **DEV-key abort (json-only dir):** copy `circom/build/keys/<c>_vk.json` into a temp dir laid out as `<tmp>/<c>/vk.json` (NO vk.bin), `run({…, vkDir:tmp, …})` → STILL THROWS (proves the gate fingerprints the bytes, not a vk.bin scan). This is the key security test from the spec.
  - **mainnet emit:** `run({network:"mainnet", vkDir:"ceremony/out", confirmMainnet:true, …})` → returns/prints the near-cli-rs command + writes `deploy/out/mainnet-init-args.json`; asserts NO sandbox/broadcast happened (e.g. it returns an `{emitted:true, command}` without touching near-workspaces). mainnet WITHOUT `--confirm-mainnet` → throws asking for confirmation.

- [ ] **Step 3: Run + commit**
`vitest run` (whole deploy suite) → green. Paste (esp. the two DEV-abort tests + mainnet-emit). Commit `feat(deploy): CLI pipeline (gates→assemble→sandbox|emit) + e2e incl json-only DEV-key abort`.

---

### Task 6: DEPLOY-RUNBOOK + README + final verification

**Files:**
- Create: `deploy/DEPLOY-RUNBOOK.md`
- Modify: `README.md` (deploy section)

- [ ] **Step 1: DEPLOY-RUNBOOK.md** — operator doc:
  - **Preconditions checklist (all REQUIRED before mainnet):** real ceremony completed + VKs published (`ceremony/RUNBOOK.md`); independent circuit soundness review done; external security audit done; **canonical mainnet USDC token id verified** (the runbook states the operator must confirm the exact account id — do not assume); owner = ledger/multisig account; production `groth16-verifier` WASM built + `check-production-readiness.sh` green.
  - **Run:** `pnpm --filter @shielded-near/deploy deploy -- --network mainnet --vk-dir <ceremony VKs> --confirm-mainnet` (with owner/usdc_token config). Review the emitted command + summary (WASM sha256, VK sha256s, owner, usdc_token).
  - **Broadcast:** the operator runs the emitted `near contract deploy …` via near-cli-rs with a ledger/multisig signer (the tool never holds the key). Note the assumed near-cli-rs version.
  - **Post-deploy verify:** view `owner`/`usdc_token`/`is_paused`; ideally submit a first real proof (deposit) and confirm acceptance. Cross-link `ceremony/RUNBOOK.md`.

- [ ] **Step 2: README** — short "## Deploying" section: the deploy tool lives in `deploy/`; sandbox validation `pnpm --filter @shielded-near/deploy test`; mainnet is operator-driven per `deploy/DEPLOY-RUNBOOK.md` and gated on ceremony + soundness review + audit; the tool refuses DEV keys + mock WASM.

- [ ] **Step 3: Final verification + commit**
- `pnpm --filter @shielded-near/deploy exec vitest run` → green.
- A sandbox deploy via the CLI with ceremony VKs → succeeds (paste).
- A mainnet-emit dry-run → prints the command + writes init-args (paste; confirm no broadcast).
- Confirm existing suites unaffected (the tool is additive): `pnpm --filter @shielded-near/circom exec vitest run` + `cargo test -p shielded-pool --test snarkjs_verify_fixture`.
```bash
git add -f deploy/DEPLOY-RUNBOOK.md README.md
git commit -m "docs(deploy): DEPLOY-RUNBOOK + README; mainnet deploy is operator-driven, gated"
```

---

## Done criteria

- The deploy tool's suite is green: gates (DEV-fingerprint + length + readiness), config (usdc_token required), assemble, emit, sandbox deploy+post-verify, and the e2e — including the **json-only DEV-key abort** (proves the gate fingerprints the deployed bytes, not a vk.bin scan).
- Sandbox path deploys+inits+post-verifies the contract with ceremony VKs; views match config.
- testnet/mainnet path emits a well-formed near-cli-rs command + init-args file with no broadcast; mainnet requires explicit confirmation + prints the gating checklist.
- The tool refuses DEV keys (any source layout) and a mock-verifier WASM.
- DEPLOY-RUNBOOK documents the preconditions (ceremony + soundness review + audit + verified USDC id + ledger/multisig owner) and the operator broadcast flow.

## Handoff / what's still gated

The actual mainnet deploy is an **operator ops event** that must NOT happen until: the real trusted-setup ceremony has produced published VKs, the independent circuit soundness review is complete, and the external security audit is complete. This tool is the machinery + safety gates for that event; it does not perform or authorize it.
