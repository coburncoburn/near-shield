import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { runReadinessCheck } from "./gates.js";
import { loadConfig } from "./config.js";
import { assembleInitArgs } from "./assemble.js";
import { emitDeployCommand } from "./emit.js";
import { deployToSandbox, type SandboxResult } from "./sandbox.js";

export interface RunOpts {
  network: "sandbox" | "testnet" | "mainnet";
  vkDir: string;       // dir with per-circuit vk.json (ceremony/out for real)
  wasm: string;        // path to the groth16-verifier opt WASM
  repoRoot: string;
  owner?: string;
  usdcToken?: string;
  account?: string;    // config overrides
  confirmMainnet?: boolean;
  /**
   * Skip the production-readiness build check.
   * Safe for sandbox in tests (readiness is unit-tested separately in gates.test.ts).
   * The CLI main() enforces: --skip-readiness is NEVER honoured for testnet or mainnet.
   * Default: false.
   */
  skipReadiness?: boolean;
  outDir?: string;
}

/** Items the operator must verify before broadcasting a mainnet tx. */
export const MAINNET_CHECKLIST = [
  "real ceremony completed + VKs published",
  "independent circuit soundness review done",
  "external security audit done",
  "canonical mainnet USDC token id verified",
  "owner = ledger/multisig",
] as const;

export type RunResult =
  | { mode: "sandbox"; sandbox: SandboxResult; receiptPath: string }
  | { mode: "emit"; command: string; argsPath: string; summary: string; checklist?: string[] };

/**
 * The canonical readiness-checked WASM artifact path (relative to repoRoot).
 * This is the path validated by scripts/check-production-readiness.sh.
 * For testnet and mainnet, opts.wasm MUST resolve to this path — any other WASM
 * is not covered by the readiness check and is therefore not permitted.
 */
export const CANONICAL_WASM = "target/wasm32-unknown-unknown/release/shielded_pool.opt.wasm";

export async function run(opts: RunOpts): Promise<RunResult> {
  // 1. Build-check: skip only when caller explicitly opts out (tests do so for speed).
  //    The CLI main() refuses --skip-readiness for mainnet/testnet. For testnet/mainnet
  //    in real use this gate ensures the WASM is the production groth16-verifier, not the mock.
  if (!opts.skipReadiness) {
    runReadinessCheck(opts.repoRoot);
  }

  // 1b. For testnet/mainnet, enforce that opts.wasm is the readiness-checked canonical
  //     artifact. --wasm <other> would pass the readiness gate (which validates the
  //     canonical path) while deploying/emitting a DIFFERENT, unvalidated file —
  //     undermining the "impossible to deploy a mock-verifier WASM" guarantee.
  //     Sandbox is exempt: local/test workflows legitimately use alternate paths.
  if (opts.network === "testnet" || opts.network === "mainnet") {
    const canonicalWasm = resolve(opts.repoRoot, CANONICAL_WASM);
    const givenWasm = resolve(opts.wasm);
    if (givenWasm !== canonicalWasm) {
      throw new Error(
        `for testnet/mainnet, --wasm must be the readiness-checked artifact ` +
          `(${canonicalWasm}); a custom WASM is not validated by check-production-readiness.sh`
      );
    }
  }

  // 2. Config: merges file + overrides; throws if usdc_token/owner/account missing.
  const cfg = loadConfig(opts.network, {
    account: opts.account,
    owner: opts.owner,
    usdcToken: opts.usdcToken,
  });

  // 3. Assemble: reads per-circuit vk.json, runs the length + DEV-fingerprint gates on
  //    the ACTUAL bytes to be deployed.  Throws for DEV keys (Gate #2) regardless of
  //    whether vk.bin is present in the directory — the fingerprint is on the bytes.
  const { initArgs, vkSha256 } = assembleInitArgs(opts.vkDir, cfg.owner, cfg.usdcToken);

  // 4. WASM sha256 for the receipt / operator summary.
  const wasmSha256 = createHash("sha256").update(readFileSync(opts.wasm)).digest("hex");

  const outDir = opts.outDir ?? join(opts.repoRoot, "deploy", "out");

  // 5. Branch on network.
  if (opts.network === "sandbox") {
    const sandbox = await deployToSandbox(opts.wasm, initArgs);
    mkdirSync(outDir, { recursive: true });
    const receiptPath = join(outDir, "sandbox-receipt.json");
    writeFileSync(
      receiptPath,
      JSON.stringify(
        {
          network: "sandbox",
          wasmSha256,
          vkSha256,
          initArgs: { owner: initArgs.owner, usdc_token: initArgs.usdc_token },
          sandbox,
        },
        null,
        2
      )
    );
    return { mode: "sandbox", sandbox, receiptPath };
  }

  // testnet / mainnet: gate on explicit confirmation for mainnet.
  if (opts.network === "mainnet" && !opts.confirmMainnet) {
    throw new Error(
      "mainnet deploy requires --confirm-mainnet. PRECONDITIONS (see deploy/DEPLOY-RUNBOOK.md): " +
        "real ceremony done + VKs published; circuit soundness review done; external audit done; " +
        "canonical mainnet USDC id verified; owner = ledger/multisig."
    );
  }

  const { argsPath, command, summary } = emitDeployCommand({
    network: opts.network,
    account: cfg.account,
    wasmPath: opts.wasm,
    wasmSha256,
    initArgs,
    vkSha256,
    outDir,
  });

  // Include the gating checklist in the result for mainnet so main() and callers
  // can display it even after --confirm-mainnet has already been accepted.
  const checklist: string[] | undefined =
    opts.network === "mainnet" ? [...MAINNET_CHECKLIST] : undefined;

  return { mode: "emit", command, argsPath, summary, checklist };
}

// ── CLI entrypoint ────────────────────────────────────────────────────────────

function parseArgs(argv: string[]): RunOpts {
  const REPO_ROOT = resolve(import.meta.dirname, "../..");
  const opts: RunOpts = {
    network: "sandbox",
    vkDir: resolve(REPO_ROOT, "ceremony/out"),
    wasm: resolve(
      REPO_ROOT,
      "target/wasm32-unknown-unknown/release/shielded_pool.opt.wasm"
    ),
    repoRoot: REPO_ROOT,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = argv[i + 1];

    if (arg === "--network") {
      if (!next || next.startsWith("--")) {
        throw new Error("--network requires a value: sandbox|testnet|mainnet");
      }
      if (next !== "sandbox" && next !== "testnet" && next !== "mainnet") {
        throw new Error(`--network must be sandbox|testnet|mainnet, got: ${next}`);
      }
      opts.network = next as "sandbox" | "testnet" | "mainnet";
      i++;
    } else if (arg === "--vk-dir") {
      if (!next || next.startsWith("--")) {
        throw new Error("--vk-dir requires a value: path to directory containing per-circuit vk.json files");
      }
      opts.vkDir = resolve(next);
      i++;
    } else if (arg === "--wasm") {
      if (!next || next.startsWith("--")) {
        throw new Error("--wasm requires a value: path to the groth16-verifier opt WASM file");
      }
      opts.wasm = resolve(next);
      i++;
    } else if (arg === "--owner" && next && !next.startsWith("--")) {
      opts.owner = next;
      i++;
    } else if (arg === "--usdc-token" && next && !next.startsWith("--")) {
      opts.usdcToken = next;
      i++;
    } else if (arg === "--account" && next && !next.startsWith("--")) {
      opts.account = next;
      i++;
    } else if (arg === "--confirm-mainnet") {
      opts.confirmMainnet = true;
    } else if (arg === "--skip-readiness") {
      // Honoured only for sandbox; reset for testnet/mainnet after full parse.
      opts.skipReadiness = true;
    } else if (arg === "--out-dir" && next && !next.startsWith("--")) {
      opts.outDir = resolve(next);
      i++;
    } else {
      throw new Error(`Unknown flag: ${arg}`);
    }
  }

  // Safety: never silently skip readiness for testnet or mainnet via CLI.
  if (opts.skipReadiness && (opts.network === "mainnet" || opts.network === "testnet")) {
    process.stderr.write(
      `WARNING: --skip-readiness is ignored for ${opts.network} to protect production safety.\n`
    );
    opts.skipReadiness = false;
  }

  return opts;
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  let result: RunResult;
  try {
    result = await run(opts);
  } catch (e) {
    process.stderr.write(`Error: ${(e as Error).message}\n`);
    process.exit(1);
  }

  if (result.mode === "sandbox") {
    console.log(`Sandbox deploy succeeded.`);
    console.log(`Receipt written to: ${result.receiptPath}`);
    console.log(
      `Views: owner=${result.sandbox.owner} usdc_token=${result.sandbox.usdcToken} paused=${result.sandbox.paused}`
    );
  } else {
    // Print the mainnet gating checklist so the operator re-verifies before broadcasting.
    if (result.checklist) {
      console.log(`\nMAINNET PRECONDITIONS — verify before broadcasting:`);
      for (const item of result.checklist) {
        console.log(`  [ ] ${item}`);
      }
    }
    console.log(`\n=== Deploy summary ===\n${result.summary}\n`);
    console.log(`Init args written to: ${result.argsPath}`);
    console.log(`\nBroadcast command (review then broadcast via near-cli-rs):\n${result.command}\n`);
  }
}

// Guard: only execute main() when this module is the direct entrypoint.
// Uses the standard ESM idiom for robustness across tsx, ts-node, and node.
const isDirectRun = import.meta.url === pathToFileURL(process.argv[1] ?? "").href;

if (isDirectRun) {
  main().catch((e) => {
    process.stderr.write(`Unhandled: ${(e as Error).message}\n`);
    process.exit(1);
  });
}
