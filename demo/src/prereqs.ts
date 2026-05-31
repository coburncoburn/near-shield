import { existsSync } from "node:fs";
import { resolve } from "node:path";

/**
 * Build prerequisites the demo depends on. Each entry pairs a path with the
 * exact command(s) the developer should run to produce it. We list everything
 * missing in a single error rather than failing fast on the first one — this
 * way the developer gets one actionable copy/paste session.
 */
interface Prereq {
  description: string;
  relPath: string;
  build: string;
}

export function getPrereqs(repoRoot: string): Prereq[] {
  return [
    {
      description: "shielded-pool deployable WASM (groth16-verifier, wasm-opt'd)",
      relPath: "target/wasm32-unknown-unknown/release/shielded_pool.opt.wasm",
      build:
        "cargo build -p shielded-pool --target wasm32-unknown-unknown --release --no-default-features --features groth16-verifier && \\\n" +
        "wasm-opt --enable-bulk-memory --llvm-memory-copy-fill-lowering -Oz --strip-debug --strip-producers \\\n" +
        "  target/wasm32-unknown-unknown/release/shielded_pool.wasm \\\n" +
        "  -o target/wasm32-unknown-unknown/release/shielded_pool.opt.wasm\n" +
        "# Or simply: bash scripts/check-production-readiness.sh",
    },
    {
      description: "mock-ft (NEP-141) WASM (wasm-opt'd; raw build emits bulk-memory ops the sandbox rejects)",
      relPath: "target/wasm32-unknown-unknown/release/mock_ft.opt.wasm",
      build:
        "cargo build -p mock-ft --target wasm32-unknown-unknown --release --no-default-features && \\\n" +
        "wasm-opt --enable-bulk-memory --llvm-memory-copy-fill-lowering -Oz --strip-debug --strip-producers \\\n" +
        "  target/wasm32-unknown-unknown/release/mock_ft.wasm \\\n" +
        "  -o target/wasm32-unknown-unknown/release/mock_ft.opt.wasm",
    },
    {
      description: "deposit circom R1CS",
      relPath: "circom/build/deposit.r1cs",
      build: "pnpm --filter @shielded-near/circom build",
    },
    {
      description: "deposit circom WASM",
      relPath: "circom/build/deposit_js/deposit.wasm",
      build: "pnpm --filter @shielded-near/circom build",
    },
    {
      description: "transfer circom R1CS",
      relPath: "circom/build/transfer.r1cs",
      build: "pnpm --filter @shielded-near/circom build",
    },
    {
      description: "transfer circom WASM",
      relPath: "circom/build/transfer_js/transfer.wasm",
      build: "pnpm --filter @shielded-near/circom build",
    },
    {
      description: "withdraw circom R1CS",
      relPath: "circom/build/withdraw.r1cs",
      build: "pnpm --filter @shielded-near/circom build",
    },
    {
      description: "withdraw circom WASM",
      relPath: "circom/build/withdraw_js/withdraw.wasm",
      build: "pnpm --filter @shielded-near/circom build",
    },
    {
      description: "deposit dev proving key",
      relPath: "circom/build/keys/deposit_dev.zkey",
      build: "bash circom/scripts/dev-setup.sh",
    },
    {
      description: "deposit verification key JSON",
      relPath: "circom/build/keys/deposit_vk.json",
      build: "bash circom/scripts/dev-setup.sh",
    },
    {
      description: "transfer dev proving key",
      relPath: "circom/build/keys/transfer_dev.zkey",
      build: "bash circom/scripts/dev-setup.sh",
    },
    {
      description: "transfer verification key JSON",
      relPath: "circom/build/keys/transfer_vk.json",
      build: "bash circom/scripts/dev-setup.sh",
    },
    {
      description: "withdraw dev proving key",
      relPath: "circom/build/keys/withdraw_dev.zkey",
      build: "bash circom/scripts/dev-setup.sh",
    },
    {
      description: "withdraw verification key JSON",
      relPath: "circom/build/keys/withdraw_vk.json",
      build: "bash circom/scripts/dev-setup.sh",
    },
  ];
}

/** Throws a single error listing every missing artifact and how to build it. */
export function assertPrereqs(repoRoot: string): void {
  const prereqs = getPrereqs(repoRoot);
  const missing = prereqs.filter((p) => !existsSync(resolve(repoRoot, p.relPath)));
  if (missing.length === 0) return;
  const lines = ["Missing build artifacts:\n"];
  for (const m of missing) {
    lines.push(`  - ${m.relPath}  (${m.description})`);
  }
  lines.push("\nBuild commands:");
  // De-dupe identical build lines while preserving order.
  const seen = new Set<string>();
  for (const m of missing) {
    if (seen.has(m.build)) continue;
    seen.add(m.build);
    lines.push("");
    lines.push(m.build);
  }
  throw new Error(lines.join("\n"));
}
