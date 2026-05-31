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

const CIRCUITS = ["deposit", "transfer", "withdraw"] as const;
type Circuit = typeof CIRCUITS[number];

export function getPrereqs(repoRoot: string): Prereq[] {
  const prereqs: Prereq[] = [
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
  ];

  for (const c of CIRCUITS) {
    prereqs.push(
      {
        description: `${c} circom R1CS`,
        relPath: `circom/build/${c}.r1cs`,
        build: "pnpm --filter @shielded-near/circom build",
      },
      {
        description: `${c} circom WASM`,
        relPath: `circom/build/${c}_js/${c}.wasm`,
        build: "pnpm --filter @shielded-near/circom build",
      },
      {
        description: `${c} dev proving key`,
        relPath: `circom/build/keys/${c}_dev.zkey`,
        build: "bash circom/scripts/dev-setup.sh",
      },
      {
        description: `${c} verification key JSON`,
        relPath: `circom/build/keys/${c}_vk.json`,
        build: "bash circom/scripts/dev-setup.sh",
      }
    );
  }

  return prereqs;
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
