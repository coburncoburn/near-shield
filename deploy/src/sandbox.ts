import { Worker } from "near-workspaces";
import type { InitArgs } from "./assemble.js";

export interface SandboxResult {
  ok: true;
  owner: string;
  usdcToken: string;
  paused: boolean;
}

/** Deploys the WASM to a fresh sandbox account, calls new(initArgs), post-verifies the views. */
export async function deployToSandbox(
  wasmPath: string,
  initArgs: InitArgs
): Promise<SandboxResult> {
  const worker = await Worker.init();
  try {
    const pool = await worker.rootAccount.createSubAccount("pool");
    await pool.deploy(wasmPath);
    // 300 Tgas: new() writes ~2.9 KB of VK bytes + builds the depth-20 tree; the
    // near-workspaces default (~30 Tgas) is too tight. Mirrors demo/src/run-demo.ts.
    await pool.call(pool, "new", initArgs as unknown as Record<string, unknown>, { gas: "300000000000000" });
    const owner = await pool.view<string>("owner", {});
    const usdcToken = await pool.view<string>("usdc_token", {});
    const paused = await pool.view<boolean>("is_paused", {});
    if (owner !== initArgs.owner)
      throw new Error(`owner view ${owner} != ${initArgs.owner}`);
    if (usdcToken !== initArgs.usdc_token)
      throw new Error(`usdc_token view ${usdcToken} != ${initArgs.usdc_token}`);
    if (paused !== false) throw new Error(`expected is_paused=false, got ${paused}`);
    return { ok: true, owner, usdcToken, paused };
  } finally {
    await worker.tearDown();
  }
}
