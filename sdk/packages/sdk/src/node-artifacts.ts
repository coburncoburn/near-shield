/**
 * Node-only artifact provider: loads circuit wasm + dev zkey from a circom
 * build directory using the Node `fs` module.
 *
 * NOT browser-safe. Keep in its own file so bundlers can tree-shake / exclude
 * the fs import when targeting browsers.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { ArtifactProvider, CircuitName } from "./snarkjs-prover.js";

/**
 * Returns an `ArtifactProvider` that reads compiled circuit artifacts from
 * `buildDir` on disk.
 *
 * Expected layout (matches the circom build script output):
 *   <buildDir>/<circuit>_js/<circuit>.wasm
 *   <buildDir>/keys/<circuit>_dev.zkey
 *
 * @param buildDir  Absolute path to the circom build output directory.
 */
export function nodeArtifactProvider(buildDir: string): ArtifactProvider {
  return async (c: CircuitName) => ({
    wasm: new Uint8Array(readFileSync(join(buildDir, `${c}_js`, `${c}.wasm`))),
    zkey: new Uint8Array(readFileSync(join(buildDir, "keys", `${c}_dev.zkey`))),
  });
}
