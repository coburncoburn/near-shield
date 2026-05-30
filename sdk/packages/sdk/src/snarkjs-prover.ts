/**
 * In-process Groth16 prover backed by snarkjs.
 *
 * `SnarkjsProver` is a stub for now — the witness-building and proof-generation
 * logic is introduced in Tasks 2–4 of Sub-project B.
 */

import type { Prover, ProveRequest } from "./prover.js";

/** The three circuits supported by the protocol. */
export type CircuitName = "deposit" | "transfer" | "withdraw";

/**
 * A function that resolves the compiled circuit artefacts (WASM witness
 * generator + proving key) for a given circuit name.
 */
export type ArtifactProvider = (
  circuit: CircuitName
) => Promise<{ wasm: Uint8Array; zkey: Uint8Array }>;

/**
 * Map a generic `ProveRequest` to the flat input object expected by the
 * circom-generated witness calculator.
 *
 * @throws {Error} Not yet implemented — see Task 2.
 */
export function proveRequestToCircomInput(
  _req: ProveRequest
): Record<string, string | string[]> {
  throw new Error("not implemented");
}

/**
 * In-process prover that drives snarkjs `groth16.fullProve` with artefacts
 * supplied by an `ArtifactProvider`.
 */
export class SnarkjsProver implements Prover {
  constructor(private readonly artifacts: ArtifactProvider) {}

  /** @throws {Error} Not yet implemented — see Tasks 3–4. */
  async prove(_req: ProveRequest): Promise<Uint8Array> {
    throw new Error("not implemented");
  }
}
