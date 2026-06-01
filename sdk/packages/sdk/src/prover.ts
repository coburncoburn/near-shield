/**
 * Prover interface and bundled implementations.
 *
 * The wallet asks a `Prover` to turn (public_inputs, witness) into proof bytes
 * in the same wire format the contract's groth16 verifier consumes (EIP-196/197
 * proof: `A || B || C` = 64 + 128 + 64 = 256 bytes).
 *
 * Implementations:
 *   - `StubProver` (default): emits `Uint8Array([0])` -- only the contract's
 *     `unit-testing` / `integration-testing` builds accept this.
 *   - `SnarkjsProver` (sdk/packages/sdk/src/snarkjs-prover.ts): in-process
 *     snarkjs prover; production deployments inject this with real ceremony keys.
 */

export interface ProveRequest {
  /** Which circuit's proving key to use. */
  circuit: "deposit" | "transfer" | "withdraw";
  /** Public inputs as 32-byte big-endian hex strings (0x-prefixed). */
  publicInputs: string[];
  /** Witness object, JSON-serializable. Schema is circuit-specific. */
  witness: Record<string, unknown>;
}

export interface Prover {
  prove(req: ProveRequest): Promise<Uint8Array>;
}

/**
 * Default prover. Returns a one-byte placeholder. Acceptable only when
 * paired with a contract built with mock-verifier semantics
 * (`unit-testing` or `integration-testing` feature). Will be rejected
 * by a `groth16-verifier` production contract.
 */
export class StubProver implements Prover {
  async prove(_req: ProveRequest): Promise<Uint8Array> {
    return new Uint8Array([0]);
  }
}
