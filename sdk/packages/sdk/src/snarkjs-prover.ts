/**
 * In-process Groth16 prover backed by snarkjs.
 *
 * `SnarkjsProver` is a stub for now — the witness-building and proof-generation
 * logic is introduced in Task 4 of Sub-project B.
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

// Ordered public input signal names per circuit (must match `component main { public [...] }`).
const PUBLIC_NAMES: Record<CircuitName, string[]> = {
  deposit: ["commitment", "amount", "auditorPubkey", "viewCtHash"],
  transfer: [
    "merkleRoot",
    "nullifier0",
    "nullifier1",
    "commitmentOut0",
    "commitmentOut1",
    "auditorPubkey",
    "recipientAuditorPubkey",
    "viewCtHashSender",
    "viewCtHashRecipient",
  ],
  withdraw: [
    "merkleRoot",
    "nullifier",
    "recipient",
    "amount",
    "relayer",
    "relayerFee",
    "auditorPubkey",
    "viewCtHash",
  ],
};

// Witness key renames: wallet uses PubKey suffix but circom uses shorter names.
const RENAME: Record<CircuitName, Record<string, string>> = {
  deposit: {},
  transfer: {
    in0OwnerPubkey: "in0Owner",
    in1OwnerPubkey: "in1Owner",
    out0OwnerPubkey: "out0Owner",
    out1OwnerPubkey: "out1Owner",
  },
  withdraw: {
    noteOwnerPubkey: "noteOwner",
    noteAuditorPubkey: "noteAuditor",
  },
};

// Convert a single hex string to a decimal string; throws on empty or non-string input.
const toField = (x: unknown): string => {
  if (typeof x !== "string" || x === "")
    throw new Error(
      `proveRequestToCircomInput: expected non-empty hex string, got ${JSON.stringify(x)}`
    );
  return BigInt(x).toString();
};

// Convert a hex string (or array of hex strings) to decimal string(s) as snarkjs expects.
const conv = (v: unknown): string | string[] =>
  Array.isArray(v) ? v.map(toField) : toField(v);

/**
 * Map a generic `ProveRequest` to the flat input object expected by the
 * circom-generated witness calculator.
 *
 * Public inputs are mapped positionally to their named signals; witness keys
 * are renamed via the per-circuit RENAME map (e.g. `in0OwnerPubkey` →
 * `in0Owner`). All values are converted from 0x-prefixed hex to decimal
 * strings as snarkjs requires.
 *
 * Pass-through policy: witness keys that are not present in RENAME are
 * forwarded to the circom input unchanged (after value conversion). snarkjs's
 * `groth16.fullProve` will reject any signal name that does not exist in the
 * compiled circuit at witness-generation time, so unknown keys surface as
 * runtime errors there. The exact-signal-set tests in snarkjs-prover.test.ts
 * are the compile-time guard for all known circuits.
 */
export function proveRequestToCircomInput(
  req: ProveRequest
): Record<string, string | string[]> {
  const circuit = req.circuit as CircuitName;
  const names = PUBLIC_NAMES[circuit];
  if (!names) throw new Error(`unknown circuit: ${req.circuit}`);
  if (req.publicInputs.length !== names.length) {
    throw new Error(
      `${req.circuit}: expected ${names.length} public inputs, got ${req.publicInputs.length}`
    );
  }
  const input: Record<string, string | string[]> = {};
  names.forEach((n, i) => {
    input[n] = conv(req.publicInputs[i]);
  });
  const rename = RENAME[circuit];
  for (const [k, v] of Object.entries(req.witness)) {
    input[rename[k] ?? k] = conv(v);
  }
  return input;
}

/**
 * In-process prover that drives snarkjs `groth16.fullProve` with artefacts
 * supplied by an `ArtifactProvider`.
 */
export class SnarkjsProver implements Prover {
  constructor(private readonly artifacts: ArtifactProvider) {}

  /** @throws {Error} Not yet implemented — see Task 4. */
  async prove(_req: ProveRequest): Promise<Uint8Array> {
    throw new Error("not implemented");
  }
}
