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
 *   - `SubprocessProver`: shells out to a configured CLI and returns its stdout
 *     bytes. The bundled `tools/prover` is currently a reference harness unless
 *     it can prove deposit/transfer/withdraw; production deployments must pass
 *     `scripts/check-production-readiness.sh`.
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

/**
 * Shells out to an external Groth16 prover binary. The binary contract:
 *
 *   stdin:  JSON `{ circuit, publicInputs, witness }`
 *   stdout: raw 256 bytes: A_g1 (64) || B_g2 (128) || C_g1 (64)
 *   exit:   0 on success, non-zero on failure (stderr carries the reason)
 *
 * Implementations of the binary handle:
 *   - loading the proving key for the requested circuit
 *   - building the arkworks/snarkjs witness from the JSON
 *   - generating the Groth16 proof
 *   - serializing to the EIP-196/197 wire format
 */
export class SubprocessProver implements Prover {
  constructor(
    /** Absolute path to the prover binary. */
    private readonly binaryPath: string,
    /** Optional working directory the binary executes in (e.g., where proving keys live). */
    private readonly cwd?: string,
    /** Optional invoker for testing -- defaults to Node child_process.spawn. */
    private readonly spawnFn?: (
      cmd: string,
      args: string[],
      opts: { cwd?: string; stdin?: string }
    ) => Promise<{ stdout: Uint8Array; stderr: string; code: number }>
  ) {}

  async prove(req: ProveRequest): Promise<Uint8Array> {
    const spawn = this.spawnFn ?? defaultSpawn;
    const { stdout, stderr, code } = await spawn(this.binaryPath, [], {
      cwd: this.cwd,
      stdin: JSON.stringify(req),
    });
    if (code !== 0) {
      throw new Error(`prover exited ${code}: ${stderr.slice(0, 500)}`);
    }
    if (stdout.length !== 256) {
      throw new Error(`prover returned ${stdout.length} bytes; expected 256 (A||B||C)`);
    }
    return stdout;
  }
}

async function defaultSpawn(
  cmd: string,
  args: string[],
  opts: { cwd?: string; stdin?: string }
): Promise<{ stdout: Uint8Array; stderr: string; code: number }> {
  const { spawn } = await import("node:child_process");
  return await new Promise((resolve, reject) => {
    const proc = spawn(cmd, args, { cwd: opts.cwd });
    const stdoutChunks: Buffer[] = [];
    let stderr = "";
    proc.stdout.on("data", (chunk: Buffer) => stdoutChunks.push(chunk));
    proc.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString("utf8")));
    proc.on("error", reject);
    proc.on("close", (code: number) => {
      resolve({ stdout: new Uint8Array(Buffer.concat(stdoutChunks)), stderr, code: code ?? -1 });
    });
    if (opts.stdin !== undefined) {
      proc.stdin.write(opts.stdin);
      proc.stdin.end();
    }
  });
}
