import { describe, expect, it } from "vitest";
import { StubProver, SubprocessProver, type ProveRequest } from "./prover.js";

const minimalRequest: ProveRequest = {
  circuit: "deposit",
  publicInputs: ["0x" + "00".repeat(32)],
  witness: {},
};

describe("StubProver", () => {
  it("returns a one-byte placeholder", async () => {
    const p = new StubProver();
    const bytes = await p.prove(minimalRequest);
    expect(bytes).toEqual(new Uint8Array([0]));
  });
});

describe("SubprocessProver", () => {
  it("calls the binary with JSON stdin and returns its 256-byte stdout", async () => {
    let receivedStdin = "";
    const fakeSpawn = async (
      cmd: string,
      _args: string[],
      opts: { cwd?: string; stdin?: string }
    ) => {
      expect(cmd).toBe("/tmp/test-prover");
      receivedStdin = opts.stdin ?? "";
      const out = new Uint8Array(256);
      for (let i = 0; i < 256; i++) out[i] = i & 0xff;
      return { stdout: out, stderr: "", code: 0 };
    };
    const p = new SubprocessProver("/tmp/test-prover", undefined, fakeSpawn);
    const proof = await p.prove(minimalRequest);
    expect(proof.length).toBe(256);
    expect(JSON.parse(receivedStdin)).toEqual(minimalRequest);
  });

  it("throws when the binary exits non-zero, surfacing stderr", async () => {
    const fakeSpawn = async () => ({
      stdout: new Uint8Array(),
      stderr: "Groth16Prover: invalid witness for deposit circuit\n",
      code: 1,
    });
    const p = new SubprocessProver("/no-where", undefined, fakeSpawn);
    await expect(p.prove(minimalRequest)).rejects.toThrow(/prover exited 1/);
    await expect(p.prove(minimalRequest)).rejects.toThrow(/invalid witness/);
  });

  it("throws when the binary returns wrong-sized output", async () => {
    const fakeSpawn = async () => ({
      stdout: new Uint8Array(100),
      stderr: "",
      code: 0,
    });
    const p = new SubprocessProver("/no-where", undefined, fakeSpawn);
    await expect(p.prove(minimalRequest)).rejects.toThrow(/expected 256/);
  });
});
