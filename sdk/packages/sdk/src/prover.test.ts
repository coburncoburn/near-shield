import { describe, expect, it } from "vitest";
import { StubProver, type ProveRequest } from "./prover.js";

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
