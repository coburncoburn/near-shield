import { describe, it, expect } from "vitest";
import { PoolClient } from "./pool-client.js";
import type { BuiltTx } from "@shielded-near/sdk";

const depositLog = JSON.stringify({
  standard: "shielded-pool", event: "deposit",
  data: {
    commitment: "0x0000000000000000000000000000000000000000000000000000000000000001",
    leaf_index: 0,
    view_ct: "0xaa",
    note_ct: "0xbb",
  },
});

/** Minimal BuiltTx stub for a deposit — satisfies toFtTransferCallArgs field requirements. */
const stubTx: BuiltTx = {
  method: "deposit",
  publicInputs: {
    commitment: "0x0000000000000000000000000000000000000000000000000000000000000001",
    amount: "100",
    auditorPubkey: "0x" + "aa".repeat(32), // 0x + 64 hex chars
    viewCtLen: 0,
  },
  proof: new Uint8Array(256),
  viewCiphertexts: [new Uint8Array(1)],
  noteCiphertexts: [new Uint8Array(1)],
} as unknown as BuiltTx;

describe("PoolClient.deposit", () => {
  it("calls caller.call with correct contract/method/attachedDeposit, grows tree by 1, and returns note ct", async () => {
    let callCount = 0;
    let capturedContractId = "";
    let capturedMethod = "";
    let capturedOpts: { gas?: bigint; attachedDeposit?: bigint } | undefined;

    const fakeCaller = {
      accountId: () => "test.near",
      call: async (
        contractId: string,
        method: string,
        _args: Record<string, unknown>,
        opts?: { gas?: bigint; attachedDeposit?: bigint },
      ) => {
        callCount++;
        capturedContractId = contractId;
        capturedMethod = method;
        capturedOpts = opts;
        return { logs: [depositLog], transactionHash: "0x0" };
      },
      view: async <T>() => "" as unknown as T,
    };

    const client = new PoolClient(fakeCaller, "pool.near", "usdc.near");
    expect(client.tree.size()).toBe(0);

    const cts = await client.deposit(stubTx);

    // The fake caller must have been invoked exactly once
    expect(callCount).toBe(1);
    // ft_transfer_call goes to the token contract (tokenId = "usdc.near")
    expect(capturedContractId).toBe("usdc.near");
    expect(capturedMethod).toBe("ft_transfer_call");
    // NEP-141 requires 1 yoctoNEAR attached
    expect(capturedOpts?.attachedDeposit).toBe(1n);

    // Tree grew by 1 and note ct was decoded correctly
    expect(client.tree.size()).toBe(1);
    expect(cts).toHaveLength(1);
    expect(cts[0].leafIndex).toBe(0n);
    // "0xbb" decodes to a single byte 0xbb
    expect(cts[0].sealed).toEqual(new Uint8Array([0xbb]));
  });

  it("deduplicates a leaf seen twice", async () => {
    const fakeCaller = {
      accountId: () => "test.near",
      call: async () => ({ logs: [depositLog], transactionHash: "0x0" }),
      view: async <T>() => "" as unknown as T,
    };

    const client = new PoolClient(fakeCaller, "pool.near", "usdc.near");
    await client.deposit(stubTx);
    await client.deposit(stubTx);
    expect(client.tree.size()).toBe(1);
  });
});
