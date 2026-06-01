import { describe, it, expect } from "vitest";
import { NearCallerSubmitter } from "./near-submitter.js";
import type { NearCaller } from "./near-caller.js";
import type { SubmitRequest } from "@shielded-near/relayer";

// ---------------------------------------------------------------------------
// Fake NearCaller that records the last call made and returns a canned hash.
// ---------------------------------------------------------------------------

interface CapturedCall {
  contractId: string;
  method: string;
  args: Record<string, unknown>;
  opts?: { gas?: bigint; attachedDeposit?: bigint };
}

function makeFakeCaller(txHash = "fake-tx-hash-abc123"): {
  caller: NearCaller;
  captured: () => CapturedCall | undefined;
} {
  let last: CapturedCall | undefined;
  const caller: NearCaller = {
    accountId: () => "relayer.testnet",
    async call(contractId, method, args, opts) {
      last = { contractId, method, args, opts };
      return { logs: [], transactionHash: txHash };
    },
    async view() {
      throw new Error("view not expected in submitter tests");
    },
  };
  return { caller, captured: () => last };
}

// ---------------------------------------------------------------------------
// A minimal valid SubmitRequest fixture.
// ---------------------------------------------------------------------------

const PROOF_BYTES = new Uint8Array([1, 2, 3, 4, 255]);

const REQ: SubmitRequest = {
  proof: PROOF_BYTES,
  merkleRoot: "0xdeadbeef01",
  nullifier: "0xnullifier99",
  recipient: "alice.testnet",
  amount: "1000000",
  auditorPubkey: "0xauditorpub",
  viewCt: "0xviewciphertext",
  relayer: "relayer.testnet",
  relayerFee: "5000",
};

const POOL_ID = "pool.shielded.testnet";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("NearCallerSubmitter", () => {
  it("calls poolId.withdraw with all 9 args using the correct mapping", async () => {
    const { caller, captured } = makeFakeCaller();
    const submitter = new NearCallerSubmitter(caller, POOL_ID);

    await submitter.submitWithdraw(REQ);

    const call = captured()!;
    expect(call.contractId).toBe(POOL_ID);
    expect(call.method).toBe("withdraw");

    const args = call.args;
    expect(args.merkle_root).toBe(REQ.merkleRoot);
    expect(args.nullifier).toBe(REQ.nullifier);
    expect(args.recipient).toBe(REQ.recipient);
    expect(args.amount).toBe(REQ.amount);
    expect(args.auditor_pubkey).toBe(REQ.auditorPubkey);
    expect(args.view_ct).toBe(REQ.viewCt);
    expect(args.relayer).toBe(REQ.relayer);
    expect(args.relayer_fee).toBe(REQ.relayerFee);
    expect(args.proof).toEqual(Array.from(REQ.proof));
  });

  it("proof arg is a plain number array (not a Uint8Array)", async () => {
    const { caller, captured } = makeFakeCaller();
    const submitter = new NearCallerSubmitter(caller, POOL_ID);

    await submitter.submitWithdraw(REQ);

    const proof = captured()!.args.proof;
    expect(Array.isArray(proof)).toBe(true);
    expect(proof).toEqual([1, 2, 3, 4, 255]);
  });

  it("passes gas=300_000_000_000_000n and attachedDeposit=1 NEAR (covers pool storage rent)", async () => {
    const { caller, captured } = makeFakeCaller();
    const submitter = new NearCallerSubmitter(caller, POOL_ID);

    await submitter.submitWithdraw(REQ);

    const opts = captured()!.opts;
    expect(opts?.gas).toBe(300_000_000_000_000n);
    expect(opts?.attachedDeposit).toBe(10n ** 24n);
  });

  it("returns the transactionHash from the caller result", async () => {
    const TX = "tx-hash-xyz987";
    const { caller } = makeFakeCaller(TX);
    const submitter = new NearCallerSubmitter(caller, POOL_ID);

    const result = await submitter.submitWithdraw(REQ);

    expect(result).toBe(TX);
  });

  it("uses the poolId passed to the constructor", async () => {
    const OTHER_POOL = "other-pool.near";
    const { caller, captured } = makeFakeCaller();
    const submitter = new NearCallerSubmitter(caller, OTHER_POOL);

    await submitter.submitWithdraw(REQ);

    expect(captured()!.contractId).toBe(OTHER_POOL);
  });
});
