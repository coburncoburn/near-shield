import { describe, expect, it } from "vitest";
import {
  RelayerError,
  RelayerService,
  type NearTxSubmitter,
  type SubmitRequest,
} from "./service.js";

class FakeSubmitter implements NearTxSubmitter {
  public received: SubmitRequest[] = [];
  constructor(private readonly hash = "tx_hash_abc") {}
  async submitWithdraw(req: SubmitRequest): Promise<string> {
    this.received.push(req);
    return this.hash;
  }
}

function baseReq(overrides: Partial<SubmitRequest> = {}): SubmitRequest {
  return {
    proof: new Uint8Array([1, 2, 3]),
    merkleRoot: "0x" + "00".repeat(32),
    nullifier: "0x" + "ab".repeat(32),
    recipient: "bob.near",
    amount: "100000000",
    auditorPubkey: "0x" + "cc".repeat(32),
    viewCt: "viewct",
    relayer: "relayer.near",
    relayerFee: "500000",
    ...overrides,
  };
}

describe("RelayerService", () => {
  it("quotes its configured account id and fee", () => {
    const submitter = new FakeSubmitter();
    const svc = new RelayerService(
      { nearAccountId: "relayer.near", feeUsdcBase: 500_000n },
      submitter
    );
    const q = svc.quote();
    expect(q.relayer).toBe("relayer.near");
    expect(q.feeUsdcBase).toBe("500000");
    expect(q.validUntil).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it("submits a valid request to NEAR and returns the tx hash", async () => {
    const submitter = new FakeSubmitter("tx_xyz");
    const svc = new RelayerService(
      { nearAccountId: "relayer.near", feeUsdcBase: 500_000n },
      submitter
    );
    const result = await svc.submit(baseReq());
    expect(result.txHash).toBe("tx_xyz");
    expect(submitter.received).toHaveLength(1);
  });

  it("rejects requests for a different relayer", async () => {
    const svc = new RelayerService(
      { nearAccountId: "relayer.near", feeUsdcBase: 500_000n },
      new FakeSubmitter()
    );
    await expect(svc.submit(baseReq({ relayer: "imposter.near" }))).rejects.toBeInstanceOf(
      RelayerError
    );
  });

  it("rejects fee mismatch (proof would otherwise be tamperable here, on-chain it never is)", async () => {
    const svc = new RelayerService(
      { nearAccountId: "relayer.near", feeUsdcBase: 500_000n },
      new FakeSubmitter()
    );
    await expect(svc.submit(baseReq({ relayerFee: "999999" }))).rejects.toBeInstanceOf(
      RelayerError
    );
  });

  it("rejects fee greater than amount", async () => {
    const svc = new RelayerService(
      { nearAccountId: "relayer.near", feeUsdcBase: 500_000n },
      new FakeSubmitter()
    );
    await expect(
      svc.submit(baseReq({ amount: "100000", relayerFee: "500000" }))
    ).rejects.toBeInstanceOf(RelayerError);
  });

  it("rejects empty proof bytes", async () => {
    const svc = new RelayerService(
      { nearAccountId: "relayer.near", feeUsdcBase: 500_000n },
      new FakeSubmitter()
    );
    await expect(
      svc.submit(baseReq({ proof: new Uint8Array() }))
    ).rejects.toBeInstanceOf(RelayerError);
  });
});
