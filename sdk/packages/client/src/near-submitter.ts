import type { NearCaller } from "./near-caller.js";
import type { NearTxSubmitter, SubmitRequest } from "@shielded-near/relayer";

export class NearCallerSubmitter implements NearTxSubmitter {
  constructor(private readonly caller: NearCaller, private readonly poolId: string) {}

  async submitWithdraw(req: SubmitRequest): Promise<string> {
    const { transactionHash } = await this.caller.call(
      this.poolId,
      "withdraw",
      {
        merkle_root: req.merkleRoot,
        nullifier: req.nullifier,
        recipient: req.recipient,
        amount: req.amount,
        auditor_pubkey: req.auditorPubkey,
        view_ct: req.viewCt,
        relayer: req.relayer,
        relayer_fee: req.relayerFee,
        proof: Array.from(req.proof),
      },
      { gas: 300_000_000_000_000n, attachedDeposit: 1n },
    );
    return transactionHash;
  }
}
