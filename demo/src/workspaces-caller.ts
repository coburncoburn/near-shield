import type { NearCaller } from "@shielded-near/client";
import { TransactionError, type NearAccount } from "near-workspaces";

/**
 * `NearCaller` adapter over a `near-workspaces` `Account`. Used by the demo
 * to drive the sandbox the same way a testnet client would drive a real RPC.
 *
 * Log handling: near-workspaces v4 exposes a flattened `.logs` getter on
 * `TransactionResult` that concatenates every receipt's logs in execution
 * order — that's what we surface so the `PoolClient` can parse NEP-297 events.
 * If logs ever come back empty, `PoolClient.assertRootMatchesChain()` will
 * throw on the first deposit (root drift), which is the trip-wire we want.
 */
export class WorkspacesCaller implements NearCaller {
  constructor(private readonly account: NearAccount) {}

  accountId(): string {
    return this.account.accountId;
  }

  async call(
    contractId: string,
    method: string,
    args: Record<string, unknown>,
    opts?: { gas?: bigint; attachedDeposit?: bigint }
  ): Promise<{ logs: string[]; transactionHash: string }> {
    const res = await this.account.callRaw(contractId, method, args, {
      gas: (opts?.gas ?? 100_000_000_000_000n).toString(),
      attachedDeposit: (opts?.attachedDeposit ?? 0n).toString(),
    });
    // callRaw (unlike call) does NOT throw on receipt failures — surface them.
    if (res.failed) {
      throw new TransactionError(res);
    }
    return {
      logs: res.logs,
      transactionHash: res.result.transaction_outcome.id,
    };
  }

  async view<T>(
    contractId: string,
    method: string,
    args: Record<string, unknown> = {}
  ): Promise<T> {
    // near-workspaces v4 treats `view` as a method on the *contract* account
    // itself: getAccount(contractId).view(methodName, args). The signer that
    // originated this `NearCaller` is irrelevant for a view call (no state
    // mutation), but using the workspace handle keeps us inside the sandbox.
    return await this.account.getAccount(contractId).view<T>(method, args);
  }
}
