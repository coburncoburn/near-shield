import type { Account } from "near-api-js";

/** Minimal NEAR transport the client needs. Injected so the same client works
 *  against a near-workspaces sandbox (demo) and testnet (near-api-js). */
export interface NearCaller {
  /** AccountId of the signer. */
  accountId(): string;
  /** Change-method call. Returns the tx outcome's logs (flattened) and transaction hash. */
  call(contractId: string, method: string, args: Record<string, unknown>,
       opts?: { gas?: bigint; attachedDeposit?: bigint }): Promise<{ logs: string[]; transactionHash: string }>;
  /** View-method call, JSON-decoded. */
  view<T>(contractId: string, method: string, args?: Record<string, unknown>): Promise<T>;
}

/** Adapter over a near-api-js Account (testnet / mainnet path). */
export class NearApiJsCaller implements NearCaller {
  constructor(private readonly account: Account) {}
  accountId(): string { return this.account.accountId; }
  async call(contractId: string, method: string, args: Record<string, unknown>,
             opts?: { gas?: bigint; attachedDeposit?: bigint }) {
    const outcome = await this.account.functionCall({
      contractId, methodName: method, args,
      gas: opts?.gas ?? 100_000_000_000_000n,
      attachedDeposit: opts?.attachedDeposit ?? 0n,
    });
    const logs = outcome.receipts_outcome.flatMap((r) => r.outcome.logs);
    return { logs, transactionHash: outcome.transaction_outcome.id };
  }
  async view<T>(contractId: string, method: string, args: Record<string, unknown> = {}) {
    return (await this.account.viewFunction({ contractId, methodName: method, args })) as T;
  }
}
