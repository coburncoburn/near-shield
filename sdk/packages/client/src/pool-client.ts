import { MerkleTree } from "./merkle-tree.js";
import { parseShieldedEvents } from "./events.js";
import type { NearCaller } from "./near-caller.js";
import { Field, type NoteCiphertext } from "@shielded-near/core";
import {
  toFtTransferCallArgs, toTransferCall, type BuiltTx,
} from "@shielded-near/sdk";

const ONE_YOCTO = 1n;

export class PoolClient {
  readonly tree = new MerkleTree();
  private seenLeaves = new Set<bigint>();

  constructor(
    private readonly caller: NearCaller,
    private readonly poolId: string,
    private readonly tokenId: string,
  ) {}

  /** Deposit via ft_transfer_call on the token; returns emitted note ciphertexts. */
  async deposit(tx: BuiltTx): Promise<NoteCiphertext[]> {
    const call = toFtTransferCallArgs(tx, this.tokenId, this.poolId);
    const { logs } = await this.caller.call(call.contractId, call.methodName, call.args,
      { gas: BigInt(call.gas), attachedDeposit: ONE_YOCTO });
    return this.ingest(logs);
  }

  async transfer(tx: BuiltTx): Promise<NoteCiphertext[]> {
    const call = toTransferCall(tx, this.poolId);
    const { logs } = await this.caller.call(call.contractId, call.methodName, call.args,
      { gas: BigInt(call.gas), attachedDeposit: BigInt(call.attachedDeposit) });
    return this.ingest(logs);
  }

  async merkleRoot(): Promise<string> {
    return await this.caller.view<string>(this.poolId, "merkle_root");
  }

  /** Parse logs, grow the local tree (asserting it matches chain), return note cts. */
  private async ingest(logs: string[]): Promise<NoteCiphertext[]> {
    const ev = parseShieldedEvents(logs);
    for (const { leafIndex, commitment } of ev.commitments) {
      if (this.seenLeaves.has(leafIndex)) continue;
      // events are ascending; demo deposits/transfers append in order
      this.tree.append(Field.fromHex(commitment));
      this.seenLeaves.add(leafIndex);
    }
    return ev.noteCiphertexts.map((n) => ({
      leafIndex: n.leafIndex, sealed: hexToBytes(n.noteCtHex),
    }));
  }

  /** Cross-check: local root must equal the contract's. Throws on drift. */
  async assertRootMatchesChain(): Promise<void> {
    const local = this.tree.root().toHex();
    const chain = await this.merkleRoot();
    if (local !== chain) throw new Error(`merkle root drift: local ${local} != chain ${chain}`);
  }

  pathFor(leafIndex: bigint): string[] { return this.tree.pathFor(leafIndex).map((f) => f.toHex()); }
}

function hexToBytes(h: string): Uint8Array {
  const s = h.startsWith("0x") ? h.slice(2) : h;
  if (s.length % 2 !== 0) throw new Error(`hex string has odd length: ${h}`);
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}
