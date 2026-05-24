/**
 * Translates a `BuiltTx` (the wallet's loose internal representation) into the
 * exact JSON shape each contract method expects when invoked over the NEAR
 * JSON-RPC. This is the typed glue between the SDK's wallet layer and the
 * Rust contract's `#[near] pub fn` signatures.
 *
 * Contract method signatures, for reference (see `contract/src/`):
 *   deposit(commitment: String, amount: U128, auditor_pubkey: String,
 *           view_ct: String, note_ct: String, proof: Vec<u8>)
 *   transfer(merkle_root: String, nullifiers: [String; 2], commitments: [String; 2],
 *            auditor_pubkey: String, recipient_auditor_pubkey: String,
 *            view_cts: [String; 2], note_cts: [String; 2], proof: Vec<u8>)
 *   withdraw(merkle_root: String, nullifier: String, recipient: AccountId,
 *            amount: U128, auditor_pubkey: String, view_ct: String,
 *            relayer: AccountId, relayer_fee: U128, proof: Vec<u8>)
 *
 *   ft_on_transfer(sender_id, amount, msg) -- production deposit path; `msg`
 *   carries a `DepositArgs` JSON identical to the direct `deposit` args.
 */

import type { BuiltTx } from "./wallet.js";

/** NEAR JSON encoding: U128 is a base-10 decimal string. */
export type U128String = string;

export interface DepositArgs {
  commitment: string;
  amount: U128String;
  auditor_pubkey: string;
  view_ct: string;
  note_ct: string;
  proof: number[];
}

export interface TransferArgs {
  merkle_root: string;
  nullifiers: [string, string];
  commitments: [string, string];
  auditor_pubkey: string;
  recipient_auditor_pubkey: string;
  view_cts: [string, string];
  note_cts: [string, string];
  proof: number[];
}

export interface WithdrawArgs {
  merkle_root: string;
  nullifier: string;
  recipient: string;
  amount: U128String;
  auditor_pubkey: string;
  view_ct: string;
  relayer: string;
  relayer_fee: U128String;
  proof: number[];
}

/**
 * A NEAR function-call envelope: the artifacts `near-api-js` (or any signer)
 * needs to broadcast a transaction. Production deposits go through
 * `ft_transfer_call` on the USDC contract with a `msg` payload — that variant
 * is built by `toFtTransferCallArgs`.
 */
export interface NearFunctionCall {
  contractId: string;
  methodName: string;
  args: Record<string, unknown>;
  /** yoctoNEAR. NEP-141 ft_transfer requires "1". */
  attachedDeposit: string;
  /** Suggested gas in raw gas units (Tgas * 1e12). */
  gas: string;
}

const ONE_HUNDRED_TGAS = (100n * 10n ** 12n).toString();
const THREE_HUNDRED_TGAS = (300n * 10n ** 12n).toString();

/** Direct `deposit` call (host-side tests + non-FT paths). */
export function toDepositArgs(tx: BuiltTx): DepositArgs {
  expectMethod(tx, "deposit");
  const pi = tx.publicInputs;
  return {
    commitment: pickString(pi, "commitment"),
    amount: pickString(pi, "amount"),
    auditor_pubkey: pickString(pi, "auditorPubkey"),
    view_ct: encodeCt(tx.viewCiphertexts[0]),
    note_ct: encodeCt(tx.noteCiphertexts[0]),
    proof: Array.from(tx.proof),
  };
}

/**
 * Production deposit: pack the same args into the `msg` of a
 * `ft_transfer_call` against the USDC contract. The USDC contract will invoke
 * our `ft_on_transfer` with this msg.
 */
export function toFtTransferCallArgs(
  tx: BuiltTx,
  usdcAccountId: string,
  poolAccountId: string
): NearFunctionCall {
  expectMethod(tx, "deposit");
  const depositArgs = toDepositArgs(tx);
  return {
    contractId: usdcAccountId,
    methodName: "ft_transfer_call",
    args: {
      receiver_id: poolAccountId,
      amount: depositArgs.amount,
      memo: null,
      msg: JSON.stringify(depositArgs),
    },
    attachedDeposit: "1",
    gas: THREE_HUNDRED_TGAS,
  };
}

export function toTransferArgs(tx: BuiltTx): TransferArgs {
  expectMethod(tx, "transfer");
  const pi = tx.publicInputs;
  const nullifiers = pickStringPair(pi, "nullifiers");
  const commitments = pickStringPair(pi, "commitments");
  return {
    merkle_root: pickString(pi, "merkleRoot"),
    nullifiers,
    commitments,
    auditor_pubkey: pickString(pi, "auditorPubkey"),
    recipient_auditor_pubkey: pickString(pi, "recipientAuditorPubkey"),
    view_cts: [encodeCt(tx.viewCiphertexts[0]), encodeCt(tx.viewCiphertexts[1])],
    note_cts: [encodeCt(tx.noteCiphertexts[0]), encodeCt(tx.noteCiphertexts[1])],
    proof: Array.from(tx.proof),
  };
}

export function toWithdrawArgs(tx: BuiltTx): WithdrawArgs {
  expectMethod(tx, "withdraw");
  const pi = tx.publicInputs;
  return {
    merkle_root: pickString(pi, "merkleRoot"),
    nullifier: pickString(pi, "nullifier"),
    recipient: pickString(pi, "recipient"),
    amount: pickString(pi, "amount"),
    auditor_pubkey: pickString(pi, "auditorPubkey"),
    view_ct: encodeCt(tx.viewCiphertexts[0]),
    relayer: pickString(pi, "relayer"),
    relayer_fee: pickString(pi, "relayerFee"),
    proof: Array.from(tx.proof),
  };
}

/** Build the function-call envelope for a transfer (caller submits directly). */
export function toTransferCall(tx: BuiltTx, poolAccountId: string): NearFunctionCall {
  return {
    contractId: poolAccountId,
    methodName: "transfer",
    args: toTransferArgs(tx) as unknown as Record<string, unknown>,
    attachedDeposit: "0",
    gas: ONE_HUNDRED_TGAS,
  };
}

/** Build the function-call envelope for a withdraw (relayer submits). */
export function toWithdrawCall(tx: BuiltTx, poolAccountId: string): NearFunctionCall {
  return {
    contractId: poolAccountId,
    methodName: "withdraw",
    args: toWithdrawArgs(tx) as unknown as Record<string, unknown>,
    attachedDeposit: "0",
    gas: ONE_HUNDRED_TGAS,
  };
}

// --- internals -----------------------------------------------------------

function expectMethod(tx: BuiltTx, expected: BuiltTx["method"]): void {
  if (tx.method !== expected) {
    throw new Error(`envelope expected method=${expected}, got ${tx.method}`);
  }
}

function pickString(pi: BuiltTx["publicInputs"], key: string): string {
  const v = pi[key];
  if (typeof v !== "string") {
    throw new Error(`public input ${key}: expected string, got ${typeof v}`);
  }
  return v;
}

function pickStringPair(pi: BuiltTx["publicInputs"], key: string): [string, string] {
  const v = pi[key];
  if (!Array.isArray(v) || v.length !== 2 || !v.every((x) => typeof x === "string")) {
    throw new Error(`public input ${key}: expected [string, string]`);
  }
  return [v[0], v[1]];
}

/**
 * Ciphertexts are sent over JSON. We use hex (chosen for round-trip simplicity
 * and to avoid base64 confusion across platforms). The Rust contract treats
 * them as opaque `String`s and just hashes them into the public input.
 */
function encodeCt(b: Uint8Array): string {
  return "0x" + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}
