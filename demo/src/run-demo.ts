/**
 * Narrated end-to-end demo of the shielded pool against a near-workspaces
 * sandbox. Drives the full deposit -> transfer -> withdraw flow with real
 * Groth16 proofs (via the `shielded-prover` CLI) and a real NEP-141 token.
 * The same code paths a testnet client uses are exercised here; only the
 * `NearCaller` differs.
 *
 * Asserts Bob's on-chain `ft_balance_of` increases by `TRANSFER_AMOUNT -
 * RELAYER_FEE` and the relayer's increases by `RELAYER_FEE` after withdraw.
 */

import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";

import { Worker, NEAR, type NearAccount } from "near-workspaces";

import {
  Field,
  openSealed,
  SEAL_CONTEXT_NOTE,
  type NoteCiphertext,
} from "@shielded-near/core";
import {
  encodeCiphertext,
  SnarkjsProver,
  nodeArtifactProvider,
  vkJsonToContractBytes,
  Wallet,
} from "@shielded-near/sdk";
import {
  NearCallerSubmitter,
  PoolClient,
} from "@shielded-near/client";
import {
  RelayerService,
  type SubmitRequest,
} from "@shielded-near/relayer";

import { assertPrereqs } from "./prereqs.js";
import { WorkspacesCaller } from "./workspaces-caller.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const REPO_ROOT = resolve(__dirname, "../..");

const POOL_OPT_WASM = resolve(
  REPO_ROOT,
  "target/wasm32-unknown-unknown/release/shielded_pool.opt.wasm"
);
const MOCK_FT_WASM = resolve(
  REPO_ROOT,
  "target/wasm32-unknown-unknown/release/mock_ft.opt.wasm"
);
const CIRCOM_BUILD = resolve(REPO_ROOT, "circom/build");

// Token: 6-decimal mock-USDC. Demo numbers (60/40) are raw base units.
const TOTAL_SUPPLY = 1_000_000_000n; // 1000 USDC base units (plenty)
const STORAGE_DEPOSIT = NEAR.parse("0.00125 N").toJSON(); // FT storage-bounds minimum

const RELAYER_FEE = 5n;
const DEPOSIT_AMOUNTS: bigint[] = [60n, 40n];
const TRANSFER_AMOUNT = 60n;

// ---------------------------------------------------------------------------
// Narration helpers
// ---------------------------------------------------------------------------

function section(title: string): void {
  console.log(`\n=== ${title} ===`);
}

function logKv(label: string, value: unknown): void {
  console.log(`  ${label}: ${value}`);
}

function hex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Decrypts each ciphertext with Bob's viewing private key and returns the
 * leafIndex of the one Bob can open. The wallet stores notes privately so the
 * demo cannot ask Bob for the leafIndex directly; it can however replicate the
 * trial-decrypt the wallet already ran (`scanNotes`) to learn which leaf is
 * Bob's. This is the cleanest demo-side bridge per the task notes.
 */
function findRecipientLeafIndex(
  cts: NoteCiphertext[],
  recipientViewingPriv: Uint8Array
): bigint {
  for (const ct of cts) {
    const opened = openSealed(recipientViewingPriv, ct.sealed, SEAL_CONTEXT_NOTE);
    if (opened) return ct.leafIndex;
  }
  throw new Error("recipient did not decrypt any of the emitted ciphertexts");
}

/**
 * Storage-registers `account` on `token`. NEP-141's `storage_deposit` is a
 * payable call attaching enough native NEAR to cover the per-account row.
 */
async function registerForToken(
  account: NearAccount,
  token: NearAccount
): Promise<void> {
  await account.call(
    token,
    "storage_deposit",
    { account_id: account.accountId, registration_only: true },
    { attachedDeposit: STORAGE_DEPOSIT }
  );
}

async function ftBalance(token: NearAccount, accountId: string): Promise<bigint> {
  const bal = await token.view<string>("ft_balance_of", { account_id: accountId });
  return BigInt(bal);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  section("Step 0: Verify build prerequisites");
  assertPrereqs(REPO_ROOT);
  logKv("pool wasm", POOL_OPT_WASM);
  logKv("ft wasm", MOCK_FT_WASM);
  logKv("circom build dir", CIRCOM_BUILD);

  const worker = await Worker.init();
  try {
    const root = worker.rootAccount;

    section("Step 1: Deploy NEP-141 token + create accounts");
    const minter = await root.createSubAccount("minter");
    const tokenAccount = await root.createSubAccount("ft");
    await tokenAccount.deploy(MOCK_FT_WASM);
    await tokenAccount.call(
      tokenAccount,
      "new",
      {
        owner_id: minter.accountId,
        total_supply: TOTAL_SUPPLY.toString(),
        metadata: {
          spec: "ft-1.0.0",
          name: "Mock USD Coin",
          symbol: "mUSDC",
          decimals: 6,
        },
      }
    );
    logKv("token", tokenAccount.accountId);
    logKv("minter (initial supply holder)", minter.accountId);

    // Pool deploy: read snarkjs VK JSONs, convert to contract bytes, call `new`.
    const poolAccount = await root.createSubAccount("pool");
    await poolAccount.deploy(POOL_OPT_WASM);
    const vkDeposit = Array.from(
      vkJsonToContractBytes(JSON.parse(readFileSync(resolve(CIRCOM_BUILD, "keys/deposit_vk.json"), "utf8")))
    );
    const vkTransfer = Array.from(
      vkJsonToContractBytes(JSON.parse(readFileSync(resolve(CIRCOM_BUILD, "keys/transfer_vk.json"), "utf8")))
    );
    const vkWithdraw = Array.from(
      vkJsonToContractBytes(JSON.parse(readFileSync(resolve(CIRCOM_BUILD, "keys/withdraw_vk.json"), "utf8")))
    );
    await poolAccount.call(poolAccount, "new", {
      owner: poolAccount.accountId,
      usdc_token: tokenAccount.accountId,
      vk_deposit: vkDeposit,
      vk_transfer: vkTransfer,
      vk_withdraw: vkWithdraw,
    }, { gas: "300000000000000" });
    logKv("pool", poolAccount.accountId);

    // Application accounts.
    const aliceNear = await root.createSubAccount("alice");
    const bobNear = await root.createSubAccount("bob");
    const relayerNear = await root.createSubAccount("relayer");

    // Storage-register every party (pool, alice, bob, relayer) on the token —
    // unregistered receivers cause ft_transfer to drop into recovery rather
    // than crediting the recipient.
    section("Step 2: Storage-register all parties on the token");
    for (const a of [poolAccount, aliceNear, bobNear, relayerNear]) {
      await registerForToken(a, tokenAccount);
      logKv(`registered`, a.accountId);
    }

    // Fund alice with enough mUSDC to cover both deposits.
    const aliceFundingNeeded = DEPOSIT_AMOUNTS.reduce((a, b) => a + b, 0n);
    await minter.call(
      tokenAccount,
      "ft_transfer",
      { receiver_id: aliceNear.accountId, amount: aliceFundingNeeded.toString() },
      { attachedDeposit: "1" }
    );
    logKv("alice funded with", `${aliceFundingNeeded} mUSDC base units`);

    // ---------- Step 3: Build wallets + shared PoolClient -----------------
    section("Step 3: Build wallets and PoolClient");
    const aliceSeed = new Uint8Array(64);
    for (let i = 0; i < 64; i++) aliceSeed[i] = (0x11 + i) & 0xff;
    const bobSeed = new Uint8Array(64);
    for (let i = 0; i < 64; i++) bobSeed[i] = (0xa0 + i) & 0xff;

    // Auditor pubkey for the demo (shared by Alice's two deposits so they can
    // be spent together — `findTransferInputs` requires matching auditors).
    const auditorPubkey = new Uint8Array(32);
    for (let i = 0; i < 32; i++) auditorPubkey[i] = (0x42 + i) & 0xff;

    const prover = new SnarkjsProver(nodeArtifactProvider(CIRCOM_BUILD));

    const alice = new Wallet({
      seed: aliceSeed,
      usdcTokenAccountId: tokenAccount.accountId,
      poolAccountId: poolAccount.accountId,
      prover,
    });
    const bob = new Wallet({
      seed: bobSeed,
      usdcTokenAccountId: tokenAccount.accountId,
      poolAccountId: poolAccount.accountId,
      prover,
    });

    const bobAddr = bob.address();
    logKv("alice owner pubkey", alice.address().ownerPubkey);
    logKv("bob owner pubkey", bobAddr.ownerPubkey);
    logKv("bob viewing pubkey", bobAddr.viewingPubkey);

    const aliceCaller = new WorkspacesCaller(aliceNear);
    const relayerCaller = new WorkspacesCaller(relayerNear);

    // PoolClient is shared across wallets; the relayer's submitter takes its own caller.
    const pool = new PoolClient(aliceCaller, poolAccount.accountId, tokenAccount.accountId);

    // ---------- Step 4: TWO deposits ---------------------------------------
    section("Step 4: Two deposits (60, then 40)");
    for (const amt of DEPOSIT_AMOUNTS) {
      const tx = await alice.buildDepositProved(
        { amount: amt, auditorPubkey },
        alice.prover
      );
      logKv(`built deposit amount`, amt);
      logKv("  commitment", tx.publicInputs.commitment);
      logKv("  proof bytes", tx.proof.length);
      const cts = await pool.deposit(tx);
      logKv("  emitted note cts", cts.length);
      const scanned = alice.scan(cts);
      logKv("  alice scanned", scanned);
      await pool.assertRootMatchesChain();
      logKv("  local root matches chain", true);
    }
    logKv("alice balance after deposits", alice.balance());
    if (alice.balance() !== DEPOSIT_AMOUNTS.reduce((a, b) => a + b, 0n)) {
      throw new Error(`unexpected alice balance ${alice.balance()}`);
    }

    // ---------- Step 5: Transfer 60 to Bob ---------------------------------
    section("Step 5: Transfer 60 to Bob (shielded)");
    const transferRoot = await pool.merkleRoot();
    logKv("merkle root", transferRoot);
    const transferTx = await alice.buildTransferProved(
      {
        amount: TRANSFER_AMOUNT,
        recipientOwnerPubkey: Field.fromHex(bobAddr.ownerPubkey),
        recipientAuditorPubkey: auditorPubkey,
        recipientViewingPubkey: hexToBytes(bobAddr.viewingPubkey),
      },
      alice.prover,
      {
        merkleRoot: transferRoot,
        merklePath0: pool.pathFor(0n),
        merklePath1: pool.pathFor(1n),
      }
    );
    logKv("transfer proof bytes", transferTx.proof.length);
    logKv("nullifiers", JSON.stringify(transferTx.publicInputs.nullifiers));
    logKv("output commitments", JSON.stringify(transferTx.publicInputs.commitments));
    const tCts = await pool.transfer(transferTx);
    bob.scan(tCts);
    alice.scan(tCts);
    alice.markSpent(0n);
    alice.markSpent(1n);
    await pool.assertRootMatchesChain();
    logKv("alice balance", alice.balance());
    logKv("bob balance", bob.balance());
    if (alice.balance() !== 40n) throw new Error(`alice expected 40, got ${alice.balance()}`);
    if (bob.balance() !== TRANSFER_AMOUNT)
      throw new Error(`bob expected ${TRANSFER_AMOUNT}, got ${bob.balance()}`);

    // ---------- Step 6: Bob withdraws via relayer --------------------------
    section("Step 6: Bob withdraws 60 via relayer");
    const bobLeafIndex = findRecipientLeafIndex(tCts, bob.viewingKey.privateKey);
    logKv("bob's note leafIndex", bobLeafIndex);
    const withdrawRoot = await pool.merkleRoot();
    logKv("merkle root for withdraw", withdrawRoot);

    const withdrawTx = await bob.buildWithdrawProved(
      {
        amount: TRANSFER_AMOUNT,
        recipientNearAccount: bobNear.accountId,
        relayer: relayerNear.accountId,
        relayerFee: RELAYER_FEE,
        merkleRoot: withdrawRoot,
        merklePath: pool.pathFor(bobLeafIndex),
      },
      bob.prover
    );
    logKv("withdraw proof bytes", withdrawTx.proof.length);
    logKv("nullifier", withdrawTx.publicInputs.nullifier);
    logKv("recipient", withdrawTx.publicInputs.recipient);

    // Build the SubmitRequest the relayer expects.
    const submitReq: SubmitRequest = {
      proof: withdrawTx.proof,
      merkleRoot: withdrawRoot,
      nullifier: String(withdrawTx.publicInputs.nullifier),
      recipient: bobNear.accountId,
      amount: String(TRANSFER_AMOUNT),
      auditorPubkey: String(withdrawTx.publicInputs.auditorPubkey),
      viewCt: encodeCiphertext(withdrawTx.viewCiphertexts[0]),
      relayer: relayerNear.accountId,
      relayerFee: String(RELAYER_FEE),
    };

    const relayerService = new RelayerService(
      { nearAccountId: relayerNear.accountId, feeUsdcBase: RELAYER_FEE },
      new NearCallerSubmitter(relayerCaller, poolAccount.accountId)
    );

    const bobBalanceBefore = await ftBalance(tokenAccount, bobNear.accountId);
    const relayerBalanceBefore = await ftBalance(tokenAccount, relayerNear.accountId);
    logKv("bob token balance before", bobBalanceBefore);
    logKv("relayer token balance before", relayerBalanceBefore);

    const result = await relayerService.submit(submitReq);
    logKv("withdraw tx hash", result.txHash);

    // ---------- Step 7: On-chain balance assertions ------------------------
    section("Step 7: Verify on-chain payouts");
    const bobBalanceAfter = await ftBalance(tokenAccount, bobNear.accountId);
    const relayerBalanceAfter = await ftBalance(tokenAccount, relayerNear.accountId);
    logKv("bob token balance after", bobBalanceAfter);
    logKv("relayer token balance after", relayerBalanceAfter);

    const expectedBobDelta = TRANSFER_AMOUNT - RELAYER_FEE;
    if (bobBalanceAfter - bobBalanceBefore !== expectedBobDelta) {
      throw new Error(
        `bob balance delta ${bobBalanceAfter - bobBalanceBefore} != expected ${expectedBobDelta}`
      );
    }
    if (relayerBalanceAfter - relayerBalanceBefore !== RELAYER_FEE) {
      throw new Error(
        `relayer balance delta ${relayerBalanceAfter - relayerBalanceBefore} != expected ${RELAYER_FEE}`
      );
    }

    console.log("\nALL ASSERTIONS PASSED. Demo complete.");
  } finally {
    await worker.tearDown();
  }
}

function hexToBytes(s: string): Uint8Array {
  const t = s.startsWith("0x") ? s.slice(2) : s;
  if (t.length % 2 !== 0) throw new Error(`odd hex length: ${s}`);
  const out = new Uint8Array(t.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(t.substr(i * 2, 2), 16);
  return out;
}

main().catch((err) => {
  console.error("\nDEMO FAILED:", err);
  process.exit(1);
});
