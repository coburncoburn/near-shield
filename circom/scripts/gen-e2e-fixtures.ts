/**
 * gen-e2e-fixtures.ts
 *
 * Generates CONNECTED snarkjs Groth16 fixtures for a realistic
 * deposit-A → deposit-B → transfer → withdraw flow.  Every proof's merkle root
 * matches the contract's tree state at that step because we insert commitments
 * into a local MerkleTree in exactly the same order the contract will.
 *
 * Connected scenario (amounts in raw base units, e.g. mock-USDC with 6 decimals):
 *   sk = 7   (sender spending key)
 *   owner = poseidon2(7, 0)  (sender owner pubkey)
 *   auditorPubkey32 = 32 bytes of 0x42,0x43,...  (same as demo)
 *   auditorField = hashBytesToField(auditorPubkey32)
 *
 *   1. Deposit A:  amount=60, blinding=1001 → commitmentA @ index 0
 *   2. Deposit B:  amount=40, blinding=1002 → commitmentB @ index 1
 *      Tree root after both deposits = R2
 *   3. Transfer:   spend A(60)@0, B(40)@1 at root R2
 *                  out0: recipient, amount=70, owner=recipOwner, blinding=2001
 *                  out1: sender change, amount=30, owner=senderOwner, blinding=2002
 *                  Append commitmentOut0@2, commitmentOut1@3 → root R3
 *   4. Withdraw:   spend out1 (amount=30, index=3) at root R3
 *                  recipient="bob.test.near", relayer="relayer.test.near",
 *                  relayerFee=2
 *
 * Each fixture directory (circom/fixtures/e2e/{deposit_a,deposit_b,transfer,withdraw}/):
 *   proof.bin   — 256-byte snarkjsProofToBytes output
 *   proof.json  — raw snarkjs proof object
 *   public.json — publicSignals array (decimal strings)
 *   params.json — named public parameter values (hex strings) needed by the
 *                 contract entrypoints (commitment, merkle_root, nullifiers,
 *                 view_ct string, etc.)
 *
 * VK bins live in circom/fixtures/{deposit,transfer,withdraw}/vk.bin
 * (written by gen-fixtures.ts; circuit-level, scenario-independent).
 *
 * Run with:
 *   pnpm --filter @shielded-near/circom exec tsx scripts/gen-e2e-fixtures.ts
 */

import * as snarkjs from "snarkjs";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

import {
  Field,
  commitNote,
  computeNullifier,
  poseidon2,
  hashBytesToField,
  keccakToField,
} from "@shielded-near/core";
import { MerkleTree } from "@shielded-near/client";
import { snarkjsProofToBytes } from "@shielded-near/sdk";

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const BUILD = path.join(ROOT, "build");
const FIXTURES_BASE = path.join(ROOT, "fixtures");
const E2E_DIR = path.join(FIXTURES_BASE, "e2e");

// ---------------------------------------------------------------------------
// Scenario constants
// ---------------------------------------------------------------------------

// Sender
const SK = new Field(7n);
const SENDER_OWNER = poseidon2(SK, Field.zero());

// Fixed auditor: 32 bytes 0x42,0x43,...0x61 (same as demo)
const AUDITOR_PUBKEY_32 = new Uint8Array(32);
for (let i = 0; i < 32; i++) AUDITOR_PUBKEY_32[i] = (0x42 + i) & 0xff;
const AUDITOR_FIELD = hashBytesToField(AUDITOR_PUBKEY_32);

// Recipient owner pubkey (just a deterministic field element)
const RECIP_OWNER = new Field(12345678901234567890n);
// Recipient auditor is same as sender auditor (same pool run)
const RECIP_AUDITOR_FIELD = AUDITOR_FIELD;
const RECIP_AUDITOR_PUBKEY_32 = AUDITOR_PUBKEY_32;

// Fixed blindings (deterministic)
const BLINDING_A = new Field(1001n);
const BLINDING_B = new Field(1002n);
const BLINDING_OUT0 = new Field(2001n);
const BLINDING_OUT1 = new Field(2002n);

// Amounts
const AMT_A = 60n;
const AMT_B = 40n;
const AMT_OUT0 = 70n;  // recipient gets
const AMT_OUT1 = 30n;  // sender change
const AMT_WITHDRAW = 30n;
const RELAYER_FEE = 2n;

// Account IDs for withdraw public inputs
const WITHDRAW_RECIPIENT_ID = "bob.test.near";
const WITHDRAW_RELAYER_ID = "relayer.test.near";

// ---------------------------------------------------------------------------
// Build artefact loader
// ---------------------------------------------------------------------------

function loadArtifacts(circuit: string): { wasm: string; zkey: string } {
  const wasmPath = path.join(BUILD, `${circuit}_js`, `${circuit}.wasm`);
  const zkeyPath = path.join(BUILD, "keys", `${circuit}_dev.zkey`);
  if (!fs.existsSync(wasmPath)) throw new Error(`missing wasm: ${wasmPath}`);
  if (!fs.existsSync(zkeyPath)) throw new Error(`missing zkey: ${zkeyPath}`);
  return { wasm: wasmPath, zkey: zkeyPath };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Convert a Field to its decimal string (for snarkjs inputs). */
function fd(f: Field): string {
  return f.value.toString();
}

/** Convert a bigint to its decimal string. */
function bd(n: bigint): string {
  return n.toString();
}

/** Convert a Merkle path (Field[]) to decimal strings. */
function pathDec(p: Field[]): string[] {
  return p.map((f) => f.value.toString());
}

/**
 * Compute the view_ct_hash used in the proof public input.
 * Matches wallet.ts viewCtHash() and contract keccak_to_field().
 */
function viewCtHashFrom(viewCt: string): Field {
  return keccakToField(new TextEncoder().encode(viewCt));
}

/**
 * Compute recipient/relayer public inputs for the withdraw circuit.
 * Matches contract::withdraw::hash_bytes_to_field(recipient.as_bytes()).
 */
function accountIdField(id: string): Field {
  return hashBytesToField(new TextEncoder().encode(id));
}

async function proveAndVerify(
  circuit: string,
  input: Record<string, string | string[]>,
  vkJson: unknown
): Promise<{ proof: unknown; publicSignals: string[] }> {
  const { wasm, zkey } = loadArtifacts(circuit);
  console.log(`  fullProve(${circuit}) ...`);
  const { proof, publicSignals } = await (snarkjs.groth16 as any).fullProve(input, wasm, zkey);
  // Verify immediately
  const ok = await (snarkjs.groth16 as any).verify(vkJson, publicSignals, proof);
  if (!ok) {
    throw new Error(`snarkjs.groth16.verify returned false for circuit '${circuit}'! Scenario is malformed.`);
  }
  console.log(`  verify OK  publicSignals=${JSON.stringify(publicSignals.slice(0, 4))}...`);
  return { proof, publicSignals };
}

function writeFixture(
  dir: string,
  proof: unknown,
  publicSignals: string[],
  params: Record<string, string | string[]>
): void {
  fs.mkdirSync(dir, { recursive: true });
  const proofBin = snarkjsProofToBytes(proof as Parameters<typeof snarkjsProofToBytes>[0]);
  if (proofBin.length !== 256) {
    throw new Error(`proof.bin must be 256 bytes, got ${proofBin.length}`);
  }
  fs.writeFileSync(path.join(dir, "proof.bin"), Buffer.from(proofBin));
  fs.writeFileSync(path.join(dir, "proof.json"), JSON.stringify(proof, null, 2));
  fs.writeFileSync(path.join(dir, "public.json"), JSON.stringify(publicSignals, null, 2));
  fs.writeFileSync(path.join(dir, "params.json"), JSON.stringify(params, null, 2));
  console.log(`  wrote ${dir}  proof.bin=${proofBin.length}B`);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  // Prerequisite check
  for (const c of ["deposit", "transfer", "withdraw"]) {
    const missing: string[] = [];
    const r1cs = path.join(BUILD, `${c}.r1cs`);
    const wasm = path.join(BUILD, `${c}_js`, `${c}.wasm`);
    const zkey = path.join(BUILD, "keys", `${c}_dev.zkey`);
    if (!fs.existsSync(r1cs)) missing.push(r1cs);
    if (!fs.existsSync(wasm)) missing.push(wasm);
    if (!fs.existsSync(zkey)) missing.push(zkey);
    if (missing.length > 0) {
      throw new Error(
        `missing circuit build artifacts — run circom/scripts/regen-fixtures.sh\n  missing: ${missing.join(", ")}`
      );
    }
  }

  // Load VKs (needed for in-script verify)
  const vkDeposit = await (snarkjs.zKey as any).exportVerificationKey(
    path.join(BUILD, "keys", "deposit_dev.zkey")
  );
  const vkTransfer = await (snarkjs.zKey as any).exportVerificationKey(
    path.join(BUILD, "keys", "transfer_dev.zkey")
  );
  const vkWithdraw = await (snarkjs.zKey as any).exportVerificationKey(
    path.join(BUILD, "keys", "withdraw_dev.zkey")
  );

  // Local MerkleTree — mirrors the contract's IncrementalMerkleTree
  const tree = new MerkleTree();

  // Roots captured in memory as each step completes; used for scenario.json.
  let rootAfterA: Field;
  let rootAfterB: Field;
  let rootAfterTransfer: Field;

  // ─── Commitment A ────────────────────────────────────────────────────────
  const noteA = {
    amount: AMT_A,
    ownerPubkey: SENDER_OWNER,
    auditorPubkey: AUDITOR_FIELD,
    blinding: BLINDING_A,
  };
  const commitmentA = commitNote(noteA);

  // ─── Commitment B ────────────────────────────────────────────────────────
  const noteB = {
    amount: AMT_B,
    ownerPubkey: SENDER_OWNER,
    auditorPubkey: AUDITOR_FIELD,
    blinding: BLINDING_B,
  };
  const commitmentB = commitNote(noteB);

  // ─── Output commitments (transfer outputs) ───────────────────────────────
  const noteOut0 = {
    amount: AMT_OUT0,
    ownerPubkey: RECIP_OWNER,
    auditorPubkey: RECIP_AUDITOR_FIELD,
    blinding: BLINDING_OUT0,
  };
  const commitmentOut0 = commitNote(noteOut0);

  const noteOut1 = {
    amount: AMT_OUT1,
    ownerPubkey: SENDER_OWNER,
    auditorPubkey: AUDITOR_FIELD,
    blinding: BLINDING_OUT1,
  };
  const commitmentOut1 = commitNote(noteOut1);

  console.log("Connected scenario:");
  console.log(`  SK              = 7`);
  console.log(`  SENDER_OWNER    = ${SENDER_OWNER.toHex()}`);
  console.log(`  AUDITOR_FIELD   = ${AUDITOR_FIELD.toHex()}`);
  console.log(`  commitmentA     = ${commitmentA.toHex()}`);
  console.log(`  commitmentB     = ${commitmentB.toHex()}`);
  console.log(`  commitmentOut0  = ${commitmentOut0.toHex()}`);
  console.log(`  commitmentOut1  = ${commitmentOut1.toHex()}`);

  // ─────────────────────────────────────────────────────────────────────────
  // STEP 1: Deposit A
  // ─────────────────────────────────────────────────────────────────────────
  console.log("\n=== deposit_a ===");

  // A deterministic "view_ct" string for deposit A
  // (In production this would be a real sealed ciphertext; here we use a
  //  deterministic placeholder that the contract just hashes opaquely.)
  const viewCtStrA = "0x4142434445464748494a4b4c4d4e4f50";  // 16 bytes of 0x41..
  const viewCtHashA = viewCtHashFrom(viewCtStrA);
  const noteCt_A = "0x1111";  // opaque note_ct placeholder

  {
    const input: Record<string, string | string[]> = {
      // public
      commitment: fd(commitmentA),
      amount: bd(AMT_A),
      auditorPubkey: fd(AUDITOR_FIELD),
      viewCtHash: fd(viewCtHashA),
      // private (witness)
      ownerPubkey: fd(SENDER_OWNER),
      blinding: fd(BLINDING_A),
      viewCtHashWitness: fd(viewCtHashA),
    };

    const { proof, publicSignals } = await proveAndVerify("deposit", input, vkDeposit);

    // Insert into local tree AFTER proof (mirrors contract: proof verifies, then insert)
    const idxA = tree.append(commitmentA);  // index 0
    console.log(`  commitmentA inserted at index ${idxA}`);

    rootAfterA = tree.root();
    console.log(`  root after deposit A = ${rootAfterA.toHex()}`);

    writeFixture(
      path.join(E2E_DIR, "deposit_a"),
      proof,
      publicSignals,
      {
        commitment: commitmentA.toHex(),
        amount: AMT_A.toString(),
        auditor_pubkey: AUDITOR_FIELD.toHex(),
        view_ct: viewCtStrA,
        note_ct: noteCt_A,
        // root after this deposit (for test assertions)
        root_after: rootAfterA.toHex(),
      }
    );
  }

  // ─────────────────────────────────────────────────────────────────────────
  // STEP 2: Deposit B
  // ─────────────────────────────────────────────────────────────────────────
  console.log("\n=== deposit_b ===");

  const viewCtStrB = "0x5152535455565758595a5b5c5d5e5f60";
  const viewCtHashB = viewCtHashFrom(viewCtStrB);
  const noteCt_B = "0x2222";

  {
    const input: Record<string, string | string[]> = {
      commitment: fd(commitmentB),
      amount: bd(AMT_B),
      auditorPubkey: fd(AUDITOR_FIELD),
      viewCtHash: fd(viewCtHashB),
      ownerPubkey: fd(SENDER_OWNER),
      blinding: fd(BLINDING_B),
      viewCtHashWitness: fd(viewCtHashB),
    };

    const { proof, publicSignals } = await proveAndVerify("deposit", input, vkDeposit);

    const idxB = tree.append(commitmentB);  // index 1
    console.log(`  commitmentB inserted at index ${idxB}`);

    rootAfterB = tree.root();
    console.log(`  root after deposit B (= transfer root R2) = ${rootAfterB.toHex()}`);

    writeFixture(
      path.join(E2E_DIR, "deposit_b"),
      proof,
      publicSignals,
      {
        commitment: commitmentB.toHex(),
        amount: AMT_B.toString(),
        auditor_pubkey: AUDITOR_FIELD.toHex(),
        view_ct: viewCtStrB,
        note_ct: noteCt_B,
        root_after: rootAfterB.toHex(),
      }
    );
  }

  // ─────────────────────────────────────────────────────────────────────────
  // STEP 3: Transfer  (spend A@0 + B@1 at current root R2)
  // ─────────────────────────────────────────────────────────────────────────
  console.log("\n=== transfer ===");

  // Capture merkle state BEFORE transfer (tree has A@0, B@1)
  const R2 = tree.root();
  const pathA = tree.pathFor(0n);  // siblings for A at index 0
  const pathB = tree.pathFor(1n);  // siblings for B at index 1

  console.log(`  R2 (transfer root) = ${R2.toHex()}`);

  const nullifierA = computeNullifier(SK, commitmentA, 0n);
  const nullifierB = computeNullifier(SK, commitmentB, 1n);

  console.log(`  nullifierA = ${nullifierA.toHex()}`);
  console.log(`  nullifierB = ${nullifierB.toHex()}`);
  console.log(`  commitmentOut0 = ${commitmentOut0.toHex()}`);
  console.log(`  commitmentOut1 = ${commitmentOut1.toHex()}`);

  // view_ct strings for transfer (sender auditor view + recipient auditor view)
  const viewCtStrTransferSender = "0x6162636465666768696a6b6c6d6e6f70";
  const viewCtStrTransferRecip  = "0x7172737475767778797a7b7c7d7e7f80";
  const viewCtHashTransferSender = viewCtHashFrom(viewCtStrTransferSender);
  const viewCtHashTransferRecip  = viewCtHashFrom(viewCtStrTransferRecip);
  const noteCtTransferRecip = "0x3333";
  const noteCtTransferChange = "0x4444";

  {
    const input: Record<string, string | string[]> = {
      // public (9 signals, in circuit order)
      merkleRoot: fd(R2),
      nullifier0: fd(nullifierA),
      nullifier1: fd(nullifierB),
      commitmentOut0: fd(commitmentOut0),
      commitmentOut1: fd(commitmentOut1),
      auditorPubkey: fd(AUDITOR_FIELD),
      recipientAuditorPubkey: fd(RECIP_AUDITOR_FIELD),
      viewCtHashSender: fd(viewCtHashTransferSender),
      viewCtHashRecipient: fd(viewCtHashTransferRecip),
      // private witness
      in0Amount: bd(AMT_A),
      in0Owner: fd(SENDER_OWNER),
      in0Blinding: fd(BLINDING_A),
      in0LeafIndex: "0",
      in0Path: pathDec(pathA),
      in1Amount: bd(AMT_B),
      in1Owner: fd(SENDER_OWNER),
      in1Blinding: fd(BLINDING_B),
      in1LeafIndex: "1",
      in1Path: pathDec(pathB),
      spendingKey: fd(SK),
      out0Amount: bd(AMT_OUT0),
      out0Owner: fd(RECIP_OWNER),
      out0Blinding: fd(BLINDING_OUT0),
      out1Amount: bd(AMT_OUT1),
      out1Owner: fd(SENDER_OWNER),
      out1Blinding: fd(BLINDING_OUT1),
      viewCtHashSenderWitness: fd(viewCtHashTransferSender),
      viewCtHashRecipientWitness: fd(viewCtHashTransferRecip),
    };

    const { proof, publicSignals } = await proveAndVerify("transfer", input, vkTransfer);

    // Insert transfer outputs into local tree (mirrors contract transfer())
    const idx0 = tree.append(commitmentOut0);  // index 2
    const idx1 = tree.append(commitmentOut1);  // index 3
    console.log(`  commitmentOut0 inserted at index ${idx0}`);
    console.log(`  commitmentOut1 inserted at index ${idx1}`);

    // r3ForFixture (= rootAfterTransfer) is the same tree state as the outer R3
    // used in the withdraw step — all are tree.root() after appending
    // commitmentOut0 and commitmentOut1.
    const r3ForFixture = tree.root();
    rootAfterTransfer = r3ForFixture;
    console.log(`  R3 (withdraw root) = ${r3ForFixture.toHex()}`);

    writeFixture(
      path.join(E2E_DIR, "transfer"),
      proof,
      publicSignals,
      {
        merkle_root: R2.toHex(),
        nullifiers: [nullifierA.toHex(), nullifierB.toHex()],
        commitments: [commitmentOut0.toHex(), commitmentOut1.toHex()],
        auditor_pubkey: AUDITOR_FIELD.toHex(),
        recipient_auditor_pubkey: RECIP_AUDITOR_FIELD.toHex(),
        view_cts: [viewCtStrTransferSender, viewCtStrTransferRecip],
        note_cts: [noteCtTransferRecip, noteCtTransferChange],
        // post-transfer root (for test assertions)
        root_after: r3ForFixture.toHex(),
      }
    );
  }

  // ─────────────────────────────────────────────────────────────────────────
  // STEP 4: Withdraw (spend out1 — sender change — at index 3, root R3)
  // ─────────────────────────────────────────────────────────────────────────
  console.log("\n=== withdraw ===");

  // out1 is the sender's change note: amount=30, owner=SENDER_OWNER, index=3
  const R3 = tree.root();
  const pathOut1 = tree.pathFor(3n);

  const nullifierOut1 = computeNullifier(SK, commitmentOut1, 3n);
  console.log(`  nullifierOut1 = ${nullifierOut1.toHex()}`);

  const viewCtStrWithdraw = "0x8182838485868788898a8b8c8d8e8f90";
  const viewCtHashWithdraw = viewCtHashFrom(viewCtStrWithdraw);

  // Recipient and relayer fields (hash_bytes_to_field of account id bytes)
  const recipientField = accountIdField(WITHDRAW_RECIPIENT_ID);
  const relayerField = accountIdField(WITHDRAW_RELAYER_ID);
  console.log(`  recipient field = ${recipientField.toHex()}`);
  console.log(`  relayer  field  = ${relayerField.toHex()}`);

  {
    const input: Record<string, string | string[]> = {
      // public (8 signals, in circuit order)
      merkleRoot: fd(R3),
      nullifier: fd(nullifierOut1),
      recipient: fd(recipientField),
      amount: bd(AMT_WITHDRAW),
      relayer: fd(relayerField),
      relayerFee: bd(RELAYER_FEE),
      auditorPubkey: fd(AUDITOR_FIELD),
      viewCtHash: fd(viewCtHashWithdraw),
      // private witness
      noteAmount: bd(AMT_WITHDRAW),
      noteOwner: fd(SENDER_OWNER),
      noteAuditor: fd(AUDITOR_FIELD),
      noteBlinding: fd(BLINDING_OUT1),
      spendingKey: fd(SK),
      leafIndex: "3",
      merklePath: pathDec(pathOut1),
      viewCtHashWitness: fd(viewCtHashWithdraw),
    };

    const { proof, publicSignals } = await proveAndVerify("withdraw", input, vkWithdraw);

    writeFixture(
      path.join(E2E_DIR, "withdraw"),
      proof,
      publicSignals,
      {
        merkle_root: R3.toHex(),
        nullifier: nullifierOut1.toHex(),
        recipient: WITHDRAW_RECIPIENT_ID,
        amount: AMT_WITHDRAW.toString(),
        auditor_pubkey: AUDITOR_FIELD.toHex(),
        view_ct: viewCtStrWithdraw,
        relayer: WITHDRAW_RELAYER_ID,
        relayer_fee: RELAYER_FEE.toString(),
      }
    );
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Write scenario summary for the Rust test to read
  // ─────────────────────────────────────────────────────────────────────────
  // Build scenario summary from in-memory root variables (already computed above)
  // rather than re-reading the just-written params.json files.
  const summary = {
    sender_owner: SENDER_OWNER.toHex(),
    auditor_field: AUDITOR_FIELD.toHex(),
    commitmentA: commitmentA.toHex(),
    commitmentB: commitmentB.toHex(),
    commitmentOut0: commitmentOut0.toHex(),
    commitmentOut1: commitmentOut1.toHex(),
    root_after_deposit_a: rootAfterA.toHex(),
    root_after_deposit_b: rootAfterB.toHex(),
    root_after_transfer: rootAfterTransfer.toHex(),
    withdraw_recipient: WITHDRAW_RECIPIENT_ID,
    withdraw_relayer: WITHDRAW_RELAYER_ID,
    relayer_fee: RELAYER_FEE.toString(),
    withdraw_amount: AMT_WITHDRAW.toString(),
    nullifier_out1: nullifierOut1.toHex(),
  };
  fs.writeFileSync(path.join(E2E_DIR, "scenario.json"), JSON.stringify(summary, null, 2));
  console.log(`\nWrote scenario summary to ${path.join(E2E_DIR, "scenario.json")}`);
  console.log("All e2e fixtures generated and snarkjs-verified.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
