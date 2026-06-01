// Run with: pnpm tsx sdk/test-vectors/scripts/capture-realistic-view-ct.ts
// Appends/regenerates the `realistic_view_ct` entry for view_ct_keccak.json.
import { Wallet } from "@shielded-near/sdk";
import { encodeCiphertext } from "@shielded-near/sdk";
import { keccakToField } from "@shielded-near/core";
import { writeFileSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const seedAlice = new Uint8Array(64).fill(1);
const seedBob = new Uint8Array(64).fill(2);
const auditorPubkey = new Uint8Array(32).fill(3);
const alice = new Wallet({ seed: seedAlice, usdcTokenAccountId: "u.t", poolAccountId: "p.t" });
const bob = new Wallet({ seed: seedBob, usdcTokenAccountId: "u.t", poolAccountId: "p.t" });

// Two scanned deposits at leaves 0,1 (same auditor) so findTransferInputs finds inputs.
for (const [i, amt] of [[0n, 60n], [1n, 40n]] as [bigint, bigint][]) {
  const tx = alice.buildDeposit({ amount: amt, auditorPubkey });
  alice.scan([{ leafIndex: i, sealed: tx.noteCiphertexts[0] }]);
}

class FakeProver { async prove() { return new Uint8Array(256); } }
const merkleInputs = {
  merkleRoot: "0x" + "00".repeat(32),
  merklePath0: Array.from({ length: 20 }, () => "0x" + "00".repeat(32)),
  merklePath1: Array.from({ length: 20 }, () => "0x" + "00".repeat(32)),
};
const tx = await alice.buildTransferProved(
  { amount: 60n, recipientOwnerPubkey: bob.ownerPubkey,
    recipientAuditorPubkey: auditorPubkey, recipientViewingPubkey: bob.viewingKey.publicKey },
  new FakeProver() as any, merkleInputs);

const encoded = new TextEncoder().encode(encodeCiphertext(tx.viewCiphertexts[0]));
const hex = (b: Uint8Array) => "0x" + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const inputHex = hex(encoded);
const fieldHex = keccakToField(encoded).toHex();
const digestHex = "0x" + Array.from(
  (await import("@noble/hashes/sha3")).keccak_256(encoded)
).map((x) => x.toString(16).padStart(2, "0")).join("");

const VECTORS_PATH = fileURLToPath(new URL("../view_ct_keccak.json", import.meta.url));
const v = JSON.parse(readFileSync(VECTORS_PATH, "utf-8"));
v.cases = v.cases.filter((c: any) => c.name !== "realistic_view_ct");
v.cases.push({ name: "realistic_view_ct", input_hex: inputHex,
               expected_digest_hex: digestHex, expected_field_hex: fieldHex });
writeFileSync(VECTORS_PATH, JSON.stringify(v, null, 2) + "\n");
console.log("Appended realistic_view_ct vector.");
