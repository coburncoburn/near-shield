import { Field } from "./field.js";
import { poseidon2, poseidon4 } from "./poseidon.js";
import { hashBytesToField } from "./hash_bytes.js";

export interface Note {
  amount: bigint;          // USDC, 6 decimals
  ownerPubkey: Field;      // derived from spending key
  auditorPubkey: Field;    // chosen at deposit
  blinding: Field;         // 256-bit random
}

/**
 * Canonical mapping from a 32-byte X25519 auditor public key to the BN254 field
 * element bound as `auditor_pubkey` in a note commitment. Hashing into the field
 * (rather than reinterpreting the 32 bytes as an integer mod p, which truncates
 * and can collide) is the single source of truth shared by the wallet (when
 * building notes) and the scanner (when verifying a note's auditor binding).
 */
export function auditorPubkeyToField(pubkey: Uint8Array): Field {
  if (pubkey.length !== 32) throw new Error("auditor pubkey must be 32 bytes");
  return hashBytesToField(pubkey);
}

/** commitment = poseidon4(amount, owner_pubkey, auditor_pubkey, blinding) */
export function commitNote(n: Note): Field {
  return poseidon4(
    new Field(n.amount),
    n.ownerPubkey,
    n.auditorPubkey,
    n.blinding
  );
}

/** nullifier = poseidon2(spending_key, poseidon2(commitment, leaf_index)) */
export function computeNullifier(
  spendingKey: Field,
  commitment: Field,
  leafIndex: bigint
): Field {
  return poseidon2(spendingKey, poseidon2(commitment, new Field(leafIndex)));
}
