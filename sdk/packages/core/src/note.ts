import { Field } from "./field.js";
import { poseidon2, poseidon4 } from "./poseidon.js";

export interface Note {
  amount: bigint;          // USDC, 6 decimals
  ownerPubkey: Field;      // derived from spending key
  auditorPubkey: Field;    // chosen at deposit
  blinding: Field;         // 256-bit random
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
