import { Field } from "./field.js";
import { poseidon2 } from "./poseidon.js";

/**
 * Reduces an arbitrary byte string to a single Field. Matches the Rust
 * contract's `contract::deposit::hash_bytes_to_field` byte-for-byte. The
 * canonical algorithm (and test vectors) live in
 * `sdk/test-vectors/view_ct_hash.json`.
 *
 * Algorithm:
 *   1. Split bytes into 31-byte chunks (last chunk zero-padded).
 *   2. Each chunk -> Field via little-endian byte interpretation.
 *   3. Empty input -> Field.zero().
 *   4. Single chunk -> that chunk.
 *   5. Multiple chunks -> linear poseidon2 fold: acc = poseidon2(acc, next).
 */
export function hashBytesToField(b: Uint8Array): Field {
  if (b.length === 0) return Field.zero();
  const chunks: Field[] = [];
  for (let i = 0; i < b.length; i += 31) {
    chunks.push(fieldFromLeBytes(b.subarray(i, i + 31)));
  }
  if (chunks.length === 1) return chunks[0];
  let acc = chunks[0];
  for (let i = 1; i < chunks.length; i++) {
    acc = poseidon2(acc, chunks[i]);
  }
  return acc;
}

function fieldFromLeBytes(bytes: Uint8Array): Field {
  // Little-endian: first byte is the least significant.
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    v = (v << 8n) | BigInt(bytes[i]);
  }
  return new Field(v);
}
