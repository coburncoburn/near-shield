import { keccak_256 } from "@noble/hashes/sha3";
import { Field } from "./field.js";

/** Reduces arbitrary bytes to a Field via keccak256 + first-31-bytes-LE.
 *  Mirrors `contract::deposit::keccak_to_field` byte-for-byte. Cross-language
 *  vectors live in `sdk/test-vectors/view_ct_keccak.json`. */
export function keccakToField(b: Uint8Array): Field {
  const digest = keccak_256(b); // 32 bytes
  return Field.fromBytesLe(digest.subarray(0, 31));
}
