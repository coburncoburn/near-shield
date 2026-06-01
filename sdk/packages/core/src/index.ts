export const VERSION = "0.1.0";

export { Field, BN254_MODULUS } from "./field.js";
export { poseidon2, poseidon4 } from "./poseidon.js";
export { hashBytesToField } from "./hash_bytes.js";
export { commitNote, computeNullifier, auditorPubkeyToField, type Note } from "./note.js";
export {
  decodeDisclosure,
  encodeDisclosure,
  generateKeyPair,
  openSealed,
  sealTo,
  SEAL_CONTEXT_NOTE,
  SEAL_CONTEXT_VIEW,
  type KeyPair,
  type ViewDisclosure,
} from "./encrypt.js";
export {
  encodeNotePayload,
  decodeNotePayload,
  scanNotes,
  type DiscoveredNote,
  type NoteCiphertext,
} from "./scanner.js";
export { keccakToField } from "./keccak_to_field.js";
