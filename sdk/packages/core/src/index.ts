export const VERSION = "0.1.0";

export { Field, BN254_MODULUS } from "./field.js";
export { poseidon2, poseidon4 } from "./poseidon.js";
export { commitNote, computeNullifier, type Note } from "./note.js";
export {
  decodeDisclosure,
  encodeDisclosure,
  generateKeyPair,
  openSealed,
  sealTo,
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
