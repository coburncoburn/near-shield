import { x25519 } from "@noble/curves/ed25519";
import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { randomBytes } from "@noble/ciphers/webcrypto";
import { sha256 } from "@noble/hashes/sha256";
import { hkdf } from "@noble/hashes/hkdf";

/**
 * Hybrid X25519 + ChaCha20-Poly1305 sealed-box style encryption.
 * Used for view ciphertexts (encrypted to the auditor pubkey) and note
 * ciphertexts (encrypted to the recipient's viewing key).
 *
 * Wire format (sealed): || ephemeral_pubkey (32) || nonce (12) || ct || tag (16) ||
 *
 * Every seal/open is domain-separated by a `context` label (HKDF `info`), so a
 * ciphertext sealed for one purpose (e.g. a note) cannot be opened in another
 * (e.g. a disclosure) even when the same recipient key is reused across roles.
 */
export interface KeyPair {
  publicKey: Uint8Array;   // 32 bytes
  privateKey: Uint8Array;  // 32 bytes
}

/** Domain-separation labels — pass the matching one to sealTo/openSealed. */
export const SEAL_CONTEXT_NOTE = "shielded-pool/note-v1";
export const SEAL_CONTEXT_VIEW = "shielded-pool/view-v1";

export function generateKeyPair(): KeyPair {
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

function deriveSymmetricKey(
  shared: Uint8Array,
  ephPub: Uint8Array,
  recipientPub: Uint8Array,
  context: string
): Uint8Array {
  // HKDF(SHA256): extract with salt = ephPub||recipientPub, expand with the
  // context label as `info` for domain separation. ChaCha20-Poly1305 is not
  // key-committing; the context only prevents cross-purpose ciphertext reuse.
  const salt = new Uint8Array(ephPub.length + recipientPub.length);
  salt.set(ephPub, 0);
  salt.set(recipientPub, ephPub.length);
  return hkdf(sha256, shared, salt, new TextEncoder().encode(context), 32);
}

export function sealTo(recipientPub: Uint8Array, plaintext: Uint8Array, context: string): Uint8Array {
  if (recipientPub.length !== 32) throw new Error("recipientPub must be 32 bytes");
  const ephPriv = x25519.utils.randomPrivateKey();
  const ephPub = x25519.getPublicKey(ephPriv);
  const shared = x25519.getSharedSecret(ephPriv, recipientPub);
  const key = deriveSymmetricKey(shared, ephPub, recipientPub, context);
  const nonce = randomBytes(12);
  const ct = chacha20poly1305(key, nonce).encrypt(plaintext);
  const out = new Uint8Array(32 + 12 + ct.length);
  out.set(ephPub, 0);
  out.set(nonce, 32);
  out.set(ct, 44);
  return out;
}

export function openSealed(recipientPriv: Uint8Array, sealed: Uint8Array, context: string): Uint8Array | null {
  if (sealed.length < 32 + 12 + 16) return null;
  const ephPub = sealed.subarray(0, 32);
  const nonce = sealed.subarray(32, 44);
  const ct = sealed.subarray(44);
  try {
    // getSharedSecret throws on an invalid/low-order ephemeral pubkey, so it
    // must be inside the try: a crafted ciphertext must yield null, never throw,
    // or one poisoned log entry halts batch scanning/auditing for everyone.
    const recipientPub = x25519.getPublicKey(recipientPriv);
    const shared = x25519.getSharedSecret(recipientPriv, ephPub);
    const key = deriveSymmetricKey(shared, ephPub, recipientPub, context);
    return chacha20poly1305(key, nonce).decrypt(ct);
  } catch {
    return null;
  }
}

/** Auditor disclosure payload, encoded as compact JSON. */
export interface ViewDisclosure {
  action: "deposit" | "transfer" | "withdraw";
  senderOwnerPubkey: string;   // hex
  recipientOwnerPubkey: string; // hex
  amounts: string[];           // decimal strings to avoid bigint JSON loss
  memo: string;
  timestamp: number;
}

export function encodeDisclosure(d: ViewDisclosure): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(d));
}

export function decodeDisclosure(b: Uint8Array): ViewDisclosure {
  return JSON.parse(new TextDecoder().decode(b)) as ViewDisclosure;
}
