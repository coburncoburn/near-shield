import { x25519 } from "@noble/curves/ed25519";
import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { randomBytes } from "@noble/ciphers/webcrypto";
import { sha256 } from "@noble/hashes/sha256";

/**
 * Hybrid X25519 + ChaCha20-Poly1305 sealed-box style encryption.
 * Used for view ciphertexts (encrypted to the auditor pubkey) and note
 * ciphertexts (encrypted to the recipient's viewing key).
 *
 * Wire format (sealed): || ephemeral_pubkey (32) || nonce (12) || ct || tag (16) ||
 */
export interface KeyPair {
  publicKey: Uint8Array;   // 32 bytes
  privateKey: Uint8Array;  // 32 bytes
}

export function generateKeyPair(): KeyPair {
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

function deriveSymmetricKey(shared: Uint8Array, ephPub: Uint8Array, recipientPub: Uint8Array): Uint8Array {
  // HKDF-lite: SHA256(shared || ephPub || recipientPub) → 32-byte key.
  const buf = new Uint8Array(shared.length + ephPub.length + recipientPub.length);
  buf.set(shared, 0);
  buf.set(ephPub, shared.length);
  buf.set(recipientPub, shared.length + ephPub.length);
  return sha256(buf);
}

export function sealTo(recipientPub: Uint8Array, plaintext: Uint8Array): Uint8Array {
  if (recipientPub.length !== 32) throw new Error("recipientPub must be 32 bytes");
  const ephPriv = x25519.utils.randomPrivateKey();
  const ephPub = x25519.getPublicKey(ephPriv);
  const shared = x25519.getSharedSecret(ephPriv, recipientPub);
  const key = deriveSymmetricKey(shared, ephPub, recipientPub);
  const nonce = randomBytes(12);
  const ct = chacha20poly1305(key, nonce).encrypt(plaintext);
  const out = new Uint8Array(32 + 12 + ct.length);
  out.set(ephPub, 0);
  out.set(nonce, 32);
  out.set(ct, 44);
  return out;
}

export function openSealed(recipientPriv: Uint8Array, sealed: Uint8Array): Uint8Array | null {
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
    const key = deriveSymmetricKey(shared, ephPub, recipientPub);
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
