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
 * Wire format (sealed):
 *   || ephemeral_pubkey (32) || key_commitment (32) || nonce (12) || ct || tag (16) ||
 *
 * Every seal/open is domain-separated by a `context` label (HKDF `info`), so a
 * ciphertext sealed for one purpose (e.g. a note) cannot be opened in another
 * (e.g. a disclosure) even when the same recipient key is reused across roles.
 *
 * ChaCha20-Poly1305 is not key-committing, so HKDF emits 64 bytes — a 32-byte
 * encryption key plus a 32-byte key commitment carried in the blob and checked
 * on open. This binds a ciphertext to exactly one derived key (defeats
 * partitioning / multi-key-opening attacks on the AEAD).
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

function deriveKeyAndCommit(
  shared: Uint8Array,
  ephPub: Uint8Array,
  recipientPub: Uint8Array,
  context: string
): { key: Uint8Array; commit: Uint8Array } {
  // HKDF(SHA256): extract with salt = ephPub||recipientPub, expand with the
  // context label as `info` for domain separation. Emit 64 bytes: a 32-byte
  // AEAD key + a 32-byte key commitment.
  const salt = new Uint8Array(ephPub.length + recipientPub.length);
  salt.set(ephPub, 0);
  salt.set(recipientPub, ephPub.length);
  const out = hkdf(sha256, shared, salt, new TextEncoder().encode(context), 64);
  return { key: out.subarray(0, 32), commit: out.subarray(32, 64) };
}

/** Constant-time equality for the key-commitment check. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function sealTo(recipientPub: Uint8Array, plaintext: Uint8Array, context: string): Uint8Array {
  if (recipientPub.length !== 32) throw new Error("recipientPub must be 32 bytes");
  const ephPriv = x25519.utils.randomPrivateKey();
  const ephPub = x25519.getPublicKey(ephPriv);
  const shared = x25519.getSharedSecret(ephPriv, recipientPub);
  const { key, commit } = deriveKeyAndCommit(shared, ephPub, recipientPub, context);
  const nonce = randomBytes(12);
  const ct = chacha20poly1305(key, nonce).encrypt(plaintext);
  const out = new Uint8Array(32 + 32 + 12 + ct.length);
  out.set(ephPub, 0);
  out.set(commit, 32);
  out.set(nonce, 64);
  out.set(ct, 76);
  return out;
}

export function openSealed(recipientPriv: Uint8Array, sealed: Uint8Array, context: string): Uint8Array | null {
  if (sealed.length < 32 + 32 + 12 + 16) return null;
  const ephPub = sealed.subarray(0, 32);
  const storedCommit = sealed.subarray(32, 64);
  const nonce = sealed.subarray(64, 76);
  const ct = sealed.subarray(76);
  try {
    // getSharedSecret throws on an invalid/low-order ephemeral pubkey, so it
    // must be inside the try: a crafted ciphertext must yield null, never throw,
    // or one poisoned log entry halts batch scanning/auditing for everyone.
    const recipientPub = x25519.getPublicKey(recipientPriv);
    const shared = x25519.getSharedSecret(recipientPriv, ephPub);
    const { key, commit } = deriveKeyAndCommit(shared, ephPub, recipientPub, context);
    // Key-commitment check: reject unless the blob commits to exactly this key.
    if (!bytesEqual(commit, storedCommit)) return null;
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
