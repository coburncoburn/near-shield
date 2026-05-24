import { openSealed } from "./encrypt.js";
import { Field } from "./field.js";
import { commitNote, type Note } from "./note.js";

/**
 * Note ciphertext as it would appear in a NEAR contract log: the sealed bytes,
 * plus the assigned `leafIndex` (so the recipient can later prove inclusion).
 */
export interface NoteCiphertext {
  leafIndex: bigint;
  sealed: Uint8Array;
}

/** A decrypted note plus its on-chain position. */
export interface DiscoveredNote {
  leafIndex: bigint;
  note: Note;
  commitment: Field;
  auditorPubkeyBytes?: Uint8Array;
}

/**
 * Trial-decrypts every ciphertext against the viewing key. Returns the notes
 * that successfully decrypted, in input order. Failed decryptions are silently
 * skipped — the scanner cannot distinguish "not for me" from "corrupted."
 */
export function scanNotes(
  viewingPrivateKey: Uint8Array,
  cts: NoteCiphertext[]
): DiscoveredNote[] {
  const out: DiscoveredNote[] = [];
  for (const ct of cts) {
    const plain = openSealed(viewingPrivateKey, ct.sealed);
    if (!plain) continue;
    const payload = decodeNotePayload(plain);
    if (!payload) continue;
    const { auditorPubkeyBytes, note } = payload;
    out.push({
      leafIndex: ct.leafIndex,
      note,
      commitment: commitNote(note),
      auditorPubkeyBytes,
    });
  }
  return out;
}

interface NotePayload {
  amount: string;          // decimal string
  ownerPubkey: string;     // hex
  auditorPubkey: string;   // hex
  auditorPubkeyBytes?: string; // hex-encoded X25519 public key
  blinding: string;        // hex
}

export interface DecodedNotePayload {
  note: Note;
  auditorPubkeyBytes?: Uint8Array;
}

export function encodeNotePayload(n: Note, auditorPubkeyBytes?: Uint8Array): Uint8Array {
  const payload: NotePayload = {
    amount: n.amount.toString(),
    ownerPubkey: n.ownerPubkey.toHex(),
    auditorPubkey: n.auditorPubkey.toHex(),
    blinding: n.blinding.toHex(),
  };
  if (auditorPubkeyBytes) {
    payload.auditorPubkeyBytes = hex(auditorPubkeyBytes);
  }
  return new TextEncoder().encode(JSON.stringify(payload));
}

export function decodeNotePayload(b: Uint8Array): DecodedNotePayload | null {
  try {
    const p = JSON.parse(new TextDecoder().decode(b)) as NotePayload;
    return {
      note: {
        amount: BigInt(p.amount),
        ownerPubkey: Field.fromHex(p.ownerPubkey),
        auditorPubkey: Field.fromHex(p.auditorPubkey),
        blinding: Field.fromHex(p.blinding),
      },
      auditorPubkeyBytes: p.auditorPubkeyBytes ? bytesFromHex(p.auditorPubkeyBytes) : undefined,
    };
  } catch {
    return null;
  }
}

function hex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

function bytesFromHex(s: string): Uint8Array {
  const t = s.startsWith("0x") ? s.slice(2) : s;
  if (t.length % 2 !== 0) throw new Error("hex byte string must have even length");
  const out = new Uint8Array(t.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(t.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
