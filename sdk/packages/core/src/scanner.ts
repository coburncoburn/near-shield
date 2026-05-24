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
    const note = decodeNotePayload(plain);
    if (!note) continue;
    out.push({
      leafIndex: ct.leafIndex,
      note,
      commitment: commitNote(note),
    });
  }
  return out;
}

interface NotePayload {
  amount: string;          // decimal string
  ownerPubkey: string;     // hex
  auditorPubkey: string;   // hex
  blinding: string;        // hex
}

export function encodeNotePayload(n: Note): Uint8Array {
  const payload: NotePayload = {
    amount: n.amount.toString(),
    ownerPubkey: n.ownerPubkey.toHex(),
    auditorPubkey: n.auditorPubkey.toHex(),
    blinding: n.blinding.toHex(),
  };
  return new TextEncoder().encode(JSON.stringify(payload));
}

export function decodeNotePayload(b: Uint8Array): Note | null {
  try {
    const p = JSON.parse(new TextDecoder().decode(b)) as NotePayload;
    return {
      amount: BigInt(p.amount),
      ownerPubkey: Field.fromHex(p.ownerPubkey),
      auditorPubkey: Field.fromHex(p.auditorPubkey),
      blinding: Field.fromHex(p.blinding),
    };
  } catch {
    return null;
  }
}
