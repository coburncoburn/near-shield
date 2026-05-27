import { decodeDisclosure, openSealed, SEAL_CONTEXT_VIEW, type ViewDisclosure } from "@shielded-near/core";

/**
 * One on-chain event with all the auditor disclosure ciphertexts the contract
 * emitted for it. Each transfer emits two (sender + recipient); deposits and
 * withdrawals emit one.
 */
export interface RawEvent {
  blockHeight: number;
  txHash: string;
  action: "deposit" | "transfer" | "withdraw";
  viewCiphertexts: Uint8Array[];
}

export interface DecryptedRecord {
  blockHeight: number;
  txHash: string;
  disclosure: ViewDisclosure;
}

/**
 * In-memory auditor index. Production deployments swap the storage layer for
 * SQLite; the decryption logic and query surface stay identical.
 *
 * Critically, the indexer only decrypts what it can — every other auditor's
 * ciphertexts trial-decrypt to null and are silently skipped. There is no
 * cross-auditor leakage by construction.
 */
export class AuditorIndex {
  private records: DecryptedRecord[] = [];

  constructor(private readonly privateKey: Uint8Array) {
    if (privateKey.length !== 32) {
      throw new Error("auditor private key must be 32 bytes");
    }
  }

  /** Ingest a batch of raw events. Returns the count of newly decrypted records. */
  ingest(events: RawEvent[]): number {
    let added = 0;
    for (const ev of events) {
      for (const ct of ev.viewCiphertexts) {
        const plain = openSealed(this.privateKey, ct, SEAL_CONTEXT_VIEW);
        if (!plain) continue;
        try {
          const disclosure = decodeDisclosure(plain);
          this.records.push({
            blockHeight: ev.blockHeight,
            txHash: ev.txHash,
            disclosure,
          });
          added++;
        } catch {
          // Malformed plaintext - ciphertext was meant for us but contents
          // were corrupted upstream. Skip silently rather than poison the index.
        }
      }
    }
    return added;
  }

  getAll(): DecryptedRecord[] {
    return [...this.records];
  }

  getForUser(ownerPubkey: string): DecryptedRecord[] {
    return this.records.filter(
      (r) =>
        r.disclosure.senderOwnerPubkey === ownerPubkey ||
        r.disclosure.recipientOwnerPubkey === ownerPubkey
    );
  }

  /**
   * Verifies that a given view ciphertext matches the expected disclosure
   * (e.g. for resolving a dispute where an auditor receives a screenshot).
   * Returns true if the ciphertext decrypts under this auditor's key AND
   * the decoded plaintext equals the expected disclosure.
   */
  verifyDisclosure(
    ct: Uint8Array,
    expected: ViewDisclosure
  ): boolean {
    const plain = openSealed(this.privateKey, ct, SEAL_CONTEXT_VIEW);
    if (!plain) return false;
    try {
      const got = decodeDisclosure(plain);
      return JSON.stringify(got) === JSON.stringify(expected);
    } catch {
      return false;
    }
  }
}
