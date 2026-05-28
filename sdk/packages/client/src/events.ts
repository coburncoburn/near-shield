/**
 * NEP-297 shielded-pool event parsing.
 *
 * The contract (contract/src/events.rs) emits plain JSON strings (no prefix
 * in production) or strings prefixed with "EVENT_JSON:" in some NEAR SDK
 * versions. Both are handled here.
 */

export interface CommitmentEntry {
  leafIndex: bigint;
  commitment: string;
}

export interface NoteCiphertextEntry {
  leafIndex: bigint;
  noteCtHex: string;
}

export interface ParsedShieldedEvents {
  commitments: CommitmentEntry[];
  noteCiphertexts: NoteCiphertextEntry[];
}

/** Parse an array of raw NEAR log strings into shielded-pool event entries.
 *  Ignores any log that is not a valid shielded-pool event.
 *  Results are sorted ascending by leafIndex. */
export function parseShieldedEvents(logs: string[]): ParsedShieldedEvents {
  const commitments: CommitmentEntry[] = [];
  const noteCiphertexts: NoteCiphertextEntry[] = [];

  for (const raw of logs) {
    // Strip optional "EVENT_JSON:" prefix (some NEAR SDK versions add it).
    const json = raw.startsWith("EVENT_JSON:") ? raw.slice("EVENT_JSON:".length) : raw;

    let parsed: unknown;
    try {
      parsed = JSON.parse(json);
    } catch {
      continue; // not valid JSON — skip
    }

    if (!isRecord(parsed)) continue;
    if (parsed["standard"] !== "shielded-pool") continue;

    const event = parsed["event"];
    const data = parsed["data"];
    if (!isRecord(data)) continue;

    if (event === "deposit") {
      const leafIndex = BigInt(data["leaf_index"] as number);
      const commitment = data["commitment"] as string;
      const noteCtHex = data["note_ct"] as string;
      commitments.push({ leafIndex, commitment });
      noteCiphertexts.push({ leafIndex, noteCtHex });
    } else if (event === "transfer") {
      const leafIndices = data["leaf_indices"] as number[];
      const comms = data["commitments"] as string[];
      const noteCts = data["note_cts"] as string[];
      for (let i = 0; i < leafIndices.length; i++) {
        const leafIndex = BigInt(leafIndices[i]);
        commitments.push({ leafIndex, commitment: comms[i] });
        noteCiphertexts.push({ leafIndex, noteCtHex: noteCts[i] });
      }
    }
    // All other shielded-pool events (withdraw, payout_recovered, …) are ignored.
  }

  // Sort both arrays ascending by leafIndex.
  commitments.sort((a, b) => (a.leafIndex < b.leafIndex ? -1 : a.leafIndex > b.leafIndex ? 1 : 0));
  noteCiphertexts.sort((a, b) => (a.leafIndex < b.leafIndex ? -1 : a.leafIndex > b.leafIndex ? 1 : 0));

  return { commitments, noteCiphertexts };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
