import { describe, it, expect } from "vitest";
import { parseShieldedEvents } from "./events.js";

const depositLog = JSON.stringify({
  standard: "shielded-pool", event: "deposit",
  data: { commitment: "0x01", leaf_index: 0, view_ct: "0xaa", note_ct: "0xbb" },
});
const transferLog = JSON.stringify({
  standard: "shielded-pool", event: "transfer",
  data: { merkle_root: "0x0", nullifiers: ["0x1","0x2"], commitments: ["0x03","0x04"],
          leaf_indices: [1,2], view_cts: ["0xc1","0xc2"], note_cts: ["0xcc","0xdd"] },
});

describe("parseShieldedEvents", () => {
  it("extracts deposit leaf + note_ct", () => {
    const ev = parseShieldedEvents([depositLog]);
    expect(ev.commitments).toEqual([{ leafIndex: 0n, commitment: "0x01" }]);
    expect(ev.noteCiphertexts).toEqual([{ leafIndex: 0n, noteCtHex: "0xbb" }]);
  });
  it("extracts BOTH transfer outputs in leaf_index order", () => {
    const ev = parseShieldedEvents([transferLog]);
    expect(ev.commitments).toEqual([
      { leafIndex: 1n, commitment: "0x03" }, { leafIndex: 2n, commitment: "0x04" },
    ]);
    expect(ev.noteCiphertexts.map((n) => n.noteCtHex)).toEqual(["0xcc", "0xdd"]);
  });
  it("ignores non-shielded and EVENT_JSON-prefixed noise gracefully", () => {
    expect(parseShieldedEvents(["random", "EVENT_JSON:" + depositLog]).commitments.length).toBe(1);
  });
});
