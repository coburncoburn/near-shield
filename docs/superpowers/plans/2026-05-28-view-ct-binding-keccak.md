# view_ct binding → keccak256 — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers-extended-cc:subagent-driven-development (if subagents available) or superpowers-extended-cc:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring `transfer` (and `withdraw` with realistic payloads) safely under NEAR's 300 Tgas per-tx cap by swapping the off-chain view_ct binding hash from pure-WASM Poseidon to NEAR's `keccak256` host fn, with no circuit change and no proving-key regen.

**Architecture:** A new helper `keccak_to_field(bytes)` (contract) / `keccakToField(bytes)` (SDK) reduces arbitrary bytes via `keccak256` → first-31-bytes little-endian → BN254 `Field`. The four contract sites that hash a submitted view_ct (deposit ×1, transfer ×2, withdraw ×1) switch to it; account-id hashing stays on Poseidon. The wallet's `viewCtHash` helper (introduced by the prior plan's Task 0) re-points to the TS keccak path. Cross-language vectors pin both implementations together.

**Tech Stack:** Rust (`near-sdk = "5.5"`, `near_sdk::env::keccak256` host fn), TypeScript (`@noble/hashes/sha3` `keccak_256` — already in `@shielded-near/core`'s deps), the existing `Field`/`Fr` types.

**Spec:** `docs/superpowers/specs/2026-05-28-view-ct-binding-keccak.md`

---

## Key facts the implementer must know

- **Circuits do not recompute the hash.** Each of `circuits/{deposit,transfer,withdraw}/src/main.nr` and `tools/prover/src/circuits/{deposit,transfer,withdraw}.rs` only enforces `view_ct_hash.enforce_equal(view_ct_hash_witness)`. Swapping the off-chain hash function leaves the R1CS — and the seeded proving keys in `target/sp-keys/` — unchanged.
- **Reduction is "first 31 bytes, little-endian".** This matches `contract/src/poseidon.rs::Field::from_bytes_le`, which iterates the slice in reverse with `out = out * 256 + byte`. 31 bytes = 248 bits, comfortably under BN254 Fr's 254-bit modulus, so the construction is lossless and total — no reduction can occur.
- **The wallet's `viewCtHash` helper exists** (introduced by the prior plan's Task 0, commit `8de553b`). It currently calls `hashBytesToField(utf8(encodeCiphertext(sealed)))`. This plan swaps the inner function to `keccakToField`. The wrapping (hash the **encoded string bytes**, not raw sealed bytes) is the Task 0 invariant — preserved.
- **`@noble/hashes` is already a direct dep** of `@shielded-near/core` (`sdk/packages/core/package.json`). No `pnpm install` needed for the import.
- **`Field.fromBytesLe` does NOT exist on the TS `Field`.** It must be added. A private `fieldFromLeBytes` already exists inside `sdk/packages/core/src/hash_bytes.ts` — Task 2 lifts that to `Field.fromBytesLe` (DRY) and refactors `hash_bytes.ts` to use it.
- **The demo's transfer path is gated.** `demo/src/run-demo.ts` currently wraps the transfer + withdraw steps behind `if (process.env.DEMO_TRANSFER === "1")` (commit `382b689`). After this fix, the full flow must run by default and the env gate is deleted.
- **Cross-language vectors live in `sdk/test-vectors/`.** The existing `view_ct_hash.json` is for Poseidon-based `hash_bytes_to_field`; do NOT touch it. A new `view_ct_keccak.json` is added with this plan.
- **`wallet.viewcthash.test.ts` will break after the SDK swap.** It currently imports `hashBytesToField` and computes the expected PI value from `hashBytesToField(utf8(encodeCiphertext(...)))`. After Task 5, the wallet computes `keccakToField(...)` instead — so the test's `expected` values must be updated to call `keccakToField` from the same import. Task 5 makes this edit explicitly. Other tests (`wallet.test.ts`, `pool-client.test.ts`) assert byte lengths and PI counts, not hash values — they're unaffected.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `sdk/packages/core/src/field.ts` (modify) | Add `Field.fromBytesLe(bytes: Uint8Array): Field`. |
| `sdk/packages/core/src/hash_bytes.ts` (modify) | Replace private `fieldFromLeBytes` with `Field.fromBytesLe`. |
| `sdk/packages/core/src/keccak_to_field.ts` (create) | `keccakToField(bytes): Field`. |
| `sdk/packages/core/src/keccak_to_field.test.ts` (create) | TS reads `sdk/test-vectors/view_ct_keccak.json`. |
| `sdk/packages/core/src/index.ts` (modify) | Re-export `keccakToField`. |
| `contract/src/deposit.rs` (modify) | Add `pub fn keccak_to_field(b: &[u8]) -> Field`; add Rust test reading the shared JSON. |
| `contract/src/{deposit,transfer,withdraw}.rs` (modify) | Swap the four `hash_bytes_to_field(view_ct…)` call sites to `keccak_to_field(view_ct…)`. |
| `sdk/packages/sdk/src/wallet.ts` (modify) | `viewCtHash` helper switches from `hashBytesToField` → `keccakToField`. |
| `sdk/test-vectors/view_ct_keccak.json` (create) | Cross-language vectors. |
| `demo/src/run-demo.ts` (modify) | Remove the `DEMO_TRANSFER=1` env gate. |
| `docs/superpowers/plans/2026-05-27-real-client-cli-demo.md` (modify) | Strike Follow-up #1. |

---

## Task 1: Add `Field.fromBytesLe` to TS, DRY `hash_bytes.ts`

**Files:**
- Modify: `sdk/packages/core/src/field.ts` (add `fromBytesLe` static)
- Modify: `sdk/packages/core/src/hash_bytes.ts` (use the new static; remove the private helper)
- Modify: `sdk/packages/core/src/field.test.ts` (or create — see Step 1)

This unblocks Task 3 (`keccakToField`). The TS reduction must match `contract/src/poseidon.rs::Field::from_bytes_le` byte-for-byte: iterate the slice **in reverse**, `acc = acc * 256 + byte`. The existing private helper in `hash_bytes.ts` already gets this right; we're lifting it.

- [ ] **Step 1: Write the failing test.** Append to (or create) `sdk/packages/core/src/field.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { Field } from "./field.js";

describe("Field.fromBytesLe", () => {
  it("empty slice -> 0", () => {
    expect(Field.fromBytesLe(new Uint8Array(0)).equals(Field.zero())).toBe(true);
  });
  it("single byte = value", () => {
    expect(Field.fromBytesLe(new Uint8Array([0x61])).equals(Field.fromU64(0x61n))).toBe(true);
  });
  it("byte order is little-endian: [0x01, 0x02] -> 0x0201", () => {
    expect(Field.fromBytesLe(new Uint8Array([0x01, 0x02])).equals(Field.fromU64(0x0201n))).toBe(true);
  });
  it("31 bytes of 0xff fits without reduction", () => {
    const v = Field.fromBytesLe(new Uint8Array(31).fill(0xff));
    // (1 << 248) - 1
    const expected = (1n << 248n) - 1n;
    expect(v.equals(new Field(expected))).toBe(true);
  });
});
```

- [ ] **Step 2: Run, verify FAIL.** `pnpm --filter @shielded-near/core test -- field` → FAIL ("`Field.fromBytesLe` is not a function" or similar).

- [ ] **Step 3: Add the static.** In `sdk/packages/core/src/field.ts`, insert before the closing brace of `class Field`:

```ts
/** Reads `bytes` little-endian (byte 0 = LSB) into a Field. The slice may be
 *  any length up to 32; values whose magnitude exceeds the BN254 modulus are
 *  reduced (Field's constructor handles that). Matches Rust
 *  `contract::poseidon::Field::from_bytes_le`. */
static fromBytesLe(bytes: Uint8Array): Field {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    v = (v << 8n) | BigInt(bytes[i]);
  }
  return new Field(v);
}
```

- [ ] **Step 4: Replace the duplicate helper in `hash_bytes.ts`.** Remove the `fieldFromLeBytes` function at the bottom of the file and change the call site `fieldFromLeBytes(b.subarray(...))` to `Field.fromBytesLe(b.subarray(...))`.

- [ ] **Step 5: Run all core tests.** `pnpm --filter @shielded-near/core test` → all pass (existing `hash_bytes` vectors must still verify).

- [ ] **Step 6: Commit.**
```bash
git add sdk/packages/core/src/field.ts sdk/packages/core/src/field.test.ts sdk/packages/core/src/hash_bytes.ts
git commit -m "refactor(core): lift Field.fromBytesLe out of hash_bytes"
```

---

## Task 2: Write the cross-language test vectors + Rust `keccak_to_field`

**Files:**
- Create: `sdk/test-vectors/view_ct_keccak.json`
- Modify: `contract/src/deposit.rs` (add `pub fn keccak_to_field` + a unit test reading the JSON)

The shared vectors live in `sdk/test-vectors/`. Both sides will assert against this file. We commit the vectors first (computed independently of any implementation) and then implement to match.

- [ ] **Step 1: Generate the vectors.** Use **hex** for inputs (the contract crate already depends on `hex` for parsing; this avoids pulling in `base64` for tests). Each case has `name`, `input_hex` (0x-prefixed; empty input is `"0x"`), `expected_digest_hex` (32-byte keccak256 digest, 0x-prefixed), and `expected_field_hex` (the 32-byte big-endian Field representation after first-31-bytes-LE reduction).

Use this one-shot Node script to compute each case (save as `/tmp/gen-vectors.mjs`, run with `node /tmp/gen-vectors.mjs`):

```js
import { keccak_256 } from "@noble/hashes/sha3";
const hex = (b) => "0x" + Buffer.from(b).toString("hex");
const cases = [
  { name: "empty", input: new Uint8Array(0) },
  { name: "single_byte_ff", input: Uint8Array.of(0xff) },
  { name: "short_ascii_viewct", input: new TextEncoder().encode("viewct") },
  { name: "thirty_one_zeros", input: new Uint8Array(31) },
  { name: "thirty_two_zeros", input: new Uint8Array(32) },
];
// Find a seed that makes digest[0] high bit set.
let i = 0;
let highBitInput; let highBitDigest;
while (true) {
  const buf = new TextEncoder().encode(`high_bit_seed_${i}`);
  const d = keccak_256(buf);
  if (d[0] & 0x80) { highBitInput = buf; highBitDigest = d; break; }
  if (++i > 10000) throw new Error("no high-bit seed found");
}
cases.push({ name: "high_bit_set", input: highBitInput });
for (const c of cases) {
  const d = keccak_256(c.input);
  const le31 = d.subarray(0, 31);
  // Field repr: 31-byte LE -> bigint -> 32-byte BE
  let v = 0n;
  for (let j = le31.length - 1; j >= 0; j--) v = (v << 8n) | BigInt(le31[j]);
  const be32 = new Uint8Array(32);
  let x = v;
  for (let j = 31; j >= 0; j--) { be32[j] = Number(x & 0xffn); x >>= 8n; }
  console.log(JSON.stringify({ name: c.name, input_hex: hex(c.input), expected_digest_hex: hex(d), expected_field_hex: hex(be32) }, null, 2) + ",");
}
```

Paste the printed entries into `sdk/test-vectors/view_ct_keccak.json`:

```json
{
  "_comment": "keccak_to_field vectors. Source of truth: contract/src/deposit.rs::keccak_to_field (env::keccak256 -> first 31 bytes LE -> Field). TS implementation in sdk/packages/core/src/keccak_to_field.ts MUST match.",
  "cases": [
    { "name": "empty", "input_hex": "0x", "expected_digest_hex": "0x...", "expected_field_hex": "0x..." }
  ]
}
```

(Trim the trailing comma after the last entry.) A 7th `realistic_view_ct` case is added in Task 5 via a committed capture script.

- [ ] **Step 2: Write the failing Rust test.** In `contract/src/deposit.rs`, append to the `tests` module (uses `hex` which is already a direct dep — no new Cargo.toml entry):

```rust
#[test]
fn keccak_to_field_vectors() {
    let raw = include_str!("../../sdk/test-vectors/view_ct_keccak.json");
    let v: serde_json::Value = serde_json::from_str(raw).unwrap();
    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let input_hex = case["input_hex"].as_str().unwrap().trim_start_matches("0x");
        let input = hex::decode(input_hex).unwrap();
        let expected_hex = case["expected_field_hex"].as_str().unwrap();
        let got = super::keccak_to_field(&input);
        assert_eq!(got.to_hex(), expected_hex, "case {name}");
    }
}
```

- [ ] **Step 3: Run, verify FAIL.** `cargo test -p shielded-pool --lib keccak_to_field_vectors` → FAIL (function not defined).

- [ ] **Step 4: Implement `keccak_to_field`.** Add to `contract/src/deposit.rs`, alongside `hash_bytes_to_field` (insert immediately after that function):

```rust
/// Reduces arbitrary bytes to a Field via `keccak256` then little-endian
/// truncation to 31 bytes (248 bits). Used for binding submitted ciphertexts
/// into a proof's public input without paying in-WASM Poseidon over the full
/// length. Cross-language vectors live in `sdk/test-vectors/view_ct_keccak.json`.
pub fn keccak_to_field(b: &[u8]) -> Field {
    let digest = near_sdk::env::keccak256(b);
    Field::from_bytes_le(&digest[..31])
}
```

(`env::keccak256` is available in any near-sdk build, including under `#[cfg(test)]` via `MockedBlockchain`. If a host-fn dependency surfaces in the test context, the test still passes because vitest-style cargo tests run in a single-threaded near-sdk testing harness; if you hit a setup error, wrap the test in `near_sdk::testing_env!(near_sdk::test_utils::VMContextBuilder::new().build())` at the top.)

- [ ] **Step 5: Run, verify PASS.** `cargo test -p shielded-pool --lib keccak_to_field_vectors` → 1 passed. Then run the full lib suite: `cargo test -p shielded-pool --lib` → 68+ passed (previously-passing tests unchanged).

- [ ] **Step 6: Commit.**
```bash
git add sdk/test-vectors/view_ct_keccak.json contract/src/deposit.rs
git commit -m "feat(contract): add keccak_to_field for the view_ct binding hash"
```

---

## Task 3: TS `keccakToField` against the same vectors

**Files:**
- Create: `sdk/packages/core/src/keccak_to_field.ts`
- Create: `sdk/packages/core/src/keccak_to_field.test.ts`
- Modify: `sdk/packages/core/src/index.ts` (re-export `keccakToField`)

- [ ] **Step 1: Write the failing test.** `sdk/packages/core/src/keccak_to_field.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { keccakToField } from "./keccak_to_field.js";

const VECTORS = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("../../../test-vectors/view_ct_keccak.json", import.meta.url)),
    "utf-8"
  )
) as { cases: { name: string; input_hex: string; expected_field_hex: string }[] };

function hexToBytes(h: string): Uint8Array {
  const s = h.startsWith("0x") ? h.slice(2) : h;
  if (s.length === 0) return new Uint8Array(0);
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

describe("keccakToField cross-language vectors", () => {
  for (const c of VECTORS.cases) {
    it(c.name, () => {
      expect(keccakToField(hexToBytes(c.input_hex)).toHex()).toBe(c.expected_field_hex);
    });
  }
});
```

- [ ] **Step 2: Run, verify FAIL.** `pnpm --filter @shielded-near/core test -- keccak_to_field` → FAIL (module not found).

- [ ] **Step 3: Implement.** `sdk/packages/core/src/keccak_to_field.ts`:

```ts
import { keccak_256 } from "@noble/hashes/sha3";
import { Field } from "./field.js";

/** Reduces arbitrary bytes to a Field via keccak256 + first-31-bytes-LE.
 *  Mirrors `contract::deposit::keccak_to_field` byte-for-byte. Cross-language
 *  vectors live in `sdk/test-vectors/view_ct_keccak.json`. */
export function keccakToField(b: Uint8Array): Field {
  const digest = keccak_256(b); // 32 bytes
  return Field.fromBytesLe(digest.subarray(0, 31));
}
```

- [ ] **Step 4: Re-export.** Add to `sdk/packages/core/src/index.ts`:
```ts
export { keccakToField } from "./keccak_to_field.js";
```

- [ ] **Step 5: Run, verify PASS.** `pnpm --filter @shielded-near/core test -- keccak_to_field` → N passed (one per vector case). Then run full core suite: `pnpm --filter @shielded-near/core test` → all green.

- [ ] **Step 6: Commit.**
```bash
git add sdk/packages/core/src/keccak_to_field.ts sdk/packages/core/src/keccak_to_field.test.ts sdk/packages/core/src/index.ts
git commit -m "feat(core): add keccakToField pinned to shared test vectors"
```

---

## Task 4: Swap the four contract view_ct hash sites

**Files:**
- Modify: `contract/src/deposit.rs` (1 site in `do_deposit`)
- Modify: `contract/src/transfer.rs` (2 sites in `do_transfer`)
- Modify: `contract/src/withdraw.rs` (1 site in `do_withdraw`)

Mechanical replacement: `hash_bytes_to_field(<expr involving view_ct>)` → `keccak_to_field(<same expr>)`. Imports adjust accordingly. Do NOT change the account-id hashes (`recipient.as_bytes()`, `relayer.as_bytes()` in `withdraw.rs`) — they stay on `hash_bytes_to_field`.

- [ ] **Step 1: Identify the precise call sites.** Run:
```bash
grep -n 'hash_bytes_to_field(view_ct\|hash_bytes_to_field(args.view_ct\|hash_bytes_to_field(view_cts' contract/src/{deposit,transfer,withdraw}.rs
```
Expected: 4 hits — `deposit.rs:do_deposit` (`args.view_ct`), `transfer.rs:do_transfer` (`view_cts[0]`, `view_cts[1]`), `withdraw.rs:do_withdraw` (`view_ct`).

- [ ] **Step 2: Apply the swap at each site.** At each location, change the function name `hash_bytes_to_field` → `keccak_to_field`. Keep the argument expression identical. If any file imports `hash_bytes_to_field` only and not `keccak_to_field`, fix the import: in `transfer.rs` and `withdraw.rs` the existing line is `use crate::deposit::hash_bytes_to_field;` — add `keccak_to_field` to the same `use` (e.g., `use crate::deposit::{hash_bytes_to_field, keccak_to_field};`). If the file no longer needs `hash_bytes_to_field`, drop it from the use — but check first: `withdraw.rs` still uses it for `recipient`/`relayer`, so keep both there. `transfer.rs` may no longer need `hash_bytes_to_field` after the swap; drop it if so.

- [ ] **Step 3: Triage existing references before running.** Before re-running suites, grep for places that might assert a specific hashed value or reference the old function over `view_ct`:
```bash
grep -rn "view_ct_hash\|hashBytesToField\|hash_bytes_to_field" contract/ sdk/packages/ tools/prover/ 2>/dev/null | grep -v node_modules | grep -v "target/"
```
Expected hits and treatment:
- `contract/src/withdraw.rs` `recipient`/`relayer` hashes — UNCHANGED (Poseidon for account ids; these stay on `hash_bytes_to_field`).
- `contract/tests/e2e_real_proofs.rs` — recomputes hashes off-chain to feed the prover witness. **CRITICAL — do NOT do a blanket alias swap.** The current alias `use shielded_pool::deposit::hash_bytes_to_field as contract_hash_bytes;` (line 28) is used at **seven** call sites; five hash view_ct (must move to keccak) and **two hash account ids (must stay Poseidon)**:
  - **Move to keccak** (the five view_ct sites — lines 259, 286, 474, 515, 516, approximately): each is `contract_hash_bytes(<view_ct or vct_*>.as_bytes())`.
  - **Keep on Poseidon** (the two account-id sites — lines 282 and 283, approximately): `contract_hash_bytes(w_recipient_id.as_bytes())` / `contract_hash_bytes(w_relayer_id.as_bytes())`. These mirror the contract's withdraw, where recipient/relayer stay on `hash_bytes_to_field`.
  Procedure: keep the existing `contract_hash_bytes` alias for the two account-id sites; ADD a second alias `use shielded_pool::deposit::keccak_to_field as contract_view_ct_hash;` and migrate ONLY the five view_ct call sites to it. Verify with `grep -n contract_hash_bytes contract/tests/e2e_real_proofs.rs` — after editing, exactly two hits remain (the recipient + relayer lines), and `grep -n contract_view_ct_hash` shows five.
- `contract/src/deposit.rs::tests::dump_view_ct_hash_vectors` — leave it; it's about the Poseidon vectors file, which we're not touching.
- `sdk/packages/sdk/src/wallet.ts` `viewCtHash` helper — handled in Task 5.
- `sdk/packages/sdk/src/wallet.viewcthash.test.ts` — handled in Task 5.
- `sdk/packages/core/src/hash_bytes.ts` and its `.test.ts` — UNCHANGED (Task 1 already DRY-refactored the helper; the Poseidon function itself stays).

- [ ] **Step 4: Re-run suites.**
```bash
cargo test -p shielded-pool --lib
cargo test -p shielded-pool --tests -- real_proof_deposit_withdraw_transfer
```
The lib suite must stay at 68+ passing. The e2e test re-runs the deposit→withdraw→transfer flow with synthetic 10-char `view_cts`; with the e2e's own helper updated in Step 3, the prover's witness now also uses `keccak_to_field` and the on-chain verifier sees a matching PI. Both sides recompute consistently — the test passes.

- [ ] **Step 5: Commit.**
```bash
git add contract/src/deposit.rs contract/src/transfer.rs contract/src/withdraw.rs contract/tests/e2e_real_proofs.rs
git commit -m "feat(contract): bind view_ct via keccak_to_field at all four sites"
```

---

## Task 5: Swap the SDK wallet's `viewCtHash` helper

**Files:**
- Modify: `sdk/packages/sdk/src/wallet.ts` (the `viewCtHash` module-level helper from prior plan's Task 0)
- Modify: `sdk/packages/sdk/src/wallet.viewcthash.test.ts` (the test imports `hashBytesToField` to compute the expected PI — must be swapped to `keccakToField` so the expected matches the new helper)
- Create: `sdk/test-vectors/scripts/capture-realistic-view-ct.ts` (committed capture script, run on demand)

The wallet's current helper (post-Task 0, in `sdk/packages/sdk/src/wallet.ts`):

```ts
function viewCtHash(sealed: Uint8Array): string {
  return hashBytesToField(new TextEncoder().encode(encodeCiphertext(sealed))).toHex();
}
```

becomes:

```ts
function viewCtHash(sealed: Uint8Array): string {
  return keccakToField(new TextEncoder().encode(encodeCiphertext(sealed))).toHex();
}
```

- [ ] **Step 1: Update the import and the helper.** Open `sdk/packages/sdk/src/wallet.ts`. Replace `import { hashBytesToField } from "@shielded-near/core";` (or wherever it appears) with `import { keccakToField } from "@shielded-near/core";`. If `hashBytesToField` is still used elsewhere in the file, keep both imports. Update the `viewCtHash` helper body as above.

- [ ] **Step 2: Update the binding test's expected value.** Open `sdk/packages/sdk/src/wallet.viewcthash.test.ts`. The test currently imports `hashBytesToField` from `@shielded-near/core` and uses it (three times) to compute the expected PI value. Replace each `hashBytesToField` call with `keccakToField`, and update the import line. Concretely:
  - Top of file: `import { hashBytesToField } from "@shielded-near/core";` → `import { keccakToField } from "@shielded-near/core";`
  - The three `hashBytesToField(new TextEncoder().encode(...))` call sites (one per `it()`) all change to `keccakToField(new TextEncoder().encode(...))`.

The test's structural assertions don't change — they still compare `publicInputs[i]` to the helper's output over `encodeCiphertext(tx.viewCiphertexts[i])`. Only the helper used to compute the expected flips.

- [ ] **Step 3: Run binding tests.** `pnpm --filter @shielded-near/sdk test -- wallet.viewcthash` → all 3 tests pass. (Before this step they would FAIL — the wallet now emits keccak hashes while the test computed Poseidon. Fix is the import + call swap above.)

- [ ] **Step 4: Run the full sdk suite.** `pnpm --filter @shielded-near/sdk test` → all green. Non-binding tests assert byte lengths and PI counts, not values, so they're unaffected.

- [ ] **Step 5: Write the realistic-vector capture script.** Create `sdk/test-vectors/scripts/capture-realistic-view-ct.ts` — a committed, deterministic generator (no Vitest add-and-delete pattern):

```ts
// Run with: pnpm tsx sdk/test-vectors/scripts/capture-realistic-view-ct.ts
// Appends/regenerates the `realistic_view_ct` entry for view_ct_keccak.json.
import { Wallet } from "@shielded-near/sdk";
import { encodeCiphertext } from "@shielded-near/sdk";
import { keccakToField } from "@shielded-near/core";
import { writeFileSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const seedAlice = new Uint8Array(64).fill(1);
const seedBob = new Uint8Array(64).fill(2);
const auditorPubkey = new Uint8Array(32).fill(3);
const alice = new Wallet({ seed: seedAlice, usdcTokenAccountId: "u.t", poolAccountId: "p.t" });
const bob = new Wallet({ seed: seedBob, usdcTokenAccountId: "u.t", poolAccountId: "p.t" });

// Two scanned deposits at leaves 0,1 (same auditor) so findTransferInputs finds inputs.
for (const [i, amt] of [[0n, 60n], [1n, 40n]] as [bigint, bigint][]) {
  const tx = alice.buildDeposit({ amount: amt, auditorPubkey });
  alice.scan([{ leafIndex: i, sealed: tx.noteCiphertexts[0] }]);
}

class FakeProver { async prove() { return new Uint8Array(256); } }
const merkleInputs = {
  merkleRoot: "0x" + "00".repeat(32),
  merklePath0: Array.from({ length: 20 }, () => "0x" + "00".repeat(32)),
  merklePath1: Array.from({ length: 20 }, () => "0x" + "00".repeat(32)),
};
const tx = await alice.buildTransferProved(
  { amount: 60n, recipientOwnerPubkey: bob.ownerPubkey,
    recipientAuditorPubkey: auditorPubkey, recipientViewingPubkey: bob.viewingKey.publicKey },
  new FakeProver() as any, merkleInputs);

const encoded = new TextEncoder().encode(encodeCiphertext(tx.viewCiphertexts[0]));
const hex = (b: Uint8Array) => "0x" + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const inputHex = hex(encoded);
const fieldHex = keccakToField(encoded).toHex();
const digestHex = "0x" + Array.from(
  (await import("@noble/hashes/sha3")).keccak_256(encoded)
).map((x) => x.toString(16).padStart(2, "0")).join("");

const VECTORS_PATH = fileURLToPath(new URL("../view_ct_keccak.json", import.meta.url));
const v = JSON.parse(readFileSync(VECTORS_PATH, "utf-8"));
v.cases = v.cases.filter((c: any) => c.name !== "realistic_view_ct");
v.cases.push({ name: "realistic_view_ct", input_hex: inputHex,
               expected_digest_hex: digestHex, expected_field_hex: fieldHex });
writeFileSync(VECTORS_PATH, JSON.stringify(v, null, 2) + "\n");
console.log("Appended realistic_view_ct vector.");
```

Run: `pnpm tsx sdk/test-vectors/scripts/capture-realistic-view-ct.ts`. Then re-run both vector tests:
```bash
cargo test -p shielded-pool --lib keccak_to_field_vectors
pnpm --filter @shielded-near/core test -- keccak_to_field
```
Both must include the new `realistic_view_ct` case and pass.

- [ ] **Step 6: Commit.**
```bash
git add sdk/packages/sdk/src/wallet.ts sdk/packages/sdk/src/wallet.viewcthash.test.ts sdk/test-vectors/view_ct_keccak.json sdk/test-vectors/scripts/capture-realistic-view-ct.ts
git commit -m "fix(sdk): derive view_ct binding via keccak (matches contract)"
```

---

## Task 6: Run the demo end-to-end + housekeeping

**Files:**
- Modify: `demo/src/run-demo.ts` (remove the `DEMO_TRANSFER=1` env gate)
- Modify: `docs/superpowers/plans/2026-05-27-real-client-cli-demo.md` (strike Follow-up #1)
- Modify: `README.md` (drop the "blocked by gas wall" caveat in the "Try the demo" block)

- [ ] **Step 1: Rebuild the pool wasm.** The contract changed, so the optimised wasm must be regenerated:
```bash
cargo build -p shielded-pool --target wasm32-unknown-unknown --release --no-default-features --features groth16-verifier
./scripts/check-production-readiness.sh   # regenerates target/wasm32-unknown-unknown/release/shielded_pool.opt.wasm
```

- [ ] **Step 2: Remove the `DEMO_TRANSFER=1` gate.** In `demo/src/run-demo.ts`, find the `if (process.env.DEMO_TRANSFER === "1") { ... } else { ... }` block. Delete the `else` branch's "Skipping..." messages and dedent the transfer + withdraw steps so they run unconditionally. Update the file header comment to drop the env-flag note.

- [ ] **Step 3: Run the demo end-to-end.** With sandbox prereqs already in place (per the prior plan's README block):
```bash
pnpm --filter @shielded-near/demo demo
```
Expected: completes through deposit → transfer → withdraw, final balance assertions on Bob's and the relayer's `ft_balance_of` both hold, exit 0. This is the **pass criterion** for the whole plan.

If the transfer step still hits a gas ceiling, do NOT modify the gas budgets — instead, profile (the implementer can add `console.log(gas_burnt)` reads from the tx outcome) to confirm whether the savings landed correctly. The expected gas burn for transfer post-fix is well under 100 Tgas (≈ 40 Poseidon for tree inserts at ≈ 4 Tgas each ≈ 160 Tgas plus the Groth16 verify ≈ 20 Tgas, so ~180 Tgas total — well under cap). If the burn is still in the 300s, recheck Task 4's swap; one missed site silently undoes the win.

- [ ] **Step 4: Strike Follow-up #1 in the prior plan.** In `docs/superpowers/plans/2026-05-27-real-client-cli-demo.md`, find the "Follow-ups" section's item 1 (transfer gas blowup) and replace it with:

```markdown
1. ~~Contract `hash_bytes_to_field` gas blowup with real-size view ciphertexts.~~ **Resolved 2026-05-28 by `docs/superpowers/plans/2026-05-28-view-ct-binding-keccak.md`** — view_ct binding now uses `keccak_to_field` (env::keccak256 host fn) at the four call sites; transfer demo runs end-to-end under cap.
```

Leave items 2–4 untouched.

- [ ] **Step 5: Update the README.** In `README.md`, find the "Try the demo (sandbox only)" section (the "Current state" callout that says the transfer step is blocked). Replace the block with a tightened version stating the demo runs end-to-end and references the keccak fix:

```markdown
> **Current state:** the demo runs the full deposit → transfer → withdraw flow end-to-end with real Groth16 proofs against a near-workspaces sandbox, and asserts Bob's on-chain `ft_balance_of` increased by `60 - relayerFee`. The view_ct binding (sandboxed for size in earlier work) uses NEAR's `keccak256` host fn — see `docs/superpowers/specs/2026-05-28-view-ct-binding-keccak.md`.
```

- [ ] **Step 6: Final regression.** Run:
```bash
pnpm -r test
cargo test -p shielded-pool --lib
cargo test -p shielded-pool --tests -- real_proof_deposit_withdraw_transfer
cargo tree -p shielded-pool 2>/dev/null | grep -i near-contract-standards   # must remain empty
```
All green.

- [ ] **Step 7: Commit.**
```bash
git add demo/src/run-demo.ts docs/superpowers/plans/2026-05-27-real-client-cli-demo.md README.md
git commit -m "demo: full transfer flow now passes; close out gas-blowup follow-up"
```

---

## Verification (use superpowers-extended-cc:verification-before-completion)

- `pnpm -r test` green; `cargo test -p shielded-pool --lib` green (68 passed); `cargo test -p shielded-pool --tests` green (incl. `real_proof_deposit_withdraw_transfer`).
- `pnpm --filter @shielded-near/demo demo` exits 0 and the final on-chain `ft_balance_of(Bob)` and `ft_balance_of(relayer)` deltas hold.
- `cargo tree -p shielded-pool | grep near-contract-standards` empty (pool dep graph unchanged).
- Proving keys in `target/sp-keys/` untouched (`git status target/sp-keys` clean).
- `sdk/test-vectors/view_ct_keccak.json` contains all 7 cases (6 hand-computed + the realistic vector captured in Task 5 Step 4).
