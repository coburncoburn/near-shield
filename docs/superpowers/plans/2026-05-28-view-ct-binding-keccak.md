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
- **Existing tests likely have hard-coded expected hash values.** Anything currently asserting a *value* (not just "non-zero" or "matches re-computation") needs updating to the new keccak-based value. Likely affected: `wallet.viewcthash.test.ts` (asserts dynamically — should still pass), `wallet.test.ts`, `pool-client.test.ts`. The plan touches each as needed.

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

- [ ] **Step 1: Generate the vectors.** Each case has a `name`, `input_b64` (base64-encoded input), `expected_digest_hex` (the 32-byte keccak256 digest, hex), and `expected_field_hex` (the 32-byte BE Field representation after first-31-bytes-LE reduction). Compute these by hand with any reference keccak256 (Python `pycryptodome` or Node `node -e 'import("@noble/hashes/sha3").then(...)'`).

Cases to include (vectors are computed BY YOU, not pasted from anywhere — verify them with a second tool to avoid copy-paste rot):

1. `empty` — `input_b64 = ""` (empty bytes)
2. `single_byte_ff` — `input_b64 = "/w=="` ([0xff])
3. `short_ascii_viewct` — `input_b64 = "dmlld2N0"` (`"viewct"`)
4. `thirty_one_zeros` — `input_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="` ([0x00; 31])
5. `thirty_two_zeros` — `input_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="` ([0x00; 32])
6. `high_bit_set` — choose any input such that `keccak256(input)[0] & 0x80 == 0x80`. Try `"high_bit_seed_001"` and increment the suffix until you find one. Record both inputs and verify the high bit is set in the digest.

Compute `expected_digest_hex = "0x" + hex(keccak256(input_bytes))` and `expected_field_hex = "0x" + hex(big_endian_32(little_endian_to_int(digest[:31])))`.

Write `sdk/test-vectors/view_ct_keccak.json` with this exact top-level shape (mirror `view_ct_hash.json`):

```json
{
  "_comment": "keccak_to_field vectors. Source of truth: contract/src/deposit.rs::keccak_to_field (env::keccak256 -> first 31 bytes LE -> Field). TS implementation in sdk/packages/core/src/keccak_to_field.ts MUST match.",
  "cases": [
    { "name": "empty", "input_b64": "", "expected_digest_hex": "0x...", "expected_field_hex": "0x..." },
    ...
  ]
}
```

A 7th `realistic_view_ct` case will be added in Task 5 once the wallet produces a real `encodeCiphertext(sealedView)` for a transfer (capture-and-paste).

- [ ] **Step 2: Write the failing Rust test.** In `contract/src/deposit.rs`, append to the `tests` module:

```rust
#[test]
fn keccak_to_field_vectors() {
    use crate::poseidon::Field;
    let raw = include_str!("../../sdk/test-vectors/view_ct_keccak.json");
    let v: serde_json::Value = serde_json::from_str(raw).unwrap();
    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let input = near_sdk::base64::prelude::Engine::decode(
            &near_sdk::base64::prelude::BASE64_STANDARD,
            case["input_b64"].as_str().unwrap(),
        ).unwrap();
        let expected_hex = case["expected_field_hex"].as_str().unwrap();
        let got = super::keccak_to_field(&input);
        assert_eq!(got.to_hex(), expected_hex, "case {name}");
    }
}
```

(If `near_sdk::base64` doesn't re-export the engine in 5.5, use the `base64` crate directly — already a transitive dep — `use base64::Engine; base64::engine::general_purpose::STANDARD.decode(...)`.)

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
) as { cases: { name: string; input_b64: string; expected_field_hex: string }[] };

describe("keccakToField cross-language vectors", () => {
  for (const c of VECTORS.cases) {
    it(c.name, () => {
      const input = Uint8Array.from(Buffer.from(c.input_b64, "base64"));
      expect(keccakToField(input).toHex()).toBe(c.expected_field_hex);
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

- [ ] **Step 3: Run the existing Rust e2e to confirm soundness regressions don't slip in.**
```bash
cargo test -p shielded-pool --lib
cargo test -p shielded-pool --tests -- real_proof_deposit_withdraw_transfer
```
The lib suite must stay at 68+ passing. The e2e test re-runs the deposit→withdraw→transfer flow with the **synthetic** 10-char `view_cts` it already uses; it should still pass (the change is the hash function, which both proving and verification recompute consistently). If a test asserts a specific hash value, update it to the new expected (rare — most likely the e2e asserts on root + nullifier + event presence, not on the bound hash value directly).

- [ ] **Step 4: Commit.**
```bash
git add contract/src/deposit.rs contract/src/transfer.rs contract/src/withdraw.rs
git commit -m "feat(contract): bind view_ct via keccak_to_field at all four sites"
```

---

## Task 5: Swap the SDK wallet's `viewCtHash` helper

**Files:**
- Modify: `sdk/packages/sdk/src/wallet.ts` (the `viewCtHash` module-level helper from prior plan's Task 0)
- Modify: `sdk/packages/sdk/src/wallet.viewcthash.test.ts` (the existing binding test from Task 0; its asserted value flips because the helper is computed differently — the test code is unchanged but the actual *value* the wallet now stores will be the keccak one)

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

- [ ] **Step 2: Run the existing binding tests.** `pnpm --filter @shielded-near/sdk test -- wallet.viewcthash` → all 3 tests pass. They compare `publicInputs[i]` to `keccakToField(...).toHex()` (matching the helper) so they update mechanically; nothing in the test file changes.

- [ ] **Step 3: Run the full sdk suite.** `pnpm --filter @shielded-near/sdk test` → all green. The non-binding tests (`wallet.test.ts`, `envelopes.test.ts`) assert proof byte lengths and PI counts, not values, so they're unaffected.

- [ ] **Step 4: Capture the `realistic_view_ct` vector** (the spec's seventh test case, deferred from Task 2). Add a `--captureRealisticVector` mode to the wallet test OR (simpler) add a one-off Vitest case that:
  1. Constructs a wallet with a fixed seed and auditor.
  2. Calls `buildTransferProved` against a `CapturingProver` with two scanned input notes.
  3. Pulls `tx.viewCiphertexts[0]`, runs `encodeCiphertext(...)`, hashes via `keccakToField`, and `console.log`s `{ input_b64: base64(utf8(encoded)), expected_field_hex: hash.toHex() }`.
  4. Run once to print the values, then DELETE the case (it was a one-off generator).

Append the printed `realistic_view_ct` entry to `sdk/test-vectors/view_ct_keccak.json`. Re-run `cargo test -p shielded-pool --lib keccak_to_field_vectors` and `pnpm --filter @shielded-near/core test -- keccak_to_field` — both must include the new vector and pass. (If the digest's first byte happens to have the high bit clear, the `realistic_view_ct` case is still useful for the gas-budget reproducibility claim — no need to repeat-roll.)

- [ ] **Step 5: Commit.**
```bash
git add sdk/packages/sdk/src/wallet.ts sdk/test-vectors/view_ct_keccak.json
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
