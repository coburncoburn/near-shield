# Switch the view_ct binding hash to a NEAR keccak256 host call

Date: 2026-05-28
Status: Design — pending implementation plan

## Problem

The pool's `transfer` (and `withdraw` with realistic payloads) exceeds NEAR's 300 Tgas per-tx cap because the contract binds the ciphertext into the proof's public input by Poseidon-hashing the encoded ciphertext string in pure WASM.

- `contract/src/deposit.rs::hash_bytes_to_field` chunks input bytes 31 at a time and folds with `poseidon2` (`contract/src/poseidon.rs`, pure WASM Montgomery arithmetic).
- A realistic sealed `ViewDisclosure` is ~351 bytes. After `encodeCiphertext` (`sdk/packages/sdk/src/envelopes.ts`) it crosses the wire as a `"0x"+hex` string — ~704 bytes. The contract hashes those bytes (per `contract/src/transfer.rs` + `withdraw.rs`): 23 chunks ≈ 22 `poseidon2` folds per view_ct.
- `transfer` hashes BOTH sender and recipient view_cts and inserts two leaves (20 `poseidon2` per insert). Total ~84 `poseidon2` calls ≈ 340–420 Tgas — over cap.
- The Rust integration test `contract/tests/e2e_real_proofs.rs` never exercised this because it submits 10-char synthetic strings (`"vct_sender"`) for `view_cts`. The real-client demo (`docs/superpowers/plans/2026-05-27-real-client-cli-demo.md`) surfaced the failure.

The view_ct binding exists to stop a malicious relayer from swapping the submitted ciphertext for an arbitrary other one while keeping the proof valid. That's a real, intended security property and **must be preserved**.

## Key non-obvious fact

The circuits do not recompute the hash. Each of `circuits/{deposit,transfer,withdraw}/src/main.nr` only enforces:

```
assert(view_ct_hash == view_ct_hash_witness);
```

(See `tools/prover/src/circuits/{deposit,transfer,withdraw}.rs` for the arkworks equivalent: `view_ct_hash.enforce_equal(&vh_witness)`.) The hash function is therefore an **off-chain contract between the SDK and the contract only**. The circuit treats `view_ct_hash` as an opaque field element. As long as the SDK and the contract agree on the byte-level construction, the R1CS — and therefore the seeded proving keys in `target/sp-keys/` — are unchanged by any change to that function.

## Goal

Bring `transfer`'s on-chain gas comfortably under 300 Tgas with realistic-size view ciphertexts, with **no proving-key regeneration**, **no circuit change**, and **no soundness regression** of the relayer-tampering property.

Non-goals: changing the binding for account-ids (`recipient`, `relayer`); changing `hash_bytes_to_field`'s semantics for any callers other than the four view_ct sites; trusted-setup ceremony work; audit.

## Approach

Introduce a new helper `keccak_to_field(bytes) -> Field` (contract) / `keccakToField(bytes) -> Field` (SDK), built on the platform-native keccak256:

- **Contract** (`contract/src/deposit.rs`, alongside the existing `hash_bytes_to_field`):
  ```rust
  pub fn keccak_to_field(b: &[u8]) -> Field {
      let digest = near_sdk::env::keccak256(b); // 32 bytes
      Field::from_bytes_le(&digest[..31])       // lossless 248-bit binding
  }
  ```
- **SDK** (new `sdk/packages/core/src/keccak_to_field.ts`):
  ```ts
  import { keccak_256 } from "@noble/hashes/sha3";
  import { Field } from "./field.js";
  export function keccakToField(b: Uint8Array): Field {
    const digest = keccak_256(b);                    // 32 bytes
    return Field.fromBytesLe(digest.subarray(0, 31)); // matches contract reduction
  }
  ```
  This requires a new `Field.fromBytesLe(bytes)` static in `sdk/packages/core/src/field.ts` that mirrors `contract/src/poseidon.rs::Field::from_bytes_le` byte-for-byte (read the slice little-endian; iterate from the highest index down so byte 0 is the least significant). The implementation plan adds this helper before any caller.
  `@noble/hashes` is already a transitive dependency of `@shielded-near/core` via `@noble/curves`; the plan pins it as a direct dep to make the keccak import explicit.

Replace **only the four view_ct hash sites** with the new helper:
- `contract/src/deposit.rs::do_deposit` — 1 site
- `contract/src/transfer.rs::do_transfer` — 2 sites (sender + recipient)
- `contract/src/withdraw.rs::do_withdraw` — 1 site

Account-id hashes (`hash_bytes_to_field(recipient.as_bytes())`, `relayer.as_bytes()` in `withdraw.rs`) stay on Poseidon. They're short inputs (≤ 2 chunks), already cross-language vector-locked (`sdk/test-vectors/view_ct_hash.json`), and migrating them buys nothing on perf. YAGNI.

The wallet's `viewCtHash` helper (introduced in Task 0 of the prior plan, `sdk/packages/sdk/src/wallet.ts`) is updated to call `keccakToField` instead of `hashBytesToField`. The witness fields (`viewCtHashWitness`, `viewCtHashSenderWitness`, `viewCtHashRecipientWitness`) automatically follow because they reuse the same helper output — the PI ↔ witness invariant established in Task 0 holds untouched.

## Components

### `keccak_to_field` (contract + SDK)

- One responsibility: reduce arbitrary bytes to a `Field` element via keccak256 + LE-31-byte truncation.
- Interface: `&[u8] -> Field` / `Uint8Array -> Field`. No options, no chunking.
- Depends on: `near_sdk::env::keccak256` (contract) and `@noble/hashes/sha3` (SDK — already an indirect dep via `@noble/curves`; `@noble/hashes` will be added explicitly to `@shielded-near/core` for clarity).

### Call-site swap

Mechanical replacement at the four sites listed in "Approach". No control-flow or witness-shape change. The contract still emits the original `view_ct` string in events (`emit_deposit` / `emit_transfer` / `emit_withdraw`) — viewing-key holders and auditors decode it exactly as before.

### Wallet integration

`sdk/packages/sdk/src/wallet.ts`'s module-level helper (post-Task 0):

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

Single line change; the wrapping invariants (hash the **encoded string bytes**, not raw sealed bytes — the value Task 0 cemented) are preserved.

### Cross-language test vectors

New file `sdk/test-vectors/view_ct_keccak.json` with the same shape as the existing `view_ct_hash.json`: a list of `{ name, input_b64, expected_digest_hex, expected_field_hex }` cases. Cases:
- `empty` (`[]`)
- `single_byte` (`[0xff]`)
- `short_ascii` (`"viewct"`)
- `31_zeros` (boundary: exactly the truncation cutoff)
- `32_zeros` (boundary: full digest)
- `high_bit_set` (an input whose keccak digest's first byte has its high bit set; validates that the LE interpretation handles unsigned >= 0x80 bytes correctly — 248 bits < 254 bits of BN254 Fr, so no modular reduction can mask a bug here)
- `realistic_view_ct` (the `encodeCiphertext` output for a fully-formed sealed `ViewDisclosure` produced by `sdk/packages/sdk/src/wallet.ts::buildTransferProved`; recorded so the auditor can independently reproduce the gas-budget claim from artifacts alone)

Both `contract/src/deposit.rs::tests::keccak_to_field_vectors` (Rust) and `sdk/packages/core/src/keccak_to_field.test.ts` (TS) read the same JSON. Same discipline as the Poseidon vectors — keeps the two implementations byte-for-byte locked across language boundaries.

## Data flow

Unchanged. The demo path is identical in every step except:

1. SDK calls `viewCtHash(sealed) = keccakToField(utf8(encodeCiphertext(sealed))).toHex()` for both the proof's `view_ct_hash` public input and witness.
2. The proved tx submits the same `"0x"+hex(sealed)` string to the contract (via `envelopes.ts`).
3. The contract computes `keccak_to_field(view_ct_string.as_bytes())` and uses it as the recomputed public input for proof verification.
4. The Groth16 verify (host fn `alt_bn128_*`) sees byte-for-byte the same set of PIs as the prover did, including the view_ct_hash.

## Error handling

No new error paths. `near_sdk::env::keccak256` is infallible. `Field::from_bytes_le` over a 31-byte slice is total (any 248-bit value fits in BN254 Fr).

## Testing

- **Cross-language vectors** (above).
- **`PoolClient` event-parsing tests, `MerkleTree` tests** — all unchanged.
- **`wallet.viewcthash.test.ts` (Task 0's binding test)** — needs a small edit: it imports `hashBytesToField` to compute the expected PI. Switch that import to `keccakToField` so the expected matches the new helper. The structural assertion (PI equals hash over the encoded-string bytes) is unchanged and still catches a future regression to raw-bytes hashing or to a different hash function.
- **Real-client demo end-to-end with `DEMO_TRANSFER=1`** — runs through transfer + withdraw. Final balance assertion (`ft_balance_of(Bob) += 60 - relayerFee`, `ft_balance_of(relayer) += relayerFee`) holds. **This is the pass criterion** for the gas fix; it closes out the open follow-up.
- **Contract gas regression**: `cargo test -p shielded-pool --tests -- real_proof_deposit_withdraw_transfer` (the existing Rust e2e). Its 10-char synthetic ciphertexts continue to pass — keccak digest of a 10-char string is one host call, well under any budget. It catches a soundness regression (a forged proof being accepted) but no longer constrains the production gas envelope; the demo does that.

## Path to production

Same as `2026-05-26-real-groth16-prover-e2e.md`: this design does not change the path to mainnet. It removes a deployment blocker but the gates are unchanged — circuit soundness review (no circuit change here, so no re-review of the constraints), trusted-setup ceremony (no change to keys), external audit (the audit should be told to inspect the binding-hash swap and the cross-language vector discipline). The audit note should be: "view_ct binding was migrated from in-WASM Poseidon to a `keccak256`-host-fn → first-31-bytes-LE reduction; both contract and SDK pinned by `sdk/test-vectors/view_ct_keccak.json`."

## Why not the other options

- **Hash raw sealed bytes (keep Poseidon)**: halves chunk count (~62 `poseidon2` calls ≈ 250–310 Tgas). Borderline-still-over-cap, no headroom for future contract growth. Larger SDK + cross-vector churn for half the win.
- **Off-chain commitment passed alongside (proof binds an SDK-claimed commitment, contract checks ciphertext-matches-commitment)**: equivalent in spirit to this design, more moving parts (the contract still has to compute *some* function over the ciphertext bytes to verify, which is where the gas blew up). Identical end-state, more rope.
- **Drop the binding (event-only view_ct)**: cheapest, but loses relayer-tamper resistance. Out of bounds.

## Plan-level housekeeping

The implementation plan derived from this spec must, as a small final step, delete or strike through the "Follow-up #1 (transfer gas blowup)" note in `docs/superpowers/plans/2026-05-27-real-client-cli-demo.md` since this work closes it, and remove the `DEMO_TRANSFER=1` env gate from `demo/src/run-demo.ts` (added by the prior plan's cleanup commit) so the demo's default run exercises the full deposit→transfer→withdraw flow with the asserted balance check.
