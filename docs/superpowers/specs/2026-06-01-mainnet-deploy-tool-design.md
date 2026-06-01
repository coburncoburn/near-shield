# Mainnet deploy tool — design

**Date:** 2026-06-01
**Status:** design approved; spec-review loop + plan pending

## Why this exists

The Groth16 proving path is complete (Sub-projects A/B/C: Circom circuits, snarkjs cutover,
ceremony tooling — all on PR #1, sandbox/DEV only). One remaining piece of the path to mainnet is
the **deploy tool**: the machinery that takes the production `groth16-verifier` WASM + the
ceremony verifying keys and deploys/initializes the contract — with hard safety gates so DEV keys
or a mock-verifier build can never reach mainnet.

The tool is built + validated now; **actually broadcasting a mainnet deploy stays gated** on the
real trusted-setup ceremony (`ceremony/RUNBOOK.md`), the independent circuit soundness review, and
the external audit. The tool itself refuses DEV keys and the mock WASM, and for mainnet it only
*emits* the deploy command for a human operator (no signing key in the tool).

## Deploy surface (verified)

The contract init (`contract/src/lib.rs`):
```rust
#[init] pub fn new(owner: AccountId, usdc_token: AccountId,
                   vk_deposit: Vec<u8>, vk_transfer: Vec<u8>, vk_withdraw: Vec<u8>) -> Self
```
Owner-only `set_paused` emergency stop; **deliberately no VK rotation** (immutable VKs — a circuit
fix means a redeploy). The demo deploys the opt WASM via near-workspaces and inits with
`Array.from(vkJsonToContractBytes(<c>_vk.json))`. Production WASM:
`target/wasm32-unknown-unknown/release/shielded_pool.opt.wasm` (groth16-verifier feature,
wasm-opt'd, size-gated by `scripts/check-production-readiness.sh`).

## Decisions (from brainstorming)

- **Mainnet broadcast model:** the tool deploys+inits directly only on a **near-workspaces
  sandbox** (automated validation); for **testnet + mainnet** it runs the gates + assembles the
  exact init args and **emits the near-cli-rs command + init JSON** for a human operator to
  broadcast (ledger/multisig). No mainnet signing key in the tool. (Testnet folded into the
  emit-command path to avoid testnet credentials in CI.)
- **Safety gates are uniform + hard** across networks (mock WASM and DEV keys refused everywhere);
  mainnet additionally prints the gating checklist + requires explicit confirmation.

## Architecture & components

A TS deploy tool (new `deploy/` workspace package; reuses `@shielded-near/sdk`
`vkJsonToContractBytes` and `near-workspaces` for the sandbox path) that runs:
**build-check → fingerprint guard → assemble `new()` init args → execute (per network)**.

### 1. Safety preconditions (the security core) — hard gates, abort on any failure

1. **Production WASM, not mock.** Run `scripts/check-production-readiness.sh` (rejects the default
   mock-verifier build, requires the `groth16-verifier` opt WASM, size-checks it). Record the WASM
   sha256.
2. **No DEV keys — fingerprint the ACTUAL bytes being deployed.** The tool computes
   `sha256(vkJsonToContractBytes(<the vk.json it is about to deploy>))` for each circuit and aborts
   if it matches a registered DEV fingerprint (the same sha256 denylist used by
   `check-production-readiness.sh`). **This is the authoritative gate** — fingerprinting the bytes
   the tool will actually send (not just whatever `vk.bin` files happen to sit in a directory)
   closes a bypass: the readiness script's `DEPLOY_VK_DIR` guard only scans `vk.bin` files, so a
   DEV-key directory that contains only `*_vk.json` (e.g. `circom/build/keys`) would pass it
   vacuously. The tool MAY additionally invoke the readiness-script guard as a complementary check,
   but the byte-level fingerprint of its own init args is what must block DEV keys regardless of
   source-dir layout. (Ceremony VKs are non-DEV → pass.)
   - DEV fingerprint source of truth: the three sha256s registered in `check-production-readiness.sh`,
     which match `circom/fixtures/<c>/vk.bin` exactly (the canonical committed DEV `vk.bin`s).
3. **VKs present + well-formed.** Each `vk.bin` is the expected length (deposit 768 / transfer 1088
   / withdraw 1024).

The tool cannot deploy DEV keys or a mock-verifier WASM on any network.

### 2. Config + init-args assembly

- Per-network **config** (committed, reviewable): deploy account id, `owner` (custody/multisig),
  `usdc_token`. **`usdc_token` is REQUIRED with no default** — the runbook directs the operator to
  verify the canonical mainnet USDC account id; the tool does not hardcode/guess it. CLI/env
  overrides for account ids.
- For each circuit: read the **ceremony** `vk.json` (`<vk-dir>/<c>/vk.json` or `<vk-dir>/<c>_vk.json`,
  e.g. `ceremony/out/`), run `vkJsonToContractBytes` → `number[]`; assemble the
  `new(owner, usdc_token, vk_deposit, vk_transfer, vk_withdraw)` JSON args. (Note: this is the
  ceremony VK source — NOT the demo's `circom/build/keys/<c>_vk.json`, which holds DEV keys; the
  sandbox path mirrors the demo's *mechanism* but reads ceremony VKs.)

### 3. Execute (per network)

- **sandbox:** near-workspaces — deploy the opt WASM, call `new` with the assembled args, then
  **post-verify**: `owner()` / `usdc_token()` match config, `is_paused() == false`; write a
  **deploy receipt** (WASM sha256, per-VK sha256, init args). This is the automated validation path.
- **testnet / mainnet:** print the exact
  `near contract deploy <account> use-file <wasm> with-init-call new json-args '<initJSON>' …`
  command + a summary (WASM sha256, VK sha256s, owner, usdc_token) + the gating checklist. **No
  broadcast.**

### 4. DEPLOY-RUNBOOK

Operator doc: the **preconditions checklist** (real ceremony completed + VKs published; independent
soundness review done; external audit done; canonical mainnet USDC id verified; owner =
ledger/multisig), running `--network mainnet`, reviewing the emitted command + summary,
broadcasting via near-cli-rs, and post-deploy verification (view calls + a first real proof).
Cross-links `ceremony/RUNBOOK.md`.

## Testing

- **Sandbox deploy+init+post-verify** with the ceremony dry-run VKs (`ceremony/out`) → succeeds;
  `owner`/`usdc_token`/`paused` views match config; receipt written.
- **Guard teeth:** `--vk-dir` pointing at the committed DEV keys (`circom/fixtures`, which has the
  registered `vk.bin` fingerprints) **aborts** the deploy via the byte-level fingerprint check.
  Crucially, also test a DEV-key dir that has only `*_vk.json` and NO `vk.bin` (e.g. a copy of
  `circom/build/keys`): the tool must STILL abort (because it fingerprints the bytes it would
  deploy), proving it doesn't rely on the vacuous `vk.bin`-only dir scan. A mock-verifier WASM is
  refused by the readiness check.
- **Mainnet emit path:** the emitted near-cli-rs command + init JSON are well-formed (correct
  method, VK byte-arrays present, owner/usdc_token), asserted **without broadcasting**.

## Risks

- **Wrong USDC token id** → required config, no default, runbook-verified against the canonical
  mainnet USDC.
- **near-cli-rs syntax drift** → the operator reviews the emitted command; the runbook pins the
  assumed CLI version.
- **Key custody (mainnet)** → outside the tool (ledger/multisig via near-cli-rs).
- **Deploying before ceremony/audit** → the gates catch DEV keys / mock WASM but cannot *prove* the
  audit happened; the runbook makes it a hard manual checklist and the tool prints the gating items
  + requires an explicit mainnet confirmation flag.

## Out of scope

- Broadcasting to mainnet (the operator does it via near-cli-rs with ledger/multisig).
- Running the real ceremony (separate ops event, `ceremony/RUNBOOK.md`).
- Owner multisig setup; mainnet account creation/funding.
- Any change to the contract, circuits, adapters, or prover.
