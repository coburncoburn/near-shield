# Deploy Runbook — Shielded USDC Pool (Mainnet)

> **Status: NOT MAINNET-READY.** The gates below have NOT been cleared.
> This runbook documents the process for when they are.

---

## Overview

The deploy tool (`deploy/`) automates the safe assembly and emission of a
`near contract deploy` command for the shielded-pool contract.  It:

1. Runs `scripts/check-production-readiness.sh` (WASM size, bulk-memory check,
   DEV-verifier rejection).
2. Loads config from `deploy/config/<network>.json` (merged with CLI overrides).
3. Reads the per-circuit `vk.json` files from the ceremony VK directory, converts
   them to on-chain bytes, and gates on:
   - **Gate #2 (DEV-key fingerprint):** refuses any VK whose sha256 matches the
     baked-in DEV fingerprints — checked on the actual bytes to be deployed,
     regardless of where the VK file lives.
   - **Gate #3 (VK length):** refuses a VK with the wrong byte length.
4. For **sandbox**: deploys to a local near-workspaces sandbox for integration
   validation, writes `deploy/out/sandbox-receipt.json`, and returns.
5. For **testnet / mainnet**: prints the MAINNET PRECONDITIONS checklist, writes
   `deploy/out/<network>-init-args.json`, and prints the `near contract deploy …`
   command. **It does NOT broadcast.**  The operator reviews and runs the command
   manually via near-cli-rs with a ledger or multisig signer.

The tool **never holds a mainnet signing key.**

---

## Preconditions checklist (ALL required before a mainnet deploy)

These are enforced as a printed operator checklist on every mainnet emit and are
hard-coded in `MAINNET_CHECKLIST` (`deploy/src/deploy.ts`). Every item must be
independently verified before the operator broadcasts:

1. **Real trusted-setup ceremony completed + VKs published.**
   The ceremony must have been run with ≥ 5 independent contributors and the VKs
   published to a verifiable transcript.  See [`ceremony/RUNBOOK.md`](../ceremony/RUNBOOK.md).
   Dev-ceremony keys (`ceremony/scripts/run-dev-ceremony.sh`) are **non-production**
   — the deploy tool rejects them via the DEV-key fingerprint gate.

2. **Independent circuit soundness review complete.**
   The three Groth16 circuits (`deposit`, `transfer`, `withdraw`) must have been
   reviewed by a party independent of the protocol authors for arithmetization
   correctness and soundness.

3. **External security audit complete.**
   Full audit of the NEAR contract, the TS SDK, and the prover by an external
   security firm.

4. **Canonical mainnet USDC token id verified.**
   The operator must confirm the exact account id of the canonical NEAR mainnet
   USDC token from an authoritative source (the USDC issuer's official docs or
   an on-chain registry).  The deploy tool and this runbook do **not** assume any
   specific account id — `usdc_token` is required in config and the tool throws
   if it is absent.

5. **Owner = ledger or multisig account (custody).**
   `owner` in the config must be a hardware-wallet or multisig account, not a
   hot/development key.

6. **Production groth16-verifier WASM built + `scripts/check-production-readiness.sh` green.**
   Run:
   ```sh
   cargo build -p shielded-pool --target wasm32-unknown-unknown --release \
     --no-default-features --features groth16-verifier
   wasm-opt --enable-bulk-memory --llvm-memory-copy-fill-lowering -Oz \
     --strip-debug --strip-producers \
     target/wasm32-unknown-unknown/release/shielded_pool.wasm \
     -o target/wasm32-unknown-unknown/release/shielded_pool.opt.wasm
   ./scripts/check-production-readiness.sh
   ```
   The script must exit 0.  It validates WASM size, bulk-memory lowering, and
   (when `DEPLOY_VK_DIR` is set) the VK fingerprint gate.

---

## Config

Create `deploy/config/mainnet.json`:

```json
{
  "account": "shielded-pool.near",
  "owner": "your-multisig-or-ledger.near",
  "usdcToken": "<canonical-mainnet-usdc-account-id>"
}
```

- `account` — the NEAR account that will hold the contract.
- `owner` — the account that becomes the contract's owner; **must** be a ledger
  or multisig, not a hot key.
- `usdcToken` — **REQUIRED**; no default.  The tool throws
  `"usdcToken" is required but missing — mainnet value must be runbook-verified`
  if absent.

CLI flags (`--account`, `--owner`, `--usdc-token`) override the file values when
provided.

---

## Run (emit — does NOT broadcast)

```sh
pnpm --filter @shielded-near/deploy deploy -- \
  --network mainnet \
  --vk-dir <path-to-ceremony-vk-dir> \
  --confirm-mainnet
```

With a complete `deploy/config/mainnet.json` the above is sufficient.  To supply
values inline (e.g. for a dry run):

```sh
pnpm --filter @shielded-near/deploy deploy -- \
  --network mainnet \
  --vk-dir "$(pwd)/ceremony/out" \
  --owner your-multisig.near \
  --usdc-token usdc.near \
  --account shielded-pool.near \
  --confirm-mainnet
```

**Flag notes:**

- `--vk-dir <dir>` — directory containing per-circuit subdirectories, each with a
  `vk.json` (e.g. `ceremony/out/deposit/vk.json`).  The fingerprint guard separately
  scans `vk.bin` files in the same directory.  Example value: `$(pwd)/ceremony/out`.

- `--wasm <path>` — path to the optimised WASM artifact.  Defaults to
  `target/wasm32-unknown-unknown/release/shielded_pool.opt.wasm` (relative to the
  repo root).  Override with `--wasm <path>` if you have placed the artifact elsewhere.

What the tool does (in order):

1. Runs `scripts/check-production-readiness.sh` (always; `--skip-readiness` is
   **refused** for mainnet and testnet — the CLI prints a warning and ignores the
   flag).
2. Loads and validates config (account + owner + usdcToken all required).
3. Reads the ceremony VKs from `--vk-dir`, converts to on-chain bytes, runs the
   DEV-fingerprint gate and length gate.
4. Prints the MAINNET PRECONDITIONS checklist.
5. Writes `deploy/out/mainnet-init-args.json` (the serialised `new()` arguments).
6. Prints the operator summary (WASM sha256, per-circuit VK sha256s, owner,
   usdc_token) and the `near contract deploy …` command.
7. **Exits without broadcasting.**

---

## Review (before broadcasting)

Verify the printed summary:

| Field | Expected |
|---|---|
| WASM sha256 | Matches the sha256 of the artifact linked in the ceremony transcript / build provenance |
| deposit / transfer / withdraw VK sha256 | Matches the sha256 of each VK published in the ceremony transcript |
| owner | Your ledger / multisig account id |
| usdc_token | The canonical mainnet USDC account id you verified above |

To compute the hashes independently and compare against the published ceremony transcript:

```sh
# WASM (Linux / WSL):
sha256sum target/wasm32-unknown-unknown/release/shielded_pool.opt.wasm
# WASM (macOS):
shasum -a 256 target/wasm32-unknown-unknown/release/shielded_pool.opt.wasm

# Per-circuit VKs (Linux / WSL):
sha256sum ceremony/out/deposit/vk.bin ceremony/out/transfer/vk.bin ceremony/out/withdraw/vk.bin
# Per-circuit VKs (macOS):
shasum -a 256 ceremony/out/deposit/vk.bin ceremony/out/transfer/vk.bin ceremony/out/withdraw/vk.bin
```

The hashes must match those published in the ceremony transcript before broadcasting.

**Do not broadcast until every field checks out.**

---

## Broadcast

The tool prints a command of the form:

```sh
near contract deploy <account> use-file '<wasm-path>' \
  with-init-call new json-args "$(cat '<argsPath>')" \
  prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' \
  network-config mainnet sign-with-keychain send
```

> **WARNING: `sign-with-keychain` is a PLACEHOLDER — do NOT use it for mainnet.**
> Mainnet broadcast MUST use `sign-with-ledger` (hardware wallet) or the appropriate
> multisig signing flow.  Broadcasting with a hot keychain key violates Precondition 5
> (owner = ledger/multisig) and is a critical security violation.

- **near-cli-rs** (not the legacy `near-cli` JS tool) is required.  The command
  was tested against near-cli-rs v0.17.  Replace `sign-with-keychain` with
  `sign-with-ledger` or a multisig signing flow as required by your signer.
- The init args are large (VK byte arrays totalling ~2.9 KiB of state) so the
  command `cat`s the written args file rather than inlining them.
- 300 Tgas matches the sandbox-validated gas cost for `new()`.

---

## Post-deploy verification

After the transaction lands, verify on-chain state:

```sh
near view <account> owner '{}'
near view <account> usdc_token '{}'
near view <account> is_paused '{}'
```

Expected: `owner` and `usdc_token` match the deployed values; `is_paused` is
`false`.

Ideally, submit a first real deposit proof and confirm it is accepted by the
contract before advertising the pool.

See [`ceremony/RUNBOOK.md`](../ceremony/RUNBOOK.md) for cross-referencing the
published VKs against the ceremony transcript.

---

## Safety notes

- **DEV-key rejection:** the tool checks the sha256 of the actual VK bytes to be
  deployed against the baked-in DEV fingerprints (`DEV_VK_FINGERPRINTS` in
  `deploy/src/gates.ts`).  This fires regardless of which directory the VK files
  come from.  There is no flag to bypass this for mainnet or testnet.

- **Mock-verifier WASM rejection:** `scripts/check-production-readiness.sh`
  rejects any WASM that does not carry the production `groth16-verifier` feature
  flag.  The deploy tool invokes this script unconditionally for mainnet/testnet.

- **No VK rotation:** the contract has no on-chain VK rotation.  A circuit fix or
  re-ceremony requires a full redeploy.

- **Emergency stop:** the contract has an owner-only `set_paused` method.  If a
  critical issue is found post-deploy, the owner (ledger/multisig) can pause
  deposits and withdrawals while a fix is prepared.

- **`--skip-readiness` refused for mainnet/testnet:** passing this flag via the
  CLI for a non-sandbox network prints a warning and the flag is silently ignored,
  preserving the production gate.

---

## Sandbox validation (CI / pre-deploy smoke test)

```sh
pnpm --filter @shielded-near/deploy test
```

Runs the full suite (33 tests) including a near-workspaces sandbox deploy+verify
with the ceremony dry-run VKs.  This validates the tool end-to-end without
touching any live network.
