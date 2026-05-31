# Groth16 Trusted-Setup Ceremony Runbook

This runbook describes how to run the **real** multi-party computation (MPC)
ceremony that produces the production Groth16 proving and verifying keys for
the three shielded-pool circuits (`deposit`, `transfer`, `withdraw`).

---

## Overview & security model

Groth16 requires a one-time trusted setup per circuit.  Each setup generates
"toxic waste" — intermediate randomness that, if known by any single party,
would allow forging proofs.  The protocol is secure if **at least one
contributor discards their entropy and does not collude**.  The final beacon
step adds public, unpredictable randomness so that the outcome cannot be biased
even if every interactive contributor is corrupted.

**NON-PRODUCTION keys** (never deploy):

| Script | Purpose |
|---|---|
| `circom/scripts/dev-setup.sh` | DEV keys — deterministic seed, fast local setup |
| `ceremony/scripts/run-dev-ceremony.sh` | Dev dry-run — simulated contributors, placeholder beacon |

The fingerprint guard (`scripts/check-production-readiness.sh`) hard-rejects
both sets of DEV keys when `DEPLOY_VK_DIR` is set.

---

## Roles

- **Coordinator** — orchestrates the ceremony, publishes the transcript
  (`ceremony/out/manifest.json`) and all final artifacts.  The coordinator
  does _not_ need to be trusted (they hold no contributor entropy).
- **Contributors** — each adds fresh entropy via an interactive `contribute`
  step.  Every contributor should run on a clean, ideally air-gapped machine,
  and discard all entropy after their step completes.

---

## Prerequisites

1. **Circuits built** — the `.r1cs` and `_js/*.wasm` artifacts must exist:

   ```sh
   pnpm --filter @shielded-near/circom build
   ```

2. **Run all ceremony scripts from the repo root** — the `_lib.sh` sourced by
   every script resolves paths relative to the repo root, and the `snarkjs`
   invocation (via `pnpm --filter @shielded-near/circom exec snarkjs`) discovers
   the workspace from that directory.

3. **Node / pnpm / snarkjs** available (they are workspace dev-dependencies;
   `pnpm install` in the repo root is sufficient).

---

## Phase 1 — Powers of Tau

Use the **Perpetual Powers of Tau** (a public, continuously-extended ceremony).
Do NOT generate a fresh Phase 1; reuse the canonical artifact.

### 1.1 Download

```sh
curl -O https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_15.ptau
```

Power 15 (2^15 = 32 768 constraints) is sufficient for all three circuits
(the largest is `transfer` at ~12 578 constraints).

### 1.2 Verify the hash

Before using the file, verify its published hash against the Hermez /
iden3 Perpetual Powers of Tau list:

  <https://github.com/iden3/snarkjs#7-prepare-phase-2>
  <https://github.com/weijiekoh/perpetualpowersoftau>

The expected `blake2b` digest for `powersOfTau28_hez_final_15.ptau` is
published in that repository's `README` and the Hermez ceremony attestations.

### 1.3 Import & prepare Phase 2

```sh
bash ceremony/scripts/phase1-import.sh /path/to/powersOfTau28_hez_final_15.ptau
```

This runs `snarkjs powersoftau verify` (checks the Phase 1 chain), then
`snarkjs powersoftau prepare phase2` to produce `ceremony/out/pot_final.ptau`,
then verifies the prepared file.  Expect it to take several minutes.

---

## Phase 2 — Per-circuit MPC (run once per circuit)

Repeat the following for each circuit: `deposit`, `transfer`, `withdraw`.
All steps below use `<c>` as a placeholder for the circuit name.

### 2.1 Coordinator initialises the zkey

```sh
bash ceremony/scripts/init-phase2.sh <c>
```

Produces `ceremony/out/<c>_0000.zkey`.

### 2.2 Contributors (sequential, one at a time)

For each contributor **N** (starting at N=0):

1. **Coordinator sends** `ceremony/out/<c>_000N.zkey` to the contributor
   (secure channel).
2. **Contributor runs on their machine** (from the repo root):

   ```sh
   bash ceremony/scripts/contribute.sh \
     <c> \
     /path/to/<c>_000N.zkey \
     /path/to/<c>_000N+1.zkey \
     "Contributor Name"
   ```

   When prompted by snarkjs, the contributor types **fresh, high-entropy
   randomness** (keyboard mashing, a dice roll, etc.).  **Do NOT pass entropy
   as a fifth CLI argument in a real ceremony** — the CLI argument is recorded
   in shell history and process tables.  The interactive prompt is the correct
   path.

3. **Contributor publishes their attestation**: the contribution hash printed
   by snarkjs (also retrievable later via `snarkjs zkey verify`), plus the
   sha256 of their output zkey recorded in `ceremony/out/manifest.json`.
4. **Contributor sends** the new zkey back to the coordinator.
5. **Contributor discards** all intermediate randomness immediately.

Repeat for each subsequent contributor.  There is no minimum number of
contributors, but more independent contributors strengthen the security
assumption.

#### Entropy hygiene

- Generate entropy on the contribution machine only.
- Never store, transmit, or reuse your randomness.
- Prefer an air-gapped or freshly reinstalled machine for high-value ceremonies.

### 2.3 Beacon

After all contributors have finished, the coordinator applies a **public,
unpredictable, pre-announced** beacon to close the ceremony:

```sh
BEACON_SOURCE="drand round 12345678" \
bash ceremony/scripts/beacon.sh \
  <c> \
  ceremony/out/<c>_final_contrib.zkey \
  ceremony/out/<c>_beacon.zkey \
  <64-hex-char-beacon-value> \
  10
```

- **`BEACON_SOURCE`** — human-readable description recorded in the manifest
  (e.g. `"drand round 12345678"` or `"Bitcoin block 900000 hash"`).
- **Beacon value** — 32 bytes as 64 lowercase hex digits, taken from the
  announced source.
- **`iterExp`** — must be 10–63 (10 is standard; higher is slower but no
  more secure in practice).

**Choosing a good beacon:**

| Source | Where to get it |
|---|---|
| drand (recommended) | <https://drand.love> — chain `default`, use a future round number announced before Phase 2 begins |
| Bitcoin block hash | Announce the target block height before the ceremony; use `blockhash` from any indexer after it is mined |

Announce the beacon source and target height/round **before** Phase 2 begins
so that no party can influence the final beacon value.

### 2.4 Finalize

```sh
bash ceremony/scripts/finalize.sh <c> ceremony/out/<c>_beacon.zkey
```

This verifies the full zkey chain (`snarkjs zkey verify`), exports the
verification key as `ceremony/out/<c>_vk.json` and `ceremony/out/<c>/vk.bin`,
and records the final hashes in `ceremony/out/manifest.json`.

---

## Publish the transcript

After all three circuits are finalized, publish:

- `ceremony/out/manifest.json` — contribution hashes, beacon, and vk.bin hashes
- `ceremony/out/<c>_vk.json` and `ceremony/out/<c>/vk.bin` for each circuit

Anyone can then re-verify independently (see next section).

---

## Verification (anyone)

```sh
bash ceremony/scripts/verify-ceremony.sh
```

This re-runs `snarkjs zkey verify` for each circuit's final zkey against the
`.r1cs` and `pot_final.ptau`, then checks that each `vk.bin` sha256 matches
the manifest.

**Per-contributor verification:** `snarkjs zkey verify` prints each
contribution's MPC hash.  Contributors can confirm their hash appears in the
output.

> **Note on the manifest:** the `contributions[].zkeySha256` field is a
> file-integrity hash of the zkey file at each step — it is **not** the snarkjs
> internal MPC contribution hash.  The authoritative per-contribution MPC hashes
> come from `snarkjs zkey verify` output.

---

## Handoff to deployment

1. Set `DEPLOY_VK_DIR` to the directory containing the ceremony `vk.bin` files:

   ```sh
   DEPLOY_VK_DIR="$(pwd)/ceremony/out" bash scripts/check-production-readiness.sh
   ```

   The script **fails** if any deploy VK matches a known DEV fingerprint.  It
   must exit 0 before any deployment proceeds.

2. Initialize the on-chain contract with the ceremony verifying keys.  The
   contract constructor (`new(... vk_deposit, vk_transfer, vk_withdraw)`) takes
   the raw bytes from `ceremony/out/<c>/vk.bin`.

**Still required before mainnet funds (out of scope for this tooling):**

- Independent circuit soundness review
- External security audit of the contract, SDK, and prover
- Production deploy script (not built here)

Until these gates pass, use only local sandbox deployments and **never deposit
real funds**.

---

## Dev dry-run (pipeline testing only)

```sh
bash ceremony/scripts/run-dev-ceremony.sh
```

Runs the entire flow locally: local Phase 1, three simulated contributors
(entropy passed via CLI), and a placeholder beacon.  Takes ~4 minutes.  The
resulting keys are **NON-PRODUCTION** and are rejected by the fingerprint guard.
Use this to test the ceremony tooling without running a real ceremony.
