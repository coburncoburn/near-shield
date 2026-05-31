# Trusted-setup ceremony tooling + dev dry-run — design

**Date:** 2026-05-31
**Status:** design approved; spec-review loop + plan pending
**Sub-project:** C of 3 (final engineering gate before mainnet-capability)

## Why this exists

Sub-projects A (Circom circuit port) and B (snarkjs integration swap) made snarkjs the sole
proving path, but all keys are DEV keys from `circom/scripts/dev-setup.sh` — a single-party,
deterministic, **untrustworthy** setup whose toxic waste is effectively known. Sub-project C
builds the **real multi-party Groth16 trusted-setup ceremony** tooling so production proving/
verifying keys can be produced where no single party knows the toxic waste, and exercises that
tooling **end-to-end as a dev dry-run**. (Specs/plans for A/B:
`docs/superpowers/{specs,plans}/2026-05-29-circom-circuit-port*`,
`…/2026-05-30-snarkjs-integration-swap*`.)

A real Groth16 ceremony has two phases: **Phase 1 (Powers of Tau)** — circuit-independent,
universal — and **Phase 2** — per-circuit. snarkjs provides mature commands for both
(`powersoftau …`, `zkey new/contribute/beacon/verify`, `zkey export verificationkey`). C wraps,
orchestrates, verifies, and documents them; it does not reimplement the MPC.

## Decisions (from brainstorming)

- **Phase-1 source:** the dev dry-run generates a small **local** Phase-1 (fast, self-contained);
  the real ceremony consumes the public **Perpetual Powers of Tau** (documented + script-supported,
  not run in dev).
- **Ceremony output handling:** the dry-run output is a **separate, validated artifact** — proven
  contract-usable + non-DEV — but the demo and regular tests **keep using the fast `dev-setup.sh`
  DEV keys**. Dry-run keys (simulated contributors + placeholder beacon) are never presented as
  production.

## Architecture & scope

A real, multi-party snarkjs Groth16 ceremony toolkit (coordinator + contributor + verify scripts +
a publishable transcript/manifest) plus a participant runbook, exercised end-to-end as a dev
dry-run producing a separate validated artifact set. A real production ceremony uses the *same*
scripts with the public Perpetual PoT + real participants + a real beacon, per the runbook.

**In scope:** the ceremony scripts, the transcript/manifest, the dev dry-run + its validation, the
runbook, and wiring the dry-run output through the existing `DEPLOY_VK_DIR` fingerprint guard.
**Out of scope:** the actual mainnet deploy script, executing the *real* ceremony (an ops event
with external participants over calendar time), and the independent circuit soundness review +
external audit (all still required before funds).

## Components / layout

New `ceremony/` area; circuit builds stay in `circom/`:

```
ceremony/
  scripts/
    phase1-dev.sh       # dev: `powersoftau new bn128 15` + contribute + prepare phase2 (local, fast)
    phase1-import.sh    # real: fetch + `powersoftau verify` Perpetual PoT (powersOfTau28_hez_final_15.ptau) + prepare phase2
    init-phase2.sh      # per circuit: `zkey new` (ptau + <c>.r1cs) -> <c>_0000.zkey
    contribute.sh       # CONTRIBUTOR command: `zkey contribute` w/ own entropy -> next zkey + attestation
    beacon.sh           # COORDINATOR: `zkey beacon` (apply final public random beacon)
    finalize.sh         # `zkey verify` full chain -> export vk.json + vk.bin (via @shielded-near/sdk adapter) + write manifest.json
    verify-ceremony.sh  # standalone: independently re-verify the whole transcript/chain
    run-dev-ceremony.sh # DEV DRY-RUN driver: phase1-dev -> init -> 3 simulated contributions -> placeholder beacon -> finalize -> validate
  RUNBOOK.md            # real-ceremony coordinator + participant instructions
  out/                  # gitignored (zkeys/ptau large; dry-run regenerates)
```

snarkjs *is* the contributor tool (`zkey contribute`); the scripts wrap/orchestrate it, add the
attestation + transcript, and verify. Each script stays small and single-purpose. `@shielded-near/sdk`'s
`vkJsonToContractBytes` (from B) produces the `vk.bin` adapter bytes in `finalize.sh` — `finalize.sh`
calls that single adapter (no second, divergent VK-export code path).

**Implementation note (from spec review):** `circom/scripts/gen-fixtures.ts` currently hardcodes the
DEV zkey path (`build/keys/<c>_dev.zkey`). Reusing it to validate ceremony output (§4.2) requires
parameterizing the zkey/output paths (e.g. via env vars or args) so it can point at the ceremony
zkeys + write a ceremony fixture dir, without disturbing the existing DEV-fixture behavior.

## The ceremony flow & transcript

**Phase 1** (circuit-independent): dev = local `powersoftau` at **power 15**; real = the public
Perpetual PoT power-15 file, `powersoftau verify`'d, then `prepare phase2`. Power 15 (= 32768) ≥
transfer's 12,578 constraints, with margin. Documented requirement: `2^power ≥ maxConstraints`.

**Phase 2** (per circuit): `zkey new` → **N sequential `zkey contribute`** (each participant, own
entropy, on the prior zkey, emitting a contribution hash) → **public random `beacon`** →
`zkey verify` → export VK + adapter bytes.

**Transcript/manifest** (`manifest.json`, publishable): ptau source + sha256; per-circuit ordered
`{contributionHash, contributorName}`; beacon `{value, source}`; final
`{zkeyHash, vkJsonSha256, vkBinSha256}`. Lets any participant confirm their contribution is in the
chain and reproduce `zkey verify`.

**Beacon:** real = a pre-announced public unpredictable value (recommend a drand round or a future
Bitcoin block hash) hashed to the beacon hex, applied via `zkey beacon`. Dev = a fixed,
loudly-labeled placeholder hex + a low iteration exponent for speed.

## Dev dry-run + validation (success criteria)

`run-dev-ceremony.sh` runs the whole flow with **3 simulated contributors** + the placeholder
beacon, writing to `ceremony/out/`. Validation:

1. `snarkjs zkey verify` passes for all three ceremony zkeys (contribution chain + beacon intact).
2. **On-contract:** a proof generated with a ceremony zkey + the adapted ceremony VK verifies via
   the contract's `verify_groth16` — reuse the Task-2 `contract/tests/snarkjs_verify_fixture.rs`
   harness pointed at ceremony fixtures (generate a ceremony fixture via the existing
   `gen-fixtures` path against the ceremony zkeys).
3. **Fingerprint guard:** `DEPLOY_VK_DIR=ceremony/out bash scripts/check-production-readiness.sh`
   **PASSES** (ceremony VKs are not DEV fingerprints); plus a sanity check that a DEV `vk.bin`
   placed there still FAILS.
4. `verify-ceremony.sh` independently re-verifies the transcript end to end.

## Runbook & wire-up

`RUNBOOK.md` covers: roles (coordinator / contributors); Phase 1 via Perpetual PoT (URL + expected
hash + `powersoftau verify`); the per-circuit sequential contribution protocol; entropy hygiene and
the "one honest contributor + unpredictable beacon ⇒ secure" property; beacon
selection/announcement; how participants verify their own contribution is included; and the
**handoff** — production sets `DEPLOY_VK_DIR` to the ceremony VK output, and the contract is
initialized with the ceremony `vk.bin`. The existing fingerprint guard already supports
`DEPLOY_VK_DIR`; no guard code change is required beyond validating the wired path in the dry-run.

## Testing

- Dev dry-run completes end to end (`run-dev-ceremony.sh`) producing zkeys + VKs + `manifest.json`.
- `snarkjs zkey verify` green for all three ceremony zkeys.
- On-contract `verify_groth16 == true` for a proof from a ceremony zkey (ceremony fixture).
- `DEPLOY_VK_DIR=ceremony/out` readiness check PASSES; a DEV vk there FAILS.
- `verify-ceremony.sh` re-verifies the chain independently.
- Existing suites (SDK, circom, contract e2e + fixture-verify) remain green (C adds tooling, does
  not change circuits/adapters/prover).

## Risks

- **PoT power vs circuit size** → power 15 gives margin; requirement `2^power ≥ maxConstraints`
  documented; re-check if circuits grow.
- **Dry-run keys ≠ production** → loudly labeled; demo/tests stay on DEV keys; the dry-run beacon +
  contributors are simulated.
- **Real Phase-1 import path not exercised in dev** (per the chosen scope) → mitigated by
  `phase1-import.sh` + the runbook documenting the exact `powersoftau verify` step and expected file
  hash.
- **snarkjs `zkey verify` is slow for transfer** → acceptable for a one-time/dry-run flow.

## Out of scope for C

- The production mainnet deploy script (initializing the live contract with ceremony VKs is
  documented as the handoff, not built).
- Executing the real multi-party ceremony (ops event).
- Circuit soundness review + external audit (still required before funds).
- Any change to the circom circuits, the adapters/mapper/prover, or the contract verifier.
