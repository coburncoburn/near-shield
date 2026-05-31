# Trusted-Setup Ceremony Tooling + Dev Dry-Run Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers-extended-cc:subagent-driven-development (if subagents available) or superpowers-extended-cc:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a real, multi-party snarkjs Groth16 trusted-setup ceremony toolkit (coordinator + contributor + verify scripts + publishable transcript + runbook) and exercise it end-to-end as a dev dry-run, producing a separate validated artifact set (zkey-verify + on-contract verify_groth16 + fingerprint-guard PASS) — while the demo/tests keep using the fast `dev-setup.sh` DEV keys (Sub-project C of 3).

**Architecture:** Thin bash scripts orchestrate snarkjs's mature ceremony commands (`powersoftau …`, `zkey new/contribute/beacon/verify`, `zkey export verificationkey`); small TS/node helpers handle the manifest (node+crypto) and the `vk.json → vk.bin` conversion (reusing `@shielded-near/sdk`'s `vkJsonToContractBytes`). The dev dry-run uses a local Phase-1 + 3 simulated contributors + a placeholder beacon; the real ceremony uses the same scripts with the public Perpetual Powers of Tau + real participants + a real beacon, per `ceremony/RUNBOOK.md`.

**Tech Stack:** snarkjs 0.7.x (via the circom pnpm package), node 22, bash, circom DEV build artifacts (`circom/build/<c>.r1cs`), `@shielded-near/sdk` adapter, the existing `contract/tests/snarkjs_verify_fixture.rs` + `circom/scripts/gen-fixtures.ts` (reused for ceremony output), `scripts/check-production-readiness.sh` `DEPLOY_VK_DIR` guard. Spec: `docs/superpowers/specs/2026-05-31-trusted-setup-ceremony-design.md`.

**Conventions:** follow @superpowers-extended-cc:verification-before-completion (paste real command output before claiming pass). Ceremony scripts are bash orchestration — the "test" per task is running the script and asserting snarkjs `verify` passes / artifacts have the right shape; the dev dry-run (Task 5) is the integration test. snarkjs is invoked via `pnpm --filter @shielded-near/circom exec snarkjs` (the circom package has snarkjs + @shielded-near/sdk). All ceremony artifacts live under `ceremony/out/` (gitignored). Power 15 (`2^15=32768 ≥ 12578` transfer constraints). DEV keys (`dev-setup.sh`) remain the default; ceremony output is a separate validated artifact and is NEVER presented as production.

---

### Task 0: Scaffold `ceremony/` + shared lib + gitignore

**Files:**
- Create: `ceremony/scripts/_lib.sh`
- Create: `ceremony/.gitignore`
- Create: `ceremony/RUNBOOK.md` (stub; filled in Task 7)
- Create: `ceremony/scripts/manifest.mjs` (node helper: append/read manifest entries)
- Modify: `circom/package.json` (add `tsx` to devDeps)

- [ ] **Step 0: ensure a TS runner resolves from the circom package**
The ceremony TS helpers (Task 3 `vk-to-bin.ts`, Task 6 `gen-fixtures.ts`) are run via `pnpm --filter @shielded-near/circom exec tsx …`, but `tsx` is NOT currently a circom dependency (verified: `pnpm --filter @shielded-near/circom exec tsx …` → "Command tsx not found"). Add `"tsx": "^4.0.0"` to `circom/package.json` `devDependencies` and run `pnpm install` from repo root. Verify `pnpm --filter @shielded-near/circom exec tsx --version` prints a version. (This also de-risks the existing `circom/scripts/regen-fixtures.sh`, which relies on the same invocation.)

- [ ] **Step 1: gitignore + lib**
`ceremony/.gitignore`:
```
out/
```
`ceremony/scripts/_lib.sh` (sourced by every script):
```bash
# shellcheck shell=bash
set -euo pipefail
CEREMONY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$CEREMONY_ROOT/.." && pwd)"
OUT_DIR="${CEREMONY_OUT:-$CEREMONY_ROOT/out}"
SNARKJS="pnpm --filter @shielded-near/circom exec snarkjs"
CIRCUITS=(deposit transfer withdraw)
POWER="${CEREMONY_POWER:-15}"

log() { printf '\n=== %s ===\n' "$*"; }

sha256_hex() {  # cross-platform (Linux sha256sum / macOS shasum)
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}
```
> Note: `pnpm --filter exec snarkjs` returns the snarkjs CLI; confirm it runs from `REPO_ROOT`. If exec resolution is fussy, the implementer may set `SNARKJS="pnpm exec snarkjs"` run from the circom dir — pick what works and note it.

- [ ] **Step 2: manifest helper** `ceremony/scripts/manifest.mjs`
A node ESM script (run via `node`) that maintains `out/manifest.json`. Subcommands: `init <ptauPath>` (records ptau sha256 + power), `add-contribution <circuit> <name> <contributionHash>`, `set-beacon <circuit> <beaconHex> <source>`, `finalize-circuit <circuit> <zkeyPath> <vkJsonPath> <vkBinPath>` (records sha256 of each). Uses `node:crypto` + `node:fs`. JSON shape per the spec's manifest section.

- [ ] **Step 3: RUNBOOK stub** `ceremony/RUNBOOK.md` — a one-line placeholder header (filled in Task 7).

- [ ] **Step 4: Verify + commit**
Run: `bash -n ceremony/scripts/_lib.sh` (syntax check) and `node ceremony/scripts/manifest.mjs init /dev/null` against a temp `CEREMONY_OUT` (smoke). Expected: no errors; a manifest.json is written.
```bash
git add -f ceremony/.gitignore ceremony/scripts/_lib.sh ceremony/scripts/manifest.mjs ceremony/RUNBOOK.md circom/package.json pnpm-lock.yaml
git commit -m "chore(ceremony): scaffold ceremony dir + shared lib + manifest helper + tsx runner"
```

---

### Task 1: Phase-1 scripts (dev local + real import)

**Files:**
- Create: `ceremony/scripts/phase1-dev.sh`
- Create: `ceremony/scripts/phase1-import.sh`

- [ ] **Step 1: phase1-dev.sh** (local Phase-1 for the dry-run)
```bash
#!/usr/bin/env bash
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
mkdir -p "$OUT_DIR"
log "Phase1 dev: powersoftau new bn128 $POWER"
$SNARKJS powersoftau new bn128 "$POWER" "$OUT_DIR/pot_0.ptau" -v
echo "dev-phase1-A" | $SNARKJS powersoftau contribute "$OUT_DIR/pot_0.ptau" "$OUT_DIR/pot_1.ptau" --name="dev-1" -v
log "Phase1 dev: prepare phase2"
$SNARKJS powersoftau prepare phase2 "$OUT_DIR/pot_1.ptau" "$OUT_DIR/pot_final.ptau" -v
$SNARKJS powersoftau verify "$OUT_DIR/pot_final.ptau"
rm -f "$OUT_DIR/pot_0.ptau" "$OUT_DIR/pot_1.ptau"
```
`chmod +x`.

- [ ] **Step 2: phase1-import.sh** (real Perpetual PoT — accepts a local path so it's testable without network)
```bash
#!/usr/bin/env bash
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
# Usage: phase1-import.sh <path-to-perpetual-ptau>   (download URL documented in RUNBOOK)
PTAU_IN="${1:?path to Perpetual PoT .ptau (e.g. powersOfTau28_hez_final_15.ptau)}"
mkdir -p "$OUT_DIR"
log "Phase1 import: verify $PTAU_IN"
$SNARKJS powersoftau verify "$PTAU_IN"
log "Phase1 import: prepare phase2"
$SNARKJS powersoftau prepare phase2 "$PTAU_IN" "$OUT_DIR/pot_final.ptau" -v
$SNARKJS powersoftau verify "$OUT_DIR/pot_final.ptau"
```
`chmod +x`. (The RUNBOOK documents the download URL `https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_15.ptau` + verifying its published hash before use.)

- [ ] **Step 3: Verify + commit**
Run: `bash ceremony/scripts/phase1-dev.sh` → expect `pot_final.ptau` created and `powersoftau verify` printing a success line. Paste the tail.
```bash
git add -f ceremony/scripts/phase1-dev.sh ceremony/scripts/phase1-import.sh
git commit -m "feat(ceremony): Phase-1 scripts (local dev + Perpetual-PoT import)"
```

---

### Task 2: Phase-2 init + contribute scripts

**Files:**
- Create: `ceremony/scripts/init-phase2.sh`
- Create: `ceremony/scripts/contribute.sh`

- [ ] **Step 1: init-phase2.sh** `<circuit>`
```bash
#!/usr/bin/env bash
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
C="${1:?circuit}"
log "Phase2 init: zkey new $C"
$SNARKJS groth16 setup "$REPO_ROOT/circom/build/${C}.r1cs" "$OUT_DIR/pot_final.ptau" "$OUT_DIR/${C}_0000.zkey" -v
```
> Use `groth16 setup` (= `zkey new` for the initial zkey). Subsequent participant contributions use `zkey contribute`. (snarkjs's `groth16 setup` produces the index-0 zkey from r1cs+ptau.)

- [ ] **Step 2: contribute.sh** `<circuit> <inZkey> <outZkey> <name> [entropy]` (the CONTRIBUTOR command)
```bash
#!/usr/bin/env bash
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
C="${1:?circuit}"; IN="${2:?in.zkey}"; OUT="${3:?out.zkey}"; NAME="${4:?contributor name}"
ENTROPY="${5:-}"
log "Phase2 contribute: $C by $NAME"
if [[ -n "$ENTROPY" ]]; then
  echo "$ENTROPY" | $SNARKJS zkey contribute "$IN" "$OUT" --name="$NAME" -v
else
  # interactive: snarkjs prompts for entropy (real contributors)
  $SNARKJS zkey contribute "$IN" "$OUT" --name="$NAME" -v
fi
# Record the contribution hash into the manifest (zkey verify prints per-contribution hashes;
# simplest: store the sha256 of the produced zkey as the attestation reference).
node "$CEREMONY_ROOT/scripts/manifest.mjs" add-contribution "$C" "$NAME" "$(sha256_hex "$OUT")"
```
`chmod +x` both.

- [ ] **Step 3: Verify + commit**
Run (after Task 1's ptau exists): `bash ceremony/scripts/init-phase2.sh deposit` then `bash ceremony/scripts/contribute.sh deposit ceremony/out/deposit_0000.zkey ceremony/out/deposit_0001.zkey "test-1" "e1"`, then `pnpm --filter @shielded-near/circom exec snarkjs zkey verify circom/build/deposit.r1cs ceremony/out/pot_final.ptau ceremony/out/deposit_0001.zkey` → expect "ZKey Ok!". Paste it.
```bash
git add -f ceremony/scripts/init-phase2.sh ceremony/scripts/contribute.sh
git commit -m "feat(ceremony): Phase-2 init + contributor scripts"
```

---

### Task 3: Beacon + finalize (+ vk.bin via the sdk adapter) + manifest

**Files:**
- Create: `ceremony/scripts/beacon.sh`
- Create: `ceremony/scripts/finalize.sh`
- Create: `ceremony/scripts/vk-to-bin.ts`

- [ ] **Step 1: vk-to-bin.ts** (single VK-export path; reuses the B adapter)
```ts
import { readFileSync, writeFileSync } from "node:fs";
import { vkJsonToContractBytes } from "@shielded-near/sdk";
const [, , vkJsonPath, vkBinPath] = process.argv;
const vk = JSON.parse(readFileSync(vkJsonPath, "utf8"));
writeFileSync(vkBinPath, Buffer.from(vkJsonToContractBytes(vk)));
```
Run via `pnpm --filter @shielded-near/circom exec tsx ceremony/scripts/vk-to-bin.ts <vk.json> <vk.bin>` (circom pkg has tsx + @shielded-near/sdk).

- [ ] **Step 2: beacon.sh** `<circuit> <inZkey> <outZkey> <beaconHex> [iterExp]`
```bash
#!/usr/bin/env bash
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
C="${1:?}"; IN="${2:?}"; OUT="${3:?}"; BEACON="${4:?32-byte hex beacon}"; ITER="${5:-10}"
log "Phase2 beacon: $C"
$SNARKJS zkey beacon "$IN" "$OUT" "$BEACON" "$ITER" -n="final beacon" -v
node "$CEREMONY_ROOT/scripts/manifest.mjs" set-beacon "$C" "$BEACON" "${BEACON_SOURCE:-dev-placeholder}"
```

- [ ] **Step 3: finalize.sh** `<circuit> <finalZkey>`
```bash
#!/usr/bin/env bash
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
C="${1:?}"; ZKEY="${2:?final.zkey}"
log "Finalize: verify chain $C"
$SNARKJS zkey verify "$REPO_ROOT/circom/build/${C}.r1cs" "$OUT_DIR/pot_final.ptau" "$ZKEY"
log "Finalize: export VK $C"
$SNARKJS zkey export verificationkey "$ZKEY" "$OUT_DIR/${C}_vk.json" -v
pnpm --filter @shielded-near/circom exec tsx "$CEREMONY_ROOT/scripts/vk-to-bin.ts" "$OUT_DIR/${C}_vk.json" "$OUT_DIR/${C}/vk.bin"
node "$CEREMONY_ROOT/scripts/manifest.mjs" finalize-circuit "$C" "$ZKEY" "$OUT_DIR/${C}_vk.json" "$OUT_DIR/${C}/vk.bin"
```
> Writes `vk.bin` under `out/<c>/vk.bin` so the fingerprint guard's `find … -name vk.bin` (Task 7) picks it up.
`chmod +x` the two .sh.

- [ ] **Step 4: Verify + commit**
Run (continuing the deposit chain from Task 2): `bash ceremony/scripts/beacon.sh deposit ceremony/out/deposit_0001.zkey ceremony/out/deposit_final.zkey 0000000000000000000000000000000000000000000000000000000000000000 8` then `bash ceremony/scripts/finalize.sh deposit ceremony/out/deposit_final.zkey`. Expect "ZKey Ok!", a `deposit_vk.json`, `out/deposit/vk.bin` of length 768, and manifest entries. Paste evidence (`wc -c ceremony/out/deposit/vk.bin` → 768).
```bash
git add -f ceremony/scripts/beacon.sh ceremony/scripts/finalize.sh ceremony/scripts/vk-to-bin.ts
git commit -m "feat(ceremony): beacon + finalize (zkey verify, VK + vk.bin, manifest)"
```

---

### Task 4: `verify-ceremony.sh` — independent transcript re-verification

**Files:**
- Create: `ceremony/scripts/verify-ceremony.sh`

- [ ] **Step 1: implement**
For each circuit: `snarkjs zkey verify <r1cs> <pot_final.ptau> <c>_final.zkey` (chain + beacon), recompute sha256 of `out/<c>/vk.bin` and assert it equals `manifest.json`'s recorded `vkBinSha256` (via `manifest.mjs check-circuit <c>` or a node compare). Exit non-zero on any failure with a clear message.

- [ ] **Step 2: Verify teeth + commit**
Run `bash ceremony/scripts/verify-ceremony.sh` against the deposit artifacts → passes. Then, as a NON-committed probe, flip a byte of `ceremony/out/deposit/vk.bin` (or corrupt the zkey) and re-run → confirm it FAILS; restore. Paste both.
```bash
git add -f ceremony/scripts/verify-ceremony.sh
git commit -m "feat(ceremony): standalone transcript/chain re-verification"
```

---

### Task 5: `run-dev-ceremony.sh` — the dev dry-run driver

**Files:**
- Create: `ceremony/scripts/run-dev-ceremony.sh`

- [ ] **Step 1: implement the driver**
```bash
#!/usr/bin/env bash
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
export BEACON_SOURCE="DEV-PLACEHOLDER-not-production"
DEV_BEACON="aaaa...aaaa"   # 64 hex chars, loudly non-random; document as DEV-only
rm -rf "$OUT_DIR"; mkdir -p "$OUT_DIR"
bash "$CEREMONY_ROOT/scripts/phase1-dev.sh"
node "$CEREMONY_ROOT/scripts/manifest.mjs" init "$OUT_DIR/pot_final.ptau"
for C in "${CIRCUITS[@]}"; do
  mkdir -p "$OUT_DIR/$C"
  bash "$CEREMONY_ROOT/scripts/init-phase2.sh" "$C"
  prev="$OUT_DIR/${C}_0000.zkey"
  for i in 1 2 3; do
    next="$OUT_DIR/${C}_000${i}.zkey"
    bash "$CEREMONY_ROOT/scripts/contribute.sh" "$C" "$prev" "$next" "dev-contributor-$i" "dev-entropy-$C-$i"
    prev="$next"
  done
  bash "$CEREMONY_ROOT/scripts/beacon.sh" "$C" "$prev" "$OUT_DIR/${C}_final.zkey" "$DEV_BEACON" 8
  bash "$CEREMONY_ROOT/scripts/finalize.sh" "$C" "$OUT_DIR/${C}_final.zkey"
done
bash "$CEREMONY_ROOT/scripts/verify-ceremony.sh"
echo "DEV DRY-RUN CEREMONY COMPLETE (NON-PRODUCTION keys in $OUT_DIR)"
```
`chmod +x`. (Loudly labels DEV; 3 simulated contributors per circuit; placeholder beacon.)

- [ ] **Step 2: Run the full dry-run + commit**
Run: `pnpm --filter @shielded-near/circom build` (ensure r1cs present) then `bash ceremony/scripts/run-dev-ceremony.sh`. Expect all three circuits to finalize, `verify-ceremony.sh` to pass, and `out/{deposit,transfer,withdraw}/vk.bin` (768/1088/1024 bytes) + `out/manifest.json`. Paste the tail + `wc -c` of the three vk.bin.
```bash
git add -f ceremony/scripts/run-dev-ceremony.sh
git commit -m "feat(ceremony): dev dry-run driver (local Phase-1, 3 contributors, placeholder beacon)"
```

---

### Task 6: On-contract validation of ceremony output

**Files:**
- Modify: `circom/scripts/gen-fixtures.ts` (parameterize zkey/vk source + output dir)
- Modify: `contract/tests/snarkjs_verify_fixture.rs` (allow a ceremony fixture dir via env) OR add `contract/tests/ceremony_verify_fixture.rs`
- Create: `ceremony/scripts/verify-on-contract.sh`

- [ ] **Step 1: parameterize gen-fixtures.ts**
Add env overrides (default to current DEV behavior): `GENFIX_ZKEY_DIR` (default `build/keys`, names `<c>_dev.zkey`), `GENFIX_VK` source, and `GENFIX_OUT_DIR` (default `circom/fixtures`). When pointed at the ceremony output, it reads `ceremony/out/<c>_final.zkey` + `ceremony/out/<c>_vk.json` and writes `ceremony/out/<c>/{proof.bin,public.bin,vk.bin}`. Don't change the default DEV-fixture behavior (the existing fixtures must still regenerate identically in shape).

- [ ] **Step 2: ceremony on-contract test**
Make `snarkjs_verify_fixture.rs` accept a `CEREMONY_FIXTURE_DIR` env (when set, load `vk.bin`/`proof.bin`/`public.bin` from `ceremony/out/<c>/` instead of `circom/fixtures/<c>/`) and assert `verify_groth16 == true` for all three; keep the default (DEV fixtures) path unchanged. (Or a dedicated `ceremony_verify_fixture.rs` — pick the lower-duplication option.)

- [ ] **Step 3: verify-on-contract.sh**
Generates ceremony fixtures (via the parameterized gen-fixtures pointed at `ceremony/out`) then runs the Rust ceremony verify (`CEREMONY_FIXTURE_DIR=ceremony/out cargo test -p shielded-pool --test snarkjs_verify_fixture …`). Asserts all three verify true.

- [ ] **Step 4: Verify + commit**
Run `bash ceremony/scripts/verify-on-contract.sh` (after Task 5's dry-run produced `ceremony/out`) → all three ceremony proofs verify on-contract. Also confirm the DEV fixtures still pass: `cargo test -p shielded-pool --test snarkjs_verify_fixture` (no env) → green. Paste both.
```bash
git add -f circom/scripts/gen-fixtures.ts contract/tests/snarkjs_verify_fixture.rs ceremony/scripts/verify-on-contract.sh
git commit -m "feat(ceremony): on-contract verify_groth16 of ceremony output (parameterized fixtures)"
```

---

### Task 7: Fingerprint-guard wiring + RUNBOOK + README

**Files:**
- Modify: `ceremony/RUNBOOK.md` (full content)
- Modify: `README.md` (mention ceremony + dry-run command; DEV keys remain default)
- (No code change expected in `scripts/check-production-readiness.sh` — validate the wired path)

- [ ] **Step 1: Validate the fingerprint guard wiring**
Run `DEPLOY_VK_DIR=ceremony/out bash scripts/check-production-readiness.sh; echo EXIT=$?` → **PASS / EXIT=0** (ceremony `vk.bin`s are not DEV fingerprints). Then, as a NON-committed probe, copy a DEV `circom/build/keys/<c>_vk.json`→vk.bin (or an existing DEV `circom/fixtures/<c>/vk.bin`) into a temp dir and run `DEPLOY_VK_DIR=<tmp> …` → confirm it FAILS. Paste both. (If the guard needs a tweak to find `out/<c>/vk.bin`, it already scans recursively for `vk.bin` — confirm; only change it if the probe shows a gap.)

- [ ] **Step 2: RUNBOOK.md** — full real-ceremony instructions: roles (coordinator/contributors); Phase 1 via Perpetual PoT (URL + `powersoftau verify` + published-hash check); the per-circuit sequential contribution protocol (each contributor: get latest zkey → `contribute.sh` with fresh entropy on an ideally air-gapped machine → publish their contribution attestation → pass on); the "one honest contributor + unpredictable beacon ⇒ secure" property + entropy hygiene; beacon selection/announcement (recommend a drand round or future Bitcoin block hash, announced in advance); how participants verify their contribution is in the final transcript (`verify-ceremony.sh` / `snarkjs zkey verify`); and the **handoff** (production sets `DEPLOY_VK_DIR` to the ceremony VK output, contract initialized with ceremony `vk.bin`; mainnet deploy + soundness review + audit remain outside C).

- [ ] **Step 3: README** — add a short "Trusted-setup ceremony" section: `bash ceremony/scripts/run-dev-ceremony.sh` for the dev dry-run; note real ceremony per `ceremony/RUNBOOK.md`; emphasize DEV keys remain the default and ceremony dry-run output is non-production.

- [ ] **Step 4: Final verification + commit**
Re-run the whole dry-run + validations to confirm the end-to-end story is green: `bash ceremony/scripts/run-dev-ceremony.sh && bash ceremony/scripts/verify-on-contract.sh && DEPLOY_VK_DIR=ceremony/out bash scripts/check-production-readiness.sh`. Also confirm existing suites unaffected: `cargo test -p shielded-pool --test snarkjs_verify_fixture` + `pnpm --filter @shielded-near/circom exec vitest run`. Paste results.
```bash
git add -f ceremony/RUNBOOK.md README.md
git commit -m "docs(ceremony): runbook + README; validate DEPLOY_VK_DIR guard wiring"
```

---

## Done criteria for Sub-project C

- `run-dev-ceremony.sh` completes the full local Phase-1 → per-circuit (init → 3 contributions → placeholder beacon → finalize) → `verify-ceremony.sh`, producing `ceremony/out/<c>/vk.bin` (768/1088/1024) + `manifest.json`.
- `snarkjs zkey verify` passes for all three ceremony zkeys; `verify-ceremony.sh` has teeth (corruption fails it).
- Ceremony output verifies on the contract's `verify_groth16` (all three), and the DEV fixtures still verify (default path unchanged).
- `DEPLOY_VK_DIR=ceremony/out` readiness check PASSES; a DEV vk there FAILS.
- `RUNBOOK.md` documents the real ceremony (Perpetual PoT, contribution protocol, beacon, verification, handoff); README points to it; DEV keys remain the default.
- Existing SDK/circom/contract suites remain green.

## Handoff (beyond C)

A real production ceremony is then an **ops event**: run these scripts with the Perpetual PoT + real external participants + a real announced beacon per the RUNBOOK, publish the transcript, set `DEPLOY_VK_DIR` to the resulting VKs, and initialize the deployed contract with the ceremony `vk.bin`. Mainnet with funds also still requires the independent **circuit soundness review** and **external audit**.
