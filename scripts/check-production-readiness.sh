#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MAX_WASM_BYTES=1572864
OPT_WASM="target/wasm32-unknown-unknown/release/shielded_pool.opt.wasm"
RAW_WASM="target/wasm32-unknown-unknown/release/shielded_pool.wasm"
FAILURES=()

fail() {
  printf 'PRODUCTION READINESS: FAIL\n\n%s\n' "$1" >&2
  exit 1
}

pass_step() {
  printf 'ok - %s\n' "$1"
}

add_failure() {
  FAILURES+=("$1")
}

finish_if_failures() {
  if [[ "${#FAILURES[@]}" -eq 0 ]]; then
    return
  fi

  printf 'PRODUCTION READINESS: FAIL\n\n' >&2
  local failure
  for failure in "${FAILURES[@]}"; do
    printf -- '- %s\n' "$failure" >&2
  done
  exit 1
}

if ! command -v cargo >/dev/null 2>&1; then
  fail "cargo is required"
fi

if ! command -v node >/dev/null 2>&1; then
  fail "node is required"
fi

if ! rustup target list --installed | grep -qx 'wasm32-unknown-unknown'; then
  fail "Rust target wasm32-unknown-unknown is not installed. Run: rustup target add wasm32-unknown-unknown"
fi
pass_step "toolchain is present"

if ! grep -q 'pub const TREE_DEPTH: u8 = 20;' contract/src/lib.rs; then
  fail "contract TREE_DEPTH is not the expected production value 20"
fi
if ! grep -q 'pub global MERKLE_DEPTH: u32 = 20;' circuits/shared/src/lib.nr; then
  fail "Noir MERKLE_DEPTH must equal contract TREE_DEPTH (20) before production"
fi
pass_step "contract and circuit Merkle depths match"

cargo check -p shielded-pool --lib --target wasm32-unknown-unknown --no-default-features --features groth16-verifier >/dev/null
pass_step "production verifier feature compiles for wasm"

if cargo check -p shielded-pool --lib --target wasm32-unknown-unknown >/tmp/shielded-pool-default-wasm-check.log 2>&1; then
  fail "default WASM build succeeded; mock verifier semantics must be rejected for deployable artifacts"
fi
if ! grep -q 'WASM contract builds must disable `unit-testing`' /tmp/shielded-pool-default-wasm-check.log; then
  fail "default WASM build failed for an unexpected reason; see /tmp/shielded-pool-default-wasm-check.log"
fi
pass_step "default mock-verifier WASM build is rejected"

if [[ ! -f "$OPT_WASM" ]]; then
  add_failure "missing optimised WASM artifact at $OPT_WASM

Build one before deployment, for example:
  cargo build -p shielded-pool --target wasm32-unknown-unknown --release --no-default-features --features groth16-verifier
  wasm-opt --enable-bulk-memory --llvm-memory-copy-fill-lowering -Oz --strip-debug --strip-producers \\
    target/wasm32-unknown-unknown/release/shielded_pool.wasm \\
    -o $OPT_WASM"
else
  if [[ -f "$RAW_WASM" && "$OPT_WASM" -ot "$RAW_WASM" ]]; then
    add_failure "optimised WASM artifact is older than $RAW_WASM; rebuild and rerun wasm-opt before deployment"
  fi

  wasm_bytes="$(wc -c < "$OPT_WASM" | tr -d ' ')"
  if [[ "$wasm_bytes" -gt "$MAX_WASM_BYTES" ]]; then
    add_failure "optimised WASM is ${wasm_bytes} bytes, above NEAR's ${MAX_WASM_BYTES}-byte per-transaction deploy limit"
  else
    pass_step "optimised WASM fits NEAR deploy limit"
  fi

  # The NEAR runtime rejects bulk-memory ops (memory.copy/fill) at deploy time
  # with PrepareError(Deserialization). Rust >=1.87's wasm32 std emits them, so
  # the build must run `wasm-opt --llvm-memory-copy-fill-lowering`. Validate the
  # artifact against the NEAR-accepted feature set (MVP + sign-ext + mutable
  # globals) so a non-deployable artifact can never pass this gate.
  if ! command -v wasm-opt >/dev/null 2>&1; then
    add_failure "wasm-opt is required to validate the deployable artifact's wasm feature set"
  elif ! wasm-opt --mvp-features --enable-sign-ext --enable-mutable-globals \
      "$OPT_WASM" -o /dev/null >/dev/null 2>&1; then
    add_failure "optimised WASM uses wasm features the NEAR runtime rejects (likely bulk-memory). Rebuild with: wasm-opt --enable-bulk-memory --llvm-memory-copy-fill-lowering -Oz --strip-debug --strip-producers $RAW_WASM -o $OPT_WASM"
  else
    pass_step "optimised WASM uses only NEAR-deployable wasm features"
  fi
fi

# ---------------------------------------------------------------------------
# DEV verifying-key fingerprint guard (Sub-project B)
#
# The VKs in circom/fixtures/<circuit>/vk.bin are generated from the snarkjs
# DEV trusted-setup (dev-setup.sh using a hardcoded ptau seed). They are
# FORBIDDEN from being used in any production deployment.
#
# Sub-project C will produce real ceremony VKs and wire them as the deploy
# target; this guard ensures the DEV keys can NEVER silently slip through.
#
# Mechanism: sha256 each candidate deploy VK file and reject if it matches
# any DEV fingerprint. The deploy VK location ($DEPLOY_VK_DIR) defaults to
# an empty sentinel so this check is a no-op until Sub-project C populates it.
# ---------------------------------------------------------------------------

# DEV key fingerprints (sha256, no filename) — Sub-project B registered values.
# To regenerate: sha256sum circom/fixtures/{deposit,transfer,withdraw}/vk.bin
DEV_VK_FINGERPRINTS=(
  "8abe07dc84b83e87f469c02456546cea85ec2797a4006a13af5dd5009697ba4f"  # deposit  DEV vk
  "1298e44b0ed0ed6227b1b6753d548359d865005afed77dabadb134c12571f171"  # transfer DEV vk
  "d72df6c51b91bed8558977fca485c9b1392cccddca285939d17a52d68dd9d4cb"  # withdraw DEV vk
)

# Sub-project C: set DEPLOY_VK_DIR to the directory holding the ceremony VK
# files (one vk.bin per circuit) before wiring a production deploy.
# Until then this block is intentionally a no-op (the directory won't exist).
DEPLOY_VK_DIR="${DEPLOY_VK_DIR:-}"

if [[ -n "$DEPLOY_VK_DIR" && -d "$DEPLOY_VK_DIR" ]]; then
  _vk_failures=0
  while IFS= read -r vk_file; do
    [[ -f "$vk_file" ]] || continue
    fingerprint="$(sha256sum "$vk_file" | awk '{print $1}')"
    for dev_fp in "${DEV_VK_FINGERPRINTS[@]}"; do
      if [[ "$fingerprint" == "$dev_fp" ]]; then
        add_failure "DEV verifying key detected in deploy VK location: $vk_file (sha256=$fingerprint). Run Sub-project C trusted-setup ceremony to produce real keys."
        _vk_failures=$((_vk_failures + 1))
        break
      fi
    done
  done < <(find "$DEPLOY_VK_DIR" -type f \( -name 'vk.bin' -o -name '*.vk.bin' \))
  if [[ "$_vk_failures" -eq 0 ]]; then
    pass_step "deploy VKs do not match any DEV fingerprint"
  fi
else
  pass_step "deploy VK fingerprint guard registered (DEPLOY_VK_DIR not set — Sub-project C pending)"
fi

finish_if_failures

printf '\nPRODUCTION READINESS: PASS\n'
