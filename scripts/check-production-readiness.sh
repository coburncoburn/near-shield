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

cargo build -q -p shielded-prover --release
PROVER="$ROOT/target/release/shielded-prover"
KEY_DIR="$ROOT/target/sp-keys"
mkdir -p "$KEY_DIR"
"$PROVER" setup --out-dir "$KEY_DIR"
pass_step "prover built and circuit keys generated"

_prover_failures=0
for c in deposit transfer withdraw; do
  fixture="$ROOT/tools/prover/fixtures/${c}.json"
  if [[ ! -f "$fixture" ]]; then
    add_failure "missing prover fixture at $fixture"
    _prover_failures=$((_prover_failures + 1))
    continue
  fi
  n="$(PROVER_KEY_DIR="$KEY_DIR" "$PROVER" < "$fixture" | wc -c | tr -d ' ')"
  if [ "$n" = "256" ]; then
    pass_step "real ${c} proof (256 bytes)"
  else
    add_failure "prover did not emit a 256-byte proof for ${c} (got ${n} bytes)"
    _prover_failures=$((_prover_failures + 1))
  fi
done
if [[ "$_prover_failures" -eq 0 ]]; then
  pass_step "prover generates real Groth16 proofs for all shielded circuits"
fi

finish_if_failures

printf '\nPRODUCTION READINESS: PASS\n'
