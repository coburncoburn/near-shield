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
  wasm-opt -Oz --enable-bulk-memory --strip-debug --strip-producers \\
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
fi

PROVER="${PROVER:-target/release/shielded-prover}"
if [[ ! -x "$PROVER" ]]; then
  add_failure "missing executable prover at $PROVER. Build it with: cargo build -p shielded-prover --release"
fi

check_prover_circuit() {
  local circuit="$1"
  if [[ ! -x "$PROVER" ]]; then
    return
  fi
  local req
  req="$(node -e "console.log(JSON.stringify({circuit:'${circuit}',publicInputs:['0x'+'00'.repeat(32)],witness:{}}))")"
  local out
  local err
  out="$(mktemp)"
  err="$(mktemp)"
  if ! printf '%s' "$req" | "$PROVER" >"$out" 2>"$err"; then
    add_failure "prover cannot generate a ${circuit} proof.

stderr:
$(cat "$err")

Production requires real proofs for deposit, transfer, and withdraw."
    return
  fi
  local size
  size="$(wc -c < "$out" | tr -d ' ')"
  if [[ "$size" -ne 256 ]]; then
    add_failure "prover returned ${size} bytes for ${circuit}; expected 256-byte Groth16 proof"
  fi
}

check_prover_circuit deposit
check_prover_circuit transfer
check_prover_circuit withdraw
if [[ "${#FAILURES[@]}" -eq 0 ]]; then
  pass_step "prover generates real proof-shaped outputs for all shielded circuits"
fi

finish_if_failures

printf '\nPRODUCTION READINESS: PASS\n'
