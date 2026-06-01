#!/usr/bin/env bash
# verify-on-contract.sh
#
# Proves that the ceremony output keys produce proofs that verify against the
# contract's verify_groth16 (NEAR alt_bn128 host functions).
#
# Prerequisites:
#   - Circuits compiled (wasm/r1cs) in circom/build/
#   - A completed ceremony in OUT_DIR (run ceremony/scripts/run-dev-ceremony.sh first)
#
# Usage:
#   bash ceremony/scripts/verify-on-contract.sh
#
# shellcheck shell=bash
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

# Requires a completed ceremony (run ceremony/scripts/run-dev-ceremony.sh first).
for C in "${CIRCUITS[@]}"; do
  [[ -f "$OUT_DIR/${C}_final.zkey" ]] || {
    echo "ERROR: $OUT_DIR/${C}_final.zkey missing — run run-dev-ceremony.sh first" >&2
    exit 1
  }
done

log "Generating ceremony fixtures from ceremony zkeys"
GENFIX_ZKEY_DIR="$OUT_DIR" GENFIX_ZKEY_SUFFIX="_final.zkey" GENFIX_OUT_DIR="$OUT_DIR" \
  pnpm --filter @shielded-near/circom exec tsx "$REPO_ROOT/circom/scripts/gen-fixtures.ts"

log "Verifying ceremony proofs on the contract"
( cd "$REPO_ROOT" && CEREMONY_FIXTURE_DIR="$OUT_DIR" cargo test -p shielded-pool --test snarkjs_verify_fixture )

echo "verify-on-contract: ceremony proofs verify on the contract verifier"
