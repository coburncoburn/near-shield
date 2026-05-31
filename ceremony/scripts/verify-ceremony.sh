#!/usr/bin/env bash
# ceremony/scripts/verify-ceremony.sh
# Standalone re-verification of a completed ceremony transcript.
# For each circuit: verifies the final zkey chain (r1cs + ptau) with
# `snarkjs zkey verify`, then checks that out/<c>/vk.bin sha256 matches
# the manifest.  Exits non-zero if any check fails.
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

[[ -f "$OUT_DIR/pot_final.ptau" ]] || {
  echo "ERROR: $OUT_DIR/pot_final.ptau missing — run the ceremony first" >&2
  exit 1
}

fail=0
for C in "${CIRCUITS[@]}"; do
  log "verify-ceremony: $C"
  ZKEY="$OUT_DIR/${C}_final.zkey"
  [[ -f "$ZKEY" ]] || { echo "ERROR: $ZKEY missing" >&2; fail=1; continue; }
  # snarkjs zkey verify exits non-zero on a bad chain (verified empirically).
  if ! $SNARKJS zkey verify "$REPO_ROOT/circom/build/${C}.r1cs" "$OUT_DIR/pot_final.ptau" "$ZKEY"; then
    echo "ERROR: zkey verify FAILED for $C" >&2; fail=1; continue
  fi
  if ! node "$CEREMONY_ROOT/scripts/manifest.mjs" check-circuit "$C" "$OUT_DIR/${C}/vk.bin"; then
    echo "ERROR: vk.bin sha256 does not match manifest for $C" >&2; fail=1
  fi
done

[[ "$fail" -eq 0 ]] || { echo "verify-ceremony: FAILED" >&2; exit 1; }
echo "verify-ceremony: all circuits OK"
