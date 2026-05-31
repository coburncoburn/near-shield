#!/usr/bin/env bash
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
C="${1:?circuit}"; require_circuit "$C"
IN="$(_abs "${2:?in.zkey}")"; OUT="$(_abs "${3:?out.zkey}")"; BEACON="${4:?32-byte hex beacon}"; ITER="${5:-10}"
[[ -f "$IN" ]] || { echo "ERROR: input zkey not found: $IN" >&2; exit 1; }
# Validate iterExp before calling snarkjs — snarkjs exits 0 even when it rejects
# an out-of-range value, so we must guard here to avoid a silent no-op.
[[ "$ITER" =~ ^[0-9]+$ && "$ITER" -ge 10 && "$ITER" -le 63 ]] || { echo "ERROR: beacon iterExp must be 10–63 (got: $ITER)" >&2; exit 1; }
mkdir -p "$(dirname "$OUT")"
log "Phase2 beacon: $C"
# BEACON_SOURCE should identify the public randomness beacon used in a real
# ceremony (e.g. "drand round 1234567" / "Bitcoin block 900000"); dev runs
# leave it unset and fall back to the placeholder.
$SNARKJS zkey beacon "$IN" "$OUT" "$BEACON" "$ITER" -n="final beacon" -v
# Assert snarkjs actually produced the output — it exits 0 even on rejection.
[[ -f "$OUT" ]] || { echo "ERROR: beacon zkey was not written — snarkjs rejected the inputs" >&2; exit 1; }
node "$CEREMONY_ROOT/scripts/manifest.mjs" set-beacon "$C" "$BEACON" "${BEACON_SOURCE:-dev-placeholder}"
