#!/usr/bin/env bash
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
C="${1:?circuit}"; require_circuit "$C"
_abs() { local p="$1"; [[ "$p" == /* ]] && echo "$p" || echo "$PWD/$p"; }
IN="$(_abs "${2:?in.zkey}")"; OUT="$(_abs "${3:?out.zkey}")"; BEACON="${4:?32-byte hex beacon}"; ITER="${5:-10}"
[[ -f "$IN" ]] || { echo "ERROR: input zkey not found: $IN" >&2; exit 1; }
log "Phase2 beacon: $C"
$SNARKJS zkey beacon "$IN" "$OUT" "$BEACON" "$ITER" -n="final beacon" -v
node "$CEREMONY_ROOT/scripts/manifest.mjs" set-beacon "$C" "$BEACON" "${BEACON_SOURCE:-dev-placeholder}"
