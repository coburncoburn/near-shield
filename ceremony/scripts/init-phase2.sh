#!/usr/bin/env bash
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
C="${1:?circuit (deposit|transfer|withdraw)}"
require_circuit "$C"
[[ ! -f "$OUT_DIR/${C}_0000.zkey" ]] || { echo "ERROR: ${C}_0000.zkey already exists — delete it to re-init" >&2; exit 1; }
log "Phase2 init: zkey new $C"
$SNARKJS groth16 setup "$REPO_ROOT/circom/build/${C}.r1cs" "$OUT_DIR/pot_final.ptau" "$OUT_DIR/${C}_0000.zkey" -v
