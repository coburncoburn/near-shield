#!/usr/bin/env bash
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
C="${1:?circuit (deposit|transfer|withdraw)}"
log "Phase2 init: zkey new $C"
$SNARKJS groth16 setup "$REPO_ROOT/circom/build/${C}.r1cs" "$OUT_DIR/pot_final.ptau" "$OUT_DIR/${C}_0000.zkey" -v
