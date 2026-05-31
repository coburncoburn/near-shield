#!/usr/bin/env bash
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
PTAU_IN="${1:?path to Perpetual PoT .ptau (e.g. powersOfTau28_hez_final_15.ptau) — download URL in ceremony/RUNBOOK.md}"
mkdir -p "$OUT_DIR"
log "Phase1 import: verify $PTAU_IN"
$SNARKJS powersoftau verify "$PTAU_IN"
log "Phase1 import: prepare phase2"
$SNARKJS powersoftau prepare phase2 "$PTAU_IN" "$OUT_DIR/pot_final.ptau" -v
$SNARKJS powersoftau verify "$OUT_DIR/pot_final.ptau"
