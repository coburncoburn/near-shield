#!/usr/bin/env bash
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
mkdir -p "$OUT_DIR"
log "Phase1 dev: powersoftau new bn128 $POWER"
$SNARKJS powersoftau new bn128 "$POWER" "$OUT_DIR/pot_0.ptau" -v
echo "dev-phase1-A" | $SNARKJS powersoftau contribute "$OUT_DIR/pot_0.ptau" "$OUT_DIR/pot_1.ptau" --name="dev-1" -v
log "Phase1 dev: prepare phase2"
$SNARKJS powersoftau prepare phase2 "$OUT_DIR/pot_1.ptau" "$OUT_DIR/pot_final.ptau" -v
$SNARKJS powersoftau verify "$OUT_DIR/pot_final.ptau"
rm -f "$OUT_DIR/pot_0.ptau" "$OUT_DIR/pot_1.ptau"
