#!/usr/bin/env bash
# DEV-ONLY dry-run of the trusted-setup ceremony: LOCAL Phase-1 + 3 SIMULATED
# contributors + a PLACEHOLDER beacon. The resulting keys are NON-PRODUCTION
# (no real participant entropy, fake beacon) and must never be deployed.
# The real ceremony uses these same scripts with phase1-import.sh (Perpetual PoT)
# + real participants + a real announced beacon — see ceremony/RUNBOOK.md.
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
export BEACON_SOURCE="DEV-PLACEHOLDER-not-production"
# 64-hex-char placeholder beacon — loudly non-random, DEV-only.
DEV_BEACON="00000000000000000000000000000000000000000000000000000000000000aa"
log "DEV DRY-RUN CEREMONY (NON-PRODUCTION) — wiping $OUT_DIR"
rm -rf "$OUT_DIR"; mkdir -p "$OUT_DIR"
bash "$CEREMONY_ROOT/scripts/phase1-dev.sh"
node "$CEREMONY_ROOT/scripts/manifest.mjs" init "$OUT_DIR/pot_final.ptau"
for C in "${CIRCUITS[@]}"; do
  mkdir -p "$OUT_DIR/$C"
  bash "$CEREMONY_ROOT/scripts/init-phase2.sh" "$C"
  prev="$OUT_DIR/${C}_0000.zkey"
  for i in 1 2 3; do
    next="$OUT_DIR/${C}_000${i}.zkey"
    bash "$CEREMONY_ROOT/scripts/contribute.sh" "$C" "$prev" "$next" "dev-contributor-$i" "dev-entropy-$C-$i"
    prev="$next"
  done
  bash "$CEREMONY_ROOT/scripts/beacon.sh" "$C" "$prev" "$OUT_DIR/${C}_final.zkey" "$DEV_BEACON" 10
  bash "$CEREMONY_ROOT/scripts/finalize.sh" "$C" "$OUT_DIR/${C}_final.zkey"
done
bash "$CEREMONY_ROOT/scripts/verify-ceremony.sh"
echo ""
echo "DEV DRY-RUN CEREMONY COMPLETE — NON-PRODUCTION keys in $OUT_DIR"
echo "(real ceremony: see ceremony/RUNBOOK.md)"
