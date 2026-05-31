#!/usr/bin/env bash
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
C="${1:?circuit}"; require_circuit "$C"
ZKEY="$(_abs "${2:?final.zkey}")"
[[ -f "$ZKEY" ]] || { echo "ERROR: zkey not found: $ZKEY" >&2; exit 1; }
mkdir -p "$OUT_DIR/$C"
log "Finalize: verify chain $C"
$SNARKJS zkey verify "$REPO_ROOT/circom/build/${C}.r1cs" "$OUT_DIR/pot_final.ptau" "$ZKEY"
log "Finalize: export VK $C"
$SNARKJS zkey export verificationkey "$ZKEY" "$OUT_DIR/${C}_vk.json" -v
pnpm --filter @shielded-near/circom exec tsx "$CEREMONY_ROOT/scripts/vk-to-bin.ts" "$OUT_DIR/${C}_vk.json" "$OUT_DIR/$C/vk.bin"
# Assert vk.bin has the expected byte count — catches any VK serialization regression.
_vk_size() { case "$1" in deposit) echo 768;; transfer) echo 1088;; withdraw) echo 1024;; esac; }
EXPECTED="$(_vk_size "$C")"
ACTUAL="$(wc -c < "$OUT_DIR/$C/vk.bin")"
[[ "$ACTUAL" -eq "$EXPECTED" ]] || { echo "ERROR: vk.bin wrong size for $C: expected $EXPECTED bytes, got $ACTUAL" >&2; exit 1; }
node "$CEREMONY_ROOT/scripts/manifest.mjs" finalize-circuit "$C" "$ZKEY" "$OUT_DIR/${C}_vk.json" "$OUT_DIR/$C/vk.bin"
