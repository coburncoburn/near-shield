#!/usr/bin/env bash
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
C="${1:?circuit}"; require_circuit "$C"
_abs() { local p="$1"; [[ "$p" == /* ]] && echo "$p" || echo "$PWD/$p"; }
ZKEY="$(_abs "${2:?final.zkey}")"
[[ -f "$ZKEY" ]] || { echo "ERROR: zkey not found: $ZKEY" >&2; exit 1; }
mkdir -p "$OUT_DIR/$C"
log "Finalize: verify chain $C"
$SNARKJS zkey verify "$REPO_ROOT/circom/build/${C}.r1cs" "$OUT_DIR/pot_final.ptau" "$ZKEY"
log "Finalize: export VK $C"
$SNARKJS zkey export verificationkey "$ZKEY" "$OUT_DIR/${C}_vk.json" -v
pnpm --filter @shielded-near/circom exec tsx "$CEREMONY_ROOT/scripts/vk-to-bin.ts" "$OUT_DIR/${C}_vk.json" "$OUT_DIR/${C}/vk.bin"
node "$CEREMONY_ROOT/scripts/manifest.mjs" finalize-circuit "$C" "$ZKEY" "$OUT_DIR/${C}_vk.json" "$OUT_DIR/${C}/vk.bin"
