#!/usr/bin/env bash
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
C="${1:?circuit}"
require_circuit "$C"
# Resolve IN/OUT to absolute paths — snarkjs runs under pnpm exec with cwd=circom/
# so relative paths passed by the caller would be wrong inside that subprocess.
_abs() {
  local p="$1"
  # If already absolute, use as-is; otherwise prepend caller's cwd.
  [[ "$p" == /* ]] && echo "$p" || echo "$PWD/$p"
}
IN="$(_abs "${2:?in.zkey}")"
OUT="$(_abs "${3:?out.zkey}")"
NAME="${4:?contributor name}"
ENTROPY="${5:-}"
[[ -f "$IN" ]] || { echo "ERROR: input zkey not found: $IN" >&2; exit 1; }
# Ensure the output directory exists
mkdir -p "$(dirname "$OUT")"
log "Phase2 contribute: $C by '$NAME'"
if [[ -n "$ENTROPY" ]]; then
  printf '%s\n' "$ENTROPY" | $SNARKJS zkey contribute "$IN" "$OUT" --name="$NAME" -v
else
  # interactive: snarkjs prompts the real contributor for entropy
  $SNARKJS zkey contribute "$IN" "$OUT" --name="$NAME" -v
fi
# Attestation: record sha256 of the output zkey FILE as an integrity reference
# (not the MPC contribution hash — obtain that via `snarkjs zkey verify`).
node "$CEREMONY_ROOT/scripts/manifest.mjs" add-contribution "$C" "$NAME" "$(sha256_hex "$OUT")"
