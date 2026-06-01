# shellcheck shell=bash
set -euo pipefail
CEREMONY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$CEREMONY_ROOT/.." && pwd)"
OUT_DIR="${CEREMONY_OUT:-$CEREMONY_ROOT/out}"
# NOTE: snarkjs runs with cwd=circom/ under `pnpm --filter exec`; ceremony
# scripts therefore pass ABSOLUTE paths ($OUT_DIR / $REPO_ROOT-based) to
# avoid any cwd dependence.
SNARKJS="pnpm --filter @shielded-near/circom exec snarkjs"  # intentionally unquoted at call sites — multi-word command; word-splitting is deliberate
CIRCUITS=(deposit transfer withdraw)
POWER="${CEREMONY_POWER:-15}"

log() { printf '\n=== %s ===\n' "$*"; }

# Resolve a path to absolute — if already absolute, pass through; else prepend
# the caller's cwd.  snarkjs runs under `pnpm exec` with cwd=circom/, so all
# paths passed to it must be absolute.
_abs() { local p="$1"; [[ "$p" == /* ]] && echo "$p" || echo "$PWD/$p"; }

require_circuit() {
  local c="$1"
  for x in "${CIRCUITS[@]}"; do [[ "$x" == "$c" ]] && return 0; done
  echo "ERROR: unknown circuit '$c'; expected one of: ${CIRCUITS[*]}" >&2; exit 1
}

sha256_hex() {  # cross-platform (Linux sha256sum / macOS shasum)
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}
