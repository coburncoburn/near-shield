# shellcheck shell=bash
set -euo pipefail
CEREMONY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$CEREMONY_ROOT/.." && pwd)"
OUT_DIR="${CEREMONY_OUT:-$CEREMONY_ROOT/out}"
# NOTE: snarkjs is invoked via pnpm --filter; paths passed to it must be
# relative to $REPO_ROOT/circom (that is snarkjs's cwd under --filter exec).
SNARKJS="pnpm --filter @shielded-near/circom exec snarkjs"
CIRCUITS=(deposit transfer withdraw)
POWER="${CEREMONY_POWER:-15}"

log() { printf '\n=== %s ===\n' "$*"; }

sha256_hex() {  # cross-platform (Linux sha256sum / macOS shasum)
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}
