#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"
pnpm --filter @shielded-near/circom build
[ -f build/keys/deposit_dev.zkey ] || bash scripts/dev-setup.sh
pnpm --filter @shielded-near/circom exec tsx scripts/gen-fixtures.ts
