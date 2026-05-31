#!/usr/bin/env bash
# regen-fixtures.sh — Regenerates cryptographic DEV Groth16 fixtures for all three circuits.
#
# Preconditions:
#   - circom is on PATH  (https://docs.circom.io/getting-started/installation/)
#   - pnpm and node are installed
#   - Run from anywhere inside the repo; script resolves its own ROOT
#
# Outputs: build/ will be populated with compiled circuits and proving keys,
#          and circom/fixtures/ will contain fresh proof/vk/public .json + .bin files.
#
# WARNING: snarkjs Groth16 proving is non-deterministic; running this changes the
#          committed .bin fixtures. Only run when circuit changes require new fixtures.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"
pnpm --filter @shielded-near/circom build
if [ ! -f build/keys/deposit_dev.zkey ] || [ ! -f build/keys/transfer_dev.zkey ] || [ ! -f build/keys/withdraw_dev.zkey ]; then
  bash scripts/dev-setup.sh
fi
pnpm --filter @shielded-near/circom exec tsx scripts/gen-fixtures.ts
# Also regenerate the connected e2e fixtures (deposit-A → deposit-B → transfer → withdraw).
pnpm --filter @shielded-near/circom exec tsx scripts/gen-e2e-fixtures.ts
