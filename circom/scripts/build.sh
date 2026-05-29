#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p build
for c in deposit transfer withdraw; do
  echo "== compiling $c =="
  circom "circuits/$c.circom" --r1cs --wasm -l node_modules -o build
done
