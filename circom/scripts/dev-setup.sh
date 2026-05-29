#!/usr/bin/env bash
# DEV-ONLY: generates ptau and zkeys for local testing.
# These keys are NEVER shipped — they use deterministic single-contribution
# entropy that is unsuitable for production. Sub-project B's fingerprint guard
# will block them; Sub-project C runs the real ceremony.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"

# P=14: sized to transfer circuit (12578 non-linear constraints ≤ 2^14=16384).
# See README.md for measured constraint counts.
P=14
SNARKJS="pnpm exec snarkjs"

mkdir -p build/keys

echo "=== [1/3] Powers of Tau new (bn128, P=$P) ==="
$SNARKJS powersoftau new bn128 "$P" build/keys/pot_0.ptau -v

echo "=== [2/3] Contribute (dev entropy) ==="
echo "dev-entropy-A" | $SNARKJS powersoftau contribute build/keys/pot_0.ptau build/keys/pot_1.ptau --name=dev -v

echo "=== [3/3] Prepare phase2 ==="
$SNARKJS powersoftau prepare phase2 build/keys/pot_1.ptau build/keys/pot_final.ptau -v

for c in deposit transfer withdraw; do
  echo "=== Groth16 setup: $c ==="
  $SNARKJS groth16 setup "build/${c}.r1cs" build/keys/pot_final.ptau "build/keys/${c}_0.zkey"

  echo "=== Zkey contribute: $c ==="
  echo "dev-entropy-${c}" | $SNARKJS zkey contribute "build/keys/${c}_0.zkey" "build/keys/${c}_dev.zkey" --name=dev -v

  echo "=== Export verification key: $c ==="
  $SNARKJS zkey export verificationkey "build/keys/${c}_dev.zkey" "build/keys/${c}_vk.json"
done

echo ""
echo "DEV setup complete. Keys written to build/keys/ (gitignored)."
