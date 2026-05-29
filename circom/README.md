This package is Sub-project A of the trusted-setup ceremony pivot: it houses
the Circom circuit sources and the snarkjs-based build toolchain for the
shielded-pool's deposit, transfer, and withdraw circuits. The arkworks prover
in `tools/prover` and the TypeScript equivalence oracle in
`@shielded-near/core` are retained as the reference implementation until
Sub-project B (the integration swap: snarkjs prove path, VK→contract
serialization adapter, dev-key fingerprint guard, prover/relayer/demo
cutover) is complete. The constraint-equivalence proofs themselves are
Sub-project A (this package).

**ALL keys produced by this package are DEV-only** — real, ceremony-grade
proving and verification keys will be produced during Sub-project C (the
Groth16 trusted-setup ceremony) and must never be substituted with anything
generated here.

## Measured constraint counts (circom 2.1.9)

| Circuit  | Non-linear constraints |
|----------|------------------------|
| deposit  | 297                    |
| withdraw | 6,048                  |
| transfer | 12,578                 |

Transfer is the largest circuit. `ceil(log2(12578)) = 14` (since 2^13 = 8192 < 12578 ≤ 2^14 = 16384),
so **ptau power P = 14** is used for DEV key generation (`scripts/dev-setup.sh`).

## DEV key generation

```bash
pnpm --filter @shielded-near/circom build   # compile circuits → build/*.r1cs + *_js/*.wasm
bash circom/scripts/dev-setup.sh             # generate build/keys/*_dev.zkey + *_vk.json
pnpm --filter @shielded-near/circom exec vitest run test/prove-verify.test.ts
```
