# NEAR Shielded USDC Pool

Privacy-preserving USDC pool on NEAR with per-user auditor view keys.

See [`docs/superpowers/specs/2026-05-24-near-shielded-pool-design.md`](docs/superpowers/specs/2026-05-24-near-shielded-pool-design.md) for the design and [`docs/superpowers/plans/2026-05-24-near-shielded-pool.md`](docs/superpowers/plans/2026-05-24-near-shielded-pool.md) for the implementation plan.

## Status: PROTOTYPE -- DEPLOYMENT GATED

Most safety preconditions are in place, but the repository is **not ready for a funds-bearing deployment** until the production-readiness gate passes:

```sh
./scripts/check-production-readiness.sh
```

Remaining release blocker:

1. **Real shielded-pool prover.** The contract has real Groth16 verification plumbing through NEAR's `alt_bn128` host functions, but `tools/prover` currently proves only a reference `mul` circuit. Production requires proof generation for the actual `deposit`, `transfer`, and `withdraw` circuits, with proving/verifying keys generated from those exact constraints.

What **is** in place:

- Cross-layer hash alignment (Rust + TS + Noir all use BN254 Poseidon with Circom params; vectors locked in `sdk/test-vectors/poseidon.json` and `view_ct_hash.json`)
- Real Groth16 verifier plumbing with wrong-public-input and wrong-witness rejection tests
- Slim on-chain Poseidon implementation with no production `ark-*`, `light-poseidon`, or `num-bigint` dependency; optimised Groth16 WASM is ~206 KiB
- Real in-circuit Merkle inclusion proofs in `transfer.nr` and `withdraw.nr` (`forged_merkle_path_fails` tests confirm soundness)
- Per-tx storage staking deposits (DoS protection on Merkle/nullifier growth)
- Failed-payout recovery (`unclaimed_payouts` book + `claim()`) so a failed FT transfer after the nullifier is spent doesn't lose funds
- Input validation hardening (size bounds, named-field hex parsing, fuzz/property tests)
- Auditor selective-disclosure design with per-user pubkey, lossless round-trip through note ciphertexts

## Layout

- `circuits/` -- Noir zk circuits (deposit, transfer, withdraw) and shared primitives
- `contract/` -- NEAR Rust contract: Merkle tree, nullifier set, FT (NEP-141) cross-contract calls, payout recovery, validation
- `sdk/packages/core` -- Field, Poseidon (cross-language vectors), Note model, hybrid encryption, note scanner, `hashBytesToField`
- `sdk/packages/sdk` -- High-level `Wallet` API and contract-shaped envelopes
- `sdk/packages/auditor` -- Indexer that decrypts disclosure ciphertexts addressed to a configured auditor key
- `sdk/packages/relayer` -- Stateless HTTP service that pays gas to submit users' withdrawal proofs

## Test status

- `cargo test -p shielded-pool --lib` -- 66 passing tests + 2 ignored vector dumps
- `cargo test -p shielded-pool --tests` -- 12 passing property/verifier tests + 1 environment-gated near-workspaces smoke + 1 ignored prover round-trip
- `nargo test --workspace` (in `circuits/`) -- 22 tests
- `pnpm -r test` -- core 39, sdk 22, auditor 7, relayer 6 = 74 tests
- `npm test` (in `tools/superpowers-validate/`) -- 16 tests

Total: **190 passing tests across four layers, with 3 intentionally ignored diagnostics/round-trips and 1 environment-gated near-workspaces smoke.** CI runs contract tests, deploy-safety checks, circuit tests, TypeScript tests, and spec validation on push (`.github/workflows/ci.yml`); the full production-readiness gate must still pass before any deployment.

## Production Gate

The production-readiness script is intentionally strict and currently fails on
the release blocker above. It fails unless:

- the SDK/prover path can generate real 256-byte proofs for `deposit`, `transfer`, and `withdraw`
- the production verifier feature compiles for `wasm32-unknown-unknown`
- default WASM builds with mock verifier semantics are rejected
- the optimised WASM artifact exists and fits under NEAR's deploy transaction limit

Until that script passes, use only local sandbox deployments and never deposit real funds.
