# NEAR Shielded USDC Pool

Privacy-preserving USDC pool on NEAR with per-user auditor view keys.

See [`docs/superpowers/specs/2026-05-24-near-shielded-pool-design.md`](docs/superpowers/specs/2026-05-24-near-shielded-pool-design.md) for the design and [`docs/superpowers/plans/2026-05-24-near-shielded-pool.md`](docs/superpowers/plans/2026-05-24-near-shielded-pool.md) for the implementation plan.

## Status: SANDBOX-READY -- NOT MAINNET-READY

The production-readiness gate now passes for sandbox deployments:

```sh
./scripts/check-production-readiness.sh
```

The prover (`tools/prover`) proves real `deposit`, `transfer`, and `withdraw` Groth16 circuits using NEAR's `alt_bn128` host functions. Proof generation and the verify-via-contract host-function test pass in any environment.

> **Sandbox only — never use with real funds.** This prototype has not undergone circuit soundness review, a trusted-setup ceremony, or an external security audit. See `docs/superpowers/specs/2026-05-26-real-groth16-prover-e2e.md` for the path-to-production gates that remain before any mainnet deployment.

Note: the near-workspaces sandbox tests (`contract/tests/integration.rs` and the real-proof `contract/tests/e2e_real_proofs.rs`) deploy the contract to a local NEAR sandbox (neard 2.11.0, bundled by near-workspaces 0.22) and drive the full on-chain deposit/withdraw/transfer flow — `e2e_real_proofs` does so with real Groth16 proofs verified via `alt_bn128`. They pass locally and can be skipped with `SKIP_NEAR_INTEGRATION=1` (as CI does); proof generation and contract-level verifier tests pass regardless.

Deploy note: since Rust 1.87 the `wasm32-unknown-unknown` target emits bulk-memory ops (`memory.copy`/`memory.fill`) from precompiled std, which the NEAR runtime rejects at deploy with `PrepareError(Deserialization)`. The deployable artifact must be produced with `wasm-opt --enable-bulk-memory --llvm-memory-copy-fill-lowering` to lower them to MVP; the production gate now validates this.

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
- `cargo test -p shielded-pool --tests` -- 14 passing property/verifier + near-workspaces sandbox tests (incl. real-proof deposit/withdraw/transfer) + 1 ignored prover round-trip; sandbox tests skippable via `SKIP_NEAR_INTEGRATION=1`
- `nargo test --workspace` (in `circuits/`) -- 22 tests
- `pnpm -r test` -- core 39, sdk 22, auditor 7, relayer 6 = 74 tests
- `npm test` (in `tools/superpowers-validate/`) -- 16 tests

Total: **192 passing tests across four layers, with 3 intentionally ignored diagnostics/round-trips.** The two near-workspaces sandbox tests now deploy to and pass against the bundled neard sandbox; CI skips the sandbox portion via `SKIP_NEAR_INTEGRATION=1`. CI runs contract tests, deploy-safety checks, circuit tests, TypeScript tests, and spec validation on push (`.github/workflows/ci.yml`); the full production-readiness gate must still pass before any deployment.

## Production Gate

The production-readiness script verifies:

- the prover binary builds, circuit keys are generated via `setup`, and real 256-byte Groth16 proofs are produced for `deposit`, `transfer`, and `withdraw`
- the production verifier feature compiles for `wasm32-unknown-unknown`
- default WASM builds with mock verifier semantics are rejected
- the optimised WASM artifact exists and fits under NEAR's deploy transaction limit
- the optimised WASM uses only NEAR-deployable wasm features (no bulk-memory; lowered to MVP)

**Remaining path-to-mainnet gates** (see spec for details):

1. Independent circuit soundness review
2. Trusted-setup ceremony for production proving/verifying keys
3. External security audit of contract + SDK + prover

Until those gates pass, use only local sandbox deployments and **never deposit real funds**.
