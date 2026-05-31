# NEAR Shielded USDC Pool

Privacy-preserving USDC pool on NEAR with per-user auditor view keys.

See [`docs/superpowers/specs/2026-05-24-near-shielded-pool-design.md`](docs/superpowers/specs/2026-05-24-near-shielded-pool-design.md) for the design and [`docs/superpowers/plans/2026-05-24-near-shielded-pool.md`](docs/superpowers/plans/2026-05-24-near-shielded-pool.md) for the implementation plan.

## Status: SANDBOX-READY -- NOT MAINNET-READY

The production-readiness gate now passes for sandbox deployments:

```sh
./scripts/check-production-readiness.sh
```

The prover (`SnarkjsProver`, in-process snarkjs) proves real `deposit`, `transfer`, and `withdraw` Groth16 circuits using NEAR's `alt_bn128` host functions. Proof generation and the verify-via-contract host-function test pass in any environment.

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

## Try the demo (sandbox only)

`@shielded-near/demo` drives a full real-client flow against a local near-workspaces sandbox: it deploys the real `groth16-verifier` pool WASM + a vendored NEP-141 (`mock-ft`), creates Alice/Bob/relayer accounts, generates real Groth16 proofs via the in-process `SnarkjsProver`, and submits them through the TS SDK.

> **Current state:** the demo runs the full deposit → transfer → withdraw flow end-to-end with real Groth16 proofs against a near-workspaces sandbox, and asserts Bob's on-chain `ft_balance_of` increased by `60 - relayerFee`. The view_ct binding uses NEAR's `keccak256` host fn — see `docs/superpowers/specs/2026-05-28-view-ct-binding-keccak.md`.

### Build prereqs (one-time)

```sh
cargo build -p shielded-pool --target wasm32-unknown-unknown --release --no-default-features --features groth16-verifier
./scripts/check-production-readiness.sh    # produces target/wasm32-unknown-unknown/release/shielded_pool.opt.wasm
cargo build -p mock-ft --target wasm32-unknown-unknown --release --no-default-features
wasm-opt --enable-bulk-memory --llvm-memory-copy-fill-lowering \
  target/wasm32-unknown-unknown/release/mock_ft.wasm \
  -o target/wasm32-unknown-unknown/release/mock_ft.opt.wasm
pnpm --filter @shielded-near/circom build  # compile circom circuits → build/*.r1cs + *_js/*.wasm
bash circom/scripts/dev-setup.sh           # generate DEV proving/verifying keys (Sub-project C produces real keys)
pnpm install
```

The prover is in-process `SnarkjsProver` (no separate binary). `wasm-opt` is required (used by `check-production-readiness.sh`); install via your OS package manager or from the [binaryen releases](https://github.com/WebAssembly/binaryen/releases).

`near-workspaces@4.0.0` ships a `neard` that is missing host functions required by `near-sdk 5.5`. The demo uses `near-workspaces` 0.22 (Rust crate), which bundles neard 2.11.0 and does not have this problem. If you see missing-host-function errors from the TS sandbox, set `SANDBOX_ARTIFACT_URL` to a neard 2.7.0 (or later) tarball before running `pnpm install`, or run `pnpm rebuild near-sandbox` with that env var set.

### Run

```sh
pnpm --filter @shielded-near/demo demo
```

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
- `pnpm -r test` -- core 55, sdk 53, auditor 7, relayer 7 = 122 tests
- `npm test` (in `tools/superpowers-validate/`) -- 16 tests

Total: **240 passing tests across four layers, with 3 intentionally ignored diagnostics/round-trips.** The two near-workspaces sandbox tests now deploy to and pass against the bundled neard sandbox; CI skips the sandbox portion via `SKIP_NEAR_INTEGRATION=1`. CI runs contract tests, deploy-safety checks, circuit tests, TypeScript tests, and spec validation on push (`.github/workflows/ci.yml`); the full production-readiness gate must still pass before any deployment.

## Trusted-setup ceremony

Before mainnet deployment, the proving/verifying keys must come from a real
multi-party computation (MPC) ceremony — the DEV keys generated by
`circom/scripts/dev-setup.sh` are **not** safe for production.

The ceremony tooling and step-by-step runbook live in `ceremony/`:

- **[`ceremony/RUNBOOK.md`](ceremony/RUNBOOK.md)** — how to run the real ceremony
  (Phase 1 Powers of Tau import, per-circuit Phase 2 MPC, beacon, finalize,
  verification, and handoff to deployment).
- **Dev dry-run** (tests the pipeline; keys are NON-PRODUCTION):

  ```sh
  bash ceremony/scripts/run-dev-ceremony.sh
  ```

- **Fingerprint guard** — `scripts/check-production-readiness.sh` hard-rejects
  DEV key fingerprints when `DEPLOY_VK_DIR` is set, so DEV keys can never
  silently slip into a production deployment:

  ```sh
  DEPLOY_VK_DIR="$(pwd)/ceremony/out" bash scripts/check-production-readiness.sh
  ```

The fast dev loop and all tests continue to use the DEV keys from
`circom/scripts/dev-setup.sh`; only the production deploy path requires the
real ceremony keys.

## Production Gate

The production-readiness script verifies:

- the production verifier feature compiles for `wasm32-unknown-unknown`
- default WASM builds with mock verifier semantics are rejected
- the optimised WASM artifact exists and fits under NEAR's deploy transaction limit
- the optimised WASM uses only NEAR-deployable wasm features (no bulk-memory; lowered to MVP)
- deploy VKs do not match the DEV key fingerprints baked into the script (guard fires once `DEPLOY_VK_DIR` is set in Sub-project C)

**Remaining path-to-mainnet gates** (see spec for details):

1. Independent circuit soundness review
2. Trusted-setup ceremony for production proving/verifying keys
3. External security audit of contract + SDK + prover

Until those gates pass, use only local sandbox deployments and **never deposit real funds**.
