# NEAR Shielded USDC Pool

Privacy-preserving USDC pool on NEAR with per-user auditor view keys.

See [`docs/superpowers/specs/2026-05-24-near-shielded-pool-design.md`](docs/superpowers/specs/2026-05-24-near-shielded-pool-design.md) for the design and [`docs/superpowers/plans/2026-05-24-near-shielded-pool.md`](docs/superpowers/plans/2026-05-24-near-shielded-pool.md) for the implementation plan.

## Status: PROTOTYPE -- NOT SAFE TO DEPLOY WITH FUNDS

One critical cryptographic precondition is not yet met. Until it is fixed, deployment to any chain handling real value would result in **trivially forgeable proofs**:

1. **Real verifier not integrated.** Host-side tests use `MockVerifier`, which accepts any non-empty proof. WASM builds with the default `unit-testing` feature are rejected, and `--no-default-features --features bb-verifier` selects a fail-closed placeholder that rejects every proof until Barretenberg verification is wired in.
2. **Hashing is aligned.** Rust contract, TypeScript SDK, and Noir circuits now use BN254 Poseidon with Circom-compatible parameters for commitments, nullifiers, owner pubkeys, and Merkle hashing. Cross-language vectors are locked in `sdk/test-vectors/poseidon.json` and mirrored by Noir tests in `circuits/shared/src/lib.nr`.

## Layout

- `circuits/` -- Noir zk circuits (deposit, transfer, withdraw) and shared primitives
- `contract/` -- NEAR Rust contract: Merkle tree, nullifier set, FT (NEP-141) cross-contract calls
- `sdk/packages/core` -- Field, Poseidon (cross-language vectors), Note model, hybrid encryption, note scanner
- `sdk/packages/sdk` -- High-level `Wallet` API: deposit, transfer, withdraw transaction building
- `sdk/packages/auditor` -- Indexer that decrypts disclosure ciphertexts addressed to a configured auditor key
- `sdk/packages/relayer` -- Stateless HTTP service that pays gas to submit users' withdrawal proofs

## Test status

- `cargo test -p shielded-pool --lib` -- 40 tests (state, methods, FT integration, mock verifier dispatch)
- `nargo test --workspace` (in `circuits/`) -- 20 tests (commitment, nullifier, Merkle proof, circuit constraints, Poseidon vectors)
- `pnpm -r test` -- core 29, sdk 18, auditor 7, relayer 6 = 60 tests
- `tools/superpowers-validate` -- 16 tests against the installed superpowers framework

CI runs all of the above on every push (`.github/workflows/ci.yml`).
