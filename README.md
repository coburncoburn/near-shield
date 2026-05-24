# NEAR Shielded USDC Pool

Privacy-preserving USDC pool on NEAR with per-user auditor view keys.

See [`docs/superpowers/specs/2026-05-24-near-shielded-pool-design.md`](docs/superpowers/specs/2026-05-24-near-shielded-pool-design.md) for the design and [`docs/superpowers/plans/2026-05-24-near-shielded-pool.md`](docs/superpowers/plans/2026-05-24-near-shielded-pool.md) for the implementation plan.

## Status: PROTOTYPE -- NOT SAFE TO DEPLOY WITH FUNDS

Two cryptographic preconditions are not yet met. Until both are fixed, deployment to any chain handling real value would result in **trivially forgeable proofs** and **circuits that prove the wrong commitments**:

1. **Real verifier not integrated.** The contract uses `MockVerifier`, which accepts any non-empty proof. A compile-time guard in `contract/src/verifier.rs` rejects production WASM builds without the `bb-verifier` feature flag (which itself still needs to wire in Barretenberg's WASM verifier).
2. **Hash function mismatch across layers.** Rust contract and TypeScript SDK use Poseidon2 (`light-poseidon` circom params). Noir circuits currently use Pedersen (see `circuits/shared/src/lib.nr`). The three layers must converge on the same Poseidon2 implementation before commitments and nullifiers agree end-to-end.

## Layout

- `circuits/` -- Noir zk circuits (deposit, transfer, withdraw) and shared primitives
- `contract/` -- NEAR Rust contract: Merkle tree, nullifier set, FT (NEP-141) cross-contract calls
- `sdk/packages/core` -- Field, Poseidon (cross-language vectors), Note model, hybrid encryption, note scanner
- `sdk/packages/sdk` -- High-level `Wallet` API: deposit, transfer, withdraw transaction building
- `sdk/packages/auditor` -- Indexer that decrypts disclosure ciphertexts addressed to a configured auditor key
- `sdk/packages/relayer` -- Stateless HTTP service that pays gas to submit users' withdrawal proofs

## Test status

- `cargo test -p shielded-pool --lib` -- 40 tests (state, methods, FT integration, mock verifier dispatch)
- `nargo test --workspace` (in `circuits/`) -- 18 tests (commitment, nullifier, Merkle proof, circuit constraints)
- `pnpm -r test` -- core 29, sdk 11, auditor 7, relayer 6 = 53 tests
- `tools/superpowers-validate` -- 16 tests against the installed superpowers framework

CI runs all of the above on every push (`.github/workflows/ci.yml`).
