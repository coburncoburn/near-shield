# NEAR Shielded USDC Pool

Privacy-preserving USDC pool on NEAR with per-user auditor view keys.

See [`docs/superpowers/specs/2026-05-24-near-shielded-pool-design.md`](docs/superpowers/specs/2026-05-24-near-shielded-pool-design.md) for the design and [`docs/superpowers/plans/2026-05-24-near-shielded-pool.md`](docs/superpowers/plans/2026-05-24-near-shielded-pool.md) for the implementation plan.

## Status: PROTOTYPE -- NOT SAFE TO DEPLOY WITH FUNDS

Most safety preconditions are in place. **Two cryptographic items remain before deployment is responsible**:

1. **Real on-chain verifier.** Host-side tests use `MockVerifier`. `--features bb-verifier` selects a fail-closed `BbVerifier` that rejects every proof until Honk verification is ported to Rust. WASM builds with `unit-testing` are rejected at compile time so mock semantics cannot leak into production.

2. **WASM size below NEAR's 1.5 MiB per-tx deploy limit.** The optimised contract is currently ~1.7 MiB. The dominant cost is `ark-bn254` + `light-poseidon`. Slimming requires a custom BN254 scalar-field crate.

What **is** in place:

- Cross-layer hash alignment (Rust + TS + Noir all use BN254 Poseidon with Circom params; vectors locked in `sdk/test-vectors/poseidon.json` and `view_ct_hash.json`)
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

- `cargo test -p shielded-pool --lib` -- 56 tests
- `cargo test -p shielded-pool --tests` -- 9 fuzz/property + 1 near-workspaces (skips deploy until WASM <1.5 MiB)
- `nargo test --workspace` (in `circuits/`) -- 22 tests
- `pnpm -r test` -- core 39, sdk 18, auditor 7, relayer 6 = 70 tests
- `tools/superpowers-validate` -- 16 tests

Total: **174 tests across four layers, all green.** CI runs them all on push (`.github/workflows/ci.yml`).
