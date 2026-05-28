# Real-client CLI demo: end-to-end shielded-pool flow against a sandbox

Date: 2026-05-27
Status: Design — pending implementation plan

## Problem

The shielded pool works end to end in two places today: the Rust integration test
`contract/tests/e2e_real_proofs.rs` (drives deposit → withdraw → transfer with real
Groth16 proofs against a near-workspaces sandbox) and the TypeScript `Wallet`
(`sdk/packages/sdk/src/wallet.ts`, builds proved transactions). But there is **no way to
exercise the system the way a real client would** — using the TypeScript SDK against a
live chain, end to end, observably.

Two concrete gaps make this impossible right now:

1. **No NEAR connection layer.** `Wallet` deliberately stops at *building* transactions.
   It does not submit them, does not read contract events to discover its own notes, and
   does not fetch on-chain state. A caller must own all of that, and no such caller
   exists in the workspace. There are no NEAR JS dependencies (`near-api-js`,
   `near-workspaces`) anywhere in `sdk/`.

2. **No Merkle inclusion paths from the contract.** The contract exposes `merkle_root()`
   as a view method (`contract/src/lib.rs`) but **no inclusion-path view**. The
   `buildTransferProved` / `buildWithdrawProved` builders require the root *and* a 20-deep
   sibling path per input note. The Rust e2e sidesteps this with hardcoded empty-tree
   helpers (`empty_path_for_leaf0`, `tree_with_two_leaves`), which only work for a fixed
   leaf layout — not a general client.

## Goal

A runnable, narrated CLI demo that drives a **full-fidelity** shielded-pool flow using the
real TypeScript SDK against a local NEAR sandbox:

- Two distinct wallets (sender + recipient) for a genuine transfer.
- Real Groth16 proofs via the `shielded-prover` binary (no stubs).
- Client-side Merkle tree reconstruction from chain events (no contract path view).
- Withdrawal routed through the real relayer service, with a relayer account paying gas
  and collecting its fee.

The demo's hard parts (chain I/O, event scanning, Merkle reconstruction) are extracted
into a **reusable connection-layer package** rather than buried in a one-off script, so a
future frontend or testnet deployment can build on the same code.

Non-goals: testnet/mainnet deployment, an HTTP relayer server, persistence across runs,
and any change to the proving statements or contract.

## Approach

A new workspace package `@shielded-near/client` (`sdk/packages/client`) provides the
connection layer the SDK lacks. A thin narrated script (`demo/run-demo.ts`) stands up a
sandbox via `near-workspaces` and drives two `Wallet`s + `RelayerService` through the full
flow on top of the client.

Clean boundary: `Wallet` owns keys, crypto, and transaction *building*; `PoolClient` owns
chain I/O. Neither reaches into the other's responsibility.

### Layout

```
sdk/packages/client/
  src/
    pool-client.ts     # PoolClient: submit calls + read events + merkle_root view
    merkle-tree.ts     # client-side append-only tree -> {root, path}
    near-submitter.ts  # NearTxSubmitter impl (near-api-js) for the relayer
    index.ts
  package.json         # @shielded-near/client; deps: near-api-js, core, sdk
  tsconfig.json
demo/
  run-demo.ts          # narrated two-wallet deposit->transfer->withdraw
  package.json         # deps: near-workspaces, client, sdk, core, relayer
```

New dependencies: `near-api-js` (in `client`) and `near-workspaces` (in `demo` only, for
sandbox lifecycle).

### Component: `PoolClient` (`pool-client.ts`)

Wraps a `near-api-js` `Account` plus the pool and USDC account ids. Holds no keys and
builds no proofs.

- **Submit.**
  - `deposit(builtTx)` → `ft_transfer_call` on the USDC contract (the production deposit
    path is `ft_on_transfer` in `contract/src/ft.rs`), with the pool as receiver and the
    deposit args in `msg`.
  - `transfer(builtTx)` / `withdraw(builtTx)` → direct function calls on the pool,
    converting the `BuiltTx` to call args via the SDK's `envelopes.ts`
    (`toTransferCall`, `toWithdrawCall`).
- **Read.** `fetchNoteCiphertexts()` parses `EmitDeposit` / `EmitTransfer` logs (see
  `contract/src/events.rs`) into `NoteCiphertext[]` (`{ leafIndex, sealed }`, the shape
  `scanNotes` consumes in `sdk/packages/core/src/scanner.ts`). The on-chain `note_ct` /
  `view_ct` fields are strings; the client decodes them back to bytes and pairs each with
  its assigned `leaf_index`.
- **State.** `merkleRoot()` issues the `merkle_root` view call. Tracked leaves (commitments
  observed in deposit/transfer events, in leaf-index order) are exposed to the tree module.

### Component: Merkle reconstruction (`merkle-tree.ts`)

The contract has no inclusion-path view, so the client maintains its own append-only
Merkle tree:

- Depth 20, BN254 Poseidon with Circom parameters via `@shielded-near/core`'s `poseidon2`
  (the same canonical hash the contract, circuits, and SDK share).
- Zero-subtree siblings precomputed: `zeros[0] = 0`, `zeros[k] = poseidon2(zeros[k-1],
  zeros[k-1])`.
- `append(commitment)` inserts at the next index; `pathFor(leafIndex)` returns the 20
  sibling hashes; `root()` returns the current root.
- **Runtime correctness check:** after appending the leaves observed up to a given point,
  the reconstructed `root()` is asserted equal to the contract's `merkle_root()` view —
  the same cross-check the Rust e2e makes (`off-chain leaf0 root must match contract tree
  root`). Reconstruction correctness is verified, not assumed.

### Component: relayer submitter (`near-submitter.ts`)

Implements the relayer's `NearTxSubmitter` interface (`submitWithdraw`, from
`sdk/packages/relayer/src/service.ts`) backed by `near-api-js`, signing with the relayer's
sandbox account. This lets `RelayerService.submit()` route a real withdraw on-chain: the
relayer account pays gas and receives the fee. The relayer is consumed **in-process** via
`RelayerService` — no HTTP server is stood up (the README's "HTTP service" framing is a
future thin wrapper, out of scope here).

### Demo flow (`run-demo.ts`)

Prerequisites are checked up front with actionable error messages, mirroring
`e2e_real_proofs.rs`:
- the `groth16-verifier` optimised WASM artifact (`shielded_pool.opt.wasm`) exists,
- the `shielded-prover` binary is built,
- proving/verifying keys are generated (`shielded-prover setup`).

Then `near-workspaces` spins a sandbox, deploys the `.opt.wasm` pool build and a mock
NEP-141 USDC contract, initialises the pool with the verifying keys, and creates accounts
for Alice, Bob, and the relayer. Narrated, step by step:

1. **Alice deposits 100 USDC.** `buildDepositProved` (real deposit proof) → `PoolClient.deposit`
   → scan events → Alice balance 100.
2. **Alice transfers 60 to Bob.** `PoolClient` reconstructs the tree and supplies root +
   paths; `buildTransferProved` (real transfer proof) → `PoolClient.transfer`. Both wallets
   rescan: Alice 40 (change note), Bob 60.
3. **Bob withdraws 60.** `buildWithdrawProved` (real withdraw proof, path from the
   reconstructed tree) → `RelayerService.submit()` via the near-api-js `NearTxSubmitter`.
   Assert Bob's on-chain USDC balance increased by `60 - relayerFee`.

Every `prove` call uses the real `SubprocessProver` → `shielded-prover` binary. The console
prints commitments, nullifiers, roots, proof sizes, and balances at each step.

## Testing

- `merkle-tree.ts`: unit tests asserting `root()` matches the known empty-tree and
  two-leaf vectors used by the Rust e2e, and that `pathFor` verifies against the root.
- `PoolClient`: unit test for `EmitDeposit` / `EmitTransfer` log parsing against captured
  log fixtures (no chain needed).
- `run-demo.ts`: the full-flow integration artifact. Gated and skippable like
  `e2e_real_proofs.rs` (needs the built WASM + prover binary + keys); fails fast with
  guidance if prerequisites are missing.
- Run via a root `pnpm demo` script.

## Path to production

This is a demo against a local sandbox only. It does not change the mainnet gates already
recorded in `2026-05-26-real-groth16-prover-e2e.md` (circuit soundness review, a real
trusted-setup ceremony, external audit). It does, however, produce the
client-integration layer (`@shielded-near/client`) that a testnet deployment or frontend
would build on, and validates Merkle reconstruction against live contract state.
