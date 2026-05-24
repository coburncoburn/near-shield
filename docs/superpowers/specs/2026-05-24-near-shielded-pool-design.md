# NEAR Shielded USDC Pool — Design (v0)

**Status:** Draft pending user review
**Date:** 2026-05-24
**Author:** brainstormed with Claude

## Summary

A privacy-preserving USDC pool on NEAR. Users deposit USDC, transfer it privately within the pool, and withdraw to any NEAR account — without revealing amounts or graph linkage on-chain. Compliance is supported via **per-user auditor pubkeys**: every action emits a ciphertext that the user's chosen auditor (and only that auditor) can decrypt to see cleartext sender/recipient/amount.

This is the v0 scope. v1 will add native BTC custody via NEAR Chain Signatures, turning this into a private cross-chain settlement layer. v2+ is open.

## Goals

- Ship a credibly private USDC pool on NEAR with sound zk circuits and external audit
- Establish the protocol's compliance posture (auditor view keys) as a first-class design property, not an afterthought
- Produce a reusable foundation for the v1 Chain Signatures extension
- Teach the author production zk skills (Noir + onchain verification) in the process
- Be portfolio-legible: a recruiter or grant reviewer should understand the contribution in one paragraph

## Non-goals (v0)

- Chain Signatures / cross-chain (v1)
- Lending, swapping, or any DeFi action beyond deposit/transfer/withdraw (v2+)
- Multi-asset support (USDC only; adding more is contract config in v1)
- Protocol treasury fees (gas + relayer fee only)
- Mobile SDK
- Hardware wallet integration for shielded keys
- Threshold or multi-party auditor keys
- On-chain sanctioned-address screening
- Hosted web UI (we ship SDK + CLI; a UI is a separate project)
- Mainnet launch before external audit

## Architecture

Three components, each with a single clear purpose.

### A. Noir circuits

Three circuits, each producing a proof verifiable on NEAR:

- `deposit.nr` — proves a new note commitment is well-formed from the declared deposit amount
- `transfer.nr` (2-in, 2-out) — proves two existing notes are being spent and two new notes are being created with value conserved
- `withdraw.nr` — proves a single note is being spent and its full amount paid to a public recipient, minus a public relayer fee

Each circuit additionally binds an **auditor disclosure ciphertext** to the witness — guaranteeing the auditor reads honest values.

### B. NEAR Rust contract (`shielded-pool`)

Single Rust contract holding all state:

- USDC vault (FT balance)
- Incremental Merkle tree of note commitments (depth 20 ≈ 1M notes)
- Rolling window of last 30 Merkle roots (handles concurrent-tx race)
- Spent-nullifier set
- Three verifier keys (deposit, transfer, withdraw)
- Owner (initially deployer; can transfer to DAO/multisig later)

### C. Client SDK + auxiliary services

TypeScript SDK packages (monorepo for v0):

- `@shielded-near/core` — proving, scanning, note management
- `@shielded-near/sdk` — high-level `Wallet` API
- `@shielded-near/auditor` — auditor decryption + indexing
- `@shielded-near/relayer` — reference relayer server
- `@shielded-near/cli` — interactive CLI

Plus a **reference auditor indexer** (tracked as a load-bearing v0 deliverable): polls NEAR logs, attempts decryption with a configured private key, writes successful decryptions to SQLite. Ships with a CLI for forensic queries. This makes the compliance story usable, not theoretical.

## Data model

### Note

```
Note {
  amount:         u64           // USDC, 6 decimals
  owner_pubkey:   Field         // derived from spending key
  auditor_pubkey: Field         // the user's chosen auditor for this note
  blinding:       Field         // 256-bit random
}

commitment = poseidon(amount, owner_pubkey, auditor_pubkey, blinding)
nullifier  = poseidon(spending_key, commitment, leaf_index)
```

`auditor_pubkey` lives **inside** the commitment so a transfer is forced to use the same auditor as its input notes. Users cannot "launder" to a friendlier auditor mid-pool.

### Keys

Per user, derived from a single seed (NEAR-wallet-sign-in by default):

- **Spending key (sk)** — required to spend; never leaves client
- **Viewing key (vk)** — decrypts incoming notes; shareable with the user's chosen auditor or used by their own SDK for scanning

### Merkle tree

- Depth 20, Poseidon hash, incremental insertion
- Rolling window of last 30 roots stored on-chain; proofs may target any root in the window

### Nullifier set

- `LookupSet<Field>`, append-only
- Spending adds the nullifier; replay attempts deterministically rejected

### Auditor disclosure ciphertext (`view_ct`)

- Encrypted to the **auditor pubkey** chosen at deposit, using hybrid X25519 + ChaCha20-Poly1305
- Ephemeral X25519 sender key encoded in the ciphertext
- Plaintext: `{ action, sender_owner_pubkey, recipient_owner_pubkey, amount(s), memo, timestamp }`
- **Circuit-enforced honesty:** the encryption is checked inside the proof, binding the ciphertext to the same witness values used throughout the circuit
- For transfers, **two** view_cts are emitted — one to the sender's auditor and one to the recipient's auditor

### Note ciphertexts (for recipient scanning)

Same scheme, encrypted to recipient's viewing key. Emitted in deposit/transfer logs. Recipients trial-decrypt to discover their notes.

## Circuits (detail)

### `deposit.nr`

**Public:** `commitment`, `amount`, `auditor_pubkey`, `view_ct`
**Private:** `owner_pubkey`, `blinding`, `view_ct_ephemeral_sk`
**Constraints:**
- `commitment == poseidon(amount, owner_pubkey, auditor_pubkey, blinding)`
- `view_ct` correctly encrypts disclosure plaintext under `auditor_pubkey` with the ephemeral key

### `transfer.nr` (2-in, 2-out)

**Public:** `merkle_root`, `nullifiers[2]`, `commitments[2]`, `auditor_pubkey`, `recipient_auditor_pubkey`, `view_ct_sender`, `view_ct_recipient`
**Private:** per input — full `Note`, `merkle_path`, `leaf_index`, `sk`; per output — full `Note`; ephemeral keys for both ciphertexts
**Constraints:**
- Both input commitments verify under `merkle_root` along their paths
- Each nullifier == `poseidon(sk, commitment, leaf_index)`
- `sk` derives each input's `owner_pubkey`
- Output commitments correctly formed from their witnesses
- Each input note's embedded auditor matches the public `auditor_pubkey` (cross-auditor laundering prevented on the sender side)
- Each output note's embedded auditor equals the public `recipient_auditor_pubkey` (cross-auditor sends are explicit and visible to both auditors)
- **Value conservation:** `sum(input.amount) == sum(output.amount)`
- All amounts in `[0, 2^64)`
- Both view_cts correctly encrypted to their respective auditor pubkeys

### `withdraw.nr`

**Public:** `merkle_root`, `nullifier`, `recipient`, `amount`, `relayer`, `relayer_fee`, `auditor_pubkey`, `view_ct`
**Private:** input `Note`, `merkle_path`, `leaf_index`, `sk`, ephemeral key
**Constraints:**
- Input commitment verifies under `merkle_root`
- Nullifier correctly formed
- `note.amount == amount` (whole-note withdraw in v0; v1 can add change output)
- Input note's embedded auditor matches public `auditor_pubkey`
- View_ct correctly encrypted

Binding `relayer` and `relayer_fee` as public inputs is what makes relayers tamper-proof.

### Performance budget

- Browser/WASM proving: ≤ 15s on a baseline laptop (transfer is the worst case)
- NEAR verification gas: ≤ 100 Tgas per action (well within block budget of 300 Tgas)
- Circuit sizes: deposit ~5k gates, transfer ~30–50k gates, withdraw ~25k gates

## Contract surface

```rust
struct Contract {
  usdc_token: AccountId,
  merkle_tree: IncrementalTree,
  recent_roots: Deque<Field>,
  nullifiers: LookupSet<Field>,
  verifier_keys: { dep: Vec<u8>, xfer: Vec<u8>, wd: Vec<u8> },
  owner: AccountId,
}
```

### Public methods

**`deposit(proof, commitment, amount, auditor_pubkey, view_ct)`**
Caller is the depositor. Pulls `amount` USDC via `ft_transfer_call`, verifies proof, inserts commitment, emits `(commitment, view_ct, note_ct)`.

**`transfer(proof, merkle_root, nullifiers[2], commitments[2], auditor_pubkey, recipient_auditor_pubkey, view_cts[2], note_cts[2])`**
Caller is anyone (user or relayer). Asserts root in window, nullifiers unspent, verifies proof, inserts commitments, marks nullifiers spent, emits logs.

**`withdraw(proof, merkle_root, nullifier, recipient, amount, auditor_pubkey, view_ct, relayer, relayer_fee)`**
Typically called by a relayer. Same checks as transfer. Pays `amount - relayer_fee` to recipient and `relayer_fee` to relayer via `ft_transfer`.

### View methods

- `merkle_root()`
- `recent_roots()`
- `is_nullifier_spent(n)`
- `get_note_logs(from_block, to_block)`

### Storage and gas

- ~32 bytes per leaf and per nullifier; NEAR storage staking absorbed via per-tx deposit (standard pattern)
- Verification gas dominated by zk verifier; benchmarked during plan phase

### Upgradeability

- Owner-controlled upgrade in v0 (deployer key)
- Plan: transfer owner to a community-multisig or DAO once mainnet-stable; renounce later if/when the protocol is considered finalized
- Documented as an operational risk in the README

## User flow

### End-user (via SDK)

1. **Key setup:** NEAR wallet sign-in derives spending + viewing keys deterministically. Cached locally, never sent to the protocol.
2. **Scan:** SDK trial-decrypts every note ciphertext since last scan against viewing key. Builds local "unspent notes" wallet.
3. **Deposit:** user picks amount and auditor pubkey → SDK builds proof (~3–5s) → submits NEAR tx with `ft_transfer_call`.
4. **Transfer:** user picks recipient `owner_pubkey` and amount → SDK picks input notes greedily, builds proof (~5–15s) → submits directly.
5. **Withdraw:** user picks NEAR recipient, amount, max acceptable relayer fee → SDK queries relayers for quotes → builds proof binding the chosen relayer → POSTs to relayer → relayer submits.

### Relayer (stateless service)

- `GET /quote` returns current fee + relayer's NEAR account
- `POST /submit` accepts `(proof, public_inputs)`, verifies they match the quote, submits the NEAR tx
- ~50 LoC, no custody, no trust gradient — proof binds `relayer` and `relayer_fee` so tampering is impossible
- Permissionless: anyone can run one. SDK ships with a default list maintained in repo; no on-chain registry.

### Auditor

1. Generate X25519 keypair offline; publish pubkey out-of-band (website, ENS, .well-known)
2. Run the reference auditor indexer with the private key configured
3. Indexer polls NEAR logs, attempts decryption of every emitted `view_ct`, writes successes to SQLite
4. Query via CLI or SDK: `getTransactionsForUser(owner_pubkey)`, `getAllTransactions()`, `verifyDisclosure(view_ct, expected_values)`

The mapping from `owner_pubkey` to real-world identity is the auditor's responsibility, established out-of-band at user onboarding (FATF Travel Rule pattern).

## Error handling

| Failure | Surface | Response |
|---|---|---|
| Invalid proof | Contract `verify` | Revert; refund attached USDC; no state mutation |
| Stale Merkle root | Contract pre-check | Revert; SDK retries with current root |
| Double-spend (nullifier seen) | Contract pre-check | Revert; SDK marks note spent locally and re-scans |
| Auditor mismatch on transfer | Inside circuit | Proof fails to build; caught client-side, never submitted |
| Underfunded deposit | NEAR FT callback | Revert via standard cross-contract pattern |
| Relayer drops tx | SDK timeout | Retry with next relayer; proof reusable while nullifier unspent |
| Relayer tampers with inputs | Contract verify | Proof rejected; relayer wastes their own gas, user unharmed |
| SDK scan misses notes (RPC outage) | SDK runtime | Idempotent re-scan from last confirmed block |
| Auditor private key leak | Out-of-band | Auditor rotates pubkey; historical privacy for that auditor's users is broken (documented limitation) |
| Verifier-key mismatch after upgrade | Contract init | Upgrade runbook includes verifier-key rotation procedure |

## Testing strategy

- **Circuit unit tests** (`#[test]` in Noir): every constraint has positive and negative cases; property tests over random witnesses
- **Contract unit tests** (Rust, `workspaces-rs`): every public method, every revert path; integration tests covering deposit→transfer→withdraw against a local sandbox
- **Cross-component integration tests** (TypeScript): SDK + local sandbox + reference relayer + reference auditor indexer; canonical test "Alice deposits 100, transfers 60 to Bob, Bob withdraws 60 to a fresh address, each auditor sees only their user's side"
- **Proof-soundness tests:** assert wrong witnesses cannot produce accepted proofs (negative tests at the SDK boundary)
- **Performance tests:** measure proving time and verification gas against budgets in CI
- **Pre-audit checklist:** no `unsafe`, no panics on attacker input, all public inputs explicitly typed and bounded
- **External security audit** of circuits + contract before any mainnet launch

## Out of scope for v0 (consolidated)

See the "Non-goals" section above. v1 adds Chain Signatures (BTC). v2 considers lending and/or multi-asset.

## Open questions deferred to plan phase

- Exact Noir prover toolchain version (verify barretenberg WASM verifier compatibility with NEAR)
- Concrete gas measurement of verifier on NEAR mainnet RPC
- Default relayer fee model (flat vs % of withdraw)
- Whether to ship a basic CLI auditor disclosure verifier as part of `@shielded-near/auditor` or as a separate package
