# Real Groth16 prover for deposit / transfer / withdraw — end to end

Date: 2026-05-26
Status: Design — pending implementation plan

## Problem

The contract ships a real Groth16 verifier on NEAR's `alt_bn128_*` host functions
(`contract/src/groth16.rs`), and the optimised `groth16-verifier` WASM is ~206 KiB
(under NEAR's 1.5 MiB per-tx deploy limit). The verifier is proven correct end to end
for a reference `Mul` circuit in `contract/tests/groth16_proof.rs`.

The remaining release blocker (per `README.md` and `scripts/check-production-readiness.sh`)
is that **`tools/prover` only proves a reference `mul` circuit**. There are no real
proofs for the actual `deposit`, `transfer`, and `withdraw` statements, so the pool
cannot perform a real shielded operation against a real verifier.

The circuits are authored in Noir (`circuits/*/src/main.nr`), which compiles to
Barretenberg Honk/UltraPlonk — incompatible with the deployed Groth16 verifier. The
original spec intended an on-chain Honk verifier; that path was abandoned for WASM size
and replaced with Groth16. So the Noir circuits now serve as the **reference
specification**, and the proving statements must be re-expressed as Groth16-provable
constraints.

## Goal

Make the full shielded-pool loop work end to end against the real verifier:

SDK builds a transaction → `tools/prover` generates a real 256-byte Groth16 proof →
the deployed `groth16-verifier` contract verifies it via `alt_bn128_*` and applies the
state transition (insert leaf, spend nullifier, pay out).

Concretely:

1. Express `deposit`, `transfer`, `withdraw` as arkworks R1CS circuits that mirror the
   Noir `main()` functions constraint-for-constraint.
2. Generate per-circuit proving keys (`.pk`) and verifying keys (`.vk`, in the contract's
   EIP-196/197 byte layout) via a deterministic `setup` mode.
3. `tools/prover` loads the proving key and produces a verifying 256-byte proof for each
   circuit from a `ProveRequest`.
4. The SDK wallet assembles the witness + public inputs (in contract order), derives the
   `view_ct_hash` matching the contract's `hash_bytes_to_field`, calls the prover, and
   returns a real proof.
5. A near-workspaces integration test deploys the real `groth16-verifier` WASM, inits it
   with the generated VKs, and runs deposit → transfer → withdraw with real proofs,
   asserting the resulting on-chain state.
6. `scripts/check-production-readiness.sh` passes (real proofs for all three circuits).

## Rationale for the chosen stack (arkworks R1CS, all-Rust)

The Groth16 pipeline already exists and is tested end to end in Rust:

- 256-byte proof wire format (`A || B || C`) — `groth16.rs::Proof::from_bytes`.
- VK wire format (`alpha || beta || gamma || delta || (n+1)·gamma_abc`) —
  `groth16.rs::VerifyingKey::from_bytes`, and the encoder `build_vk_bytes` in
  `groth16_proof.rs`.
- The CLI shape (`ProveRequest` JSON on stdin → 256 bytes on stdout) — `tools/prover`
  and `sdk/.../prover.ts`.
- `ark-groth16`, `ark-r1cs-std`, `ark-relations`, `ark-bn254` are already dependencies.

Re-expressing the circuits in arkworks R1CS reuses all of that with no new toolchain and
no contract changes. circom+snarkjs would rebuild this working pipeline plus add a Node
proving toolchain; the originally-specced Honk path would re-break the WASM size budget.

## Circuit interface (fixed by the contract)

Public inputs **must** be declared in exactly the order the contract assembles them, and
the circuit's number of public inputs must equal the contract's `pi` length (so
`gamma_abc_g1.len() == n + 1`).

### deposit — 4 public inputs (`contract/src/deposit.rs`)
`[ commitment, amount, auditor_pubkey, view_ct_hash ]`

Constraints (from `circuits/deposit/src/main.nr`):
- `commit_note(amount, owner_pubkey, auditor_pubkey, blinding) == commitment`
- `view_ct_hash == view_ct_hash_witness`

### transfer — 9 public inputs (`contract/src/transfer.rs`)
`[ merkle_root, nullifier0, nullifier1, commitment_out0, commitment_out1,
   auditor_pubkey, recipient_auditor_pubkey, view_ct_hash_sender, view_ct_hash_recipient ]`

Constraints (from `circuits/transfer/src/main.nr`):
- `owner_pubkey_of(spending_key) == in0_owner_pubkey` and `== in1_owner_pubkey`
- `nullifier_of(spending_key, c_in0, in0_leaf_index) == nullifier0` (and `1`)
- Merkle inclusion of `c_in0`, `c_in1` under `merkle_root` (depth 20)
- `commit_note(out0 with recipient_auditor_pubkey) == commitment_out0` (and `1`)
- `in0_amount + in1_amount == out0_amount + out1_amount`
- `view_ct_hash_sender == witness` and `view_ct_hash_recipient == witness`
- Both input notes carry `auditor_pubkey` (the public input), enforced by using it as
  the auditor field inside `commit_note` for the input commitments.

### withdraw — 8 public inputs (`contract/src/withdraw.rs`)
`[ merkle_root, nullifier, recipient, amount, relayer, relayer_fee,
   auditor_pubkey, view_ct_hash ]`

Constraints (from `circuits/withdraw/src/main.nr`):
- `owner_pubkey_of(spending_key) == note_owner_pubkey`
- `nullifier_of(spending_key, commitment, leaf_index) == nullifier`
- `note_amount == amount`
- `note_auditor_pubkey == auditor_pubkey`
- `amount >= relayer_fee` (64-bit comparison; Noir casts both to `u64`)
- `view_ct_hash == view_ct_hash_witness`
- Merkle inclusion of `commitment` under `merkle_root` (depth 20)
- `recipient` and `relayer` are public inputs with a trivial binding (`x·1 = x`) so they
  remain committed public inputs (matching Noir's `assert(recipient == recipient)`).

### Public-input value encoding (no in-circuit re-hashing)

The contract derives some public inputs off-circuit and passes the **already-reduced
field value** as the public input:
- `amount`, `relayer_fee` → `Field::from_u128(...)`
- `view_ct_hash`, `recipient`, `relayer` → `hash_bytes_to_field(bytes)` (a Poseidon fold
  over 31-byte chunks).

The circuits therefore take these as opaque `Fr` public inputs and bind them only by
equality to a witness (`view_ct_hash`) or to themselves (`recipient`, `relayer`). No
in-circuit byte-sponge is required — matching the Noir circuits, which take
`view_ct_hash` as a public input rather than recomputing it.

## Shared hash/circuit primitives (`circuits/shared/src/lib.nr` is the reference)

- `commit_note(note) = poseidon4(amount, owner_pubkey, auditor_pubkey, blinding)`
- `nullifier_of(sk, c, i) = poseidon2(sk, poseidon2(c, i))`
- `owner_pubkey_of(sk) = poseidon2(sk, 0)`
- `verify_merkle_proof(root, leaf, index, path[DEPTH])`: ladder of `poseidon2`, where at
  level `k` the bit `(index >> k) & 1` selects whether `current` is the left (0) or right
  (1) child; assert final `== root`. `DEPTH = 20`.

Poseidon uses BN254 with Circom-compatible parameters. The locked cross-language vectors
that everything must reproduce:
- `poseidon2(1, 2) = 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a`
- `poseidon4(1,2,3,4) = 0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465`

## Architecture

New circuit library under `tools/prover/src/circuits/`, shared by the binary and the
integration tests:

- **`gadgets.rs`** — R1CS gadgets over `FpVar<Fr>` (via `ark-r1cs-std`):
  - `poseidon2(a, b)` and `poseidon4(a,b,c,d)`: full/partial round Poseidon permutation
    (x⁵ S-box, MDS mix) using the Circom parameter set. Round constants and MDS matrices
    sourced from the same `light-poseidon` Circom parameters already used to lock the
    host-side vectors.
  - `commit_note`, `nullifier`, `owner_pubkey` — thin wrappers over the above.
  - `merkle_inclusion(root, leaf, index_bits, path)` — depth-20 ladder with a
    `Boolean`-conditioned swap per level.
  - `enforce_u64_geq(a, b)` — 64-bit-bounded comparison for the withdraw fee bound.
- **`deposit.rs`, `transfer.rs`, `withdraw.rs`** — each a `ConstraintSynthesizer<Fr>`:
  - `blank()` constructor with all witness/input values `None` (used by setup, which
    needs only the constraint shape).
  - `new(public_inputs, witness)` constructor with concrete values (used by prove).
  - `generate_constraints` declares public inputs in contract order via
    `new_input_variable`, allocates witnesses via `new_witness_variable`, and enforces
    the constraints listed above.
- **`keys.rs`** — promotes `build_vk_bytes` / `build_proof_bytes` (currently duplicated in
  `groth16_proof.rs` and `tools/prover/src/main.rs`) into one place: arkworks
  `VerifyingKey`/`Proof` → contract EIP-196/197 bytes.

### Prover binary modes (`tools/prover/src/main.rs`)

- **`setup`** (`cargo run -- setup --out-dir <dir>` or a `mode` field): for each circuit,
  `Groth16::circuit_specific_setup(Circuit::blank(), &mut seeded_rng)`, write
  `<circuit>.pk` (arkworks compressed) and `<circuit>.vk` (contract bytes). Fixed seed →
  reproducible keys.
- **`prove`** (default; reads `ProveRequest` from stdin): match `circuit`, load
  `<circuit>.pk`, build `Circuit::new(...)` from `publicInputs` + `witness`, derive the
  public-input field vector, assert it matches `publicInputs`, `Groth16::prove`, write the
  256-byte proof to stdout. Retains the `mul` circuit for the existing reference test.

`ProveRequest.witness` JSON per circuit (0x-prefixed 32-byte hex for field values):
- deposit: `{ ownerPubkey, blinding, viewCtHashWitness }`
- withdraw: `{ noteAmount, noteOwnerPubkey, noteAuditorPubkey, noteBlinding,
  spendingKey, leafIndex, merklePath: [..20], viewCtHashWitness }`
- transfer: input/output note fields, `spendingKey`, both `leafIndex` + `merklePath`,
  and both view-hash witnesses.

### Key management & contract init

`setup` is run as a build/test fixture step. The generated `.vk` bytes are passed to the
contract's `new(vk_deposit, vk_transfer, vk_withdraw, ...)` at init. The integration test
runs `setup` (or loads committed key fixtures) and feeds the VKs into the deploy.

This is a **deterministic, seeded prototype setup** — not a secure trusted-setup ceremony
(the toxic waste is known to anyone who runs it). It is suitable only for local sandbox
deployments. `README.md` already restricts the repo to sandbox use until a real ceremony
exists; this spec does not change that.

### SDK wiring (`sdk/packages/sdk/src/wallet.ts`, `prover.ts`)

The `ProveRequest` shape and `SubprocessProver` already exist. Add proved (async)
builders that:
1. Compute ciphertexts (existing logic) and `view_ct_hash` via the existing
   `hashBytesToField` (already byte-for-byte matched to the contract).
2. Assemble public inputs in contract order and the witness JSON.
3. Call the injected `Prover` and place the returned 256 bytes into `BuiltTx.proof`.

The existing synchronous builders that emit `Uint8Array([0])` remain for mock-verifier
sandbox flows.

## Testing

1. **Poseidon gadget vector gate (built first; everything depends on it):** synthesize the
   `poseidon2`/`poseidon4` gadgets on `[1,2]` and `[1,2,3,4]`, extract the assigned
   witness, and assert it equals the locked hex above. If this fails, no circuit work
   proceeds.
2. **Merkle gadget:** depth-2 and depth-20 inclusion proofs verify; a wrong sibling fails
   to satisfy — mirroring the Noir `merkle_proof_*` tests.
3. **Per-circuit positive proofs:** an honest witness yields a proof that
   `groth16::verify_groth16` accepts under the generated VK and contract-ordered public
   inputs (extends `groth16_proof.rs`).
4. **Per-circuit negative cases:** mirror the Noir `should_fail` tests — wrong amount,
   forged Merkle path, value-conservation violation, auditor laundering, wrong spending
   key. Each must be **unsatisfiable** (no proof) or rejected by the verifier.
5. **End-to-end near-workspaces test (un-skipped):** build/deploy the `groth16-verifier`
   WASM, init with generated VKs, then:
   - deposit with a real proof → assert the leaf is inserted and the root advances;
   - transfer with a real proof spending the deposited note → assert nullifiers spent,
     output commitments inserted;
   - withdraw with a real proof → assert nullifier spent and payout recorded.
6. **`scripts/check-production-readiness.sh` passes** — real 256-byte proofs for all
   three circuits, prod verifier compiles for `wasm32`, default mock WASM rejected, opt
   WASM under the deploy limit.

## Out of scope / documented gaps

- **In-circuit amount range-checks for value conservation.** The Noir reference enforces
  conservation with bare `Field` equality and does not range-check amounts, so a malicious
  prover could exploit field-modular wraparound. This port **matches the Noir reference**
  (does not add range checks) to preserve parity, and documents the gap. The withdraw
  `amount >= relayer_fee` bound **is** implemented because it exists in the Noir reference.
- **Secure trusted-setup ceremony.** Setup is deterministic/seeded; production requires a
  real multi-party ceremony. Tracked separately.
- **Replacing or regenerating the Noir circuits.** They remain the reference spec; this
  work does not change them.

## Success criteria

- `cargo test -p shielded-pool` (lib + tests, including the un-skipped near-workspaces E2E)
  passes with real proofs.
- `tools/prover` produces verifying proofs for `deposit`, `transfer`, `withdraw`.
- `scripts/check-production-readiness.sh` exits 0.
- The Poseidon gadget reproduces the locked cross-language vectors.
