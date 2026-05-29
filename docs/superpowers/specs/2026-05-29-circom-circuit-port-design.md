# Circom circuit port + equivalence validation — design

**Date:** 2026-05-29
**Status:** design approved; spec-review loop + plan still pending (paused before resume)
**Sub-project:** A of 3 (see "Initiative context" below)

## Why this exists

The mainnet gate that matters most is the **trusted-setup ceremony** (Gate 4 of the
path-to-production in `docs/superpowers/specs/2026-05-26-real-groth16-prover-e2e.md`).
Today the Groth16 proving/verifying keys come from a hardcoded seed
(`tools/prover/src/main.rs`, `StdRng::seed_from_u64(0x5151_3ded)`), so the toxic waste is
publicly derivable and anyone can forge proofs. A real ceremony needs a multi-party
Powers-of-Tau + per-circuit Phase-2 MPC.

A Groth16 Phase-2 ceremony binds to a **specific R1CS/QAP**, so the ceremony tooling
decision also decides the proving stack. We evaluated three paths:

1. **arkworks-native Phase-2 MPC** over the existing `ark-groth16` circuits — keeps the
   circuits unchanged but relies on thin/research-grade arkworks MPC tooling that becomes
   new audit surface.
2. **Full replace: port circuits to Circom + use the snarkjs ceremony** — the most
   battle-tested BN254 Groth16 ceremony tooling (Perpetual Powers of Tau + `snarkjs zkey`
   contribute/verify/beacon, the iden3/hermez lineage), zero bespoke-MPC audit surface.
3. **Hybrid bridge** (arkworks R1CS ↔ snarkjs zkey) — unaudited format glue on the
   trust-critical path; rejected as fragile.

**Decision: Path 2, full replace.** A *full* replace (delete the arkworks circuits +
prover, make Circom/snarkjs the sole proving path) dissolves the "two sources of truth"
objection that would otherwise apply. The deciding technical fact: the codebase is
**already standardized on the circomlib Poseidon parameterization** — the arkworks gadget
uses `light_poseidon::parameters::bn254_x5` and its own comment
(`tools/prover/src/circuits/gadgets.rs:21`) says it matches "light-poseidon's circom
variant," and the contract (`contract/src/poseidon.rs`) + SDK are pinned to the same
shared test vectors. So circomlib's `Poseidon` produces byte-identical hashes to the
deployed contract and SDK, and the Circom port stays **contained to the proving layer** —
no cascade into on-chain hashing or the SDK commitment/nullifier/Merkle logic. Because the
soundness review (Gate 3) has not run yet, redirecting it at the Circom circuits instead of
the arkworks ones is not a sunk-cost loss.

NEAR compatibility is a non-issue: `contract/src/groth16.rs` is a generic standard Groth16
verifier over BN254 `alt_bn128` host functions. A proof is three curve points and a VK is a
handful of points; the verifier does not care whether arkworks or Circom/snarkjs produced
them. The earlier Noir→Honk→Groth16 pivot was about the *verifier's* WASM size, not the
proving system — Circom rides the same on-chain verifier. Integration needs only (a) a
VK/proof serialization adapter (snarkjs decimal JSON → EIP-196/197 little-endian bytes) and
(b) matching the standard pairing convention (the contract already negates A itself, which
matches snarkjs's un-negated `pi_a`). Those land in Sub-project B.

## Initiative context — three sequential sub-projects

| | Sub-project | Produces | Depends on |
|---|---|---|---|
| **A (this spec)** | Circom circuit port + equivalence validation | 3 Circom circuits + DEV keys, proven equivalent to the arkworks circuits and matching the locked vectors | nothing |
| **B** | Integration swap | snarkjs prove path in SDK/relayer/demo, VK→contract serialization adapter, dev-key fingerprint guard, e2e green | A |
| **C** | The ceremony | Perpetual-PoT import + Phase-2 contribution tooling + beacon + transcript + participant runbook → production keys | A (slots into B's pin) |

They are strictly ordered: the ceremony (C) is meaningless until A exists, because Phase-2
binds to a final R1CS. A is therefore first, and it is where all fund-loss risk
concentrates (faithfully reproducing the constraints). B and C are committed follow-on
specs.

## Architecture & layout

New top-level `circom/` tree, separate from `circuits/` (which keeps the Noir reference, to
avoid confusion):

```
circom/
  circuits/
    deposit.circom  transfer.circom  withdraw.circom
    lib/  commit.circom  merkle.circom  range.circom   # shared templates
  scripts/
    build.sh        # circom compile -> .r1cs + _js witness calculator
    dev-setup.sh    # tiny local ptau + groth16 setup -> DEV zkey/vk (tests only)
  test/
    vectors.test.ts      # Poseidon parity gate + commit/nullifier/merkle parity
    equivalence.test.ts  # honest + every negative case, mirrored from arkworks
  build/                 # gitignored artifacts
```

The arkworks `tools/prover` **stays in the tree throughout A** as the equivalence oracle —
compute commitments/nullifiers/roots both ways and assert equality. It is deleted only in
Sub-project B, once the snarkjs prove path is green. Witness generation uses circom's wasm
calculator; proving/verifying via snarkjs.

## Circuits (public inputs declared in **contract order**)

Public-input order must match the contract verifier exactly so the pinned VK's `gamma_abc`
lines up; declaring Circom public signals in contract order achieves this, and B's
contract-roundtrip fully verifies it.

### `deposit.circom`
- Public: `commitment, amount, auditor_pubkey, view_ct_hash`
- Private: `owner_pubkey, blinding, view_ct_hash_witness`
- Constraints: `Poseidon4(amount, owner, auditor, blinding) === commitment`;
  `view_ct_hash === view_ct_hash_witness`.
- **Faithful-port note:** deposit has **no** amount range check in the source
  (`tools/prover/src/circuits/deposit.rs`). Ported as-is — not redesigned — and flagged for
  the Gate-3 soundness reviewer rather than silently adding a constraint.

### `transfer.circom` (largest)
- Public (9): `merkle_root, nullifier0, nullifier1, commitment_out0, commitment_out1,
  auditor_pubkey, recipient_auditor_pubkey, view_ct_hash_sender, view_ct_hash_recipient`
- Reproduces, from `tools/prover/src/circuits/transfer.rs`:
  - two input commitments `Poseidon4(amount, owner, auditor, blinding)`;
  - `owner = Poseidon2(sk, 0)` equals both input owners;
  - two nullifiers `Poseidon2(sk, Poseidon2(commitment, leaf_index))`;
  - `n0 ≠ n1` (IsZero-on-difference trick);
  - both leaf indices bound to exactly 20 bits (`Num2Bits(20)`);
  - two depth-20 Merkle inclusions;
  - two output commitments under `recipient_auditor_pubkey`;
  - **128-bit range checks on all four amounts** (the mint-exploit guard);
  - `in0 + in1 === out0 + out1`;
  - two view_ct_hash bindings.

### `withdraw.circom`
- Public (8): `merkle_root, nullifier, recipient, amount, relayer, relayer_fee,
  auditor_pubkey, view_ct_hash`
- Reproduces, from `tools/prover/src/circuits/withdraw.rs`:
  - commitment; `owner = Poseidon2(sk, 0)` equals note owner; nullifier;
  - `note_amount === amount`; `note_auditor === auditor`;
  - **`amount ≥ relayer_fee`** via 64-bit decomposition of `a`, `b`, and `a − b`;
  - view_ct_hash binding; leaf-index 20-bit bound; depth-20 Merkle inclusion.
- `recipient`/`relayer`/`relayer_fee` are bound *only* by being public inputs (the arkworks
  code uses `enforce_equal(x, x)` no-ops). In Circom bind them with explicit trivial
  constraints so the compiler keeps them in the public-signal set.

## Validation & testing (where the safety lives)

1. **Poseidon parity kill-gate (Task 1, blocks all other work):** circomlib
   `Poseidon([1,2])` must equal
   `0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a` and
   `Poseidon([1,2,3,4])` must equal
   `0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465`
   (the locked vectors from `tools/prover/src/circuits/gadgets.rs`). If this fails,
   **stop** — the "no cascade into contract/SDK" premise is false and the whole approach is
   re-evaluated before porting further.
2. **Parity corpus:** for randomized inputs, assert circom-computed
   `commit_note`/`owner`/`nullifier`/Merkle-root equal the arkworks-computed values. Proves
   on-chain commitments/nullifiers/roots still agree with the deployed contract.
3. **Equivalence / negative corpus:** mirror *every* arkworks test — honest = satisfiable;
   each attack = rejected:
   - deposit: honest sat; wrong amount unsat.
   - transfer: honest sat; value violation unsat; wraparound mint unsat; forged Merkle
     unsat; same-input-note unsat; leaf-index-above-depth unsat.
   - withdraw: honest sat; wrong spending key unsat; forged Merkle unsat; fee>amount unsat;
     leaf-index-above-depth unsat.
   In snarkjs, "unsatisfiable" = witness generation / constraint check rejects the crafted
   witness.
4. **snarkjs prove→verify roundtrip** per circuit with the DEV keys (full
   contract-verifier roundtrip is Sub-project B).

## Toolchain & versions

Pinned: **circom 2.x** (Rust compiler), **circomlib** (`Poseidon`, `Num2Bits`, comparators,
mux), **snarkjs**, and a pinned Node version. DEV keys come from a small *local*
`powersoftau` sized to the measured constraint count (transfer is largest — estimated
~12–15k constraints, so a 2^15–2^16 local ptau; exact power pinned after the first compile).
DEV keys are loudly labeled and never shippable — the fingerprint guard enforcing that is
Sub-project B; real keys are Sub-project C.

## Risks tracked

- **circomlib Poseidon mismatch** → gated in Task 1 (kill-gate).
- **public-input ordering mismatch** → mitigated by declaring in contract order; fully
  verified by the contract-roundtrip in Sub-project B.
- **constraint count → ptau power** → measured post-compile, then pinned.
- **deposit's missing amount range-check** → preserved as-is (faithful port), flagged for
  Gate-3 soundness review, not changed here.

## Out of scope for A

- Prover/SDK/relayer/demo swap, VK serialization adapter, dev-key fingerprint guard
  (Sub-project B).
- The real multi-party ceremony, Perpetual-PoT import, Phase-2 tooling, beacon, transcript,
  participant runbook (Sub-project C).
- Any change to `contract/`, the Noir reference circuits, or the SDK hashing.
