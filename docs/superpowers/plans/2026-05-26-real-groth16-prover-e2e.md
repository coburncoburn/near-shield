# Real Groth16 Prover End-to-End Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `tools/prover` generate real Groth16 proofs for the `deposit`, `transfer`, and `withdraw` statements, generate per-circuit verifying keys the contract loads, and prove the full loop works end to end against the deployed `alt_bn128` verifier on a local sandbox.

**Architecture:** Re-express the Noir reference circuits (`circuits/*/src/main.nr`) as arkworks R1CS circuits inside `tools/prover/src/circuits/`. Reuse the existing 256-byte proof and EIP-196/197 VK wire formats (already proven to round-trip through `contract/src/groth16.rs`). A `setup` mode emits proving keys (`.pk`) and contract-format verifying keys (`.vk`); a `prove` mode loads a `.pk` and produces a proof from a `ProveRequest`.

**Tech Stack:** Rust, arkworks (`ark-groth16`, `ark-r1cs-std`, `ark-relations`, `ark-bn254`, `ark-serialize`), `light-poseidon` (for Circom Poseidon round constants), near-workspaces (E2E test), TypeScript SDK (`SubprocessProver`).

**Reference spec:** `docs/superpowers/specs/2026-05-26-real-groth16-prover-e2e.md`

---

## Background facts the implementer must know

**Poseidon (Circom params) native permutation** — the gadget must mirror this exactly. From `light-poseidon` 0.2:
- State width `t`: `poseidon2` → `t=3`, `poseidon4` → `t=5`. Domain tag prefix is `0`, so `state = [0, inputs...]`.
- `full_rounds = 8` (so `half = 4`), `partial_rounds` from params, `alpha = 5`.
- Round loop: for rounds `0..4` apply (ARK, full S-box, MDS); for `4..4+partial` apply (ARK, partial S-box on lane 0 only, MDS); for the last `4` apply (ARK, full S-box, MDS).
- ARK at round `r`: `state[i] += ark[r*t + i]`. Full S-box: every lane `x → x^5`. Partial S-box: `state[0] → state[0]^5`. MDS: `state[i] = Σ_j state[j] * mds[i][j]`. Result is `state[0]`.
- Params source: `light_poseidon::parameters::bn254_x5::get_poseidon_parameters::<Fr>(t)` returns `PoseidonParameters { ark: Vec<Fr>, mds: Vec<Vec<Fr>>, full_rounds, partial_rounds, width, alpha }`.

**Locked cross-language vectors** (everything must reproduce these):
- `poseidon2(1,2) = 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a`
- `poseidon4(1,2,3,4) = 0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465`

**Circuit primitives** (from `circuits/shared/src/lib.nr`):
- `commit_note = poseidon4(amount, owner_pubkey, auditor_pubkey, blinding)`
- `nullifier_of(sk, c, i) = poseidon2(sk, poseidon2(c, i))`
- `owner_pubkey_of(sk) = poseidon2(sk, 0)`
- Merkle: depth-20 ladder of `poseidon2`; at level `k` the bit `(index >> k) & 1` selects whether `current` is left (0) or right (1) child.

**Public-input order (MUST match the contract; allocate `new_input` in this exact order):**
- deposit (4): `commitment, amount, auditor_pubkey, view_ct_hash`
- transfer (9): `merkle_root, nullifier0, nullifier1, commitment_out0, commitment_out1, auditor_pubkey, recipient_auditor_pubkey, view_ct_hash_sender, view_ct_hash_recipient`
- withdraw (8): `merkle_root, nullifier, recipient, amount, relayer, relayer_fee, auditor_pubkey, view_ct_hash`

**Proof / VK wire format** (already implemented in `contract/tests/groth16_proof.rs`, to be promoted to `tools/prover/src/keys.rs`):
- G1 → 64 bytes: `x_le(32) || y_le(32)`; identity → all zero.
- G2 → 128 bytes: `x.c0_le || x.c1_le || y.c0_le || y.c1_le`.
- Proof = `A_g1(64) || B_g2(128) || C_g1(64)` = 256 bytes.
- VK = `alpha_g1(64) || beta_g2(128) || gamma_g2(128) || delta_g2(128) || (n+1)·gamma_abc_g1(64 each)`.

---

## File Structure

- Create `tools/prover/src/circuits/mod.rs` — module root, re-exports.
- Create `tools/prover/src/circuits/gadgets.rs` — Poseidon/merkle/range R1CS gadgets.
- Create `tools/prover/src/circuits/deposit.rs` — `DepositCircuit`.
- Create `tools/prover/src/circuits/transfer.rs` — `TransferCircuit`.
- Create `tools/prover/src/circuits/withdraw.rs` — `WithdrawCircuit`.
- Create `tools/prover/src/keys.rs` — Fr/byte helpers, VK & proof encoders.
- Create `tools/prover/src/lib.rs` — expose `circuits`, `keys` for tests.
- Modify `tools/prover/Cargo.toml` — add `ark-r1cs-std`, `light-poseidon`; add a `[lib]` target.
- Modify `tools/prover/src/main.rs` — `setup` and `prove` modes wired to the three circuits.
- Create `tools/prover/tests/verify_via_contract.rs` — per-circuit proof verifies through `shielded_pool::groth16::verify_groth16`.
- Modify `sdk/packages/sdk/src/wallet.ts` — async proved builders that call the injected `Prover`.
- Create `contract/tests/e2e_real_proofs.rs` — near-workspaces deploy + deposit/transfer/withdraw with real proofs.
- Modify `scripts/check-production-readiness.sh` if needed (verify it invokes `setup` + per-circuit prove).

---

## Phase 1 — Prover crate scaffolding

### Task 1: Add dependencies and a library target

**Files:**
- Modify: `tools/prover/Cargo.toml`
- Create: `tools/prover/src/lib.rs`

- [ ] **Step 1: Add deps and lib target to `tools/prover/Cargo.toml`**

Under `[dependencies]` add:

```toml
ark-r1cs-std = { version = "0.4", default-features = false }
light-poseidon = { version = "0.2", default-features = false }
```

Add a library target (keep the existing `[[bin]]`/default bin):

```toml
[lib]
name = "shielded_prover"
path = "src/lib.rs"
```

Under `[dev-dependencies]` add (for the verify-via-contract test):

```toml
shielded-pool = { path = "../../contract" }
```

- [ ] **Step 2: Create `tools/prover/src/lib.rs`**

```rust
//! Shielded-pool prover library: R1CS circuits and key/proof serialization
//! shared between the `prover` binary and integration tests.

pub mod circuits;
pub mod keys;
```

- [ ] **Step 3: Verify the workspace still resolves**

Run: `cargo metadata --format-version=1 -q >/dev/null && echo OK`
Expected: `OK` (no resolution errors). It will not compile yet — modules are empty — that's fine; metadata only resolves the graph.

- [ ] **Step 4: Commit**

```bash
git add tools/prover/Cargo.toml tools/prover/src/lib.rs
git commit -m "chore(prover): add r1cs-std + light-poseidon deps and lib target"
```

---

## Phase 2 — Poseidon gadget + vector gate (foundational; nothing proceeds until this passes)

### Task 2: Poseidon gadget reproducing the locked vectors

**Files:**
- Create: `tools/prover/src/circuits/mod.rs`
- Create: `tools/prover/src/circuits/gadgets.rs`

- [ ] **Step 1: Create `tools/prover/src/circuits/mod.rs`**

```rust
pub mod gadgets;
pub mod deposit;
pub mod transfer;
pub mod withdraw;
```

(The `deposit`/`transfer`/`withdraw` modules are added in later tasks; create empty files now so the module compiles.)

```bash
: > tools/prover/src/circuits/deposit.rs
: > tools/prover/src/circuits/transfer.rs
: > tools/prover/src/circuits/withdraw.rs
```

- [ ] **Step 2: Write the failing gadget vector test in `tools/prover/src/circuits/gadgets.rs`**

Write the full gadget module plus the test. The test synthesizes the gadget on constants and checks the assigned witness equals the locked hex.

```rust
//! R1CS gadgets over BN254 Fr, matching the Circom-parameter Poseidon used by
//! the contract (`contract/src/poseidon.rs`), the Noir circuits, and the SDK.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::ToBitsGadget;
use ark_relations::r1cs::SynthesisError;
use light_poseidon::parameters::bn254_x5::get_poseidon_parameters;
use light_poseidon::PoseidonParameters;

/// Circom Poseidon parameters for state width `t` (t = n_inputs + 1).
fn params(t: u8) -> PoseidonParameters<Fr> {
    get_poseidon_parameters::<Fr>(t).expect("bn254_x5 params")
}

/// In-circuit Poseidon permutation matching `light-poseidon`'s circom variant.
/// `inputs.len()` must equal `t - 1`.
fn poseidon(inputs: &[FpVar<Fr>], t: u8) -> Result<FpVar<Fr>, SynthesisError> {
    let p = params(t);
    let width = p.width;
    debug_assert_eq!(inputs.len() + 1, width);

    // state = [domain_tag(0), inputs...]
    let mut state: Vec<FpVar<Fr>> = Vec::with_capacity(width);
    state.push(FpVar::constant(Fr::zero()));
    for inp in inputs {
        state.push(inp.clone());
    }

    let half = p.full_rounds / 2;
    let total = p.full_rounds + p.partial_rounds;

    for round in 0..total {
        // ARK
        for i in 0..width {
            let c = FpVar::constant(p.ark[round * width + i]);
            state[i] = &state[i] + &c;
        }
        // S-box
        let full = round < half || round >= half + p.partial_rounds;
        if full {
            for i in 0..width {
                state[i] = state[i].pow_by_constant([p.alpha])?;
            }
        } else {
            state[0] = state[0].pow_by_constant([p.alpha])?;
        }
        // MDS
        let mut next: Vec<FpVar<Fr>> = Vec::with_capacity(width);
        for i in 0..width {
            let mut acc = FpVar::constant(Fr::zero());
            for j in 0..width {
                let m = FpVar::constant(p.mds[i][j]);
                acc += &state[j] * &m;
            }
            next.push(acc);
        }
        state = next;
    }

    Ok(state[0].clone())
}

pub fn poseidon2(a: &FpVar<Fr>, b: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    poseidon(&[a.clone(), b.clone()], 3)
}

pub fn poseidon4(
    a: &FpVar<Fr>,
    b: &FpVar<Fr>,
    c: &FpVar<Fr>,
    d: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    poseidon(&[a.clone(), b.clone(), c.clone(), d.clone()], 5)
}

pub fn commit_note(
    amount: &FpVar<Fr>,
    owner_pubkey: &FpVar<Fr>,
    auditor_pubkey: &FpVar<Fr>,
    blinding: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    poseidon4(amount, owner_pubkey, auditor_pubkey, blinding)
}

pub fn owner_pubkey_of(spending_key: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    poseidon2(spending_key, &FpVar::constant(Fr::zero()))
}

pub fn nullifier_of(
    spending_key: &FpVar<Fr>,
    commitment: &FpVar<Fr>,
    leaf_index: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let inner = poseidon2(commitment, leaf_index)?;
    poseidon2(spending_key, &inner)
}

/// Enforce `value` fits in `n_bits` bits (value < 2^n_bits).
pub fn enforce_bits(value: &FpVar<Fr>, n_bits: usize) -> Result<(), SynthesisError> {
    let bits = value.to_bits_le()?;
    for b in bits.iter().skip(n_bits) {
        b.enforce_equal(&Boolean::FALSE)?;
    }
    Ok(())
}

/// Enforce `a >= b` treating both as 64-bit unsigned (matches Noir `as u64`).
pub fn enforce_u64_geq(a: &FpVar<Fr>, b: &FpVar<Fr>) -> Result<(), SynthesisError> {
    enforce_bits(a, 64)?;
    enforce_bits(b, 64)?;
    let diff = a - b;
    enforce_bits(&diff, 64)?; // a - b in [0, 2^64) <=> a >= b given both < 2^64
    Ok(())
}

/// Depth-`DEPTH` Merkle inclusion: enforce `leaf` at `leaf_index` hashes up to
/// `root` along `path` (sibling per level). `index_bits` are the LE bits of
/// `leaf_index` (at least `DEPTH` of them).
pub fn merkle_inclusion(
    root: &FpVar<Fr>,
    leaf: &FpVar<Fr>,
    index_bits: &[Boolean<Fr>],
    path: &[FpVar<Fr>],
) -> Result<(), SynthesisError> {
    let mut current = leaf.clone();
    for (level, sibling) in path.iter().enumerate() {
        let bit = &index_bits[level];
        // bit == 0: current is left, sibling is right; bit == 1: swapped.
        let left = FpVar::conditionally_select(bit, sibling, &current)?;
        let right = FpVar::conditionally_select(bit, &current, sibling)?;
        current = poseidon2(&left, &right)?;
    }
    current.enforce_equal(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    fn fr_hex(f: Fr) -> String {
        use ark_ff::BigInteger;
        let bytes = f.into_bigint().to_bytes_be();
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.extend_from_slice(&bytes);
        format!("0x{}", hex::encode(padded))
    }

    #[test]
    fn poseidon2_gadget_matches_locked_vector() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let a = FpVar::new_witness(cs.clone(), || Ok(Fr::from(1u64))).unwrap();
        let b = FpVar::new_witness(cs.clone(), || Ok(Fr::from(2u64))).unwrap();
        let h = poseidon2(&a, &b).unwrap();
        let v = h.value().unwrap();
        assert_eq!(
            fr_hex(v),
            "0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a"
        );
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn poseidon4_gadget_matches_locked_vector() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let vars: Vec<_> = [1u64, 2, 3, 4]
            .iter()
            .map(|x| FpVar::new_witness(cs.clone(), || Ok(Fr::from(*x))).unwrap())
            .collect();
        let h = poseidon4(&vars[0], &vars[1], &vars[2], &vars[3]).unwrap();
        let v = h.value().unwrap();
        assert_eq!(
            fr_hex(v),
            "0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465"
        );
        assert!(cs.is_satisfied().unwrap());
    }
}
```

Add `hex` to `tools/prover/Cargo.toml` `[dev-dependencies]` if not present: `hex = "0.4"`.

- [ ] **Step 3: Run the vector gate; verify it fails first if anything is off, then passes**

Run: `cargo test -p shielded-prover --lib circuits::gadgets::tests -- --nocapture`
Expected: PASS (both vectors match). If a vector mismatches, STOP — the constant source or permutation is wrong; fix before any further task. (Note: the crate package name in commands is whatever `name` is under `[package]` in `tools/prover/Cargo.toml`; use that. Below this is written as `-p shielded-prover` — adjust to the actual package name.)

- [ ] **Step 4: Add merkle + range gadget tests**

Append to the `tests` module in `gadgets.rs`:

```rust
    #[test]
    fn merkle_depth2_leaf0_verifies() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mk = |x: u64| FpVar::new_witness(cs.clone(), || Ok(Fr::from(x))).unwrap();
        let (l0, l1, l2, l3) = (mk(10), mk(20), mk(30), mk(40));
        let h01 = poseidon2(&l0, &l1).unwrap();
        let h23 = poseidon2(&l2, &l3).unwrap();
        let root = poseidon2(&h01, &h23).unwrap();
        let bits = vec![Boolean::FALSE, Boolean::FALSE]; // index 0
        merkle_inclusion(&root, &l0, &bits, &[l1.clone(), h23.clone()]).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn merkle_wrong_sibling_unsatisfiable() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mk = |x: u64| FpVar::new_witness(cs.clone(), || Ok(Fr::from(x))).unwrap();
        let (l0, l1, l2, l3) = (mk(10), mk(20), mk(30), mk(40));
        let h01 = poseidon2(&l0, &l1).unwrap();
        let h23 = poseidon2(&l2, &l3).unwrap();
        let root = poseidon2(&h01, &h23).unwrap();
        let bits = vec![Boolean::FALSE, Boolean::FALSE];
        merkle_inclusion(&root, &l0, &bits, &[l2.clone(), h23.clone()]).unwrap(); // wrong sibling
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn range_check_rejects_oversize() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let big = FpVar::new_witness(cs.clone(), || {
            Ok(Fr::from(1u128 << 100) * Fr::from(1u128 << 30))
        })
        .unwrap();
        enforce_bits(&big, 128).unwrap();
        assert!(!cs.is_satisfied().unwrap()); // ~2^130 does not fit in 128 bits
    }
```

- [ ] **Step 5: Run all gadget tests**

Run: `cargo test -p shielded-prover --lib circuits::gadgets`
Expected: PASS (5 tests).

- [ ] **Step 6: Commit**

```bash
git add tools/prover/src/circuits/mod.rs tools/prover/src/circuits/gadgets.rs tools/prover/Cargo.toml tools/prover/src/circuits/deposit.rs tools/prover/src/circuits/transfer.rs tools/prover/src/circuits/withdraw.rs
git commit -m "feat(prover): Poseidon/merkle/range R1CS gadgets matching locked vectors"
```

---

## Phase 3 — Key & proof serialization

### Task 3: VK/proof byte encoders and field helpers

**Files:**
- Create: `tools/prover/src/keys.rs`

- [ ] **Step 1: Write `tools/prover/src/keys.rs`**

```rust
//! arkworks <-> contract wire-format conversion for Groth16 VKs and proofs.
//! Mirrors `contract/src/groth16.rs` byte layout (EIP-196/197, little-endian).

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};

pub fn g1_to_eip196(p: G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    if p.is_zero() {
        return out;
    }
    let (x, y) = p.xy().unwrap();
    let xb = x.into_bigint().to_bytes_le();
    let yb = y.into_bigint().to_bytes_le();
    out[..xb.len()].copy_from_slice(&xb);
    out[32..32 + yb.len()].copy_from_slice(&yb);
    out
}

pub fn g2_to_eip197(p: G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    if p.is_zero() {
        return out;
    }
    let (x, y) = p.xy().unwrap();
    let segs = [
        x.c0.into_bigint().to_bytes_le(),
        x.c1.into_bigint().to_bytes_le(),
        y.c0.into_bigint().to_bytes_le(),
        y.c1.into_bigint().to_bytes_le(),
    ];
    for (i, s) in segs.iter().enumerate() {
        out[i * 32..i * 32 + s.len()].copy_from_slice(s);
    }
    out
}

pub fn build_proof_bytes(proof: &ark_groth16::Proof<Bn254>) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(&g1_to_eip196(proof.a));
    out.extend_from_slice(&g2_to_eip197(proof.b));
    out.extend_from_slice(&g1_to_eip196(proof.c));
    out
}

pub fn build_vk_bytes(vk: &ark_groth16::VerifyingKey<Bn254>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&g1_to_eip196(vk.alpha_g1));
    out.extend_from_slice(&g2_to_eip197(vk.beta_g2));
    out.extend_from_slice(&g2_to_eip197(vk.gamma_g2));
    out.extend_from_slice(&g2_to_eip197(vk.delta_g2));
    for g1 in &vk.gamma_abc_g1 {
        out.extend_from_slice(&g1_to_eip196(*g1));
    }
    out
}

/// Parse a 0x-prefixed 64-hex-char big-endian field element.
pub fn parse_hex_fr(s: &str) -> anyhow::Result<Fr> {
    let t = s.strip_prefix("0x").unwrap_or(s);
    anyhow::ensure!(t.len() == 64, "expected 64 hex chars, got {}", t.len());
    let mut be = [0u8; 32];
    for i in 0..32 {
        be[i] = u8::from_str_radix(&t[i * 2..i * 2 + 2], 16)?;
    }
    Ok(Fr::from_be_bytes_mod_order(&be))
}
```

- [ ] **Step 2: Add a round-trip unit test**

Append to `keys.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_fr_roundtrips_small() {
        let f = parse_hex_fr(
            "0x0000000000000000000000000000000000000000000000000000000000000005",
        )
        .unwrap();
        assert_eq!(f, Fr::from(5u64));
    }
}
```

- [ ] **Step 3: Run**

Run: `cargo test -p shielded-prover --lib keys`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add tools/prover/src/keys.rs
git commit -m "feat(prover): VK/proof EIP-196/197 encoders + hex Fr parser"
```

---

## Phase 4 — The three circuits

> Each circuit allocates **public inputs first, in contract order**, then witnesses. `blank()` yields all-`None` for setup; `new(...)` carries concrete values for proving. `generate_constraints` consumes `self`.

### Task 4: DepositCircuit

**Files:**
- Modify: `tools/prover/src/circuits/deposit.rs`

- [ ] **Step 1: Write `tools/prover/src/circuits/deposit.rs`**

```rust
use ark_bn254::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::circuits::gadgets::commit_note;

/// deposit.nr: commitment well-formedness + view-hash binding.
/// Public inputs (order): commitment, amount, auditor_pubkey, view_ct_hash.
#[derive(Clone, Default)]
pub struct DepositCircuit {
    // public
    pub commitment: Option<Fr>,
    pub amount: Option<Fr>,
    pub auditor_pubkey: Option<Fr>,
    pub view_ct_hash: Option<Fr>,
    // witness
    pub owner_pubkey: Option<Fr>,
    pub blinding: Option<Fr>,
    pub view_ct_hash_witness: Option<Fr>,
}

impl DepositCircuit {
    pub fn blank() -> Self {
        Self::default()
    }
}

impl ConstraintSynthesizer<Fr> for DepositCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let miss = || SynthesisError::AssignmentMissing;
        let commitment = FpVar::new_input(cs.clone(), || self.commitment.ok_or_else(miss))?;
        let amount = FpVar::new_input(cs.clone(), || self.amount.ok_or_else(miss))?;
        let auditor = FpVar::new_input(cs.clone(), || self.auditor_pubkey.ok_or_else(miss))?;
        let view_ct_hash = FpVar::new_input(cs.clone(), || self.view_ct_hash.ok_or_else(miss))?;

        let owner = FpVar::new_witness(cs.clone(), || self.owner_pubkey.ok_or_else(miss))?;
        let blinding = FpVar::new_witness(cs.clone(), || self.blinding.ok_or_else(miss))?;
        let vh_witness =
            FpVar::new_witness(cs.clone(), || self.view_ct_hash_witness.ok_or_else(miss))?;

        let computed = commit_note(&amount, &owner, &auditor, &blinding)?;
        computed.enforce_equal(&commitment)?;
        view_ct_hash.enforce_equal(&vh_witness)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::gadgets::{commit_note as _cn};
    use ark_relations::r1cs::ConstraintSystem;

    // Native helper: compute commit_note value for building a consistent witness.
    fn native_commit(amount: Fr, owner: Fr, auditor: Fr, blinding: Fr) -> Fr {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mk = |v: Fr| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap();
        _cn(&mk(amount), &mk(owner), &mk(auditor), &mk(blinding))
            .unwrap()
            .value()
            .unwrap()
    }

    #[test]
    fn honest_deposit_satisfiable() {
        let (amount, owner, auditor, blinding) =
            (Fr::from(100u64), Fr::from(11u64), Fr::from(22u64), Fr::from(33u64));
        let commitment = native_commit(amount, owner, auditor, blinding);
        let c = DepositCircuit {
            commitment: Some(commitment),
            amount: Some(amount),
            auditor_pubkey: Some(auditor),
            view_ct_hash: Some(Fr::from(7u64)),
            owner_pubkey: Some(owner),
            blinding: Some(blinding),
            view_ct_hash_witness: Some(Fr::from(7u64)),
        };
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn wrong_amount_unsatisfiable() {
        let (amount, owner, auditor, blinding) =
            (Fr::from(100u64), Fr::from(11u64), Fr::from(22u64), Fr::from(33u64));
        let commitment = native_commit(amount, owner, auditor, blinding);
        let c = DepositCircuit {
            commitment: Some(commitment),
            amount: Some(Fr::from(200u64)), // public lies
            auditor_pubkey: Some(auditor),
            view_ct_hash: Some(Fr::from(7u64)),
            owner_pubkey: Some(owner),
            blinding: Some(blinding),
            view_ct_hash_witness: Some(Fr::from(7u64)),
        };
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
}
```

Add `use ark_r1cs_std::R1CSVar;` import if `.value()` needs it (it lives in the `R1CSVar` trait). Place it alongside the other `ark_r1cs_std` imports in the test module: `use ark_r1cs_std::R1CSVar;`.

- [ ] **Step 2: Run**

Run: `cargo test -p shielded-prover --lib circuits::deposit`
Expected: PASS (2 tests).

- [ ] **Step 3: Commit**

```bash
git add tools/prover/src/circuits/deposit.rs
git commit -m "feat(prover): DepositCircuit R1CS with positive/negative tests"
```

### Task 5: WithdrawCircuit

**Files:**
- Modify: `tools/prover/src/circuits/withdraw.rs`

- [ ] **Step 1: Write `tools/prover/src/circuits/withdraw.rs`**

```rust
use ark_bn254::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::ToBitsGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::circuits::gadgets::{
    commit_note, enforce_u64_geq, merkle_inclusion, nullifier_of, owner_pubkey_of,
};

pub const DEPTH: usize = 20;

/// withdraw.nr: single-note whole-amount withdraw.
/// Public inputs (order): merkle_root, nullifier, recipient, amount, relayer,
/// relayer_fee, auditor_pubkey, view_ct_hash.
#[derive(Clone)]
pub struct WithdrawCircuit {
    pub merkle_root: Option<Fr>,
    pub nullifier: Option<Fr>,
    pub recipient: Option<Fr>,
    pub amount: Option<Fr>,
    pub relayer: Option<Fr>,
    pub relayer_fee: Option<Fr>,
    pub auditor_pubkey: Option<Fr>,
    pub view_ct_hash: Option<Fr>,
    // witness
    pub note_amount: Option<Fr>,
    pub note_owner_pubkey: Option<Fr>,
    pub note_auditor_pubkey: Option<Fr>,
    pub note_blinding: Option<Fr>,
    pub spending_key: Option<Fr>,
    pub leaf_index: Option<Fr>,
    pub merkle_path: Option<[Fr; DEPTH]>,
    pub view_ct_hash_witness: Option<Fr>,
}

impl WithdrawCircuit {
    pub fn blank() -> Self {
        Self {
            merkle_root: None,
            nullifier: None,
            recipient: None,
            amount: None,
            relayer: None,
            relayer_fee: None,
            auditor_pubkey: None,
            view_ct_hash: None,
            note_amount: None,
            note_owner_pubkey: None,
            note_auditor_pubkey: None,
            note_blinding: None,
            spending_key: None,
            leaf_index: None,
            merkle_path: None,
            view_ct_hash_witness: None,
        }
    }
}

impl ConstraintSynthesizer<Fr> for WithdrawCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let miss = || SynthesisError::AssignmentMissing;

        // Public inputs in contract order.
        let root = FpVar::new_input(cs.clone(), || self.merkle_root.ok_or_else(miss))?;
        let nullifier = FpVar::new_input(cs.clone(), || self.nullifier.ok_or_else(miss))?;
        let recipient = FpVar::new_input(cs.clone(), || self.recipient.ok_or_else(miss))?;
        let amount = FpVar::new_input(cs.clone(), || self.amount.ok_or_else(miss))?;
        let relayer = FpVar::new_input(cs.clone(), || self.relayer.ok_or_else(miss))?;
        let relayer_fee = FpVar::new_input(cs.clone(), || self.relayer_fee.ok_or_else(miss))?;
        let auditor = FpVar::new_input(cs.clone(), || self.auditor_pubkey.ok_or_else(miss))?;
        let view_ct_hash = FpVar::new_input(cs.clone(), || self.view_ct_hash.ok_or_else(miss))?;

        // Witnesses.
        let note_amount = FpVar::new_witness(cs.clone(), || self.note_amount.ok_or_else(miss))?;
        let note_owner =
            FpVar::new_witness(cs.clone(), || self.note_owner_pubkey.ok_or_else(miss))?;
        let note_auditor =
            FpVar::new_witness(cs.clone(), || self.note_auditor_pubkey.ok_or_else(miss))?;
        let note_blinding =
            FpVar::new_witness(cs.clone(), || self.note_blinding.ok_or_else(miss))?;
        let sk = FpVar::new_witness(cs.clone(), || self.spending_key.ok_or_else(miss))?;
        let leaf_index = FpVar::new_witness(cs.clone(), || self.leaf_index.ok_or_else(miss))?;
        let mut path = Vec::with_capacity(DEPTH);
        for i in 0..DEPTH {
            let v = FpVar::new_witness(cs.clone(), || {
                self.merkle_path.map(|p| p[i]).ok_or_else(miss)
            })?;
            path.push(v);
        }
        let vh_witness =
            FpVar::new_witness(cs.clone(), || self.view_ct_hash_witness.ok_or_else(miss))?;

        // Keep recipient/relayer as bound public inputs (Noir: assert(x==x)).
        recipient.enforce_equal(&recipient)?;
        relayer.enforce_equal(&relayer)?;

        let commitment = commit_note(&note_amount, &note_owner, &note_auditor, &note_blinding)?;

        owner_pubkey_of(&sk)?.enforce_equal(&note_owner)?;
        nullifier_of(&sk, &commitment, &leaf_index)?.enforce_equal(&nullifier)?;
        note_amount.enforce_equal(&amount)?;
        note_auditor.enforce_equal(&auditor)?;
        enforce_u64_geq(&amount, &relayer_fee)?;
        view_ct_hash.enforce_equal(&vh_witness)?;

        let bits = leaf_index.to_bits_le()?;
        merkle_inclusion(&root, &commitment, &bits[..DEPTH], &path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;

    // Native evaluators built by synthesizing the gadgets in a throwaway CS.
    fn eval2(a: Fr, b: Fr) -> Fr {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mk = |v: Fr| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap();
        crate::circuits::gadgets::poseidon2(&mk(a), &mk(b))
            .unwrap()
            .value()
            .unwrap()
    }
    fn eval4(a: Fr, b: Fr, c: Fr, d: Fr) -> Fr {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mk = |v: Fr| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap();
        crate::circuits::gadgets::poseidon4(&mk(a), &mk(b), &mk(c), &mk(d))
            .unwrap()
            .value()
            .unwrap()
    }
    fn owner_of(sk: Fr) -> Fr {
        eval2(sk, Fr::from(0u64))
    }
    fn null_of(sk: Fr, c: Fr, i: Fr) -> Fr {
        eval2(sk, eval2(c, i))
    }

    /// Build a depth-DEPTH root + path for a single leaf at index 0, empty tree.
    fn empty_path_for_leaf0(leaf: Fr) -> (Fr, [Fr; DEPTH]) {
        let mut z = Fr::from(0u64);
        let mut zeros = [Fr::from(0u64); DEPTH];
        for level in 0..DEPTH {
            zeros[level] = z;
            z = eval2(z, z);
        }
        let mut current = leaf;
        for level in 0..DEPTH {
            current = eval2(current, zeros[level]);
        }
        (current, zeros)
    }

    fn honest() -> WithdrawCircuit {
        let sk = Fr::from(7u64);
        let owner = owner_of(sk);
        let auditor = Fr::from(22u64);
        let blinding = Fr::from(33u64);
        let amount = Fr::from(100u64);
        let commitment = eval4(amount, owner, auditor, blinding);
        let n = null_of(sk, commitment, Fr::from(0u64));
        let (root, path) = empty_path_for_leaf0(commitment);
        WithdrawCircuit {
            merkle_root: Some(root),
            nullifier: Some(n),
            recipient: Some(Fr::from(99u64)),
            amount: Some(amount),
            relayer: Some(Fr::from(77u64)),
            relayer_fee: Some(Fr::from(5u64)),
            auditor_pubkey: Some(auditor),
            view_ct_hash: Some(Fr::from(13u64)),
            note_amount: Some(amount),
            note_owner_pubkey: Some(owner),
            note_auditor_pubkey: Some(auditor),
            note_blinding: Some(blinding),
            spending_key: Some(sk),
            leaf_index: Some(Fr::from(0u64)),
            merkle_path: Some(path),
            view_ct_hash_witness: Some(Fr::from(13u64)),
        }
    }

    #[test]
    fn honest_withdraw_satisfiable() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        honest().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn wrong_spending_key_unsatisfiable() {
        let mut c = honest();
        c.spending_key = Some(Fr::from(8u64)); // owner won't match
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn forged_merkle_path_unsatisfiable() {
        let mut c = honest();
        let (fake_root, fake_path) = empty_path_for_leaf0(Fr::from(999u64));
        c.merkle_root = Some(fake_root);
        c.merkle_path = Some(fake_path);
        // commitment/nullifier still for the real note → inclusion fails.
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn fee_exceeds_amount_unsatisfiable() {
        let mut c = honest();
        c.relayer_fee = Some(Fr::from(101u64)); // > amount(100)
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
}
```

- [ ] **Step 2: Run**

Run: `cargo test -p shielded-prover --lib circuits::withdraw`
Expected: PASS (4 tests).

- [ ] **Step 3: Commit**

```bash
git add tools/prover/src/circuits/withdraw.rs
git commit -m "feat(prover): WithdrawCircuit R1CS (merkle+nullifier+fee) with tests"
```

### Task 6: TransferCircuit

**Files:**
- Modify: `tools/prover/src/circuits/transfer.rs`

- [ ] **Step 1: Write `tools/prover/src/circuits/transfer.rs`**

```rust
use ark_bn254::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::ToBitsGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::circuits::gadgets::{
    commit_note, enforce_bits, merkle_inclusion, nullifier_of, owner_pubkey_of,
};

pub const DEPTH: usize = 20;
const AMOUNT_BITS: usize = 128;

/// transfer.nr: 2-in 2-out shielded transfer.
/// Public inputs (order): merkle_root, nullifier0, nullifier1, commitment_out0,
/// commitment_out1, auditor_pubkey, recipient_auditor_pubkey,
/// view_ct_hash_sender, view_ct_hash_recipient.
#[derive(Clone)]
pub struct TransferCircuit {
    pub merkle_root: Option<Fr>,
    pub nullifier0: Option<Fr>,
    pub nullifier1: Option<Fr>,
    pub commitment_out0: Option<Fr>,
    pub commitment_out1: Option<Fr>,
    pub auditor_pubkey: Option<Fr>,
    pub recipient_auditor_pubkey: Option<Fr>,
    pub view_ct_hash_sender: Option<Fr>,
    pub view_ct_hash_recipient: Option<Fr>,
    // inputs (witness)
    pub in0_amount: Option<Fr>,
    pub in0_owner_pubkey: Option<Fr>,
    pub in0_blinding: Option<Fr>,
    pub in0_leaf_index: Option<Fr>,
    pub in0_path: Option<[Fr; DEPTH]>,
    pub in1_amount: Option<Fr>,
    pub in1_owner_pubkey: Option<Fr>,
    pub in1_blinding: Option<Fr>,
    pub in1_leaf_index: Option<Fr>,
    pub in1_path: Option<[Fr; DEPTH]>,
    pub spending_key: Option<Fr>,
    // outputs (witness)
    pub out0_amount: Option<Fr>,
    pub out0_owner_pubkey: Option<Fr>,
    pub out0_blinding: Option<Fr>,
    pub out1_amount: Option<Fr>,
    pub out1_owner_pubkey: Option<Fr>,
    pub out1_blinding: Option<Fr>,
    pub view_ct_hash_sender_witness: Option<Fr>,
    pub view_ct_hash_recipient_witness: Option<Fr>,
}

impl TransferCircuit {
    pub fn blank() -> Self {
        // All-None. Uses Default-like construction.
        Self {
            merkle_root: None, nullifier0: None, nullifier1: None,
            commitment_out0: None, commitment_out1: None, auditor_pubkey: None,
            recipient_auditor_pubkey: None, view_ct_hash_sender: None,
            view_ct_hash_recipient: None, in0_amount: None, in0_owner_pubkey: None,
            in0_blinding: None, in0_leaf_index: None, in0_path: None, in1_amount: None,
            in1_owner_pubkey: None, in1_blinding: None, in1_leaf_index: None, in1_path: None,
            spending_key: None, out0_amount: None, out0_owner_pubkey: None, out0_blinding: None,
            out1_amount: None, out1_owner_pubkey: None, out1_blinding: None,
            view_ct_hash_sender_witness: None, view_ct_hash_recipient_witness: None,
        }
    }
}

impl ConstraintSynthesizer<Fr> for TransferCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let miss = || SynthesisError::AssignmentMissing;
        macro_rules! pin { ($f:expr) => { FpVar::new_input(cs.clone(), || $f.ok_or_else(miss))? }; }
        macro_rules! wit { ($f:expr) => { FpVar::new_witness(cs.clone(), || $f.ok_or_else(miss))? }; }

        // Public inputs in contract order.
        let root = pin!(self.merkle_root);
        let null0 = pin!(self.nullifier0);
        let null1 = pin!(self.nullifier1);
        let cout0 = pin!(self.commitment_out0);
        let cout1 = pin!(self.commitment_out1);
        let auditor = pin!(self.auditor_pubkey);
        let recip_auditor = pin!(self.recipient_auditor_pubkey);
        let vh_sender = pin!(self.view_ct_hash_sender);
        let vh_recipient = pin!(self.view_ct_hash_recipient);

        // Input witnesses.
        let in0_amount = wit!(self.in0_amount);
        let in0_owner = wit!(self.in0_owner_pubkey);
        let in0_blind = wit!(self.in0_blinding);
        let in0_idx = wit!(self.in0_leaf_index);
        let mut in0_path = Vec::with_capacity(DEPTH);
        for i in 0..DEPTH { in0_path.push(FpVar::new_witness(cs.clone(), || self.in0_path.map(|p| p[i]).ok_or_else(miss))?); }
        let in1_amount = wit!(self.in1_amount);
        let in1_owner = wit!(self.in1_owner_pubkey);
        let in1_blind = wit!(self.in1_blinding);
        let in1_idx = wit!(self.in1_leaf_index);
        let mut in1_path = Vec::with_capacity(DEPTH);
        for i in 0..DEPTH { in1_path.push(FpVar::new_witness(cs.clone(), || self.in1_path.map(|p| p[i]).ok_or_else(miss))?); }
        let sk = wit!(self.spending_key);

        // Output witnesses.
        let out0_amount = wit!(self.out0_amount);
        let out0_owner = wit!(self.out0_owner_pubkey);
        let out0_blind = wit!(self.out0_blinding);
        let out1_amount = wit!(self.out1_amount);
        let out1_owner = wit!(self.out1_owner_pubkey);
        let out1_blind = wit!(self.out1_blinding);
        let vh_sender_w = wit!(self.view_ct_hash_sender_witness);
        let vh_recipient_w = wit!(self.view_ct_hash_recipient_witness);

        // Input commitments carry the public auditor_pubkey.
        let c_in0 = commit_note(&in0_amount, &in0_owner, &auditor, &in0_blind)?;
        let c_in1 = commit_note(&in1_amount, &in1_owner, &auditor, &in1_blind)?;

        // Spending key derives both owners.
        let owner = owner_pubkey_of(&sk)?;
        owner.enforce_equal(&in0_owner)?;
        owner.enforce_equal(&in1_owner)?;

        // Nullifier correctness.
        nullifier_of(&sk, &c_in0, &in0_idx)?.enforce_equal(&null0)?;
        nullifier_of(&sk, &c_in1, &in1_idx)?.enforce_equal(&null1)?;

        // Merkle inclusion under the same root.
        let b0 = in0_idx.to_bits_le()?;
        merkle_inclusion(&root, &c_in0, &b0[..DEPTH], &in0_path)?;
        let b1 = in1_idx.to_bits_le()?;
        merkle_inclusion(&root, &c_in1, &b1[..DEPTH], &in1_path)?;

        // Outputs bound to recipient_auditor_pubkey.
        commit_note(&out0_amount, &out0_owner, &recip_auditor, &out0_blind)?.enforce_equal(&cout0)?;
        commit_note(&out1_amount, &out1_owner, &recip_auditor, &out1_blind)?.enforce_equal(&cout1)?;

        // Amount range checks (hardening beyond Noir): each amount < 2^128.
        enforce_bits(&in0_amount, AMOUNT_BITS)?;
        enforce_bits(&in1_amount, AMOUNT_BITS)?;
        enforce_bits(&out0_amount, AMOUNT_BITS)?;
        enforce_bits(&out1_amount, AMOUNT_BITS)?;

        // Value conservation (exact, given the range bounds prevent wraparound).
        (&in0_amount + &in1_amount).enforce_equal(&(&out0_amount + &out1_amount))?;

        // View hash bindings.
        vh_sender.enforce_equal(&vh_sender_w)?;
        vh_recipient.enforce_equal(&vh_recipient_w)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;

    fn eval2(a: Fr, b: Fr) -> Fr {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mk = |v: Fr| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap();
        crate::circuits::gadgets::poseidon2(&mk(a), &mk(b)).unwrap().value().unwrap()
    }
    fn eval4(a: Fr, b: Fr, c: Fr, d: Fr) -> Fr {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mk = |v: Fr| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap();
        crate::circuits::gadgets::poseidon4(&mk(a), &mk(b), &mk(c), &mk(d)).unwrap().value().unwrap()
    }
    fn owner_of(sk: Fr) -> Fr { eval2(sk, Fr::from(0u64)) }
    fn null_of(sk: Fr, c: Fr, i: Fr) -> Fr { eval2(sk, eval2(c, i)) }

    /// Tree with two leaves at indices 0 and 1, rest zero. Returns (root, path0, path1).
    fn tree_two(leaf0: Fr, leaf1: Fr) -> (Fr, [Fr; DEPTH], [Fr; DEPTH]) {
        let mut z = Fr::from(0u64);
        let mut zeros = [Fr::from(0u64); DEPTH];
        for level in 0..DEPTH { zeros[level] = z; z = eval2(z, z); }
        let mut path0 = [Fr::from(0u64); DEPTH];
        let mut path1 = [Fr::from(0u64); DEPTH];
        path0[0] = leaf1;
        path1[0] = leaf0;
        for level in 1..DEPTH { path0[level] = zeros[level]; path1[level] = zeros[level]; }
        let mut current = eval2(leaf0, leaf1);
        for level in 1..DEPTH { current = eval2(current, zeros[level]); }
        (current, path0, path1)
    }

    fn honest() -> TransferCircuit {
        let sk = Fr::from(7u64);
        let owner = owner_of(sk);
        let auditor = Fr::from(22u64);
        let recip_auditor = Fr::from(33u64);
        let c_in0 = eval4(Fr::from(60u64), owner, auditor, Fr::from(1u64));
        let c_in1 = eval4(Fr::from(40u64), owner, auditor, Fr::from(2u64));
        let n0 = null_of(sk, c_in0, Fr::from(0u64));
        let n1 = null_of(sk, c_in1, Fr::from(1u64));
        let (root, path0, path1) = tree_two(c_in0, c_in1);
        let cout0 = eval4(Fr::from(70u64), Fr::from(100u64), recip_auditor, Fr::from(3u64));
        let cout1 = eval4(Fr::from(30u64), owner, recip_auditor, Fr::from(4u64));
        TransferCircuit {
            merkle_root: Some(root), nullifier0: Some(n0), nullifier1: Some(n1),
            commitment_out0: Some(cout0), commitment_out1: Some(cout1),
            auditor_pubkey: Some(auditor), recipient_auditor_pubkey: Some(recip_auditor),
            view_ct_hash_sender: Some(Fr::from(13u64)), view_ct_hash_recipient: Some(Fr::from(14u64)),
            in0_amount: Some(Fr::from(60u64)), in0_owner_pubkey: Some(owner), in0_blinding: Some(Fr::from(1u64)), in0_leaf_index: Some(Fr::from(0u64)), in0_path: Some(path0),
            in1_amount: Some(Fr::from(40u64)), in1_owner_pubkey: Some(owner), in1_blinding: Some(Fr::from(2u64)), in1_leaf_index: Some(Fr::from(1u64)), in1_path: Some(path1),
            spending_key: Some(sk),
            out0_amount: Some(Fr::from(70u64)), out0_owner_pubkey: Some(Fr::from(100u64)), out0_blinding: Some(Fr::from(3u64)),
            out1_amount: Some(Fr::from(30u64)), out1_owner_pubkey: Some(owner), out1_blinding: Some(Fr::from(4u64)),
            view_ct_hash_sender_witness: Some(Fr::from(13u64)), view_ct_hash_recipient_witness: Some(Fr::from(14u64)),
        }
    }

    #[test]
    fn honest_transfer_satisfiable() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        honest().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn value_violation_unsatisfiable() {
        let mut c = honest();
        // outputs 150 + 30 != 100
        let recip_auditor = Fr::from(33u64);
        c.out0_amount = Some(Fr::from(150u64));
        c.commitment_out0 = Some(eval4(Fr::from(150u64), Fr::from(100u64), recip_auditor, Fr::from(3u64)));
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn wraparound_mint_unsatisfiable() {
        // out0 = p - 40 + 100 (huge), out1 small, so out0+out1 ≡ in0+in1 (mod p)
        // but out0 ≥ 2^128, so the range check must reject.
        let mut c = honest();
        let recip_auditor = Fr::from(33u64);
        let huge = -Fr::from(40u64) + Fr::from(100u64); // = p - 40 + 100
        c.out0_amount = Some(huge);
        c.out1_amount = Some(Fr::from(40u64));
        c.commitment_out0 = Some(eval4(huge, Fr::from(100u64), recip_auditor, Fr::from(3u64)));
        c.commitment_out1 = Some(eval4(Fr::from(40u64), owner_of(Fr::from(7u64)), recip_auditor, Fr::from(4u64)));
        c.out1_owner_pubkey = Some(owner_of(Fr::from(7u64)));
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn forged_merkle_path_unsatisfiable() {
        let mut c = honest();
        let (fake_root, fp0, fp1) = tree_two(Fr::from(999u64), Fr::from(1000u64));
        c.merkle_root = Some(fake_root);
        c.in0_path = Some(fp0);
        c.in1_path = Some(fp1);
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
}
```

- [ ] **Step 2: Run**

Run: `cargo test -p shielded-prover --lib circuits::transfer`
Expected: PASS (4 tests).

- [ ] **Step 3: Commit**

```bash
git add tools/prover/src/circuits/transfer.rs
git commit -m "feat(prover): TransferCircuit R1CS (2in/2out, range-checked) with tests"
```

---

## Phase 5 — Prover binary: setup + prove

### Task 7: `setup` mode emits .pk and contract-format .vk

**Files:**
- Modify: `tools/prover/src/main.rs`

- [ ] **Step 1: Replace `tools/prover/src/main.rs` run logic to dispatch on argv mode**

Keep the existing `mul` proving path. Add a `setup` subcommand and a circuit-aware `prove` path. Full new `main.rs`:

```rust
//! Shielded-pool Groth16 prover CLI.
//!
//! Modes:
//!   setup  --out-dir <dir>      generate {deposit,transfer,withdraw}.pk/.vk
//!   prove  (default, stdin)     read ProveRequest JSON, write 256-byte proof
//!
//! Proof wire format: A_g1(64) || B_g2(128) || C_g1(64) (EIP-196/197 LE).

use anyhow::{anyhow, bail, Context, Result};
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use shielded_prover::circuits::deposit::DepositCircuit;
use shielded_prover::circuits::transfer::{TransferCircuit, DEPTH as T_DEPTH};
use shielded_prover::circuits::withdraw::{WithdrawCircuit, DEPTH as W_DEPTH};
use shielded_prover::keys::{build_proof_bytes, build_vk_bytes, parse_hex_fr};

#[derive(Deserialize)]
struct ProveRequest {
    circuit: String,
    #[serde(rename = "publicInputs")]
    public_inputs: Vec<String>,
    witness: Value,
}

/// Fixed seed so `setup` reproduces identical proving/verifying keys and
/// `prove` is deterministic. NOT a secure ceremony — prototype only.
fn rng() -> StdRng {
    StdRng::seed_from_u64(0x5151_3ded_u64)
}

fn setup(out_dir: &str) -> Result<()> {
    fs::create_dir_all(out_dir)?;
    write_keys(out_dir, "deposit", DepositCircuit::blank())?;
    write_keys(out_dir, "transfer", TransferCircuit::blank())?;
    write_keys(out_dir, "withdraw", WithdrawCircuit::blank())?;
    Ok(())
}

fn write_keys<C: ark_relations::r1cs::ConstraintSynthesizer<Fr> + Clone>(
    out_dir: &str,
    name: &str,
    blank: C,
) -> Result<()> {
    let mut r = rng();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(blank, &mut r)
        .with_context(|| format!("setup {name}"))?;
    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes)?;
    fs::write(Path::new(out_dir).join(format!("{name}.pk")), &pk_bytes)?;
    fs::write(Path::new(out_dir).join(format!("{name}.vk")), build_vk_bytes(&vk))?;
    Ok(())
}

fn load_pk(out_dir: &str, name: &str) -> Result<ProvingKey<Bn254>> {
    let bytes = fs::read(Path::new(out_dir).join(format!("{name}.pk")))
        .with_context(|| format!("read {name}.pk (run `setup` first)"))?;
    ProvingKey::<Bn254>::deserialize_compressed(bytes.as_slice())
        .with_context(|| format!("parse {name}.pk"))
}

fn w(v: &Value, k: &str) -> Result<Fr> {
    let s = v.get(k).and_then(|x| x.as_str()).ok_or_else(|| anyhow!("witness.{k} missing"))?;
    parse_hex_fr(s)
}
fn w_path<const N: usize>(v: &Value, k: &str) -> Result<[Fr; N]> {
    let arr = v.get(k).and_then(|x| x.as_array()).ok_or_else(|| anyhow!("witness.{k} missing array"))?;
    anyhow::ensure!(arr.len() == N, "witness.{k} must have {N} entries");
    let mut out = [Fr::from(0u64); N];
    for (i, e) in arr.iter().enumerate() {
        out[i] = parse_hex_fr(e.as_str().ok_or_else(|| anyhow!("witness.{k}[{i}] not string"))?)?;
    }
    Ok(out)
}

fn prove(req: ProveRequest, key_dir: &str) -> Result<Vec<u8>> {
    let mut r = rng();
    let pis: Vec<Fr> = req.public_inputs.iter().map(|s| parse_hex_fr(s)).collect::<Result<_>>()?;
    let wt = &req.witness;
    let proof = match req.circuit.as_str() {
        "deposit" => {
            anyhow::ensure!(pis.len() == 4, "deposit expects 4 public inputs");
            let c = DepositCircuit {
                commitment: Some(pis[0]), amount: Some(pis[1]),
                auditor_pubkey: Some(pis[2]), view_ct_hash: Some(pis[3]),
                owner_pubkey: Some(w(wt, "ownerPubkey")?),
                blinding: Some(w(wt, "blinding")?),
                view_ct_hash_witness: Some(w(wt, "viewCtHashWitness")?),
            };
            let pk = load_pk(key_dir, "deposit")?;
            Groth16::<Bn254>::prove(&pk, c, &mut r)?
        }
        "withdraw" => {
            anyhow::ensure!(pis.len() == 8, "withdraw expects 8 public inputs");
            let c = WithdrawCircuit {
                merkle_root: Some(pis[0]), nullifier: Some(pis[1]), recipient: Some(pis[2]),
                amount: Some(pis[3]), relayer: Some(pis[4]), relayer_fee: Some(pis[5]),
                auditor_pubkey: Some(pis[6]), view_ct_hash: Some(pis[7]),
                note_amount: Some(w(wt, "noteAmount")?),
                note_owner_pubkey: Some(w(wt, "noteOwnerPubkey")?),
                note_auditor_pubkey: Some(w(wt, "noteAuditorPubkey")?),
                note_blinding: Some(w(wt, "noteBlinding")?),
                spending_key: Some(w(wt, "spendingKey")?),
                leaf_index: Some(w(wt, "leafIndex")?),
                merkle_path: Some(w_path::<{ W_DEPTH }>(wt, "merklePath")?),
                view_ct_hash_witness: Some(w(wt, "viewCtHashWitness")?),
            };
            let pk = load_pk(key_dir, "withdraw")?;
            Groth16::<Bn254>::prove(&pk, c, &mut r)?
        }
        "transfer" => {
            anyhow::ensure!(pis.len() == 9, "transfer expects 9 public inputs");
            let c = TransferCircuit {
                merkle_root: Some(pis[0]), nullifier0: Some(pis[1]), nullifier1: Some(pis[2]),
                commitment_out0: Some(pis[3]), commitment_out1: Some(pis[4]),
                auditor_pubkey: Some(pis[5]), recipient_auditor_pubkey: Some(pis[6]),
                view_ct_hash_sender: Some(pis[7]), view_ct_hash_recipient: Some(pis[8]),
                in0_amount: Some(w(wt, "in0Amount")?), in0_owner_pubkey: Some(w(wt, "in0OwnerPubkey")?),
                in0_blinding: Some(w(wt, "in0Blinding")?), in0_leaf_index: Some(w(wt, "in0LeafIndex")?),
                in0_path: Some(w_path::<{ T_DEPTH }>(wt, "in0Path")?),
                in1_amount: Some(w(wt, "in1Amount")?), in1_owner_pubkey: Some(w(wt, "in1OwnerPubkey")?),
                in1_blinding: Some(w(wt, "in1Blinding")?), in1_leaf_index: Some(w(wt, "in1LeafIndex")?),
                in1_path: Some(w_path::<{ T_DEPTH }>(wt, "in1Path")?),
                spending_key: Some(w(wt, "spendingKey")?),
                out0_amount: Some(w(wt, "out0Amount")?), out0_owner_pubkey: Some(w(wt, "out0OwnerPubkey")?),
                out0_blinding: Some(w(wt, "out0Blinding")?),
                out1_amount: Some(w(wt, "out1Amount")?), out1_owner_pubkey: Some(w(wt, "out1OwnerPubkey")?),
                out1_blinding: Some(w(wt, "out1Blinding")?),
                view_ct_hash_sender_witness: Some(w(wt, "viewCtHashSenderWitness")?),
                view_ct_hash_recipient_witness: Some(w(wt, "viewCtHashRecipientWitness")?),
            };
            let pk = load_pk(key_dir, "transfer")?;
            Groth16::<Bn254>::prove(&pk, c, &mut r)?
        }
        other => bail!("unsupported circuit '{other}'"),
    };
    Ok(build_proof_bytes(&proof))
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let key_dir = std::env::var("PROVER_KEY_DIR").unwrap_or_else(|_| "keys".to_string());

    if args.get(1).map(|s| s.as_str()) == Some("setup") {
        let out = args.iter().position(|a| a == "--out-dir")
            .and_then(|i| args.get(i + 1)).cloned().unwrap_or(key_dir);
        return setup(&out);
    }

    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf).context("read stdin")?;
    let req: ProveRequest = serde_json::from_str(&buf).context("parse ProveRequest")?;
    let bytes = prove(req, &key_dir)?;
    std::io::stdout().write_all(&bytes).context("write stdout")?;
    std::io::stdout().flush()?;
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("prover error: {e:#}");
        std::process::exit(1);
    }
}
```

- [ ] **Step 2: Build the binary**

Run: `cargo build -p shielded-prover`
Expected: compiles cleanly.

- [ ] **Step 3: Run setup and confirm key files + VK sizes**

```bash
cargo run -p shielded-prover -- setup --out-dir /tmp/spkeys
ls -l /tmp/spkeys
```

Expected: `deposit.pk transfer.pk withdraw.pk deposit.vk transfer.vk withdraw.vk` exist. VK sizes: header `64 + 3*128 = 448` bytes plus `(n+1)*64` — deposit `448 + 5*64 = 768`, withdraw `448 + 9*64 = 1024`, transfer `448 + 10*64 = 1088`. Verify:

```bash
stat -f%z /tmp/spkeys/deposit.vk /tmp/spkeys/withdraw.vk /tmp/spkeys/transfer.vk
```

Expected: `768`, `1024`, `1088`.

- [ ] **Step 4: Commit**

```bash
git add tools/prover/src/main.rs
git commit -m "feat(prover): setup mode + circuit-aware prove for deposit/transfer/withdraw"
```

---

## Phase 6 — Proof verifies through the contract verifier

### Task 8: verify-via-contract integration test

**Files:**
- Create: `tools/prover/tests/verify_via_contract.rs`

- [ ] **Step 1: Write the test**

This dev-depends on `shielded-pool` (added in Task 1) to call `verify_groth16`. It generates setup + proof in-process for each circuit and asserts the contract verifier accepts it, and rejects a tampered public input.

```rust
use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::testing_env;

use shielded_pool::groth16::{verify_groth16, Proof, VerifyingKey};
use shielded_pool::poseidon::Field as MyField;
use shielded_prover::circuits::withdraw::WithdrawCircuit;
use shielded_prover::keys::{build_proof_bytes, build_vk_bytes};

fn fr_to_myfield(f: Fr) -> MyField {
    let mut be = f.into_bigint().to_bytes_be();
    while be.len() < 32 { be.insert(0, 0); }
    MyField::from_be_bytes(&be)
}

// Reuse the withdraw test fixture builder via a local clone of its honest()
// construction. (Kept minimal: import not possible since it's in a #[cfg(test)]
// module, so build a trivial-but-valid withdraw witness here.)
fn eval2(a: Fr, b: Fr) -> Fr {
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;
    let cs = ConstraintSystem::<Fr>::new_ref();
    let mk = |v: Fr| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap();
    shielded_prover::circuits::gadgets::poseidon2(&mk(a), &mk(b)).unwrap().value().unwrap()
}
fn eval4(a: Fr, b: Fr, c: Fr, d: Fr) -> Fr {
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;
    let cs = ConstraintSystem::<Fr>::new_ref();
    let mk = |v: Fr| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap();
    shielded_prover::circuits::gadgets::poseidon4(&mk(a), &mk(b), &mk(c), &mk(d)).unwrap().value().unwrap()
}

const DEPTH: usize = 20;

fn honest_withdraw() -> (WithdrawCircuit, Vec<Fr>) {
    let sk = Fr::from(7u64);
    let owner = eval2(sk, Fr::from(0u64));
    let auditor = Fr::from(22u64);
    let blinding = Fr::from(33u64);
    let amount = Fr::from(100u64);
    let commitment = eval4(amount, owner, auditor, blinding);
    let n = eval2(sk, eval2(commitment, Fr::from(0u64)));
    // empty tree, leaf at index 0
    let mut z = Fr::from(0u64);
    let mut zeros = [Fr::from(0u64); DEPTH];
    for level in 0..DEPTH { zeros[level] = z; z = eval2(z, z); }
    let mut root = commitment;
    for level in 0..DEPTH { root = eval2(root, zeros[level]); }
    let recipient = Fr::from(99u64);
    let relayer = Fr::from(77u64);
    let relayer_fee = Fr::from(5u64);
    let vh = Fr::from(13u64);
    let circuit = WithdrawCircuit {
        merkle_root: Some(root), nullifier: Some(n), recipient: Some(recipient),
        amount: Some(amount), relayer: Some(relayer), relayer_fee: Some(relayer_fee),
        auditor_pubkey: Some(auditor), view_ct_hash: Some(vh),
        note_amount: Some(amount), note_owner_pubkey: Some(owner),
        note_auditor_pubkey: Some(auditor), note_blinding: Some(blinding),
        spending_key: Some(sk), leaf_index: Some(Fr::from(0u64)),
        merkle_path: Some(zeros), view_ct_hash_witness: Some(vh),
    };
    let public = vec![root, n, recipient, amount, relayer, relayer_fee, auditor, vh];
    (circuit, public)
}

#[test]
fn withdraw_proof_verifies_via_contract() {
    testing_env!(VMContextBuilder::new().build());
    let mut rng = StdRng::seed_from_u64(0x1234_5678);
    let (circuit, public) = honest_withdraw();

    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();

    let parsed_vk = VerifyingKey::from_bytes(&build_vk_bytes(&vk)).unwrap();
    let parsed_proof = Proof::from_bytes(&build_proof_bytes(&proof)).unwrap();
    let inputs: Vec<MyField> = public.iter().map(|f| fr_to_myfield(*f)).collect();

    assert!(verify_groth16(&parsed_vk, &parsed_proof, &inputs), "real withdraw proof rejected");
}

#[test]
fn withdraw_proof_wrong_public_input_rejected() {
    testing_env!(VMContextBuilder::new().build());
    let mut rng = StdRng::seed_from_u64(0x9999);
    let (circuit, public) = honest_withdraw();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();

    let parsed_vk = VerifyingKey::from_bytes(&build_vk_bytes(&vk)).unwrap();
    let parsed_proof = Proof::from_bytes(&build_proof_bytes(&proof)).unwrap();
    let mut bad = public.clone();
    bad[3] = Fr::from(101u64); // claim amount 101 instead of 100
    let inputs: Vec<MyField> = bad.iter().map(|f| fr_to_myfield(*f)).collect();
    assert!(!verify_groth16(&parsed_vk, &parsed_proof, &inputs), "tampered input accepted");
}
```

NOTE: `shielded_prover::circuits::gadgets` must be `pub` (it is, via `pub mod gadgets`). `shielded-pool` default features include `unit-testing`, which is what enables `near_sdk::test_utils` — confirm the dev-dependency does not set `default-features = false`.

- [ ] **Step 2: Run**

Run: `cargo test -p shielded-prover --test verify_via_contract`
Expected: PASS (2 tests). This proves the arkworks→contract byte round-trip works for a real circuit.

- [ ] **Step 3: Commit**

```bash
git add tools/prover/tests/verify_via_contract.rs
git commit -m "test(prover): withdraw proof verifies through contract alt_bn128 path"
```

---

## Phase 7 — SDK proved builders

### Task 9: async proved builders that call the injected Prover

**Files:**
- Modify: `sdk/packages/sdk/src/wallet.ts`

- [ ] **Step 1: Read the current wallet builders to mirror public-input/witness assembly**

Run: `sed -n '1,220p' sdk/packages/sdk/src/wallet.ts`
Expected: see the synchronous `buildDeposit/buildTransfer/buildWithdraw` and the `Prover`/`ProveRequest` interface from `prover.ts`. (No code change in this step — orientation only.)

- [ ] **Step 2: Add `buildWithdrawProved` (and deposit/transfer analogues) that assemble the ProveRequest and await the prover**

For each method, add an async sibling that:
1. computes the same `publicInputs` the synchronous builder produces, ordered exactly as the contract expects;
2. computes `viewCtHash` via `hashBytesToField(viewCt)` (already imported in core);
3. builds the witness object with the keys the prover expects (see Task 7/8: `noteAmount`, `noteOwnerPubkey`, `merklePath: string[20]`, etc., all 0x-prefixed 32-byte hex);
4. calls `await prover.prove({ circuit, publicInputs, witness })`;
5. returns the `BuiltTx` with `proof` set to the returned bytes.

Concrete `buildWithdrawProved` (add to the `Wallet` class; mirror field-derivation from the existing synchronous `buildWithdraw`):

```typescript
async buildWithdrawProved(req: WithdrawRequest, prover: Prover): Promise<BuiltTx> {
  const tx = this.buildWithdraw(req); // existing sync builder: public inputs + ciphertexts
  const note = req.note;
  const viewCtHash = hashBytesToField(tx.viewCiphertexts[0]).toHex();
  const merklePath = req.merklePath.map((f) => f.toHex()); // length 20
  const witness = {
    noteAmount: Field.fromU128(note.amount).toHex(),
    noteOwnerPubkey: note.ownerPubkey.toHex(),
    noteAuditorPubkey: note.auditorPubkey.toHex(),
    noteBlinding: note.blinding.toHex(),
    spendingKey: this.spendingKey.toHex(),
    leafIndex: Field.fromU128(BigInt(req.leafIndex)).toHex(),
    merklePath,
    viewCtHashWitness: viewCtHash,
  };
  const publicInputs = [
    tx.publicInputs.merkleRoot as string,
    tx.publicInputs.nullifier as string,
    tx.publicInputs.recipient as string,
    tx.publicInputs.amount as string,
    tx.publicInputs.relayer as string,
    tx.publicInputs.relayerFee as string,
    tx.publicInputs.auditorPubkey as string,
    viewCtHash,
  ];
  const proof = await prover.prove({ circuit: "withdraw", publicInputs, witness });
  return { ...tx, proof };
}
```

The exact field accessors (`tx.publicInputs.*`, `req.merklePath`, `note.*`) must match the existing types in `wallet.ts`/`types.ts`; adjust names to the real ones discovered in Step 1. Add `buildDepositProved` and `buildTransferProved` following the same shape with their respective public-input orders (deposit 4, transfer 9) and witness keys from Task 7.

- [ ] **Step 3: Write a vitest that the proved builder produces a 256-byte proof using a fake Prover**

Add to `sdk/packages/sdk/src/wallet.test.ts` (or the existing wallet test file):

```typescript
import { describe, it, expect } from "vitest";

class FakeProver {
  lastRequest: unknown;
  async prove(req: unknown): Promise<Uint8Array> {
    this.lastRequest = req;
    return new Uint8Array(256); // shape-only
  }
}

describe("buildWithdrawProved", () => {
  it("assembles 8 public inputs and a witness, returns the prover's bytes", async () => {
    const { wallet, withdrawReq } = makeWithdrawFixture(); // existing helper or inline
    const prover = new FakeProver();
    const tx = await wallet.buildWithdrawProved(withdrawReq, prover as any);
    expect(tx.proof.length).toBe(256);
    expect((prover.lastRequest as any).circuit).toBe("withdraw");
    expect((prover.lastRequest as any).publicInputs).toHaveLength(8);
    expect((prover.lastRequest as any).witness.merklePath).toHaveLength(20);
  });
});
```

If no fixture helper exists, construct a `Wallet` and a minimal `WithdrawRequest` inline using the same values the existing synchronous `buildWithdraw` test uses.

- [ ] **Step 4: Run**

Run: `cd sdk && pnpm --filter @shielded-near/sdk test wallet`
(Replace `@shielded-near/sdk` with the actual package name from `sdk/packages/sdk/package.json`.)
Expected: the new test passes; existing wallet tests still pass.

- [ ] **Step 5: Commit**

```bash
git add sdk/packages/sdk/src/wallet.ts sdk/packages/sdk/src/wallet.test.ts
git commit -m "feat(sdk): async proved tx builders that call the injected prover"
```

---

## Phase 8 — End-to-end on a real sandbox

### Task 10: near-workspaces deploy + real-proof deposit/transfer/withdraw

**Files:**
- Create: `contract/tests/e2e_real_proofs.rs`

This test builds the `groth16-verifier` WASM, runs `setup`, deploys, inits with the generated VKs, then performs a real deposit and asserts state. (Transfer/withdraw follow the same pattern; deposit is shown in full. Add transfer/withdraw after deposit passes.)

- [ ] **Step 1: Confirm the WASM + prover binary build under the features the test needs**

```bash
cargo build -p shielded-pool --target wasm32-unknown-unknown --release --no-default-features --features groth16-verifier
cargo build -p shielded-prover --release
cargo run -p shielded-prover --release -- setup --out-dir target/sp-keys
```

Expected: WASM at `target/wasm32-unknown-unknown/release/shielded_pool.wasm`; `target/sp-keys/{deposit,transfer,withdraw}.vk` exist.

- [ ] **Step 2: Write the deposit E2E test**

Gate it behind the existing `SKIP_NEAR_INTEGRATION` env convention used by the current near-workspaces test, so CI can opt in.

```rust
//! End-to-end: deploy the real groth16-verifier WASM, init with generated VKs,
//! and run a real-proof deposit. Skipped when SKIP_NEAR_INTEGRATION is set.

use std::process::{Command, Stdio};
use std::io::Write;

fn prover_bin() -> String {
    // built by `cargo build -p shielded-prover --release`
    "target/release/shielded-prover".to_string()
}

fn prove(circuit: &str, public_inputs: &[String], witness: serde_json::Value, key_dir: &str) -> Vec<u8> {
    let req = serde_json::json!({ "circuit": circuit, "publicInputs": public_inputs, "witness": witness });
    let mut child = Command::new(prover_bin())
        .env("PROVER_KEY_DIR", key_dir)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().expect("spawn prover");
    child.stdin.take().unwrap().write_all(req.to_string().as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "prover failed: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.stdout.len(), 256, "proof must be 256 bytes");
    out.stdout
}

#[tokio::test]
async fn e2e_real_deposit() -> anyhow::Result<()> {
    if std::env::var("SKIP_NEAR_INTEGRATION").is_ok() {
        eprintln!("skipping: SKIP_NEAR_INTEGRATION set");
        return Ok(());
    }
    let key_dir = "target/sp-keys";
    let vk = |n: &str| std::fs::read(format!("{key_dir}/{n}.vk")).expect("vk; run prover setup");

    let worker = near_workspaces::sandbox().await?;
    let wasm = std::fs::read("target/wasm32-unknown-unknown/release/shielded_pool.wasm")?;
    let contract = worker.dev_deploy(&wasm).await?;

    // init with generated VKs (and whatever other args `new` needs — usdc token, owner).
    contract.call("new")
        .args_json(serde_json::json!({
            "owner": contract.id(),
            "usdc_token": contract.id(),
            "vk_deposit": vk("deposit"),
            "vk_transfer": vk("transfer"),
            "vk_withdraw": vk("withdraw"),
        }))
        .transact().await?.into_result()?;

    // Deposit fields. commitment = poseidon4(amount, owner, auditor, blinding),
    // computed off-chain with the prover's gadget (helper `eval4` below).
    let amount: u128 = 1_000_000;
    let owner = eval2(Fr::from(7u64), Fr::from(0u64)); // owner_pubkey_of(sk=7)
    let auditor = Fr::from(22u64);
    let blinding = Fr::from(33u64);
    let commitment = eval4(Fr::from(amount), owner, auditor, blinding);

    // view_ct / note_ct are opaque ciphertext strings here; the contract hashes
    // view_ct via hash_bytes_to_field to form the 4th public input. Recompute
    // the SAME hash off-chain (port of contract::deposit::hash_bytes_to_field:
    // 31-byte LE chunks folded by poseidon2). For a single short ciphertext this
    // is one chunk: hash = poseidon2-fold over chunks; use `hash_bytes` helper.
    let view_ct = "deadbeef";
    let note_ct = "cafe";
    let view_ct_hash = hash_bytes_to_field(view_ct.as_bytes()); // helper defined in this test file

    let public_inputs = vec![
        fr_hex(commitment), fr_hex(Fr::from(amount)), fr_hex(auditor), fr_hex(view_ct_hash),
    ];
    let witness = serde_json::json!({
        "ownerPubkey": fr_hex(owner),
        "blinding": fr_hex(blinding),
        "viewCtHashWitness": fr_hex(view_ct_hash),
    });
    let proof = prove("deposit", &public_inputs, witness, key_dir);

    let root_before: String = contract.view("merkle_root").await?.json()?;
    contract.call("deposit")
        .args_json(serde_json::json!({
            "args": {
                "commitment": fr_hex(commitment),
                "amount": amount.to_string(),
                "auditor_pubkey": fr_hex(auditor),
                "view_ct": view_ct,
                "note_ct": note_ct,
                "proof": proof,
            }
        }))
        .deposit(near_workspaces::types::NearToken::from_near(1)) // storage staking
        .max_gas()
        .transact().await?.into_result()?;
    let root_after: String = contract.view("merkle_root").await?.json()?;
    assert_ne!(root_before, root_after, "deposit did not advance the Merkle root");
    Ok(())
}
```

Helpers this test file must define (in addition to `prove` from Step earlier):
- `eval2` / `eval4`: synthesize `shielded_prover::circuits::gadgets::poseidon2/4` in a throwaway `ConstraintSystem` and read `.value()` (exactly as in `tools/prover/src/circuits/withdraw.rs` tests). Make `shielded-prover` a dev-dependency of `contract`.
- `fr_hex(f: Fr) -> String`: 0x + big-endian 32-byte hex (same as the gadget test's `fr_hex`).
- `hash_bytes_to_field(&[u8]) -> Fr`: port of `contract::deposit::hash_bytes_to_field` — split into 31-byte little-endian chunks, single chunk → that field; multiple → left-fold with `eval2`. Read `contract/src/deposit.rs:28` for the exact rule and mirror it. The SDK's `hashBytesToField` (`sdk/packages/core/src/hash_bytes.ts`) documents the same algorithm and can be used to cross-check.

The `deposit` entry takes a single `args: DepositArgs { commitment: String, amount: U128, auditor_pubkey: String, view_ct: String, note_ct: String, proof: Vec<u8> }` (see `contract/src/deposit.rs:47`). Confirm the exact deposit method wrapper name and whether it is `deposit` or routed through `ft_on_transfer`; the unit-test `deposit` entry at `contract/src/deposit.rs:96` is the one to call here.

- [ ] **Step 3: Run the E2E deposit**

Run: `cargo build -p shielded-prover --release && cargo run -p shielded-prover --release -- setup --out-dir target/sp-keys && cargo test -p shielded-pool --test e2e_real_proofs`
Expected: PASS — deposit with a real proof verifies on the deployed contract and the Merkle root advances.

- [ ] **Step 4: Add transfer and withdraw flows to the same test file**

Extend the test: after deposit, build a transfer spending the deposited note (its `leaf_index` from the deposit result, real `merklePath` from the contract's tree state or reconstructed), assert nullifiers spent; then a withdraw, assert payout recorded. Use the same `prove(...)` helper. Mirror the witness assembly from Task 7.

- [ ] **Step 5: Run full E2E**

Run: `cargo test -p shielded-pool --test e2e_real_proofs`
Expected: PASS — deposit → transfer → withdraw all verify with real proofs.

- [ ] **Step 6: Commit**

```bash
git add contract/tests/e2e_real_proofs.rs contract/Cargo.toml
git commit -m "test(e2e): real-proof deposit/transfer/withdraw against deployed verifier"
```

---

## Phase 9 — Production-readiness gate + docs

### Task 11: wire setup+prove into the readiness script and flip status

**Files:**
- Modify: `scripts/check-production-readiness.sh`
- Modify: `README.md`

- [ ] **Step 1: Read the current readiness script's "real proofs" check**

Run: `sed -n '40,200p' scripts/check-production-readiness.sh`
Expected: find the step that currently fails on "tools/prover proves only mul" / the 256-byte real-proof check.

- [ ] **Step 2: Update the script to generate keys and prove all three circuits**

Replace the failing real-prover step with: build the prover, run `setup`, and for each of `deposit`/`transfer`/`withdraw` pipe a known-good `ProveRequest` (from a committed fixture under `tools/prover/fixtures/<circuit>.json`) into the binary and assert stdout is exactly 256 bytes. Create those three fixture JSON files using the honest witnesses from the circuit tests (Tasks 4–6). Example check (bash):

```bash
mkdir -p "$ROOT/target/sp-keys"
cargo run -q -p shielded-prover --release -- setup --out-dir "$ROOT/target/sp-keys"
for c in deposit transfer withdraw; do
  n=$(PROVER_KEY_DIR="$ROOT/target/sp-keys" cargo run -q -p shielded-prover --release \
        < "$ROOT/tools/prover/fixtures/$c.json" | wc -c | tr -d ' ')
  [ "$n" = "256" ] || add_failure "prover did not emit a 256-byte proof for $c (got $n)"
done
```

- [ ] **Step 3: Create the three fixture files**

`tools/prover/fixtures/withdraw.json` (values from `WithdrawCircuit` honest fixture; compute the hashed fields with `cargo run -p shielded-prover -- ...` or a tiny throwaway, then hardcode). Each file is `{ "circuit": "...", "publicInputs": [...], "witness": {...} }` with 0x-prefixed 32-byte hex. Deposit and transfer analogues likewise.

- [ ] **Step 4: Run the readiness gate**

Run: `bash scripts/check-production-readiness.sh`
Expected: `PRODUCTION READINESS: ...` — the real-proof checks now pass. (Other gates like WASM size already pass.) If it still reports the prover blocker, the wiring in Step 2 is incomplete.

- [ ] **Step 5: Update README status**

In `README.md`, change the "Remaining release blocker" section: the prover blocker is resolved for **sandbox**. Add a pointer to the new "Path to production" section in the spec for the remaining mainnet gates (trusted setup ceremony, circuit soundness review, external audit). Do NOT claim mainnet-ready. Keep the sandbox-only warning.

- [ ] **Step 6: Run the full suite**

Run: `cargo test -p shielded-pool && cargo test -p shielded-prover && (cd sdk && pnpm -r test)`
Expected: all green (E2E test honors `SKIP_NEAR_INTEGRATION` if the sandbox is unavailable).

- [ ] **Step 7: Commit**

```bash
git add scripts/check-production-readiness.sh tools/prover/fixtures README.md
git commit -m "feat: production-readiness gate proves all three circuits; README sandbox-ready"
```

---

## Self-review notes (for the executor)

- **Crate package name:** commands above use `-p shielded-prover`; the actual name is the `[package].name` in `tools/prover/Cargo.toml`. Use the real name everywhere.
- **`rng()` seed literal:** must be a valid Rust integer literal — use `StdRng::seed_from_u64(0x5151_3ded_u64)` and delete the `SETUP_SEED` const. Determinism matters so the same `setup` reproduces the same VKs.
- **Public-input order is load-bearing.** If a proof verifies in `verify_via_contract` but fails on-chain in the E2E test, the first suspect is public-input ordering or the SDK's `view_ct_hash` not matching the contract's `hash_bytes_to_field`.
- **The Poseidon vector gate (Task 2) is the keystone.** If it fails, every downstream proof is meaningless — do not proceed past it.
- **Setup is a seeded prototype, not a ceremony.** The spec's Path to production gates 3–5 (soundness review, trusted-setup ceremony, audit) remain before any funds.
