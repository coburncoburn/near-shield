//! R1CS gadgets over BN254 Fr, matching the Circom-parameter Poseidon used by
//! the contract (`contract/src/poseidon.rs`), the Noir circuits, and the SDK.

use ark_bn254::Fr;
use ark_ff::Zero;
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

    let mut state: Vec<FpVar<Fr>> = Vec::with_capacity(width);
    state.push(FpVar::constant(Fr::zero()));
    for inp in inputs {
        state.push(inp.clone());
    }

    let half = p.full_rounds / 2;
    let total = p.full_rounds + p.partial_rounds;

    for round in 0..total {
        for i in 0..width {
            let c = FpVar::constant(p.ark[round * width + i]);
            state[i] = &state[i] + &c;
        }
        let full = round < half || round >= half + p.partial_rounds;
        if full {
            for i in 0..width {
                state[i] = state[i].pow_by_constant([p.alpha])?;
            }
        } else {
            state[0] = state[0].pow_by_constant([p.alpha])?;
        }
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
    enforce_bits(&diff, 64)?;
    Ok(())
}

/// Depth-`DEPTH` Merkle inclusion. `index_bits` are LE bits of leaf_index.
pub fn merkle_inclusion(
    root: &FpVar<Fr>,
    leaf: &FpVar<Fr>,
    index_bits: &[Boolean<Fr>],
    path: &[FpVar<Fr>],
) -> Result<(), SynthesisError> {
    let mut current = leaf.clone();
    for (level, sibling) in path.iter().enumerate() {
        let bit = &index_bits[level];
        let left = FpVar::conditionally_select(bit, sibling, &current)?;
        let right = FpVar::conditionally_select(bit, &current, sibling)?;
        current = poseidon2(&left, &right)?;
    }
    current.enforce_equal(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::PrimeField;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::R1CSVar;
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

    #[test]
    fn merkle_depth2_leaf0_verifies() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mk = |x: u64| FpVar::new_witness(cs.clone(), || Ok(Fr::from(x))).unwrap();
        let (l0, l1, l2, l3) = (mk(10), mk(20), mk(30), mk(40));
        let h01 = poseidon2(&l0, &l1).unwrap();
        let h23 = poseidon2(&l2, &l3).unwrap();
        let root = poseidon2(&h01, &h23).unwrap();
        let bits = vec![Boolean::FALSE, Boolean::FALSE];
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
        merkle_inclusion(&root, &l0, &bits, &[l2.clone(), h23.clone()]).unwrap();
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
        assert!(!cs.is_satisfied().unwrap());
    }
}
