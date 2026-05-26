use ark_bn254::Fr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::ToBitsGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::circuits::gadgets::{
    commit_note, enforce_bits, enforce_u64_geq, merkle_inclusion, nullifier_of, owner_pubkey_of,
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
            merkle_root: None, nullifier: None, recipient: None, amount: None,
            relayer: None, relayer_fee: None, auditor_pubkey: None, view_ct_hash: None,
            note_amount: None, note_owner_pubkey: None, note_auditor_pubkey: None,
            note_blinding: None, spending_key: None, leaf_index: None,
            merkle_path: None, view_ct_hash_witness: None,
        }
    }
}

impl ConstraintSynthesizer<Fr> for WithdrawCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let miss = || SynthesisError::AssignmentMissing;

        let root = FpVar::new_input(cs.clone(), || self.merkle_root.ok_or_else(miss))?;
        let nullifier = FpVar::new_input(cs.clone(), || self.nullifier.ok_or_else(miss))?;
        let recipient = FpVar::new_input(cs.clone(), || self.recipient.ok_or_else(miss))?;
        let amount = FpVar::new_input(cs.clone(), || self.amount.ok_or_else(miss))?;
        let relayer = FpVar::new_input(cs.clone(), || self.relayer.ok_or_else(miss))?;
        let relayer_fee = FpVar::new_input(cs.clone(), || self.relayer_fee.ok_or_else(miss))?;
        let auditor = FpVar::new_input(cs.clone(), || self.auditor_pubkey.ok_or_else(miss))?;
        let view_ct_hash = FpVar::new_input(cs.clone(), || self.view_ct_hash.ok_or_else(miss))?;

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

        recipient.enforce_equal(&recipient)?;
        relayer.enforce_equal(&relayer)?;

        let commitment = commit_note(&note_amount, &note_owner, &note_auditor, &note_blinding)?;

        owner_pubkey_of(&sk)?.enforce_equal(&note_owner)?;
        nullifier_of(&sk, &commitment, &leaf_index)?.enforce_equal(&nullifier)?;
        note_amount.enforce_equal(&amount)?;
        note_auditor.enforce_equal(&auditor)?;
        enforce_u64_geq(&amount, &relayer_fee)?;
        view_ct_hash.enforce_equal(&vh_witness)?;

        // Bind leaf_index to DEPTH bits. Without this, high bits are free while
        // merkle_inclusion only consumes the low DEPTH bits, yet nullifier_of
        // binds the full field value — so the same note at index i, i+2^DEPTH,
        // ... would yield distinct nullifiers and be spendable repeatedly.
        enforce_bits(&leaf_index, DEPTH)?;
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
            merkle_root: Some(root), nullifier: Some(n), recipient: Some(Fr::from(99u64)),
            amount: Some(amount), relayer: Some(Fr::from(77u64)), relayer_fee: Some(Fr::from(5u64)),
            auditor_pubkey: Some(auditor), view_ct_hash: Some(Fr::from(13u64)),
            note_amount: Some(amount), note_owner_pubkey: Some(owner),
            note_auditor_pubkey: Some(auditor), note_blinding: Some(blinding),
            spending_key: Some(sk), leaf_index: Some(Fr::from(0u64)),
            merkle_path: Some(path), view_ct_hash_witness: Some(Fr::from(13u64)),
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
        c.spending_key = Some(Fr::from(8u64));
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
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn fee_exceeds_amount_unsatisfiable() {
        let mut c = honest();
        c.relayer_fee = Some(Fr::from(101u64));
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    // Regression: leaf_index must be range-checked to DEPTH bits. An index of
    // 2^DEPTH has the same low DEPTH bits as index 0, so merkle inclusion still
    // holds, and we recompute the nullifier for it so that constraint also
    // holds. Only the range check stands between this and a multi-spend of one
    // note (distinct nullifiers for i, i+2^DEPTH, ...). Must be unsatisfiable.
    #[test]
    fn leaf_index_above_depth_unsatisfiable() {
        let sk = Fr::from(7u64);
        let owner = owner_of(sk);
        let auditor = Fr::from(22u64);
        let blinding = Fr::from(33u64);
        let amount = Fr::from(100u64);
        let commitment = eval4(amount, owner, auditor, blinding);
        let evil_index = Fr::from(1u64 << DEPTH); // low DEPTH bits == 0, == index 0
        let mut c = honest(); // merkle_root/path are for leaf at index 0
        c.leaf_index = Some(evil_index);
        c.nullifier = Some(null_of(sk, commitment, evil_index)); // nullifier constraint holds
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
}
