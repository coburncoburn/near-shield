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

        let root = pin!(self.merkle_root);
        let null0 = pin!(self.nullifier0);
        let null1 = pin!(self.nullifier1);
        let cout0 = pin!(self.commitment_out0);
        let cout1 = pin!(self.commitment_out1);
        let auditor = pin!(self.auditor_pubkey);
        let recip_auditor = pin!(self.recipient_auditor_pubkey);
        let vh_sender = pin!(self.view_ct_hash_sender);
        let vh_recipient = pin!(self.view_ct_hash_recipient);

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

        let out0_amount = wit!(self.out0_amount);
        let out0_owner = wit!(self.out0_owner_pubkey);
        let out0_blind = wit!(self.out0_blinding);
        let out1_amount = wit!(self.out1_amount);
        let out1_owner = wit!(self.out1_owner_pubkey);
        let out1_blind = wit!(self.out1_blinding);
        let vh_sender_w = wit!(self.view_ct_hash_sender_witness);
        let vh_recipient_w = wit!(self.view_ct_hash_recipient_witness);

        let c_in0 = commit_note(&in0_amount, &in0_owner, &auditor, &in0_blind)?;
        let c_in1 = commit_note(&in1_amount, &in1_owner, &auditor, &in1_blind)?;

        let owner = owner_pubkey_of(&sk)?;
        owner.enforce_equal(&in0_owner)?;
        owner.enforce_equal(&in1_owner)?;

        nullifier_of(&sk, &c_in0, &in0_idx)?.enforce_equal(&null0)?;
        nullifier_of(&sk, &c_in1, &in1_idx)?.enforce_equal(&null1)?;

        // Bind both leaf indices to DEPTH bits: merkle_inclusion only consumes
        // the low DEPTH bits, but nullifier_of binds the full field value, so an
        // unconstrained high part would let one note produce many nullifiers.
        enforce_bits(&in0_idx, DEPTH)?;
        enforce_bits(&in1_idx, DEPTH)?;
        let b0 = in0_idx.to_bits_le()?;
        merkle_inclusion(&root, &c_in0, &b0[..DEPTH], &in0_path)?;
        let b1 = in1_idx.to_bits_le()?;
        merkle_inclusion(&root, &c_in1, &b1[..DEPTH], &in1_path)?;

        commit_note(&out0_amount, &out0_owner, &recip_auditor, &out0_blind)?.enforce_equal(&cout0)?;
        commit_note(&out1_amount, &out1_owner, &recip_auditor, &out1_blind)?.enforce_equal(&cout1)?;

        enforce_bits(&in0_amount, AMOUNT_BITS)?;
        enforce_bits(&in1_amount, AMOUNT_BITS)?;
        enforce_bits(&out0_amount, AMOUNT_BITS)?;
        enforce_bits(&out1_amount, AMOUNT_BITS)?;

        (&in0_amount + &in1_amount).enforce_equal(&(&out0_amount + &out1_amount))?;

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
        let recip_auditor = Fr::from(33u64);
        c.out0_amount = Some(Fr::from(150u64));
        c.commitment_out0 = Some(eval4(Fr::from(150u64), Fr::from(100u64), recip_auditor, Fr::from(3u64)));
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn wraparound_mint_unsatisfiable() {
        let mut c = honest();
        let recip_auditor = Fr::from(33u64);
        // A field element well above 2^128 (does NOT fit in AMOUNT_BITS).
        let huge = Fr::from(1u128 << 100) * Fr::from(1u128 << 30);
        // Pick out1 so value conservation holds in the field: huge + out1 == 100.
        let out1 = Fr::from(100u64) - huge;
        c.out0_amount = Some(huge);
        c.out1_amount = Some(out1);
        c.commitment_out0 = Some(eval4(huge, Fr::from(100u64), recip_auditor, Fr::from(3u64)));
        c.commitment_out1 = Some(eval4(out1, owner_of(Fr::from(7u64)), recip_auditor, Fr::from(4u64)));
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

    // Regression: in0_leaf_index must be range-checked to DEPTH bits. 2^DEPTH
    // shares the low DEPTH bits of index 0, so merkle inclusion still holds; we
    // recompute nullifier0 for it so that constraint holds too. Only the range
    // check prevents one input note from yielding many distinct nullifiers.
    #[test]
    fn input_leaf_index_above_depth_unsatisfiable() {
        let sk = Fr::from(7u64);
        let owner = owner_of(sk);
        let auditor = Fr::from(22u64);
        let c_in0 = eval4(Fr::from(60u64), owner, auditor, Fr::from(1u64));
        let evil_index = Fr::from(1u64 << DEPTH); // low DEPTH bits == 0, == index 0
        let mut c = honest(); // in0 path/root are for leaf at index 0
        c.in0_leaf_index = Some(evil_index);
        c.nullifier0 = Some(null_of(sk, c_in0, evil_index)); // nullifier holds
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
}
