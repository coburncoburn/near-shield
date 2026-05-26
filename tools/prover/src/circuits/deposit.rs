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
    pub commitment: Option<Fr>,
    pub amount: Option<Fr>,
    pub auditor_pubkey: Option<Fr>,
    pub view_ct_hash: Option<Fr>,
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
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;

    fn native_commit(amount: Fr, owner: Fr, auditor: Fr, blinding: Fr) -> Fr {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mk = |v: Fr| FpVar::new_witness(cs.clone(), || Ok(v)).unwrap();
        commit_note(&mk(amount), &mk(owner), &mk(auditor), &mk(blinding))
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
            amount: Some(Fr::from(200u64)),
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
