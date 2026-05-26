use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
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
    bad[3] = Fr::from(101u64);
    let inputs: Vec<MyField> = bad.iter().map(|f| fr_to_myfield(*f)).collect();
    assert!(!verify_groth16(&parsed_vk, &parsed_proof, &inputs), "tampered input accepted");
}
