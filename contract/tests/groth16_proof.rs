//! End-to-end proof: arkworks generates a real Groth16 proof, we serialize
//! it to EIP-196/197 wire format, the contract's `groth16::verify_groth16`
//! validates it via NEAR's `alt_bn128_*` host functions (mocked in unit
//! tests by the near-sdk runtime, real on chain).
//!
//! This is the proof that the verifier actually works -- not just that the
//! code compiles, but that real prover output round-trips through the wire
//! format and verifies under the host-function precompile path.

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::testing_env;
use shielded_pool::groth16::{verify_groth16, Proof, VerifyingKey};
use shielded_pool::poseidon::Field as MyField;

/// Toy circuit: proves knowledge of a, b such that a * b == public.
/// Mirrors the structure of a Honk/Groth16 deposit witness without doing
/// the real Poseidon math, which we cover in dedicated cross-language tests.
#[derive(Clone)]
struct Mul {
    a: Option<Fr>,
    b: Option<Fr>,
    c: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for Mul {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a_var = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b_var = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c_var = cs.new_input_variable(|| self.c.ok_or(SynthesisError::AssignmentMissing))?;
        cs.enforce_constraint(lc!() + a_var, lc!() + b_var, lc!() + c_var)
    }
}

// ----- EIP-196/197 wire format encoders -----

fn fr_to_le_32(f: Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = f.into_bigint().to_bytes_le();
    out[..bytes.len()].copy_from_slice(&bytes);
    out
}

fn g1_to_eip196(p: G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    if p.is_zero() {
        return out;
    }
    let (x, y) = p.xy().unwrap();
    // EIP-196: x_le || y_le (32 + 32 bytes, little-endian per the host fn).
    let x_bytes = x.into_bigint().to_bytes_le();
    let y_bytes = y.into_bigint().to_bytes_le();
    out[..x_bytes.len()].copy_from_slice(&x_bytes);
    out[32..32 + y_bytes.len()].copy_from_slice(&y_bytes);
    out
}

fn g2_to_eip197(p: G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    if p.is_zero() {
        return out;
    }
    let (x, y) = p.xy().unwrap();
    // BN254 G2 is over Fq2. NEAR host fn expects: x.c0 || x.c1 || y.c0 || y.c1
    let x_c0 = x.c0.into_bigint().to_bytes_le();
    let x_c1 = x.c1.into_bigint().to_bytes_le();
    let y_c0 = y.c0.into_bigint().to_bytes_le();
    let y_c1 = y.c1.into_bigint().to_bytes_le();
    out[..x_c0.len()].copy_from_slice(&x_c0);
    out[32..32 + x_c1.len()].copy_from_slice(&x_c1);
    out[64..64 + y_c0.len()].copy_from_slice(&y_c0);
    out[96..96 + y_c1.len()].copy_from_slice(&y_c1);
    out
}

fn build_vk_bytes(ark_vk: &ark_groth16::VerifyingKey<Bn254>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&g1_to_eip196(ark_vk.alpha_g1));
    out.extend_from_slice(&g2_to_eip197(ark_vk.beta_g2));
    out.extend_from_slice(&g2_to_eip197(ark_vk.gamma_g2));
    out.extend_from_slice(&g2_to_eip197(ark_vk.delta_g2));
    for g1 in &ark_vk.gamma_abc_g1 {
        out.extend_from_slice(&g1_to_eip196(*g1));
    }
    out
}

fn build_proof_bytes(ark_proof: &ark_groth16::Proof<Bn254>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&g1_to_eip196(ark_proof.a));
    out.extend_from_slice(&g2_to_eip197(ark_proof.b));
    out.extend_from_slice(&g1_to_eip196(ark_proof.c));
    out
}

fn fr_to_myfield(f: Fr) -> MyField {
    // MyField is the contract's BN254 Fr wrapper; round-trip via big-endian bytes.
    let mut bytes = f.into_bigint().to_bytes_be();
    while bytes.len() < 32 {
        bytes.insert(0, 0);
    }
    MyField::from_be_bytes(&bytes)
}

#[test]
fn real_groth16_proof_verifies_via_alt_bn128_host_fns() {
    testing_env!(VMContextBuilder::new().build());

    let mut rng = StdRng::seed_from_u64(0x5_153_1d3d_u64);

    // Setup
    let circuit = Mul { a: Some(Fr::from(3u64)), b: Some(Fr::from(5u64)), c: Some(Fr::from(15u64)) };
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();

    // Prove
    let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut rng).unwrap();

    // Sanity-check via arkworks's own verifier first
    let prepared_vk = Groth16::<Bn254>::process_vk(&vk).unwrap();
    let ark_says_ok = Groth16::<Bn254>::verify_with_processed_vk(
        &prepared_vk,
        &[Fr::from(15u64)],
        &proof,
    )
    .unwrap();
    assert!(ark_says_ok, "arkworks rejected its own proof");

    // Now: serialize to EIP-196/197 and verify through our contract path
    let vk_bytes = build_vk_bytes(&vk);
    let proof_bytes = build_proof_bytes(&proof);

    let parsed_vk = VerifyingKey::from_bytes(&vk_bytes).expect("parse VK");
    let parsed_proof = Proof::from_bytes(&proof_bytes).expect("parse proof");
    let public_inputs = vec![fr_to_myfield(Fr::from(15u64))];

    let ok = verify_groth16(&parsed_vk, &parsed_proof, &public_inputs);
    assert!(ok, "host-function path rejected a real Groth16 proof");
}

#[test]
fn real_groth16_proof_with_wrong_public_input_rejects() {
    testing_env!(VMContextBuilder::new().build());

    let mut rng = StdRng::seed_from_u64(0xb4dd474);

    let circuit = Mul { a: Some(Fr::from(7u64)), b: Some(Fr::from(11u64)), c: Some(Fr::from(77u64)) };
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();

    let vk_bytes = build_vk_bytes(&vk);
    let proof_bytes = build_proof_bytes(&proof);
    let parsed_vk = VerifyingKey::from_bytes(&vk_bytes).unwrap();
    let parsed_proof = Proof::from_bytes(&proof_bytes).unwrap();

    // Lie about the public input: claim c = 78 instead of 77.
    let bad_inputs = vec![fr_to_myfield(Fr::from(78u64))];
    let ok = verify_groth16(&parsed_vk, &parsed_proof, &bad_inputs);
    assert!(!ok, "verifier accepted a wrong-public-input claim");
}

#[test]
fn real_groth16_proof_from_other_witness_rejects() {
    // Build VK for one witness, then submit a proof from a DIFFERENT witness
    // and try to claim the original public input. The pairing check should
    // fail since the proof attests to a different statement under that VK.
    testing_env!(VMContextBuilder::new().build());

    let mut rng = StdRng::seed_from_u64(0xfee1_dead_u64);

    // Setup for c = a * b where a=2, b=6, c=12.
    let setup_circuit = Mul { a: Some(Fr::from(2u64)), b: Some(Fr::from(6u64)), c: Some(Fr::from(12u64)) };
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup_circuit, &mut rng).unwrap();

    // Prove a DIFFERENT statement under the same pk: c=20 (a=4, b=5).
    let other_circuit = Mul { a: Some(Fr::from(4u64)), b: Some(Fr::from(5u64)), c: Some(Fr::from(20u64)) };
    let other_proof = Groth16::<Bn254>::prove(&pk, other_circuit, &mut rng).unwrap();

    let vk_bytes = build_vk_bytes(&vk);
    let proof_bytes = build_proof_bytes(&other_proof);
    let parsed_vk = VerifyingKey::from_bytes(&vk_bytes).unwrap();
    let parsed_proof = Proof::from_bytes(&proof_bytes).unwrap();

    // Claim public input = 12, but the proof is for c=20.
    let lying_inputs = vec![fr_to_myfield(Fr::from(12u64))];
    let ok = verify_groth16(&parsed_vk, &parsed_proof, &lying_inputs);
    assert!(!ok, "verifier accepted a proof for the wrong statement");
}
