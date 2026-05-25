//! End-to-end with the real CLI: invoke the prover binary as a subprocess,
//! capture its 256-byte EIP-196/197 output, and verify it via the contract's
//! `verify_groth16` function. Mirrors what the TypeScript `SubprocessProver`
//! will do at runtime.
//!
//! Note: this test re-runs `circuit_specific_setup` inside the prover CLI on
//! every invocation, so the VK isn't shared with what we'd verify against.
//! Instead, we verify the prover by parsing its output and running the same
//! arkworks setup deterministically -- if the prover's RNG and ours align, we
//! get a matching VK. (Production CLIs persist VK/PK and load them.)

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
use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Clone)]
struct Mul {
    a: Option<Fr>,
    b: Option<Fr>,
    c: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for Mul {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| self.c.ok_or(SynthesisError::AssignmentMissing))?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)
    }
}

fn g1_to_eip196(p: G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    if let Some((x, y)) = p.xy() {
        let xb = x.into_bigint().to_bytes_le();
        let yb = y.into_bigint().to_bytes_le();
        out[..xb.len()].copy_from_slice(&xb);
        out[32..32 + yb.len()].copy_from_slice(&yb);
    }
    out
}

fn g2_to_eip197(p: G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    if let Some((x, y)) = p.xy() {
        let segs = [
            x.c0.into_bigint().to_bytes_le(),
            x.c1.into_bigint().to_bytes_le(),
            y.c0.into_bigint().to_bytes_le(),
            y.c1.into_bigint().to_bytes_le(),
        ];
        for (i, s) in segs.iter().enumerate() {
            out[i * 32..i * 32 + s.len()].copy_from_slice(s);
        }
    }
    out
}

fn build_vk_bytes(vk: &ark_groth16::VerifyingKey<Bn254>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&g1_to_eip196(vk.alpha_g1));
    out.extend_from_slice(&g2_to_eip197(vk.beta_g2));
    out.extend_from_slice(&g2_to_eip197(vk.gamma_g2));
    out.extend_from_slice(&g2_to_eip197(vk.delta_g2));
    for g in &vk.gamma_abc_g1 {
        out.extend_from_slice(&g1_to_eip196(*g));
    }
    out
}

fn prover_path() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{manifest_dir}/../target/release/shielded-prover")
}

#[test]
#[ignore] // requires `cargo build -p shielded-prover --release` first
fn cli_prover_output_verifies_via_contract() {
    testing_env!(VMContextBuilder::new().build());

    let path = prover_path();
    if !std::path::Path::new(&path).exists() {
        eprintln!("SKIP: prover binary missing at {path}; run `cargo build -p shielded-prover --release` first");
        return;
    }

    // Match the prover's seed (0xcafe_babe) and statement (a=3, b=5, c=15).
    let mut rng = StdRng::seed_from_u64(0xcafe_babe);
    let setup_circuit = Mul {
        a: Some(Fr::from(3u64)),
        b: Some(Fr::from(5u64)),
        c: Some(Fr::from(15u64)),
    };
    let (_pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup_circuit, &mut rng).unwrap();

    let req = serde_json::json!({
        "circuit": "mul",
        "publicInputs": ["0x000000000000000000000000000000000000000000000000000000000000000f"],
        "witness": {
            "a": "0x0000000000000000000000000000000000000000000000000000000000000003",
            "b": "0x0000000000000000000000000000000000000000000000000000000000000005",
        }
    });

    let mut child = Command::new(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn prover");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(req.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().expect("wait prover");
    assert!(output.status.success(), "prover failed: {:?}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(output.stdout.len(), 256, "expected 256-byte proof");

    let vk_bytes = build_vk_bytes(&vk);
    let parsed_vk = VerifyingKey::from_bytes(&vk_bytes).expect("parse VK");
    let parsed_proof = Proof::from_bytes(&output.stdout).expect("parse proof");
    let inputs = vec![MyField::from_u64(15)];

    let ok = verify_groth16(&parsed_vk, &parsed_proof, &inputs);
    assert!(ok, "contract rejected real proof produced by CLI");
}
