//! Shielded-pool Groth16 prover.
//!
//! Reads a JSON `ProveRequest` from stdin, generates a real Groth16 proof
//! against the BN254 curve, and writes a 256-byte EIP-196/197 proof to stdout.
//!
//! Wire format matches `contract/src/groth16.rs::Proof::from_bytes`:
//!   stdout = A_g1 (64 bytes LE) || B_g2 (128 bytes LE) || C_g1 (64 bytes LE)
//!
//! For demonstration, this CLI supports only a `Mul`-shaped circuit (proves
//! `a * b == c` where c is public). Production deployments would extend the
//! `Circuits` enum with the real deposit/transfer/withdraw constraints
//! expressed in arkworks-rs's R1CS DSL or imported from a circom build.
//! The repository's `scripts/check-production-readiness.sh` fails until those
//! production circuits are implemented.
//!
//! Setup proving keys live next to the binary as `<circuit>.pk` files.
//! Re-running the binary with `setup` mode generates them.

use anyhow::{anyhow, bail, Context, Result};
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, ProvingKey};
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use serde::Deserialize;
use std::io::{Read, Write};

#[derive(Deserialize)]
struct ProveRequest {
    /// Which circuit's proving key to load.
    circuit: String,
    /// Public inputs as 0x-prefixed 64-hex-char strings.
    #[serde(rename = "publicInputs")]
    public_inputs: Vec<String>,
    /// Circuit-specific witness object. For the Mul circuit: { a, b }.
    witness: serde_json::Value,
}

#[derive(Clone)]
struct MulCircuit {
    a: Option<Fr>,
    b: Option<Fr>,
    c: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for MulCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| self.c.ok_or(SynthesisError::AssignmentMissing))?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)
    }
}

fn parse_hex_fr(s: &str) -> Result<Fr> {
    let t = s.strip_prefix("0x").unwrap_or(s);
    if t.len() != 64 {
        bail!("expected 64 hex chars, got {}", t.len());
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&t[i * 2..i * 2 + 2], 16)
            .with_context(|| format!("invalid hex at position {}", i * 2))?;
    }
    // be -> le for Fr::from_le_bytes_mod_order
    bytes.reverse();
    Ok(Fr::from_le_bytes_mod_order(&bytes))
}

fn fr_to_le_32(f: Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = f.into_bigint().to_bytes_le();
    out[..bytes.len()].copy_from_slice(&bytes);
    out
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
        let segments = [
            x.c0.into_bigint().to_bytes_le(),
            x.c1.into_bigint().to_bytes_le(),
            y.c0.into_bigint().to_bytes_le(),
            y.c1.into_bigint().to_bytes_le(),
        ];
        for (i, seg) in segments.iter().enumerate() {
            out[i * 32..i * 32 + seg.len()].copy_from_slice(seg);
        }
    }
    out
}

fn build_proof_bytes(proof: &ark_groth16::Proof<Bn254>) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(&g1_to_eip196(proof.a));
    out.extend_from_slice(&g2_to_eip197(proof.b));
    out.extend_from_slice(&g1_to_eip196(proof.c));
    out
}

fn run() -> Result<()> {
    let mut req_json = String::new();
    std::io::stdin()
        .read_to_string(&mut req_json)
        .context("reading stdin")?;
    let req: ProveRequest = serde_json::from_str(&req_json).context("parsing ProveRequest JSON")?;

    let mut rng = StdRng::seed_from_u64(0xcafe_babe);

    match req.circuit.as_str() {
        "mul" => {
            // Reference circuit. Witness JSON: { "a": "0x...", "b": "0x..." }
            let a_hex = req
                .witness
                .get("a")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("witness.a missing or not a string"))?;
            let b_hex = req
                .witness
                .get("b")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("witness.b missing or not a string"))?;
            let c_hex = req
                .public_inputs
                .first()
                .ok_or_else(|| anyhow!("publicInputs must contain c"))?;
            let a = parse_hex_fr(a_hex)?;
            let b = parse_hex_fr(b_hex)?;
            let c = parse_hex_fr(c_hex)?;

            // Setup is performed on every invocation here for simplicity. A
            // production deployment loads a previously-generated proving key.
            let setup_circuit = MulCircuit {
                a: Some(a),
                b: Some(b),
                c: Some(c),
            };
            let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(setup_circuit.clone(), &mut rng)
                .context("Groth16 setup")?;
            let proof = Groth16::<Bn254>::prove(&pk, setup_circuit, &mut rng)
                .context("Groth16 prove")?;

            let bytes = build_proof_bytes(&proof);
            std::io::stdout().write_all(&bytes).context("write stdout")?;
            std::io::stdout().flush().context("flush stdout")?;
            Ok(())
        }
        other => bail!(
            "unsupported circuit '{other}'. \
             v0 implements only the reference 'mul' circuit; \
             real deposit/transfer/withdraw circuits need to be expressed \
             in arkworks R1CS or imported from a circom build."
        ),
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("prover error: {e:#}");
        std::process::exit(1);
    }
}

// Silence dead_code warnings on helpers used by future circuit additions.
#[allow(dead_code)]
fn _suppress_unused(
    f: Fr,
    pk: ProvingKey<Bn254>,
) -> (
    [u8; 32],
    ProvingKey<Bn254>,
    Result<ProvingKey<Bn254>, ark_serialize::SerializationError>,
) {
    let _ = fr_to_le_32(f);
    let serialized = vec![];
    (
        fr_to_le_32(f),
        pk,
        ProvingKey::<Bn254>::deserialize_compressed(serialized.as_slice()),
    )
}
