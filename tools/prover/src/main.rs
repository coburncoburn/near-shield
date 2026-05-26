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
