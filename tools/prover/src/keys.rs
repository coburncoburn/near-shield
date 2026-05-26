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
