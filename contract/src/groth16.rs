//! Groth16 verifier using NEAR's `alt_bn128_*` host functions.
//!
//! This is a **real**, on-chain proof verifier. The expensive operations
//! (multiexponentiation in G1 and the final pairing check) are delegated to
//! NEAR's native precompiles via [`env::alt_bn128_g1_multiexp`] and
//! [`env::alt_bn128_pairing_check`], which makes the WASM contract code
//! itself small.
//!
//! ## Wire format (matches EIP-196/EIP-197)
//!
//! G1 point: 64 bytes = `x.le_32_bytes() || y.le_32_bytes()`
//! G2 point: 128 bytes = `x.c0 || x.c1 || y.c0 || y.c1` (each 32 bytes LE)
//!
//! `alt_bn128_g1_multiexp` input: concatenated `[ G1_64 || scalar_32 ]` pairs
//! returning a single G1 (64 bytes).
//!
//! `alt_bn128_pairing_check` input: concatenated `[ G1_64 || G2_128 ]` pairs
//! returning bool: true iff `prod e(G1_i, G2_i) == 1`.
//!
//! ## Groth16 verification equation
//!
//! Given proof = (A: G1, B: G2, C: G1), VK = (alpha: G1, beta: G2, gamma: G2,
//! delta: G2, gamma_abc: [G1; n+1]), and `inputs: [Fr; n]`:
//!
//!   L = gamma_abc[0] + sum_i (inputs[i] * gamma_abc[i+1])
//!
//!   e(A, B) == e(alpha, beta) * e(L, gamma) * e(C, delta)
//!
//! Rearranged for pairing-check (product == 1):
//!
//!   e(-A, B) * e(alpha, beta) * e(L, gamma) * e(C, delta) == 1

use crate::poseidon::Field;
use crate::verifier::Verifier;
use near_sdk::env;

const G1_LEN: usize = 64;
const G2_LEN: usize = 128;
const FR_LEN: usize = 32;

#[derive(Clone)]
pub struct VerifyingKey {
    /// 64 bytes: alpha (G1)
    pub alpha_g1: [u8; G1_LEN],
    /// 128 bytes: beta (G2)
    pub beta_g2: [u8; G2_LEN],
    /// 128 bytes: gamma (G2)
    pub gamma_g2: [u8; G2_LEN],
    /// 128 bytes: delta (G2)
    pub delta_g2: [u8; G2_LEN],
    /// (n+1) × 64 bytes: gamma_abc[0..=n] (G1)
    pub gamma_abc_g1: Vec<[u8; G1_LEN]>,
}

#[derive(Clone)]
pub struct Proof {
    pub a_g1: [u8; G1_LEN],
    pub b_g2: [u8; G2_LEN],
    pub c_g1: [u8; G1_LEN],
}

impl Proof {
    /// Parse a 256-byte proof: `A || B || C`.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != G1_LEN + G2_LEN + G1_LEN {
            return None;
        }
        let mut a_g1 = [0u8; G1_LEN];
        let mut b_g2 = [0u8; G2_LEN];
        let mut c_g1 = [0u8; G1_LEN];
        a_g1.copy_from_slice(&bytes[..G1_LEN]);
        b_g2.copy_from_slice(&bytes[G1_LEN..G1_LEN + G2_LEN]);
        c_g1.copy_from_slice(&bytes[G1_LEN + G2_LEN..]);
        Some(Self { a_g1, b_g2, c_g1 })
    }
}

impl VerifyingKey {
    /// Parse the standard wire format: `alpha || beta || gamma || delta || (n+1) gamma_abc`.
    /// Returns None on length mismatch.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let header = G1_LEN + 3 * G2_LEN;
        if bytes.len() < header || (bytes.len() - header) % G1_LEN != 0 {
            return None;
        }
        let mut alpha_g1 = [0u8; G1_LEN];
        let mut beta_g2 = [0u8; G2_LEN];
        let mut gamma_g2 = [0u8; G2_LEN];
        let mut delta_g2 = [0u8; G2_LEN];
        alpha_g1.copy_from_slice(&bytes[0..G1_LEN]);
        beta_g2.copy_from_slice(&bytes[G1_LEN..G1_LEN + G2_LEN]);
        gamma_g2.copy_from_slice(&bytes[G1_LEN + G2_LEN..G1_LEN + 2 * G2_LEN]);
        delta_g2.copy_from_slice(&bytes[G1_LEN + 2 * G2_LEN..header]);
        let n_plus_one = (bytes.len() - header) / G1_LEN;
        let mut gamma_abc_g1 = Vec::with_capacity(n_plus_one);
        for i in 0..n_plus_one {
            let mut g1 = [0u8; G1_LEN];
            g1.copy_from_slice(&bytes[header + i * G1_LEN..header + (i + 1) * G1_LEN]);
            gamma_abc_g1.push(g1);
        }
        Some(Self {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
        })
    }
}

/// Negates a G1 point. The y-coordinate is replaced with `MODULUS - y`.
/// Used to put a pairing on the "minus" side of the equation.
fn negate_g1(p: &[u8; G1_LEN]) -> [u8; G1_LEN] {
    // The BN254 base field modulus q.
    const Q: [u8; 32] = [
        0x47, 0xFD, 0x7C, 0xD8, 0x16, 0x8C, 0x20, 0x3C, 0x8D, 0xCA, 0x71, 0x68, 0x91, 0x6A, 0x81,
        0x97, 0x5D, 0x58, 0x81, 0x81, 0xB6, 0x45, 0x50, 0xB8, 0x29, 0xA0, 0x31, 0xE1, 0x72, 0x4E,
        0x64, 0x30,
    ];
    let mut out = *p;
    // out.y is in bytes[32..64] in little-endian. y' = Q - y.
    let y = &p[32..64];
    let mut borrow: i32 = 0;
    for i in 0..32 {
        let q_i = Q[i] as i32;
        let y_i = y[i] as i32;
        let mut d = q_i - y_i - borrow;
        if d < 0 {
            d += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[32 + i] = d as u8;
    }
    out
}

/// Computes `L = gamma_abc[0] + sum_i (inputs[i] * gamma_abc[i+1])` via the
/// `alt_bn128_g1_multiexp` host function.
fn compute_linear_combination(
    gamma_abc: &[[u8; G1_LEN]],
    inputs: &[Field],
) -> Option<[u8; G1_LEN]> {
    if gamma_abc.len() != inputs.len() + 1 {
        return None;
    }
    // multiexp([(gamma_abc[0], 1), (gamma_abc[1], inputs[0]), ..., (gamma_abc[n], inputs[n-1])])
    let mut buf = Vec::with_capacity((inputs.len() + 1) * (G1_LEN + FR_LEN));
    // First term: gamma_abc[0] * 1
    buf.extend_from_slice(&gamma_abc[0]);
    let mut one = [0u8; FR_LEN];
    one[0] = 1;
    buf.extend_from_slice(&one);
    for (i, scalar) in inputs.iter().enumerate() {
        buf.extend_from_slice(&gamma_abc[i + 1]);
        // Fr is little-endian on the wire per EIP-196.
        let mut s_le = scalar.to_bytes_be();
        s_le.reverse();
        buf.extend_from_slice(&s_le);
    }
    let result = env::alt_bn128_g1_multiexp(&buf);
    if result.len() != G1_LEN {
        return None;
    }
    let mut out = [0u8; G1_LEN];
    out.copy_from_slice(&result);
    Some(out)
}

/// Verifies a Groth16 proof against a VK and public inputs using NEAR's
/// `alt_bn128_pairing_check`.
pub fn verify_groth16(vk: &VerifyingKey, proof: &Proof, inputs: &[Field]) -> bool {
    let l = match compute_linear_combination(&vk.gamma_abc_g1, inputs) {
        Some(l) => l,
        None => return false,
    };
    let neg_a = negate_g1(&proof.a_g1);

    // Pairing check: e(-A, B) * e(alpha, beta) * e(L, gamma) * e(C, delta) == 1
    let mut buf = Vec::with_capacity(4 * (G1_LEN + G2_LEN));
    buf.extend_from_slice(&neg_a);
    buf.extend_from_slice(&proof.b_g2);
    buf.extend_from_slice(&vk.alpha_g1);
    buf.extend_from_slice(&vk.beta_g2);
    buf.extend_from_slice(&l);
    buf.extend_from_slice(&vk.gamma_g2);
    buf.extend_from_slice(&proof.c_g1);
    buf.extend_from_slice(&vk.delta_g2);

    env::alt_bn128_pairing_check(&buf)
}

/// Production-ready `Verifier` implementation. Stores the VK; verifies
/// (proof, public_inputs) using the host-function pairing check.
#[cfg(all(
    feature = "groth16-verifier",
    not(feature = "unit-testing"),
    not(feature = "integration-testing")
))]
pub struct Groth16Verifier {
    vk: VerifyingKey,
}

#[cfg(all(
    feature = "groth16-verifier",
    not(feature = "unit-testing"),
    not(feature = "integration-testing")
))]
impl Groth16Verifier {
    pub fn new(vk_bytes: &[u8]) -> Self {
        let vk = VerifyingKey::from_bytes(vk_bytes).expect("invalid VK bytes");
        Self { vk }
    }
}

#[cfg(all(
    feature = "groth16-verifier",
    not(feature = "unit-testing"),
    not(feature = "integration-testing")
))]
impl Verifier for Groth16Verifier {
    fn verify(&self, proof: &[u8], public_inputs: &[Field]) -> bool {
        let proof = match Proof::from_bytes(proof) {
            Some(p) => p,
            None => return false,
        };
        verify_groth16(&self.vk, &proof, public_inputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vk_round_trips_known_byte_count() {
        // n=2 public inputs -> n+1 = 3 gamma_abc terms
        let n_plus_one = 3;
        let total = G1_LEN + 3 * G2_LEN + n_plus_one * G1_LEN;
        let bytes = vec![0u8; total];
        let vk = VerifyingKey::from_bytes(&bytes).expect("parse");
        assert_eq!(vk.gamma_abc_g1.len(), n_plus_one);
    }

    #[test]
    fn vk_rejects_misaligned_bytes() {
        let bad = vec![0u8; G1_LEN + 3 * G2_LEN + 33]; // 33 is not a multiple of 64
        assert!(VerifyingKey::from_bytes(&bad).is_none());
    }

    #[test]
    fn proof_round_trips_256_bytes() {
        let bytes = vec![0u8; G1_LEN + G2_LEN + G1_LEN];
        assert!(Proof::from_bytes(&bytes).is_some());
    }

    #[test]
    fn proof_rejects_wrong_length() {
        assert!(Proof::from_bytes(&[0u8; 100]).is_none());
        assert!(Proof::from_bytes(&[]).is_none());
    }

    #[test]
    fn negate_g1_zero_yields_zero_y_components_unchanged() {
        // Negating identity-like all-zero G1 keeps x=0; y' = q - 0 = q (representable
        // since we just check the byte-level subtraction works without underflow).
        let p = [0u8; G1_LEN];
        let neg = negate_g1(&p);
        // The y bytes should now equal Q (full modulus encoding).
        assert_ne!(&neg[32..64], &p[32..64]);
    }

    #[test]
    fn negate_g1_x_coordinate_unchanged() {
        let mut p = [0u8; G1_LEN];
        for i in 0..32 {
            p[i] = i as u8;
        }
        let neg = negate_g1(&p);
        assert_eq!(&neg[..32], &p[..32]);
    }

    #[test]
    fn compute_linear_combination_size_mismatch_returns_none() {
        // Without invoking the host function (would panic in unit-test env),
        // we just check our size-mismatch precondition.
        let gamma_abc = vec![[0u8; G1_LEN]; 3];
        let inputs = vec![Field::zero(); 5]; // wrong size; expects 2
        assert!(compute_linear_combination(&gamma_abc, &inputs).is_none());
    }
}
