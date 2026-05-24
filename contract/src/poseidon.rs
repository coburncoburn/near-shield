use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field(pub Fr);

impl Field {
    pub fn from_u64(x: u64) -> Self {
        Field(Fr::from(x))
    }
    pub fn from_u128(x: u128) -> Self {
        Field(Fr::from(x))
    }
    pub fn from_bytes_le(b: &[u8]) -> Self {
        Field(Fr::from_le_bytes_mod_order(b))
    }
    pub fn from_be_bytes(b: &[u8]) -> Self {
        Field(Fr::from_be_bytes_mod_order(b))
    }
    pub fn to_bytes_be(&self) -> [u8; 32] {
        let bi = self.0.into_bigint();
        let mut out = [0u8; 32];
        let bytes = bi.to_bytes_be();
        out[32 - bytes.len()..].copy_from_slice(&bytes);
        out
    }
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_bytes_be()))
    }
    pub fn zero() -> Self {
        Field(Fr::from(0u64))
    }
}

pub fn poseidon2(a: Field, b: Field) -> Field {
    let mut h = Poseidon::<Fr>::new_circom(2).expect("poseidon-2 init");
    Field(h.hash(&[a.0, b.0]).expect("poseidon-2 hash"))
}

pub fn poseidon4(a: Field, b: Field, c: Field, d: Field) -> Field {
    let mut h = Poseidon::<Fr>::new_circom(4).expect("poseidon-4 init");
    Field(h.hash(&[a.0, b.0, c.0, d.0]).expect("poseidon-4 hash"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_u64_then_to_hex_roundtrip() {
        let a = Field::from_u64(1);
        assert_eq!(
            a.to_hex(),
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        );
    }

    #[test]
    fn zero_is_zero() {
        assert_eq!(
            Field::zero().to_hex(),
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn poseidon2_is_deterministic() {
        let a = Field::from_u64(1);
        let b = Field::from_u64(2);
        let h1 = poseidon2(a, b);
        let h2 = poseidon2(a, b);
        assert_eq!(h1, h2);
    }

    #[test]
    fn poseidon2_distinguishes_inputs() {
        let h1 = poseidon2(Field::from_u64(1), Field::from_u64(2));
        let h2 = poseidon2(Field::from_u64(2), Field::from_u64(1));
        assert_ne!(h1, h2);
    }

    #[test]
    fn poseidon4_is_deterministic() {
        let a = Field::from_u64(1);
        let b = Field::from_u64(2);
        let c = Field::from_u64(3);
        let d = Field::from_u64(4);
        assert_eq!(poseidon4(a, b, c, d), poseidon4(a, b, c, d));
    }

    #[test]
    fn poseidon2_known_vector() {
        // light-poseidon (circom params) of [1, 2] over BN254.
        // The exact hex must match what we lock in for cross-language tests.
        let h = poseidon2(Field::from_u64(1), Field::from_u64(2));
        // Note: this vector is locked from the actual `light-poseidon` output and
        // is the value SDK/Noir cross-tests must match.
        assert_eq!(
            h.to_hex(),
            "0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a"
        );
    }
}
