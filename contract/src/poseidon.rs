#[path = "poseidon_constants.rs"]
mod poseidon_constants;

use poseidon_constants::{
    MONT_NEG_INV, MONT_R2, MODULUS, POSEIDON2_C, POSEIDON2_M, POSEIDON4_C, POSEIDON4_M,
};

const LIMBS: usize = 4;

/// BN254 scalar-field element stored in Montgomery form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field([u64; LIMBS]);

impl Field {
    pub fn from_u64(x: u64) -> Self {
        Self::from_raw([x, 0, 0, 0])
    }

    pub fn from_u128(x: u128) -> Self {
        Self::from_raw([x as u64, (x >> 64) as u64, 0, 0])
    }

    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        let mut out = Self::zero();
        for &byte in bytes.iter().rev() {
            out = out.mul_small(256).add_small(byte as u64);
        }
        out
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut out = Self::zero();
        for &byte in bytes {
            out = out.mul_small(256).add_small(byte as u64);
        }
        out
    }

    pub fn to_bytes_be(&self) -> [u8; 32] {
        let raw = self.to_raw();
        let mut out = [0u8; 32];
        for (i, limb) in raw.iter().enumerate() {
            out[24 - i * 8..32 - i * 8].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_bytes_be()))
    }

    pub fn zero() -> Self {
        Self([0; LIMBS])
    }

    fn from_montgomery(limbs: [u64; LIMBS]) -> Self {
        Self(limbs)
    }

    fn from_raw(mut raw: [u64; LIMBS]) -> Self {
        while geq(&raw, &MODULUS) {
            raw = sub_raw(raw, MODULUS);
        }
        Self(montgomery_mul_raw(raw, MONT_R2))
    }

    fn to_raw(self) -> [u64; LIMBS] {
        montgomery_mul_raw(self.0, [1, 0, 0, 0])
    }

    fn add(self, rhs: Self) -> Self {
        let (sum, carry) = add_raw(self.0, rhs.0);
        let reduced = if carry || geq(&sum, &MODULUS) {
            sub_raw(sum, MODULUS)
        } else {
            sum
        };
        Self(reduced)
    }

    fn mul(self, rhs: Self) -> Self {
        Self(montgomery_mul_raw(self.0, rhs.0))
    }

    fn square(self) -> Self {
        self.mul(self)
    }

    fn pow5(self) -> Self {
        let squared = self.square();
        squared.square().mul(self)
    }

    fn add_small(self, rhs: u64) -> Self {
        self.add(Self::from_u64(rhs))
    }

    fn mul_small(self, rhs: u64) -> Self {
        self.mul(Self::from_u64(rhs))
    }
}

pub fn poseidon2(a: Field, b: Field) -> Field {
    poseidon::<3, 195>(&[a, b], &POSEIDON2_C, &POSEIDON2_M)
}

pub fn poseidon4(a: Field, b: Field, c: Field, d: Field) -> Field {
    poseidon::<5, 340>(&[a, b, c, d], &POSEIDON4_C, &POSEIDON4_M)
}

fn poseidon<const T: usize, const C: usize>(
    inputs: &[Field],
    constants: &[[u64; LIMBS]; C],
    matrix: &[[[u64; LIMBS]; T]; T],
) -> Field {
    debug_assert_eq!(inputs.len() + 1, T);

    let mut state = [Field::zero(); T];
    for (i, input) in inputs.iter().enumerate() {
        state[i + 1] = *input;
    }

    let partial_rounds = C / T - 8;
    for round in 0..(8 + partial_rounds) {
        for i in 0..T {
            state[i] = state[i].add(Field::from_montgomery(constants[round * T + i]));
            if round < 4 || round >= 4 + partial_rounds || i == 0 {
                state[i] = state[i].pow5();
            }
        }
        state = mix(state, matrix);
    }

    state[0]
}

fn mix<const T: usize>(state: [Field; T], matrix: &[[[u64; LIMBS]; T]; T]) -> [Field; T] {
    let mut out = [Field::zero(); T];
    for row in 0..T {
        let mut acc = Field::zero();
        for col in 0..T {
            acc = acc.add(Field::from_montgomery(matrix[row][col]).mul(state[col]));
        }
        out[row] = acc;
    }
    out
}

fn add_raw(a: [u64; LIMBS], b: [u64; LIMBS]) -> ([u64; LIMBS], bool) {
    let mut out = [0u64; LIMBS];
    let mut carry = 0u128;
    for i in 0..LIMBS {
        let v = a[i] as u128 + b[i] as u128 + carry;
        out[i] = v as u64;
        carry = v >> 64;
    }
    (out, carry != 0)
}

fn sub_raw(a: [u64; LIMBS], b: [u64; LIMBS]) -> [u64; LIMBS] {
    let mut out = [0u64; LIMBS];
    let mut borrow = 0u64;
    for i in 0..LIMBS {
        let (v1, b1) = a[i].overflowing_sub(b[i]);
        let (v2, b2) = v1.overflowing_sub(borrow);
        out[i] = v2;
        borrow = (b1 || b2) as u64;
    }
    out
}

fn geq(a: &[u64; LIMBS], b: &[u64; LIMBS]) -> bool {
    for i in (0..LIMBS).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

fn montgomery_mul_raw(a: [u64; LIMBS], b: [u64; LIMBS]) -> [u64; LIMBS] {
    let mut t = [0u64; LIMBS * 2 + 1];

    for i in 0..LIMBS {
        let mut carry = 0u128;
        for j in 0..LIMBS {
            let k = i + j;
            let v = t[k] as u128 + a[i] as u128 * b[j] as u128 + carry;
            t[k] = v as u64;
            carry = v >> 64;
        }
        add_carry(&mut t, i + LIMBS, carry as u64);
    }

    for i in 0..LIMBS {
        let m = t[i].wrapping_mul(MONT_NEG_INV);
        let mut carry = 0u128;
        for (j, modulus_limb) in MODULUS.iter().enumerate() {
            let k = i + j;
            let v = t[k] as u128 + m as u128 * *modulus_limb as u128 + carry;
            t[k] = v as u64;
            carry = v >> 64;
        }
        add_carry(&mut t, i + LIMBS, carry as u64);
    }

    let mut out = [t[4], t[5], t[6], t[7]];
    if t[8] != 0 || geq(&out, &MODULUS) {
        out = sub_raw(out, MODULUS);
    }
    out
}

fn add_carry(t: &mut [u64; LIMBS * 2 + 1], mut idx: usize, mut carry: u64) {
    while carry != 0 {
        let (next, overflow) = t[idx].overflowing_add(carry);
        t[idx] = next;
        carry = overflow as u64;
        idx += 1;
    }
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
    fn from_u128_then_to_hex_roundtrip() {
        let a = Field::from_u128(1u128 << 80);
        assert_eq!(
            a.to_hex(),
            "0x0000000000000000000000000000000000000000000100000000000000000000"
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
    fn bytes_reduce_modulus() {
        let mut modulus = [0u8; 32];
        for (i, limb) in MODULUS.iter().enumerate() {
            modulus[24 - i * 8..32 - i * 8].copy_from_slice(&limb.to_be_bytes());
        }
        assert_eq!(Field::from_be_bytes(&modulus), Field::zero());
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
    #[ignore]
    fn dump_cross_lang_vectors() {
        // Run with: cargo test -p shielded-pool poseidon::tests::dump_cross_lang_vectors -- --ignored --nocapture
        println!("p2_1_2={}", poseidon2(Field::from_u64(1), Field::from_u64(2)).to_hex());
        println!("p2_3_4={}", poseidon2(Field::from_u64(3), Field::from_u64(4)).to_hex());
        println!("p2_0_0={}", poseidon2(Field::zero(), Field::zero()).to_hex());
        println!("p4_1_2_3_4={}", poseidon4(Field::from_u64(1), Field::from_u64(2), Field::from_u64(3), Field::from_u64(4)).to_hex());
        println!("p4_0_0_0_0={}", poseidon4(Field::zero(), Field::zero(), Field::zero(), Field::zero()).to_hex());
    }

    #[test]
    fn poseidon2_known_vector() {
        let h = poseidon2(Field::from_u64(1), Field::from_u64(2));
        assert_eq!(
            h.to_hex(),
            "0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a"
        );
    }

    #[test]
    fn poseidon4_known_vector() {
        let h = poseidon4(Field::from_u64(1), Field::from_u64(2), Field::from_u64(3), Field::from_u64(4));
        assert_eq!(
            h.to_hex(),
            "0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465"
        );
    }
}
