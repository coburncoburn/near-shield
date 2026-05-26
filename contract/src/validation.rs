//! Input validation: bound and shape-check every public-input field before
//! any logic touches it. Reject early with explicit messages.
//!
//! Audit-prep hardening: every public method routes its untrusted inputs
//! through helpers here so the panic sites are concentrated and easy to
//! review.

use crate::poseidon::Field;
use near_sdk::require;

/// Maximum ciphertext byte length we accept on-chain. Bounds the storage
/// footprint per tx and the work done by `hash_bytes_to_field`. 8 KiB easily
/// covers a JSON disclosure or note ciphertext.
pub const MAX_CIPHERTEXT_BYTES: usize = 8 * 1024;

/// Maximum size of a serialized proof. Groth16 proofs are 256 bytes; we allow
/// generous headroom for backend changes while rejecting obvious garbage.
pub const MAX_PROOF_BYTES: usize = 64 * 1024;

/// Validates a 32-byte hex string ("0x" + 64 hex chars) and parses it as a
/// Field. Panics with a clear message on malformed input.
pub fn parse_hex32_or_panic(s: &str, field_name: &str) -> Field {
    require!(
        s.len() == 66 && s.starts_with("0x"),
        format!(
            "{}: must be '0x' + 64 hex chars (got {} chars)",
            field_name,
            s.len()
        )
    );
    match crate::deposit::parse_hex32(s) {
        Some(f) => f,
        None => near_sdk::env::panic_str(&format!("{field_name}: invalid hex characters")),
    }
}

pub fn check_ciphertext_bytes(ct: &str, field_name: &str) {
    let len = ct.len();
    require!(
        len <= MAX_CIPHERTEXT_BYTES,
        format!(
            "{}: ciphertext length {} exceeds limit {}",
            field_name, len, MAX_CIPHERTEXT_BYTES
        )
    );
}

pub fn check_proof_bytes(proof: &[u8]) {
    require!(!proof.is_empty(), "proof: must not be empty");
    require!(
        proof.len() <= MAX_PROOF_BYTES,
        format!(
            "proof: length {} exceeds limit {}",
            proof.len(),
            MAX_PROOF_BYTES
        )
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn ctx() {
        testing_env!(VMContextBuilder::new().build());
    }

    #[test]
    fn parse_hex32_accepts_well_formed() {
        ctx();
        let s = format!("0x{}", "ab".repeat(32));
        parse_hex32_or_panic(&s, "test");
    }

    #[test]
    #[should_panic(expected = "test: must be '0x' + 64 hex chars")]
    fn parse_hex32_rejects_short() {
        ctx();
        parse_hex32_or_panic("0xab", "test");
    }

    #[test]
    #[should_panic(expected = "test: must be '0x' + 64 hex chars")]
    fn parse_hex32_rejects_missing_prefix() {
        ctx();
        parse_hex32_or_panic(&"a".repeat(66), "test");
    }

    #[test]
    #[should_panic(expected = "test: invalid hex characters")]
    fn parse_hex32_rejects_non_hex() {
        ctx();
        parse_hex32_or_panic(&format!("0x{}", "zz".repeat(32)), "test");
    }

    #[test]
    fn check_ciphertext_accepts_under_limit() {
        ctx();
        let s = "a".repeat(MAX_CIPHERTEXT_BYTES);
        check_ciphertext_bytes(&s, "ct");
    }

    #[test]
    #[should_panic(expected = "exceeds limit")]
    fn check_ciphertext_rejects_oversize() {
        ctx();
        let s = "a".repeat(MAX_CIPHERTEXT_BYTES + 1);
        check_ciphertext_bytes(&s, "ct");
    }

    #[test]
    fn check_proof_accepts_non_empty_under_limit() {
        ctx();
        check_proof_bytes(&[1, 2, 3]);
    }

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn check_proof_rejects_empty() {
        ctx();
        check_proof_bytes(&[]);
    }

    #[test]
    #[should_panic(expected = "exceeds limit")]
    fn check_proof_rejects_oversize() {
        ctx();
        let p = vec![0u8; MAX_PROOF_BYTES + 1];
        check_proof_bytes(&p);
    }
}
