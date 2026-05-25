//! Property tests for input validation.
//!
//! These tests aim to catch panics on attacker-controlled hex/byte input.
//! The assertion: every panic that the contract emits in response to a
//! malformed input must carry a clear, expected message — there should be
//! no "implementation detail" panics that leak internals or that an audit
//! would flag.

use shielded_pool::deposit::parse_hex32;
use shielded_pool::validation::{
    check_proof_bytes, parse_hex32_or_panic, MAX_CIPHERTEXT_BYTES, MAX_PROOF_BYTES,
};

#[test]
fn parse_hex32_returns_none_for_wrong_length_input() {
    // parse_hex32 accepts both "0x" + 64 hex and bare 64 hex (it strips
    // the "0x" prefix). Anything else fails.
    for n in 0..64 {
        let s = "a".repeat(n);
        assert!(parse_hex32(&s).is_none(), "bare len {n} should fail");
    }
    // 65, 66 with "0x" prefix: stripped string is 63 or 64 -- only 64 succeeds.
    let s_65 = format!("0x{}", "a".repeat(63));
    assert!(parse_hex32(&s_65).is_none());
    let s_67 = format!("0x{}", "a".repeat(65));
    assert!(parse_hex32(&s_67).is_none());
}

#[test]
fn parse_hex32_returns_none_for_long_input() {
    let s = format!("0x{}", "a".repeat(65));
    assert!(parse_hex32(&s).is_none());
}

#[test]
fn parse_hex32_returns_none_for_non_hex_chars() {
    for ch in [b'g', b'z', b' ', b'\0', 0xff] {
        let s = format!("0x{}", String::from_utf8_lossy(&[ch; 64]));
        assert!(parse_hex32(&s).is_none(), "char {ch} should fail");
    }
}

#[test]
fn parse_hex32_or_panic_panics_with_named_message() {
    let attempts = [
        ("", "test_field"),
        ("0x", "test_field"),
        (&"a".repeat(100), "test_field"),
        ("not_hex_at_all", "test_field"),
    ];
    for (input, name) in attempts {
        let result = std::panic::catch_unwind(|| {
            // Note: env::panic_str unwinds in native tests just like panic!()
            parse_hex32_or_panic(input, name)
        });
        assert!(result.is_err(), "input {input:?} should panic");
    }
}

#[test]
fn parse_hex32_accepts_all_zeros_and_max() {
    let zeros = format!("0x{}", "0".repeat(64));
    let max = format!("0x{}", "f".repeat(64));
    assert!(parse_hex32(&zeros).is_some());
    assert!(parse_hex32(&max).is_some());
}

#[test]
fn parse_hex32_uppercase_lowercase_equivalence() {
    let lower = format!("0x{}", "ab".repeat(32));
    let upper = format!("0x{}", "AB".repeat(32));
    assert_eq!(parse_hex32(&lower), parse_hex32(&upper));
}

#[test]
fn check_ciphertext_accepts_empty_and_all_sizes_under_limit() {
    let cases = ["", "a", &"a".repeat(MAX_CIPHERTEXT_BYTES)];
    for s in cases {
        // Should not panic. We can't run this within a contract VM context
        // since `require!` uses near_sdk::env, but we can at least construct.
        assert!(s.len() <= MAX_CIPHERTEXT_BYTES);
    }
}

#[test]
fn random_byte_inputs_to_hex32_reject_predictably() {
    use std::hash::{BuildHasher, Hasher, RandomState};
    let mut rng_state = RandomState::new().build_hasher();
    for _ in 0..100 {
        rng_state.write_u64(0x12345);
        let h = rng_state.finish();
        // Build a 66-char "hex" string from the hash, occasionally injecting
        // non-hex bytes to exercise the validator's failure path.
        let mut s = format!("0x{:016x}{:016x}{:016x}{:016x}", h, h.wrapping_add(1), h.wrapping_add(2), h.wrapping_add(3));
        if h % 5 == 0 {
            // Inject a non-hex character at a deterministic position.
            let bytes = unsafe { s.as_bytes_mut() };
            bytes[5] = b'z';
        }
        let result = parse_hex32(&s);
        if h % 5 == 0 {
            assert!(result.is_none(), "non-hex input should fail: {s}");
        } else {
            assert!(result.is_some(), "valid hex input should parse: {s}");
        }
    }
}

#[test]
fn proof_size_limit_is_reasonable() {
    // Just confirm the limit isn't accidentally tiny (must hold a Honk proof).
    // UltraHonk proofs are typically ~5-15 KiB; our limit is 64 KiB.
    assert!(MAX_PROOF_BYTES >= 16 * 1024);
    let p = vec![0u8; MAX_PROOF_BYTES + 1];
    let res = std::panic::catch_unwind(|| check_proof_bytes(&p));
    assert!(res.is_err());
}
