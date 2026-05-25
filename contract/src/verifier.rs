use crate::poseidon::Field;

/// Interface for zk proof verifiers. v0 ships a `MockVerifier` for host-side
/// tests and a fail-closed `BbVerifier` placeholder for the real Barretenberg
/// integration that lands in a later task.
pub trait Verifier {
    fn verify(&self, proof: &[u8], public_inputs: &[Field]) -> bool;
}

/// Mock verifier: accepts any non-empty proof regardless of public inputs.
/// Used to drive contract-level unit tests of state transitions before the
/// real verifier is wired in.
///
/// SAFETY: A deployable WASM build with `unit-testing` is rejected by the
/// compile_error gates below. The `integration-testing` feature *deliberately*
/// allows WASM builds with mock semantics — for sandbox tests only — and is
/// gated separately so it can never silently slip into a production artifact.
#[cfg(any(test, feature = "unit-testing", feature = "integration-testing"))]
#[derive(Default)]
pub struct MockVerifier;

#[cfg(any(test, feature = "unit-testing", feature = "integration-testing"))]
impl Verifier for MockVerifier {
    fn verify(&self, proof: &[u8], _public_inputs: &[Field]) -> bool {
        !proof.is_empty()
    }
}

/// Production verifier placeholder. Until this is wired to Barretenberg, it
/// rejects every proof so a `bb-verifier` build is not forgeable by accident.
#[cfg(all(
    feature = "bb-verifier",
    not(feature = "unit-testing"),
    not(feature = "integration-testing")
))]
#[derive(Default)]
pub struct BbVerifier;

#[cfg(all(
    feature = "bb-verifier",
    not(feature = "unit-testing"),
    not(feature = "integration-testing")
))]
impl Verifier for BbVerifier {
    fn verify(&self, _proof: &[u8], _public_inputs: &[Field]) -> bool {
        false
    }
}

/// Selects the active verifier for a given verifier-key blob. The factory
/// pattern is necessary because Groth16Verifier needs the VK at construction
/// time, while MockVerifier and BbVerifier are stateless.
#[cfg(any(test, feature = "unit-testing", feature = "integration-testing"))]
pub fn select_verifier(_vk_bytes: &[u8]) -> impl Verifier {
    MockVerifier
}

#[cfg(all(
    feature = "bb-verifier",
    not(feature = "unit-testing"),
    not(feature = "integration-testing"),
    not(feature = "groth16-verifier")
))]
pub fn select_verifier(_vk_bytes: &[u8]) -> impl Verifier {
    BbVerifier
}

#[cfg(all(
    feature = "groth16-verifier",
    not(feature = "unit-testing"),
    not(feature = "integration-testing")
))]
pub fn select_verifier(vk_bytes: &[u8]) -> impl Verifier {
    crate::groth16::Groth16Verifier::new(vk_bytes)
}

// Compile-time checks reject deployable builds that would use mock verifier
// semantics or omit the real verifier feature. `integration-testing` is
// exempted from the unit-testing reject because near-workspaces sandbox tests
// need a WASM build with permissive verification.
#[cfg(all(
    target_family = "wasm",
    feature = "unit-testing",
    not(feature = "integration-testing")
))]
compile_error!(
    "WASM contract builds must disable `unit-testing`. \
     For sandbox integration tests use `--features integration-testing` instead. \
     For deployment use `--no-default-features --features bb-verifier`."
);

#[cfg(all(
    target_family = "wasm",
    not(feature = "unit-testing"),
    not(feature = "integration-testing"),
    not(feature = "bb-verifier"),
    not(feature = "groth16-verifier")
))]
compile_error!(
    "Production contract build must enable a real verifier feature. \
     Building without a real verifier would make zk proofs trivially forgeable. \
     Use one of: \
     `cargo near build --no-default-features --features groth16-verifier` (recommended; \
     uses NEAR's alt_bn128 host functions, real on-chain verification), or \
     `cargo near build --no-default-features --features bb-verifier` (fail-closed \
     placeholder until Barretenberg Honk is ported)."
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_verifier_accepts_non_empty_proof() {
        let v = MockVerifier::default();
        assert!(v.verify(&[1, 2, 3], &[Field::from_u64(1)]));
    }

    #[test]
    fn mock_verifier_rejects_empty_proof() {
        let v = MockVerifier::default();
        assert!(!v.verify(&[], &[Field::from_u64(1)]));
    }

    #[test]
    fn mock_verifier_is_indifferent_to_public_inputs() {
        let v = MockVerifier::default();
        assert!(v.verify(&[1], &[]));
        assert!(v.verify(&[1], &[Field::from_u64(99); 10]));
    }
}
