use crate::poseidon::Field;

/// Interface for zk proof verifiers. v0 ships a `MockVerifier` for unit tests
/// and an unimplemented `BbVerifier` placeholder for the real barretenberg
/// integration that lands in a later task.
pub trait Verifier {
    fn verify(&self, proof: &[u8], public_inputs: &[Field]) -> bool;
}

/// Mock verifier: accepts any non-empty proof regardless of public inputs.
/// Used to drive contract-level unit tests of state transitions before the
/// real verifier is wired in.
///
/// SAFETY: This type is `#[cfg(any(test, feature = "unit-testing"))]`-gated
/// so it cannot exist in a production WASM build. Any deployment must enable
/// the `bb-verifier` feature, which swaps in the real Barretenberg verifier.
#[cfg(any(test, feature = "unit-testing"))]
#[derive(Default)]
pub struct MockVerifier;

#[cfg(any(test, feature = "unit-testing"))]
impl Verifier for MockVerifier {
    fn verify(&self, proof: &[u8], _public_inputs: &[Field]) -> bool {
        !proof.is_empty()
    }
}

/// Compile-time check: a production build with no real verifier feature is
/// rejected, preventing accidental deployment with `MockVerifier` semantics.
#[cfg(all(
    target_family = "wasm",
    not(feature = "bb-verifier"),
    not(feature = "unit-testing")
))]
compile_error!(
    "Production contract build must enable the `bb-verifier` feature. \
     Building without a real verifier would make zk proofs trivially forgeable. \
     Run: `cargo near build --features bb-verifier`"
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
