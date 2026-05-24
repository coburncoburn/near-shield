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
#[derive(Default)]
pub struct MockVerifier;

impl Verifier for MockVerifier {
    fn verify(&self, proof: &[u8], _public_inputs: &[Field]) -> bool {
        !proof.is_empty()
    }
}

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
