use crate::poseidon::{poseidon2, Field};
use crate::verifier::{select_verifier, Verifier};
use crate::{events, Contract};
use near_sdk::json_types::U128;
use near_sdk::serde::{Deserialize, Serialize};

// Imports needed only by the test/sandbox-only direct `deposit()` entry point
// (gated below); absent from deployable builds along with the method itself.
#[cfg(any(test, feature = "integration-testing"))]
use crate::storage::{require_storage_deposit, DEPOSIT_BYTES};
#[cfg(any(test, feature = "integration-testing"))]
use crate::ContractExt;
#[cfg(any(test, feature = "integration-testing"))]
use near_sdk::near;

pub fn parse_hex32(s: &str) -> Option<Field> {
    let trimmed = s.trim_start_matches("0x");
    if trimmed.len() != 64 {
        return None;
    }
    let bytes = hex::decode(trimmed).ok()?;
    Some(Field::from_be_bytes(&bytes))
}

/// Reduces an arbitrary byte string to a single Field. This is the canonical
/// construction for binding opaque ciphertexts (view_ct, note_ct) into proof
/// public inputs. The TypeScript SDK MUST implement the same construction
/// (cross-language vectors live in `sdk/test-vectors/view_ct_hash.json`).
///
/// Algorithm:
///   1. Split bytes into 31-byte chunks (last chunk zero-padded).
///   2. Each chunk -> Field via little-endian byte interpretation.
///   3. Empty input -> Field::zero().
///   4. Single chunk -> that chunk.
///   5. Multiple chunks -> linear Poseidon-2 fold: acc = poseidon2(acc, next).
pub fn hash_bytes_to_field(b: &[u8]) -> Field {
    let chunks: Vec<Field> = b.chunks(31).map(|c| Field::from_bytes_le(c)).collect();
    if chunks.is_empty() {
        return Field::zero();
    }
    if chunks.len() == 1 {
        return chunks[0];
    }
    let mut acc = chunks[0];
    for next in &chunks[1..] {
        acc = poseidon2(acc, *next);
    }
    acc
}

/// Reduces arbitrary bytes to a Field via `keccak256` then little-endian
/// truncation to 31 bytes (248 bits). Used for binding submitted ciphertexts
/// into a proof's public input without paying in-WASM Poseidon over the full
/// length. Cross-language vectors live in `sdk/test-vectors/view_ct_keccak.json`.
pub fn keccak_to_field(b: &[u8]) -> Field {
    let digest = near_sdk::env::keccak256(b);
    Field::from_bytes_le(&digest[..31])
}

/// JSON payload the user attaches to a NEP-141 `ft_transfer_call(msg=...)`
/// when depositing USDC into the shielded pool.
#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct DepositArgs {
    pub commitment: String,
    pub amount: U128,
    pub auditor_pubkey: String,
    pub view_ct: String,
    pub note_ct: String,
    pub proof: Vec<u8>,
}

impl Contract {
    /// Internal deposit core. Called both by the legacy direct `deposit()`
    /// entry (kept for unit tests) and by `ft_on_transfer` (the production
    /// path that requires real USDC to have been transferred in).
    pub(crate) fn do_deposit(&mut self, args: DepositArgs) {
        use crate::validation::{
            check_ciphertext_bytes, check_proof_bytes, parse_hex32_or_panic,
        };
        assert!(!self.paused, "contract is paused");
        check_proof_bytes(&args.proof);
        check_ciphertext_bytes(&args.view_ct, "view_ct");
        check_ciphertext_bytes(&args.note_ct, "note_ct");
        let commitment_field = parse_hex32_or_panic(&args.commitment, "commitment");
        let auditor_field = parse_hex32_or_panic(&args.auditor_pubkey, "auditor_pubkey");

        let pi = [
            commitment_field,
            Field::from_u128(args.amount.0),
            auditor_field,
            hash_bytes_to_field(args.view_ct.as_bytes()),
        ];
        assert!(
            select_verifier(&self.vk_deposit).verify(&args.proof, &pi),
            "invalid proof"
        );

        let leaf_index = self.tree.insert(commitment_field);
        self.recent_roots.push(self.tree.root());
        events::emit_deposit(&args.commitment, leaf_index, &args.view_ct, &args.note_ct);
    }
}

// SECURITY: `deposit()` inserts a commitment with NO backing USDC transfer —
// the deposit proof only attests commitment well-formedness (no secret, no
// funds) and proving keys are public, so exposing this in production would let
// anyone mint unbacked notes and drain the pool. The ONLY safe deposit path is
// `ft_on_transfer` (ft.rs), which binds the amount to a real token transfer.
// This direct entry point is therefore compiled ONLY for unit tests and the
// sandbox `integration-testing` build (both use the permissive MockVerifier and
// never hold real funds); it is absent from any deployable artifact.
#[cfg(any(test, feature = "integration-testing"))]
#[near]
impl Contract {
    /// Direct deposit (no FT transfer). TEST/SANDBOX ONLY — see the security
    /// note above. The production deposit path is `ft_on_transfer` in `ft.rs`.
    #[payable]
    pub fn deposit(
        &mut self,
        commitment: String,
        amount: U128,
        auditor_pubkey: String,
        view_ct: String,
        note_ct: String,
        proof: Vec<u8>,
    ) {
        require_storage_deposit(DEPOSIT_BYTES);
        self.do_deposit(DepositArgs {
            commitment,
            amount,
            auditor_pubkey,
            view_ct,
            note_ct,
            proof,
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::Contract;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use near_sdk::AccountId;

    fn alice() -> AccountId {
        "alice.near".parse().unwrap()
    }
    fn usdc() -> AccountId {
        "usdc.near".parse().unwrap()
    }
    fn owner() -> AccountId {
        "owner.near".parse().unwrap()
    }

    fn setup() -> Contract {
        let mut ctx = VMContextBuilder::new();
        ctx.predecessor_account_id(alice())
            .attached_deposit(near_sdk::NearToken::from_near(1));
        testing_env!(ctx.build());
        Contract::new(
            owner(),
            usdc(),
            vec![1, 2, 3],
            vec![1, 2, 3],
            vec![1, 2, 3],
        )
    }

    fn hex32(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; 32]))
    }

    #[test]
    #[ignore]
    fn dump_view_ct_hash_vectors() {
        // Run with: cargo test -p shielded-pool --lib deposit::tests::dump_view_ct_hash_vectors -- --ignored --nocapture
        let cases: &[(&str, &[u8])] = &[
            ("empty", b""),
            ("a", b"a"),
            ("hello", b"hello"),
            ("viewct", b"viewct"),
            (
                "long_62_bytes",
                b"this is a longer string that exceeds 31 bytes for chunking",
            ),
            ("31_zeros", &[0u8; 31]),
            ("62_ff", &[0xffu8; 62]),
        ];
        for (name, bytes) in cases {
            println!("{}={}", name, super::hash_bytes_to_field(bytes).to_hex());
        }
    }

    #[test]
    fn deposit_with_valid_mock_proof_inserts_into_tree() {
        let mut c = setup();
        let pre_root = c.merkle_root();
        c.deposit(
            hex32(0x01),
            100_000_000u128.into(),
            hex32(0x02),
            "viewct".into(),
            "notect".into(),
            vec![1, 2, 3],
        );
        assert_ne!(c.merkle_root(), pre_root);
    }

    #[test]
    #[should_panic(expected = "proof: must not be empty")]
    fn deposit_with_empty_proof_rejects() {
        let mut c = setup();
        c.deposit(
            hex32(0x01),
            100_000_000u128.into(),
            hex32(0x02),
            "viewct".into(),
            "notect".into(),
            vec![],
        );
    }

    #[test]
    #[should_panic(expected = "commitment: must be '0x' + 64 hex chars")]
    fn deposit_rejects_malformed_commitment() {
        let mut c = setup();
        c.deposit(
            "0xnothex".into(),
            100u128.into(),
            hex32(0x02),
            "v".into(),
            "n".into(),
            vec![1],
        );
    }

    #[test]
    fn deposit_root_appears_in_recent_roots() {
        let mut c = setup();
        c.deposit(
            hex32(0x01),
            10u128.into(),
            hex32(0x02),
            "v".into(),
            "n".into(),
            vec![1],
        );
        let root = c.merkle_root();
        assert!(c.recent_roots.contains(&crate::deposit::parse_hex32(&root).unwrap()));
    }

    #[test]
    fn keccak_to_field_vectors() {
        let raw = include_str!("../../sdk/test-vectors/view_ct_keccak.json");
        let v: serde_json::Value = serde_json::from_str(raw).unwrap();
        for case in v["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let input_hex = case["input_hex"].as_str().unwrap().trim_start_matches("0x");
            let input = hex::decode(input_hex).unwrap();
            let expected_digest_hex = case["expected_digest_hex"].as_str().unwrap();
            let got_digest = near_sdk::env::keccak256(&input);
            let got_digest_hex = format!("0x{}", hex::encode(&got_digest));
            assert_eq!(got_digest_hex, expected_digest_hex, "case {name} (digest)");
            let expected_hex = case["expected_field_hex"].as_str().unwrap();
            let got = super::keccak_to_field(&input);
            assert_eq!(got.to_hex(), expected_hex, "case {name}");
        }
    }
}
