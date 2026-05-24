use crate::poseidon::Field;
use crate::verifier::{SelectedVerifier, Verifier};
use crate::{events, Contract, ContractExt};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{json_types::U128, near};

pub(crate) fn parse_hex32(s: &str) -> Option<Field> {
    let trimmed = s.trim_start_matches("0x");
    if trimmed.len() != 64 {
        return None;
    }
    let bytes = hex::decode(trimmed).ok()?;
    Some(Field::from_be_bytes(&bytes))
}

pub(crate) fn hash_bytes_to_field(b: &[u8]) -> Field {
    use light_poseidon::{Poseidon, PoseidonHasher};
    let chunks: Vec<Field> = b.chunks(31).map(|c| Field::from_bytes_le(c)).collect();
    if chunks.is_empty() {
        return Field::zero();
    }
    if chunks.len() == 1 {
        return chunks[0];
    }
    let mut acc = chunks[0];
    for next in &chunks[1..] {
        let mut h = Poseidon::<ark_bn254::Fr>::new_circom(2).expect("poseidon-2 init");
        acc = Field(h.hash(&[acc.0, next.0]).expect("poseidon-2 hash"));
    }
    acc
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
        let commitment_field = parse_hex32(&args.commitment).expect("bad commitment hex");
        let auditor_field = parse_hex32(&args.auditor_pubkey).expect("bad auditor hex");

        let pi = [
            commitment_field,
            Field::from_u128(args.amount.0),
            auditor_field,
            hash_bytes_to_field(args.view_ct.as_bytes()),
        ];
        assert!(
            SelectedVerifier::default().verify(&args.proof, &pi),
            "invalid proof"
        );

        let leaf_index = self.tree.insert(commitment_field);
        self.recent_roots.push(self.tree.root());
        events::emit_deposit(&args.commitment, leaf_index, &args.view_ct, &args.note_ct);
    }
}

#[near]
impl Contract {
    /// Direct deposit (no FT transfer). Used by tests and by future variants
    /// where the contract is funded out-of-band. The production deposit path
    /// is `ft_on_transfer` in `ft.rs`.
    pub fn deposit(
        &mut self,
        commitment: String,
        amount: U128,
        auditor_pubkey: String,
        view_ct: String,
        note_ct: String,
        proof: Vec<u8>,
    ) {
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
        ctx.predecessor_account_id(alice());
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
    #[should_panic(expected = "invalid proof")]
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
    #[should_panic(expected = "bad commitment hex")]
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
}
