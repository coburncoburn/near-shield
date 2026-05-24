use crate::deposit::{hash_bytes_to_field, parse_hex32};
use crate::poseidon::Field;
use crate::verifier::{MockVerifier, Verifier};
use crate::{events, Contract, ContractExt};
use near_sdk::{json_types::U128, near, AccountId};

#[near]
impl Contract {
    /// Spends a single input note and pays out USDC to a public recipient,
    /// less a relayer fee. Typically called by a relayer on behalf of the
    /// withdrawing user.
    pub fn withdraw(
        &mut self,
        merkle_root: String,
        nullifier: String,
        recipient: AccountId,
        amount: U128,
        auditor_pubkey: String,
        view_ct: String,
        relayer: AccountId,
        relayer_fee: U128,
        proof: Vec<u8>,
    ) {
        assert!(relayer_fee.0 <= amount.0, "fee exceeds amount");

        let root = parse_hex32(&merkle_root).expect("bad root hex");
        assert!(self.recent_roots.contains(&root), "stale root");

        let n = parse_hex32(&nullifier).expect("bad nullifier hex");
        assert!(!self.nullifiers.contains(&n), "double spend");

        let ap = parse_hex32(&auditor_pubkey).expect("bad auditor pubkey");

        let pi = [
            root,
            n,
            hash_bytes_to_field(recipient.as_bytes()),
            Field::from_u128(amount.0),
            hash_bytes_to_field(relayer.as_bytes()),
            Field::from_u128(relayer_fee.0),
            ap,
            hash_bytes_to_field(view_ct.as_bytes()),
        ];
        assert!(
            MockVerifier::default().verify(&proof, &pi),
            "invalid proof"
        );

        self.nullifiers.insert(n);
        events::emit_withdraw(
            &nullifier,
            recipient.as_str(),
            amount.0,
            relayer.as_str(),
            relayer_fee.0,
            &view_ct,
        );

        // FT payout (ft_transfer to recipient and relayer) is wired up in
        // the FT integration task. v0 in-memory tests stop at event emission.
    }
}

#[cfg(test)]
mod tests {
    use crate::poseidon::Field;
    use crate::Contract;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use near_sdk::AccountId;

    fn setup() -> Contract {
        testing_env!(VMContextBuilder::new().build());
        Contract::new(
            "owner.near".parse::<AccountId>().unwrap(),
            "usdc.near".parse::<AccountId>().unwrap(),
            vec![1, 2, 3],
            vec![1, 2, 3],
            vec![1, 2, 3],
        )
    }

    fn hex32(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; 32]))
    }

    fn seed_root(c: &mut Contract, v: u64) -> String {
        c.recent_roots.push(Field::from_u64(v));
        Field::from_u64(v).to_hex()
    }

    #[test]
    fn withdraw_with_valid_mock_proof_marks_spent() {
        let mut c = setup();
        let root = seed_root(&mut c, 7);
        c.withdraw(
            root,
            hex32(0xab),
            "bob.near".parse::<AccountId>().unwrap(),
            100_000_000u128.into(),
            hex32(0xcd),
            "viewct".into(),
            "relayer.near".parse::<AccountId>().unwrap(),
            500_000u128.into(),
            vec![1, 2, 3],
        );
        let n = Field::from_be_bytes(&[0xab; 32]);
        assert!(c.nullifiers.contains(&n));
    }

    #[test]
    #[should_panic(expected = "fee exceeds amount")]
    fn withdraw_fee_too_high_rejects() {
        let mut c = setup();
        let root = seed_root(&mut c, 7);
        c.withdraw(
            root,
            hex32(0xab),
            "bob.near".parse::<AccountId>().unwrap(),
            100u128.into(),
            hex32(0xcd),
            "v".into(),
            "relayer.near".parse::<AccountId>().unwrap(),
            200u128.into(),
            vec![1, 2, 3],
        );
    }

    #[test]
    #[should_panic(expected = "double spend")]
    fn withdraw_double_spend_rejects() {
        let mut c = setup();
        let root = seed_root(&mut c, 7);
        c.withdraw(
            root.clone(),
            hex32(0xab),
            "bob.near".parse::<AccountId>().unwrap(),
            100u128.into(),
            hex32(0xcd),
            "v".into(),
            "relayer.near".parse::<AccountId>().unwrap(),
            10u128.into(),
            vec![1, 2, 3],
        );
        // Second withdraw with same nullifier must reject.
        c.withdraw(
            root,
            hex32(0xab),
            "bob.near".parse::<AccountId>().unwrap(),
            100u128.into(),
            hex32(0xcd),
            "v".into(),
            "relayer.near".parse::<AccountId>().unwrap(),
            10u128.into(),
            vec![1, 2, 3],
        );
    }

    #[test]
    #[should_panic(expected = "invalid proof")]
    fn withdraw_with_empty_proof_rejects() {
        let mut c = setup();
        let root = seed_root(&mut c, 7);
        c.withdraw(
            root,
            hex32(0xab),
            "bob.near".parse::<AccountId>().unwrap(),
            100u128.into(),
            hex32(0xcd),
            "v".into(),
            "relayer.near".parse::<AccountId>().unwrap(),
            10u128.into(),
            vec![],
        );
    }

    #[test]
    #[should_panic(expected = "stale root")]
    fn withdraw_with_unknown_root_rejects() {
        let mut c = setup();
        c.withdraw(
            hex32(0x99),
            hex32(0xab),
            "bob.near".parse::<AccountId>().unwrap(),
            100u128.into(),
            hex32(0xcd),
            "v".into(),
            "relayer.near".parse::<AccountId>().unwrap(),
            10u128.into(),
            vec![1, 2, 3],
        );
    }
}
