use crate::poseidon::Field;
use crate::{deposit::DepositArgs, Contract, ContractExt};
use near_sdk::json_types::U128;
use near_sdk::{env, near, require, AccountId, Gas, Promise, PromiseOrValue};

/// Gas budget for an `ft_transfer` cross-contract call. NEP-141 payouts are
/// tiny — 5 Tgas is comfortable.
const FT_TRANSFER_GAS: Gas = Gas::from_tgas(5);

#[near]
impl Contract {
    /// NEP-141 callback: USDC is being transferred *into* this contract. The
    /// caller (the USDC token contract) calls this hook with the depositor's
    /// account, the amount, and a JSON `msg` containing the shielded-deposit
    /// payload. We run the deposit logic and return `0` unused tokens (we
    /// accept the full amount).
    pub fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        require!(
            env::predecessor_account_id() == self.usdc_token,
            "only USDC token may call ft_on_transfer"
        );
        let args: DepositArgs = near_sdk::serde_json::from_str(&msg)
            .expect("bad ft_on_transfer msg: expected DepositArgs JSON");
        require!(args.amount.0 == amount.0, "amount mismatch between FT transfer and proof");
        let _ = sender_id; // identity of the depositor not needed by the circuit
        self.do_deposit(args);
        PromiseOrValue::Value(U128(0))
    }

    /// Internal helper used by withdraw to pay USDC out via ft_transfer.
    pub(crate) fn pay_ft(&self, to: AccountId, amount: u128) -> Promise {
        Promise::new(self.usdc_token.clone()).function_call(
            "ft_transfer".to_string(),
            near_sdk::serde_json::to_vec(&near_sdk::serde_json::json!({
                "receiver_id": to,
                "amount": U128(amount),
                "memo": Option::<String>::None,
            }))
            .expect("serialize ft_transfer args"),
            near_sdk::NearToken::from_yoctonear(1), // NEP-141 requires 1 yocto attached
            FT_TRANSFER_GAS,
        )
    }
}

/// Convenience: parse a 32-byte hex field used in FT-deposit-msg validation tests.
#[allow(dead_code)]
pub(crate) fn hex_field(hex_str: &str) -> Field {
    crate::deposit::parse_hex32(hex_str).expect("bad hex32")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Contract;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{testing_env, AccountId};

    fn usdc() -> AccountId {
        "usdc.near".parse().unwrap()
    }

    fn setup_with_usdc_predecessor() -> Contract {
        let mut ctx = VMContextBuilder::new();
        ctx.predecessor_account_id(usdc());
        testing_env!(ctx.build());
        Contract::new(
            "owner.near".parse().unwrap(),
            usdc(),
            vec![1, 2, 3],
            vec![1, 2, 3],
            vec![1, 2, 3],
        )
    }

    fn hex32(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; 32]))
    }

    fn deposit_msg(amount: u128) -> String {
        near_sdk::serde_json::to_string(&near_sdk::serde_json::json!({
            "commitment": hex32(0x01),
            "amount": U128(amount),
            "auditor_pubkey": hex32(0x02),
            "view_ct": "v",
            "note_ct": "n",
            "proof": [1, 2, 3],
        }))
        .unwrap()
    }

    #[test]
    fn ft_on_transfer_with_matching_amount_processes_deposit() {
        let mut c = setup_with_usdc_predecessor();
        let pre_root = c.merkle_root();
        let result = c.ft_on_transfer("alice.near".parse().unwrap(), U128(100), deposit_msg(100));
        match result {
            PromiseOrValue::Value(unused) => assert_eq!(unused.0, 0),
            _ => panic!("expected immediate Value return"),
        }
        assert_ne!(c.merkle_root(), pre_root);
    }

    #[test]
    #[should_panic(expected = "amount mismatch")]
    fn ft_on_transfer_amount_mismatch_panics() {
        let mut c = setup_with_usdc_predecessor();
        c.ft_on_transfer("alice.near".parse().unwrap(), U128(50), deposit_msg(100));
    }

    #[test]
    #[should_panic(expected = "only USDC token")]
    fn ft_on_transfer_wrong_predecessor_rejects() {
        // Predecessor is not USDC.
        let mut ctx = VMContextBuilder::new();
        ctx.predecessor_account_id("attacker.near".parse().unwrap());
        testing_env!(ctx.build());
        let mut c = Contract::new(
            "owner.near".parse().unwrap(),
            usdc(),
            vec![1, 2, 3],
            vec![1, 2, 3],
            vec![1, 2, 3],
        );
        c.ft_on_transfer("alice.near".parse().unwrap(), U128(100), deposit_msg(100));
    }
}
