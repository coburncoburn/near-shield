use near_contract_standards::fungible_token::{
    FungibleToken, FungibleTokenCore, FungibleTokenResolver,
    metadata::{FungibleTokenMetadata, FungibleTokenMetadataProvider},
};
use near_contract_standards::storage_management::{
    StorageBalance, StorageBalanceBounds, StorageManagement,
};
use near_sdk::{
    AccountId, NearToken, PanicOnDefault, PromiseOrValue,
    collections::LazyOption,
    near,
    json_types::U128,
};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    token: FungibleToken,
    metadata: LazyOption<FungibleTokenMetadata>,
}

#[near]
impl Contract {
    /// Initialise the token, minting the full supply to `owner_id`.
    #[init]
    pub fn new(
        owner_id: AccountId,
        total_supply: U128,
        metadata: FungibleTokenMetadata,
    ) -> Self {
        metadata.assert_valid();
        let mut this = Self {
            token: FungibleToken::new(b"a"),
            metadata: LazyOption::new(b"m", Some(&metadata)),
        };
        this.token.internal_register_account(&owner_id);
        this.token.internal_deposit(&owner_id, total_supply.into());
        near_contract_standards::fungible_token::events::FtMint {
            owner_id: &owner_id,
            amount: total_supply,
            memo: Some("initial supply minted to owner"),
        }
        .emit();
        this
    }
}

// ── FungibleTokenCore ────────────────────────────────────────────────────────

#[near]
impl FungibleTokenCore for Contract {
    #[payable]
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        self.token.ft_transfer(receiver_id, amount, memo)
    }

    #[payable]
    fn ft_transfer_call(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128> {
        self.token.ft_transfer_call(receiver_id, amount, memo, msg)
    }

    fn ft_total_supply(&self) -> U128 {
        self.token.ft_total_supply()
    }

    fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        self.token.ft_balance_of(account_id)
    }
}

// ── FungibleTokenResolver ────────────────────────────────────────────────────

#[near]
impl FungibleTokenResolver for Contract {
    #[private]
    fn ft_resolve_transfer(
        &mut self,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
    ) -> U128 {
        let (used_amount, burned_amount) =
            self.token.internal_ft_resolve_transfer(&sender_id, receiver_id, amount);
        if burned_amount > 0 {
            near_sdk::log!("Account @{} burned {}", sender_id, burned_amount);
        }
        used_amount.into()
    }
}

// ── StorageManagement ────────────────────────────────────────────────────────

#[near]
impl StorageManagement for Contract {
    #[payable]
    fn storage_deposit(
        &mut self,
        account_id: Option<AccountId>,
        registration_only: Option<bool>,
    ) -> StorageBalance {
        self.token.storage_deposit(account_id, registration_only)
    }

    #[payable]
    fn storage_withdraw(&mut self, amount: Option<NearToken>) -> StorageBalance {
        self.token.storage_withdraw(amount)
    }

    #[payable]
    fn storage_unregister(&mut self, force: Option<bool>) -> bool {
        if let Some((account_id, balance)) =
            self.token.internal_storage_unregister(force)
        {
            near_sdk::log!("Closed @{} with {}", account_id, balance);
            true
        } else {
            false
        }
    }

    fn storage_balance_bounds(&self) -> StorageBalanceBounds {
        self.token.storage_balance_bounds()
    }

    fn storage_balance_of(&self, account_id: AccountId) -> Option<StorageBalance> {
        self.token.storage_balance_of(account_id)
    }
}

// ── FungibleTokenMetadataProvider ────────────────────────────────────────────

#[near]
impl FungibleTokenMetadataProvider for Contract {
    fn ft_metadata(&self) -> FungibleTokenMetadata {
        self.metadata.get().unwrap()
    }
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use near_contract_standards::fungible_token::metadata::FT_METADATA_SPEC;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn owner() -> AccountId {
        "owner.near".parse().unwrap()
    }

    fn metadata() -> FungibleTokenMetadata {
        FungibleTokenMetadata {
            spec: FT_METADATA_SPEC.to_string(),
            name: "Mock USD Coin".to_string(),
            symbol: "mUSDC".to_string(),
            icon: None,
            reference: None,
            reference_hash: None,
            decimals: 6,
        }
    }

    fn setup() -> VMContextBuilder {
        let mut ctx = VMContextBuilder::new();
        ctx.current_account_id("ft.near".parse().unwrap())
            .signer_account_id(owner())
            .predecessor_account_id(owner())
            .attached_deposit(NearToken::from_yoctonear(0));
        ctx
    }

    #[test]
    fn new_mints_total_supply_to_owner() {
        let ctx = setup();
        testing_env!(ctx.build());

        let total_supply = U128(1_000_000_000_000u128); // 1 million with 6 decimals
        let contract = Contract::new(owner(), total_supply, metadata());

        assert_eq!(
            contract.ft_total_supply(),
            total_supply,
            "total_supply should equal minted amount"
        );
        assert_eq!(
            contract.ft_balance_of(owner()),
            total_supply,
            "owner balance should equal total supply"
        );
    }

    #[test]
    fn balance_of_unregistered_account_returns_zero() {
        let ctx = setup();
        testing_env!(ctx.build());

        let contract = Contract::new(owner(), U128(1_000u128), metadata());
        let stranger: AccountId = "stranger.near".parse().unwrap();
        assert_eq!(
            contract.ft_balance_of(stranger),
            U128(0),
            "unregistered account should have zero balance"
        );
    }
}
