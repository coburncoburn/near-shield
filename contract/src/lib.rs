use near_sdk::store::LookupMap;
use near_sdk::{near, AccountId, PanicOnDefault};

pub mod deposit;
pub mod events;
pub mod ft;
pub mod merkle;
pub mod nullifiers;
pub mod poseidon;
pub mod roots;
pub mod storage;
pub mod transfer;
pub mod validation;
pub mod verifier;
pub mod withdraw;

use merkle::IncrementalMerkleTree;
use nullifiers::NullifierSet;
use roots::RootsWindow;

pub const TREE_DEPTH: u8 = 20;
pub const ROOTS_WINDOW: u32 = 30;

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    pub owner: AccountId,
    pub usdc_token: AccountId,
    pub tree: IncrementalMerkleTree,
    pub recent_roots: RootsWindow,
    pub nullifiers: NullifierSet,
    pub vk_deposit: Vec<u8>,
    pub vk_transfer: Vec<u8>,
    pub vk_withdraw: Vec<u8>,
    /// Recovery book: USDC owed to accounts whose `ft_transfer` failed during
    /// a withdrawal. Claimable via `claim()`.
    pub unclaimed_payouts: LookupMap<AccountId, u128>,
}

#[near]
impl Contract {
    #[init]
    pub fn new(
        owner: AccountId,
        usdc_token: AccountId,
        vk_deposit: Vec<u8>,
        vk_transfer: Vec<u8>,
        vk_withdraw: Vec<u8>,
    ) -> Self {
        Self {
            owner,
            usdc_token,
            tree: IncrementalMerkleTree::new(b"m", TREE_DEPTH),
            recent_roots: RootsWindow::new(b"r", ROOTS_WINDOW),
            nullifiers: NullifierSet::new(b"n"),
            vk_deposit,
            vk_transfer,
            vk_withdraw,
            unclaimed_payouts: LookupMap::new(b"u"),
        }
    }

    pub fn owner(&self) -> AccountId {
        self.owner.clone()
    }
    pub fn usdc_token(&self) -> AccountId {
        self.usdc_token.clone()
    }
    pub fn merkle_root(&self) -> String {
        self.tree.root().to_hex()
    }
    pub fn is_nullifier_spent(&self, n_hex: String) -> bool {
        match deposit::parse_hex32(&n_hex) {
            Some(f) => self.nullifiers.contains(&f),
            None => false,
        }
    }
}
