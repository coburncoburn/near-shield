//! Storage staking helpers.
//!
//! Each shielded operation appends to storage:
//!   - `deposit`: 1 Merkle leaf (32 B) + 1 root window slot (32 B) + log bytes
//!   - `transfer`: 2 nullifier entries (~32 B each) + 2 Merkle leaves + 2 logs
//!   - `withdraw`: 1 nullifier entry + log bytes
//!
//! NEAR's storage staking model requires the caller to attach NEAR that covers
//! the bytes added. These constants are upper-bound estimates with margin; the
//! contract refunds the excess in a future patch (todo: refund to predecessor).
//!
//! Rationale: without this, an attacker can spam free deposits to inflate the
//! Merkle tree to its 1M-leaf capacity, exhausting storage cost on the pool
//! account (which the deployer pays).

use near_sdk::{env, require, NearToken};

/// NEAR storage cost per byte: 1e19 yoctoNEAR (= 10^-5 NEAR).
const YOCTO_PER_BYTE: u128 = 10_000_000_000_000_000_000;

/// Conservative byte estimates per action, including:
/// - on-chain state writes (Merkle leaves, nullifier entries, root window)
/// - log overhead the contract emits
pub const DEPOSIT_BYTES: u64 = 512; // 1 leaf + root slot + log preamble + view_ct/note_ct headers
pub const TRANSFER_BYTES: u64 = 1024; // 2 leaves + 2 nullifiers + 2 logs
pub const WITHDRAW_BYTES: u64 = 256; // 1 nullifier + log

pub fn require_storage_deposit(bytes: u64) {
    let required = NearToken::from_yoctonear((bytes as u128) * YOCTO_PER_BYTE);
    let attached = env::attached_deposit();
    require!(
        attached >= required,
        format!(
            "insufficient storage deposit: need {} yoctoNEAR for {} bytes, got {}",
            required.as_yoctonear(),
            bytes,
            attached.as_yoctonear()
        )
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn ctx_with_deposit(yocto: u128) {
        let mut ctx = VMContextBuilder::new();
        ctx.attached_deposit(NearToken::from_yoctonear(yocto));
        testing_env!(ctx.build());
    }

    #[test]
    fn passes_when_attached_meets_cost() {
        ctx_with_deposit(DEPOSIT_BYTES as u128 * YOCTO_PER_BYTE);
        require_storage_deposit(DEPOSIT_BYTES);
    }

    #[test]
    fn passes_when_attached_exceeds_cost() {
        ctx_with_deposit(DEPOSIT_BYTES as u128 * YOCTO_PER_BYTE * 10);
        require_storage_deposit(DEPOSIT_BYTES);
    }

    #[test]
    #[should_panic(expected = "insufficient storage deposit")]
    fn rejects_when_attached_below_cost() {
        ctx_with_deposit(1);
        require_storage_deposit(DEPOSIT_BYTES);
    }

    #[test]
    #[should_panic(expected = "insufficient storage deposit")]
    fn rejects_zero_attached() {
        ctx_with_deposit(0);
        require_storage_deposit(DEPOSIT_BYTES);
    }
}
