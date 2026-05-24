use near_sdk::near;

pub mod merkle;
pub mod nullifiers;
pub mod poseidon;
pub mod roots;

#[near(contract_state)]
#[derive(Default)]
pub struct Contract {}

#[near]
impl Contract {
    #[init]
    pub fn new() -> Self {
        Self {}
    }
}
