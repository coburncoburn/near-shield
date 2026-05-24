use near_sdk::serde_json::json;

pub fn emit_deposit(commitment: &str, leaf_index: u64, view_ct: &str, note_ct: &str) {
    near_sdk::env::log_str(
        &json!({
            "standard": "shielded-pool",
            "event": "deposit",
            "data": {
                "commitment": commitment,
                "leaf_index": leaf_index,
                "view_ct": view_ct,
                "note_ct": note_ct,
            }
        })
        .to_string(),
    );
}

pub fn emit_transfer(
    merkle_root: &str,
    nullifiers: [&str; 2],
    commitments: [&str; 2],
    leaf_indices: [u64; 2],
    view_cts: [&str; 2],
    note_cts: [&str; 2],
) {
    near_sdk::env::log_str(
        &json!({
            "standard": "shielded-pool",
            "event": "transfer",
            "data": {
                "merkle_root": merkle_root,
                "nullifiers": nullifiers,
                "commitments": commitments,
                "leaf_indices": leaf_indices,
                "view_cts": view_cts,
                "note_cts": note_cts,
            }
        })
        .to_string(),
    );
}

pub fn emit_withdraw(
    nullifier: &str,
    recipient: &str,
    amount: u128,
    relayer: &str,
    relayer_fee: u128,
    view_ct: &str,
) {
    near_sdk::env::log_str(
        &json!({
            "standard": "shielded-pool",
            "event": "withdraw",
            "data": {
                "nullifier": nullifier,
                "recipient": recipient,
                "amount": amount.to_string(),
                "relayer": relayer,
                "relayer_fee": relayer_fee.to_string(),
                "view_ct": view_ct,
            }
        })
        .to_string(),
    );
}
