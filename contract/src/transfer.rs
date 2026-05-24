use crate::deposit::{hash_bytes_to_field, parse_hex32};
use crate::poseidon::Field;
use crate::verifier::{MockVerifier, Verifier};
use crate::{events, Contract, ContractExt};
use near_sdk::near;

#[near]
impl Contract {
    /// Spends two input notes (by their nullifiers) and produces two output
    /// notes (by their commitments), all inside the shielded pool.
    pub fn transfer(
        &mut self,
        merkle_root: String,
        nullifiers: [String; 2],
        commitments: [String; 2],
        auditor_pubkey: String,
        recipient_auditor_pubkey: String,
        view_cts: [String; 2],
        note_cts: [String; 2],
        proof: Vec<u8>,
    ) {
        let root = parse_hex32(&merkle_root).expect("bad root hex");
        assert!(self.recent_roots.contains(&root), "stale root");

        let n0 = parse_hex32(&nullifiers[0]).expect("bad nullifier 0");
        let n1 = parse_hex32(&nullifiers[1]).expect("bad nullifier 1");
        assert_ne!(n0, n1, "nullifiers must differ");
        assert!(!self.nullifiers.contains(&n0), "double spend");
        assert!(!self.nullifiers.contains(&n1), "double spend");

        let c0 = parse_hex32(&commitments[0]).expect("bad commitment 0");
        let c1 = parse_hex32(&commitments[1]).expect("bad commitment 1");
        let ap = parse_hex32(&auditor_pubkey).expect("bad auditor pubkey");
        let rap = parse_hex32(&recipient_auditor_pubkey).expect("bad recipient auditor pubkey");

        let pi = [
            root,
            n0,
            n1,
            c0,
            c1,
            ap,
            rap,
            hash_bytes_to_field(view_cts[0].as_bytes()),
            hash_bytes_to_field(view_cts[1].as_bytes()),
        ];
        assert!(
            MockVerifier::default().verify(&proof, &pi),
            "invalid proof"
        );

        self.nullifiers.insert(n0);
        self.nullifiers.insert(n1);
        let li0 = self.tree.insert(c0);
        let li1 = self.tree.insert(c1);
        self.recent_roots.push(self.tree.root());

        events::emit_transfer(
            &merkle_root,
            [&nullifiers[0], &nullifiers[1]],
            [&commitments[0], &commitments[1]],
            [li0, li1],
            [&view_cts[0], &view_cts[1]],
            [&note_cts[0], &note_cts[1]],
        );

        let _ = Field::zero(); // silence unused import in some build configurations
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

    fn seed_root(c: &mut Contract, value: u64) -> String {
        c.recent_roots.push(Field::from_u64(value));
        Field::from_u64(value).to_hex()
    }

    #[test]
    fn transfer_with_valid_mock_proof_marks_nullifiers_spent() {
        let mut c = setup();
        let root = seed_root(&mut c, 7);
        c.transfer(
            root,
            [hex32(0xaa), hex32(0xbb)],
            [hex32(0xcc), hex32(0xdd)],
            hex32(0xee),
            hex32(0xff),
            ["v1".into(), "v2".into()],
            ["n1".into(), "n2".into()],
            vec![1, 2, 3],
        );
        let n_aa = Field::from_be_bytes(&[0xaa; 32]);
        let n_bb = Field::from_be_bytes(&[0xbb; 32]);
        assert!(c.nullifiers.contains(&n_aa));
        assert!(c.nullifiers.contains(&n_bb));
    }

    #[test]
    #[should_panic(expected = "stale root")]
    fn transfer_with_unknown_root_rejects() {
        let mut c = setup();
        c.transfer(
            hex32(0x99),
            [hex32(0xaa), hex32(0xbb)],
            [hex32(0xcc), hex32(0xdd)],
            hex32(0xee),
            hex32(0xff),
            ["v1".into(), "v2".into()],
            ["n1".into(), "n2".into()],
            vec![1, 2, 3],
        );
    }

    #[test]
    #[should_panic(expected = "double spend")]
    fn transfer_double_spend_rejects() {
        let mut c = setup();
        let root = seed_root(&mut c, 7);
        c.transfer(
            root,
            [hex32(0xaa), hex32(0xbb)],
            [hex32(0xcc), hex32(0xdd)],
            hex32(0xee),
            hex32(0xff),
            ["v1".into(), "v2".into()],
            ["n1".into(), "n2".into()],
            vec![1, 2, 3],
        );
        let root2 = seed_root(&mut c, 8);
        c.transfer(
            root2,
            [hex32(0xaa), hex32(0xb2)],
            [hex32(0xc2), hex32(0xd2)],
            hex32(0xee),
            hex32(0xff),
            ["v".into(), "v".into()],
            ["n".into(), "n".into()],
            vec![1, 2, 3],
        );
    }

    #[test]
    #[should_panic(expected = "nullifiers must differ")]
    fn transfer_rejects_identical_nullifiers() {
        let mut c = setup();
        let root = seed_root(&mut c, 7);
        c.transfer(
            root,
            [hex32(0xaa), hex32(0xaa)],
            [hex32(0xcc), hex32(0xdd)],
            hex32(0xee),
            hex32(0xff),
            ["v".into(), "v".into()],
            ["n".into(), "n".into()],
            vec![1, 2, 3],
        );
    }
}
