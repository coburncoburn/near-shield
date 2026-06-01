/**
 * Canonical honest-input builders shared across circuit tests and prove-verify.
 * This module contains NO test framework code — only pure builder functions
 * and their dependencies from @shielded-near/core and @shielded-near/client.
 */
import { BN254_MODULUS, Field, commitNote, computeNullifier, poseidon2 } from "@shielded-near/core";
import { MerkleTree } from "@shielded-near/client";

// Re-export so callers that need these for negative tests can import from one place.
export { BN254_MODULUS, Field, commitNote, computeNullifier, poseidon2 };
export { MerkleTree };

/**
 * Canonical honest deposit inputs.
 * Exported so prove-verify tests can import and reuse them.
 * Mirrors deposit.rs: amount=100, owner=11, auditor=22, blinding=33.
 */
export function honestDepositInput() {
  const amount = 100n;
  const ownerPubkey = new Field(11n);
  const auditorPubkey = new Field(22n);
  const blinding = new Field(33n);
  const viewCtHash = 7n; // arbitrary hash value
  // Field wrappers are required by the commitNote oracle; the circuit receives .value (bigint).
  const commitment = commitNote({ amount, ownerPubkey, auditorPubkey, blinding });
  return {
    commitment: commitment.value,
    amount,
    auditorPubkey: auditorPubkey.value,
    viewCtHash,
    ownerPubkey: ownerPubkey.value,
    blinding: blinding.value,
    viewCtHashWitness: viewCtHash,
  };
}

/**
 * Canonical honest transfer inputs.
 * Exported so prove-verify tests can import and reuse them.
 * Mirrors transfer.rs::honest():
 *   sk=7, owner=poseidon2(7,0), auditor=22, recipAuditor=33
 *   inputs: 60+40=100, outputs: 70+30=100
 */
export function honestTransferInput() {
  const sk = new Field(7n);
  const owner = poseidon2(sk, new Field(0n));
  const auditor = new Field(22n);
  const recipAuditor = new Field(33n);

  // Input commitments
  const c_in0 = commitNote({ amount: 60n, ownerPubkey: owner, auditorPubkey: auditor, blinding: new Field(1n) });
  const c_in1 = commitNote({ amount: 40n, ownerPubkey: owner, auditorPubkey: auditor, blinding: new Field(2n) });

  // Build merkle tree with both input commitments
  const tree = new MerkleTree();
  tree.append(c_in0); // index 0
  tree.append(c_in1); // index 1

  const merkleRoot = tree.root();
  const in0Path = tree.pathFor(0n);
  const in1Path = tree.pathFor(1n);

  // Nullifiers
  const nullifier0 = computeNullifier(sk, c_in0, 0n);
  const nullifier1 = computeNullifier(sk, c_in1, 1n);

  // Output commitments: recipient gets 70, sender change is 30
  const commitmentOut0 = commitNote({ amount: 70n, ownerPubkey: new Field(100n), auditorPubkey: recipAuditor, blinding: new Field(3n) });
  const commitmentOut1 = commitNote({ amount: 30n, ownerPubkey: owner, auditorPubkey: recipAuditor, blinding: new Field(4n) });

  return {
    merkleRoot: merkleRoot.value,
    nullifier0: nullifier0.value,
    nullifier1: nullifier1.value,
    commitmentOut0: commitmentOut0.value,
    commitmentOut1: commitmentOut1.value,
    auditorPubkey: auditor.value,
    recipientAuditorPubkey: recipAuditor.value,
    viewCtHashSender: 13n,
    viewCtHashRecipient: 14n,
    in0Amount: 60n,
    in0Owner: owner.value,
    in0Blinding: 1n,
    in0LeafIndex: 0n,
    in0Path: in0Path.map((f) => f.value),
    in1Amount: 40n,
    in1Owner: owner.value,
    in1Blinding: 2n,
    in1LeafIndex: 1n,
    in1Path: in1Path.map((f) => f.value),
    spendingKey: sk.value,
    out0Amount: 70n,
    out0Owner: 100n,
    out0Blinding: 3n,
    out1Amount: 30n,
    out1Owner: owner.value,
    out1Blinding: 4n,
    viewCtHashSenderWitness: 13n,
    viewCtHashRecipientWitness: 14n,
  };
}

/**
 * Canonical honest withdraw inputs.
 * Exported so prove-verify tests can import and reuse them.
 * Mirrors withdraw.rs::honest():
 *   sk=7, owner=poseidon2(7,0), auditor=22, blinding=33, amount=100,
 *   recipient=99, relayer=77, relayerFee=5, viewCtHash=13, leafIndex=0.
 */
export function honestWithdrawInput() {
  const sk = new Field(7n);
  const owner = poseidon2(sk, new Field(0n));
  const auditor = new Field(22n);
  const blinding = new Field(33n);
  const amount = 100n;
  const recipient = 99n;
  const relayer = 77n;
  const relayerFee = 5n;
  const viewCtHash = 13n;

  const commitment = commitNote({
    amount,
    ownerPubkey: owner,
    auditorPubkey: auditor,
    blinding,
  });

  const tree = new MerkleTree();
  tree.append(commitment); // index 0

  const merkleRoot = tree.root();
  const merklePath = tree.pathFor(0n);
  const nullifier = computeNullifier(sk, commitment, 0n);

  return {
    // public
    merkleRoot: merkleRoot.value,
    nullifier: nullifier.value,
    recipient,
    amount,
    relayer,
    relayerFee,
    auditorPubkey: auditor.value,
    viewCtHash,
    // private
    noteAmount: amount,
    noteOwner: owner.value,
    noteAuditor: auditor.value,
    noteBlinding: blinding.value,
    spendingKey: sk.value,
    leafIndex: 0n,
    merklePath: merklePath.map((f) => f.value),
    viewCtHashWitness: viewCtHash, // mirrors public viewCtHash — intentional duplication
  };
}
