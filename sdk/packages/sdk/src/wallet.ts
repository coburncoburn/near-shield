import { x25519 } from "@noble/curves/ed25519";
import {
  Field,
  auditorPubkeyToField,
  commitNote,
  computeNullifier,
  encodeDisclosure,
  encodeNotePayload,
  generateKeyPair,
  hashBytesToField,
  keccakToField,
  poseidon2,
  scanNotes,
  sealTo,
  SEAL_CONTEXT_NOTE,
  SEAL_CONTEXT_VIEW,
  type DiscoveredNote,
  type KeyPair,
  type Note,
  type NoteCiphertext,
  type ViewDisclosure,
} from "@shielded-near/core";

import { StubProver, type Prover } from "./prover.js";
import { encodeCiphertext } from "./envelopes.js";

export interface WalletConfig {
  /** Seed bytes (e.g. NEAR-wallet-sign-in-derived). Used to derive sk and vk. */
  seed: Uint8Array;
  /** USDC FT contract account id, used in tx envelopes. */
  usdcTokenAccountId: string;
  /** The shielded pool contract account id. */
  poolAccountId: string;
  /**
   * The Groth16 prover. Production deployments inject a `SubprocessProver`
   * pointing at a real prover binary; tests use the default `StubProver`
   * which emits a one-byte placeholder (only accepted by mock-verifier
   * contract builds).
   */
  prover?: Prover;
}

export interface DepositRequest {
  amount: bigint;
  auditorPubkey: Uint8Array;
}

export interface TransferRequest {
  amount: bigint;
  recipientOwnerPubkey: Field;
  recipientAuditorPubkey: Uint8Array;
  recipientViewingPubkey: Uint8Array;
  memo?: string;
}

export interface WithdrawRequest {
  amount: bigint;
  recipientNearAccount: string;
  relayer: string;
  relayerFee: bigint;
  /**
   * Merkle inclusion path for the input note (20 sibling hashes, 0x-prefixed
   * 32-byte hex). Required only by `buildWithdrawProved`; the synchronous
   * `buildWithdraw` ignores this field.
   */
  merklePath?: string[];
  /**
   * Merkle root at the time of proving. Required only by `buildWithdrawProved`.
   */
  merkleRoot?: string;
}

export interface TransferMerkleInputs {
  /** Merkle root at the time of proving. */
  merkleRoot: string;
  /** Merkle inclusion path for input note 0 (20 sibling hashes, 0x-prefixed hex). */
  merklePath0: string[];
  /** Merkle inclusion path for input note 1 (20 sibling hashes, 0x-prefixed hex). */
  merklePath1: string[];
}

/**
 * A "built transaction": the artifacts a relayer or self-submitter feeds into
 * NEAR. We split building from submitting so tests can verify the witness/proof
 * shape without needing a live chain.
 */
export interface BuiltTx {
  method: "deposit" | "transfer" | "withdraw";
  publicInputs: Record<string, string | string[] | number>;
  proof: Uint8Array;
  viewCiphertexts: Uint8Array[];
  noteCiphertexts: Uint8Array[];
}

/**
 * v0 Wallet: handles key derivation, note scanning, and transaction *building*.
 * The synchronous builders below still emit placeholder proofs for mock-verifier
 * sandbox flows. Funds-bearing deployments must use an injected production
 * prover and the async proved builders once the real deposit/transfer/withdraw
 * proving keys are available.
 */
export class Wallet {
  readonly spendingKey: Field;
  readonly ownerPubkey: Field;
  readonly viewingKey: KeyPair;
  readonly prover: Prover;
  private notes: DiscoveredNote[] = [];
  private spent = new Set<bigint>();

  constructor(private readonly config: WalletConfig) {
    if (config.seed.length < 32) {
      throw new Error("seed must be >= 32 bytes");
    }
    this.prover = config.prover ?? new StubProver();
    // Derive sk and vk deterministically from the seed.
    this.spendingKey = Field.fromHex(
      "0x" + Array.from(config.seed.slice(0, 32)).map((b) => b.toString(16).padStart(2, "0")).join("")
    );
    this.ownerPubkey = poseidon2(this.spendingKey, Field.zero());
    // The viewing keypair: deterministic-from-seed in production; here we
    // derive one from a hash but for v0 testing accept either deterministic
    // or freshly generated. Use second half of seed if available.
    if (config.seed.length >= 64) {
      this.viewingKey = {
        privateKey: config.seed.slice(32, 64),
        publicKey: deriveX25519Pub(config.seed.slice(32, 64)),
      };
    } else {
      this.viewingKey = generateKeyPair();
    }
  }

  /** Returns the user's owner pubkey for sharing out-of-band as their "address". */
  address(): { ownerPubkey: string; viewingPubkey: string } {
    return {
      ownerPubkey: this.ownerPubkey.toHex(),
      viewingPubkey: hex(this.viewingKey.publicKey),
    };
  }

  /** Ingest new note ciphertexts from on-chain logs. */
  scan(cts: NoteCiphertext[]): number {
    const found = scanNotes(this.viewingKey.privateKey, cts);
    this.notes.push(...found);
    return found.length;
  }

  /**
   * Marks the note at `leafIndex` as spent so it is excluded from `balance()`
   * and input selection. Callers invoke this after a transfer/withdraw is
   * confirmed on-chain (the wallet builds but does not submit txs, so it can't
   * know a spend landed on its own).
   */
  markSpent(leafIndex: bigint): void {
    this.spent.add(leafIndex);
  }

  balance(): bigint {
    return this.notes.reduce(
      (sum, n) => (this.spent.has(n.leafIndex) ? sum : sum + n.note.amount),
      0n
    );
  }

  buildDeposit(req: DepositRequest): BuiltTx {
    const auditorPubkeyField = auditorPubkeyToField(req.auditorPubkey);
    const blinding = randomField();
    const note: Note = {
      amount: req.amount,
      ownerPubkey: this.ownerPubkey,
      auditorPubkey: auditorPubkeyField,
      blinding,
    };
    const commitment = commitNote(note);
    const disclosure: ViewDisclosure = {
      action: "deposit",
      senderOwnerPubkey: this.ownerPubkey.toHex(),
      recipientOwnerPubkey: this.ownerPubkey.toHex(),
      amounts: [req.amount.toString()],
      memo: "",
      timestamp: Math.floor(Date.now() / 1000),
    };
    const viewCt = sealTo(req.auditorPubkey, encodeDisclosure(disclosure), SEAL_CONTEXT_VIEW);
    const noteCt = sealTo(this.viewingKey.publicKey, encodeNotePayload(note, req.auditorPubkey), SEAL_CONTEXT_NOTE);
    return {
      method: "deposit",
      publicInputs: {
        commitment: commitment.toHex(),
        amount: req.amount.toString(),
        auditorPubkey: auditorPubkeyField.toHex(),
        viewCtLen: viewCt.length,
      },
      proof: new Uint8Array([0]),
      viewCiphertexts: [viewCt],
      noteCiphertexts: [noteCt],
    };
  }

  buildTransfer(req: TransferRequest): BuiltTx {
    if (req.amount <= 0n) {
      throw new Error("transfer amount must be positive");
    }
    const inputs = this.findTransferInputs(req.amount);
    if (!inputs) {
      throw new Error(`no two unspent notes cover ${req.amount} with the same auditor (have: ${this.balance()})`);
    }

    const [input0, input1] = inputs;
    const senderAuditorField = input0.note.auditorPubkey;
    const senderAuditorPubkey = input0.auditorPubkeyBytes;
    if (!senderAuditorPubkey) {
      throw new Error("input note is missing auditor pubkey bytes; rescan notes emitted by the current SDK");
    }
    const nullifier0 = computeNullifier(this.spendingKey, input0.commitment, input0.leafIndex);
    const nullifier1 = computeNullifier(this.spendingKey, input1.commitment, input1.leafIndex);
    const inputTotal = input0.note.amount + input1.note.amount;

    const recipientAuditorField = auditorPubkeyToField(req.recipientAuditorPubkey);
    const recipientOut: Note = {
      amount: req.amount,
      ownerPubkey: req.recipientOwnerPubkey,
      auditorPubkey: recipientAuditorField,
      blinding: randomField(),
    };
    const changeOut: Note = {
      amount: inputTotal - req.amount,
      ownerPubkey: this.ownerPubkey,
      auditorPubkey: senderAuditorField,
      blinding: randomField(),
    };
    assertValueConserved(recipientOut.amount, changeOut.amount, inputTotal);
    const c_recipient = commitNote(recipientOut);
    const c_change = commitNote(changeOut);

    const disclosure: ViewDisclosure = {
      action: "transfer",
      senderOwnerPubkey: this.ownerPubkey.toHex(),
      recipientOwnerPubkey: req.recipientOwnerPubkey.toHex(),
      amounts: [req.amount.toString(), changeOut.amount.toString()],
      memo: req.memo ?? "",
      timestamp: Math.floor(Date.now() / 1000),
    };
    const viewCtSender = sealTo(senderAuditorPubkey, encodeDisclosure(disclosure), SEAL_CONTEXT_VIEW);
    const viewCtRecipient = sealTo(req.recipientAuditorPubkey, encodeDisclosure(disclosure), SEAL_CONTEXT_VIEW);

    // Note ciphertexts: one to recipient's vk (for the recipient output) and
    // one to the sender's own vk (for the change output).
    const noteCtRecipient = sealTo(req.recipientViewingPubkey, encodeNotePayload(recipientOut, req.recipientAuditorPubkey), SEAL_CONTEXT_NOTE);
    const noteCtChange = sealTo(this.viewingKey.publicKey, encodeNotePayload(changeOut, senderAuditorPubkey), SEAL_CONTEXT_NOTE);

    return {
      method: "transfer",
      publicInputs: {
        merkleRoot: "",
        nullifiers: [nullifier0.toHex(), nullifier1.toHex()],
        commitments: [c_recipient.toHex(), c_change.toHex()],
        auditorPubkey: senderAuditorField.toHex(),
        recipientAuditorPubkey: recipientAuditorField.toHex(),
        amounts: [req.amount.toString(), changeOut.amount.toString()],
      },
      proof: new Uint8Array([0]),
      viewCiphertexts: [viewCtSender, viewCtRecipient],
      noteCiphertexts: [noteCtRecipient, noteCtChange],
    };
  }

  buildWithdraw(req: WithdrawRequest): BuiltTx {
    if (req.relayerFee > req.amount) {
      throw new Error("relayer_fee exceeds amount");
    }
    const note = this.notes.find(
      (n) => n.note.amount === req.amount && !this.spent.has(n.leafIndex)
    );
    if (!note) {
      throw new Error(`no unspent note with amount exactly ${req.amount} (v0 whole-note withdraw)`);
    }
    const nullifier = computeNullifier(this.spendingKey, note.commitment, note.leafIndex);
    const disclosure: ViewDisclosure = {
      action: "withdraw",
      senderOwnerPubkey: this.ownerPubkey.toHex(),
      recipientOwnerPubkey: req.recipientNearAccount,
      amounts: [req.amount.toString(), req.relayerFee.toString()],
      memo: "",
      timestamp: Math.floor(Date.now() / 1000),
    };
    const auditorField = note.note.auditorPubkey;
    if (!note.auditorPubkeyBytes) {
      throw new Error("input note is missing auditor pubkey bytes; rescan notes emitted by the current SDK");
    }
    const viewCt = sealTo(note.auditorPubkeyBytes, encodeDisclosure(disclosure), SEAL_CONTEXT_VIEW);
    return {
      method: "withdraw",
      publicInputs: {
        merkleRoot: "",
        nullifier: nullifier.toHex(),
        recipient: req.recipientNearAccount,
        amount: req.amount.toString(),
        relayer: req.relayer,
        relayerFee: req.relayerFee.toString(),
        auditorPubkey: auditorField.toHex(),
      },
      proof: new Uint8Array([0]),
      viewCiphertexts: [viewCt],
      noteCiphertexts: [],
    };
  }

  /**
   * Builds a deposit transaction with a real Groth16 proof from the given
   * `Prover`. Returns a `BuiltTx` identical to `buildDeposit` except
   * `proof` is the full 256-byte EIP-196/197 serialisation.
   */
  async buildDepositProved(req: DepositRequest, prover: Prover): Promise<BuiltTx> {
    const auditorPubkeyField = auditorPubkeyToField(req.auditorPubkey);
    const blinding = randomField();
    const note: Note = {
      amount: req.amount,
      ownerPubkey: this.ownerPubkey,
      auditorPubkey: auditorPubkeyField,
      blinding,
    };
    const commitment = commitNote(note);
    const disclosure: ViewDisclosure = {
      action: "deposit",
      senderOwnerPubkey: this.ownerPubkey.toHex(),
      recipientOwnerPubkey: this.ownerPubkey.toHex(),
      amounts: [req.amount.toString()],
      memo: "",
      timestamp: Math.floor(Date.now() / 1000),
    };
    const viewCt = sealTo(req.auditorPubkey, encodeDisclosure(disclosure), SEAL_CONTEXT_VIEW);
    const noteCt = sealTo(this.viewingKey.publicKey, encodeNotePayload(note, req.auditorPubkey), SEAL_CONTEXT_NOTE);

    const viewCtHashHex = viewCtHash(viewCt);

    // Public inputs ordered: commitment, amount, auditorPubkey, view_ct_hash
    const publicInputsArr: string[] = [
      commitment.toHex(),
      new Field(req.amount).toHex(),
      auditorPubkeyField.toHex(),
      viewCtHashHex,
    ];

    const witness: Record<string, unknown> = {
      ownerPubkey: this.ownerPubkey.toHex(),
      blinding: blinding.toHex(),
      viewCtHashWitness: viewCtHashHex,
    };

    const proof = await prover.prove({ circuit: "deposit", publicInputs: publicInputsArr, witness });

    return {
      method: "deposit",
      publicInputs: {
        commitment: commitment.toHex(),
        amount: req.amount.toString(),
        auditorPubkey: auditorPubkeyField.toHex(),
        viewCtLen: viewCt.length,
      },
      proof,
      viewCiphertexts: [viewCt],
      noteCiphertexts: [noteCt],
    };
  }

  /**
   * Builds a transfer transaction with a real Groth16 proof from the given
   * `Prover`. The caller must supply `merkleInputs` with the merkle root and
   * inclusion paths for both input notes (the wallet cannot fetch on-chain
   * state itself).
   */
  async buildTransferProved(
    req: TransferRequest,
    prover: Prover,
    merkleInputs: TransferMerkleInputs
  ): Promise<BuiltTx> {
    if (req.amount <= 0n) {
      throw new Error("transfer amount must be positive");
    }
    const inputs = this.findTransferInputs(req.amount);
    if (!inputs) {
      throw new Error(`no two unspent notes cover ${req.amount} with the same auditor (have: ${this.balance()})`);
    }

    const [input0, input1] = inputs;
    const senderAuditorField = input0.note.auditorPubkey;
    const senderAuditorPubkey = input0.auditorPubkeyBytes;
    if (!senderAuditorPubkey) {
      throw new Error("input note is missing auditor pubkey bytes; rescan notes emitted by the current SDK");
    }
    const nullifier0 = computeNullifier(this.spendingKey, input0.commitment, input0.leafIndex);
    const nullifier1 = computeNullifier(this.spendingKey, input1.commitment, input1.leafIndex);
    const inputTotal = input0.note.amount + input1.note.amount;

    const recipientAuditorField = auditorPubkeyToField(req.recipientAuditorPubkey);
    const recipientBlinding = randomField();
    const changeBlinding = randomField();
    const recipientOut: Note = {
      amount: req.amount,
      ownerPubkey: req.recipientOwnerPubkey,
      auditorPubkey: recipientAuditorField,
      blinding: recipientBlinding,
    };
    const changeOut: Note = {
      amount: inputTotal - req.amount,
      ownerPubkey: this.ownerPubkey,
      auditorPubkey: senderAuditorField,
      blinding: changeBlinding,
    };
    assertValueConserved(recipientOut.amount, changeOut.amount, inputTotal);
    const c_recipient = commitNote(recipientOut);
    const c_change = commitNote(changeOut);

    const disclosure: ViewDisclosure = {
      action: "transfer",
      senderOwnerPubkey: this.ownerPubkey.toHex(),
      recipientOwnerPubkey: req.recipientOwnerPubkey.toHex(),
      amounts: [req.amount.toString(), changeOut.amount.toString()],
      memo: req.memo ?? "",
      timestamp: Math.floor(Date.now() / 1000),
    };
    const viewCtSender = sealTo(senderAuditorPubkey, encodeDisclosure(disclosure), SEAL_CONTEXT_VIEW);
    const viewCtRecipient = sealTo(req.recipientAuditorPubkey, encodeDisclosure(disclosure), SEAL_CONTEXT_VIEW);

    const noteCtRecipient = sealTo(req.recipientViewingPubkey, encodeNotePayload(recipientOut, req.recipientAuditorPubkey), SEAL_CONTEXT_NOTE);
    const noteCtChange = sealTo(this.viewingKey.publicKey, encodeNotePayload(changeOut, senderAuditorPubkey), SEAL_CONTEXT_NOTE);

    const viewCtHashSenderHex = viewCtHash(viewCtSender);
    const viewCtHashRecipientHex = viewCtHash(viewCtRecipient);

    // Public inputs ordered (9):
    // merkle_root, nullifier0, nullifier1, commitment_out0, commitment_out1,
    // auditor_pubkey, recipient_auditor_pubkey, view_ct_hash_sender, view_ct_hash_recipient
    const publicInputsArr: string[] = [
      merkleInputs.merkleRoot,
      nullifier0.toHex(),
      nullifier1.toHex(),
      c_recipient.toHex(),
      c_change.toHex(),
      senderAuditorField.toHex(),
      recipientAuditorField.toHex(),
      viewCtHashSenderHex,
      viewCtHashRecipientHex,
    ];

    const padPath = (p: string[]): string[] => {
      const out = [...p];
      while (out.length < 20) out.push(Field.zero().toHex());
      return out.slice(0, 20);
    };

    const witness: Record<string, unknown> = {
      in0Amount: new Field(input0.note.amount).toHex(),
      in0OwnerPubkey: input0.note.ownerPubkey.toHex(),
      in0Blinding: input0.note.blinding.toHex(),
      in0LeafIndex: new Field(input0.leafIndex).toHex(),
      in0Path: padPath(merkleInputs.merklePath0),
      in1Amount: new Field(input1.note.amount).toHex(),
      in1OwnerPubkey: input1.note.ownerPubkey.toHex(),
      in1Blinding: input1.note.blinding.toHex(),
      in1LeafIndex: new Field(input1.leafIndex).toHex(),
      in1Path: padPath(merkleInputs.merklePath1),
      spendingKey: this.spendingKey.toHex(),
      out0Amount: new Field(recipientOut.amount).toHex(),
      out0OwnerPubkey: recipientOut.ownerPubkey.toHex(),
      out0Blinding: recipientBlinding.toHex(),
      out1Amount: new Field(changeOut.amount).toHex(),
      out1OwnerPubkey: changeOut.ownerPubkey.toHex(),
      out1Blinding: changeBlinding.toHex(),
      viewCtHashSenderWitness: viewCtHashSenderHex,
      viewCtHashRecipientWitness: viewCtHashRecipientHex,
    };

    const proof = await prover.prove({ circuit: "transfer", publicInputs: publicInputsArr, witness });

    return {
      method: "transfer",
      publicInputs: {
        merkleRoot: merkleInputs.merkleRoot,
        nullifiers: [nullifier0.toHex(), nullifier1.toHex()],
        commitments: [c_recipient.toHex(), c_change.toHex()],
        auditorPubkey: senderAuditorField.toHex(),
        recipientAuditorPubkey: recipientAuditorField.toHex(),
        amounts: [req.amount.toString(), changeOut.amount.toString()],
      },
      proof,
      viewCiphertexts: [viewCtSender, viewCtRecipient],
      noteCiphertexts: [noteCtRecipient, noteCtChange],
    };
  }

  /**
   * Builds a withdraw transaction with a real Groth16 proof from the given
   * `Prover`. `req.merklePath` (20 siblings) and `req.merkleRoot` must be
   * populated by the caller from on-chain state.
   */
  async buildWithdrawProved(req: WithdrawRequest, prover: Prover): Promise<BuiltTx> {
    if (req.relayerFee > req.amount) {
      throw new Error("relayer_fee exceeds amount");
    }
    if (!req.merklePath || req.merklePath.length !== 20) {
      throw new Error("buildWithdrawProved requires req.merklePath with exactly 20 elements");
    }
    if (!req.merkleRoot) {
      throw new Error("buildWithdrawProved requires req.merkleRoot");
    }
    const note = this.notes.find(
      (n) => n.note.amount === req.amount && !this.spent.has(n.leafIndex)
    );
    if (!note) {
      throw new Error(`no unspent note with amount exactly ${req.amount} (v0 whole-note withdraw)`);
    }
    const nullifier = computeNullifier(this.spendingKey, note.commitment, note.leafIndex);
    const disclosure: ViewDisclosure = {
      action: "withdraw",
      senderOwnerPubkey: this.ownerPubkey.toHex(),
      recipientOwnerPubkey: req.recipientNearAccount,
      amounts: [req.amount.toString(), req.relayerFee.toString()],
      memo: "",
      timestamp: Math.floor(Date.now() / 1000),
    };
    const auditorField = note.note.auditorPubkey;
    if (!note.auditorPubkeyBytes) {
      throw new Error("input note is missing auditor pubkey bytes; rescan notes emitted by the current SDK");
    }
    const viewCt = sealTo(note.auditorPubkeyBytes, encodeDisclosure(disclosure), SEAL_CONTEXT_VIEW);

    const viewCtHashHex = viewCtHash(viewCt);

    // Public inputs ordered (8):
    // merkle_root, nullifier, recipient, amount, relayer, relayer_fee,
    // auditor_pubkey, view_ct_hash
    const recipientField = fieldFromAccountId(req.recipientNearAccount);
    const relayerField = fieldFromAccountId(req.relayer);
    const publicInputsArr: string[] = [
      req.merkleRoot,
      nullifier.toHex(),
      recipientField.toHex(),
      new Field(req.amount).toHex(),
      relayerField.toHex(),
      new Field(req.relayerFee).toHex(),
      auditorField.toHex(),
      viewCtHashHex,
    ];

    const witness: Record<string, unknown> = {
      noteAmount: new Field(note.note.amount).toHex(),
      noteOwnerPubkey: note.note.ownerPubkey.toHex(),
      noteAuditorPubkey: note.note.auditorPubkey.toHex(),
      noteBlinding: note.note.blinding.toHex(),
      spendingKey: this.spendingKey.toHex(),
      leafIndex: new Field(note.leafIndex).toHex(),
      merklePath: req.merklePath,
      viewCtHashWitness: viewCtHashHex,
    };

    const proof = await prover.prove({ circuit: "withdraw", publicInputs: publicInputsArr, witness });

    return {
      method: "withdraw",
      publicInputs: {
        merkleRoot: req.merkleRoot,
        nullifier: nullifier.toHex(),
        recipient: req.recipientNearAccount,
        amount: req.amount.toString(),
        relayer: req.relayer,
        relayerFee: req.relayerFee.toString(),
        auditorPubkey: auditorField.toHex(),
      },
      proof,
      viewCiphertexts: [viewCt],
      noteCiphertexts: [],
    };
  }

  private findTransferInputs(amount: bigint): [DiscoveredNote, DiscoveredNote] | null {
    for (let i = 0; i < this.notes.length; i++) {
      for (let j = i + 1; j < this.notes.length; j++) {
        const a = this.notes[i];
        const b = this.notes[j];
        if (this.spent.has(a.leafIndex) || this.spent.has(b.leafIndex)) continue;
        if (!a.note.auditorPubkey.equals(b.note.auditorPubkey)) continue;
        if (!sameBytes(a.auditorPubkeyBytes, b.auditorPubkeyBytes)) continue;
        if (a.note.amount + b.note.amount >= amount) {
          return [a, b];
        }
      }
    }
    return null;
  }
}

// --- Helpers ---

/**
 * Derives the view_ct_hash public input value from raw sealed bytes. Hashes the
 * bytes of the encoded ("0x"+hex) string — the exact bytes the contract receives
 * and hashes on-chain — so the proof's public input matches what the contract
 * computes from `args.view_ct.as_bytes()`.
 */
function viewCtHash(sealed: Uint8Array): string {
  return keccakToField(new TextEncoder().encode(encodeCiphertext(sealed))).toHex();
}

function randomField(): Field {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return new Field(BigInt("0x" + hex(bytes)));
}

/**
 * Defends the core money-conservation invariant client-side: outputs must sum
 * to inputs and the change must be non-negative. The circuit also enforces
 * `in0+in1 == out0+out1`, but asserting here catches a bad note-selection or a
 * future change-formula edit before a malformed (or value-leaking) tx is built.
 */
function assertValueConserved(recipientAmount: bigint, changeAmount: bigint, inputTotal: bigint): void {
  if (changeAmount < 0n) {
    throw new Error("transfer change is negative (inputs do not cover amount)");
  }
  if (recipientAmount + changeAmount !== inputTotal) {
    throw new Error("transfer value conservation violated (outputs must equal inputs)");
  }
}

function hex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

function deriveX25519Pub(priv: Uint8Array): Uint8Array {
  return x25519.getPublicKey(priv);
}

function sameBytes(a: Uint8Array | undefined, b: Uint8Array | undefined): boolean {
  if (!a || !b || a.length !== b.length) return false;
  return a.every((x, i) => x === b[i]);
}

/**
 * Encodes a NEAR account-id string as a Field element by hashing its UTF-8
 * bytes using hashBytesToField. This matches how the circuit treats string
 * public inputs (the prover binary applies the same transformation).
 */
function fieldFromAccountId(accountId: string): Field {
  return hashBytesToField(new TextEncoder().encode(accountId));
}
