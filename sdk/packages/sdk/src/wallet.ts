import { x25519 } from "@noble/curves/ed25519";
import {
  Field,
  commitNote,
  computeNullifier,
  encodeDisclosure,
  encodeNotePayload,
  generateKeyPair,
  poseidon2,
  scanNotes,
  sealTo,
  type DiscoveredNote,
  type KeyPair,
  type Note,
  type NoteCiphertext,
  type ViewDisclosure,
} from "@shielded-near/core";

import { StubProver, type Prover } from "./prover.js";

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
}

/**
 * A "built transaction": the artifacts a relayer or self-submitter feeds into
 * NEAR. We split building from submitting so tests can verify the witness/proof
 * shape without needing a live chain.
 */
export interface BuiltTx {
  method: "deposit" | "transfer" | "withdraw";
  publicInputs: Record<string, string | string[] | number>;
  proof: Uint8Array; // placeholder until barretenberg prover integration
  viewCiphertexts: Uint8Array[];
  noteCiphertexts: Uint8Array[];
}

/**
 * v0 Wallet: handles key derivation, note scanning, and transaction *building*.
 * Proof generation is stubbed (`proof = Uint8Array([0])`) until the bb prover
 * is integrated (Phase 5 / 7 work). The structure of the produced public inputs
 * and ciphertexts is final and tested.
 */
export class Wallet {
  readonly spendingKey: Field;
  readonly ownerPubkey: Field;
  readonly viewingKey: KeyPair;
  readonly prover: Prover;
  private notes: DiscoveredNote[] = [];

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

  balance(): bigint {
    return this.notes.reduce((sum, n) => sum + n.note.amount, 0n);
  }

  buildDeposit(req: DepositRequest): BuiltTx {
    const auditorPubkeyField = pubkeyToField(req.auditorPubkey);
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
    const viewCt = sealTo(req.auditorPubkey, encodeDisclosure(disclosure));
    const noteCt = sealTo(this.viewingKey.publicKey, encodeNotePayload(note, req.auditorPubkey));
    return {
      method: "deposit",
      publicInputs: {
        commitment: commitment.toHex(),
        amount: req.amount.toString(),
        auditorPubkey: auditorPubkeyField.toHex(),
        viewCtLen: viewCt.length,
      },
      proof: new Uint8Array([0]), // bb prover wires in here (Phase 5/7)
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

    const recipientAuditorField = pubkeyToField(req.recipientAuditorPubkey);
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
    const viewCtSender = sealTo(senderAuditorPubkey, encodeDisclosure(disclosure));
    const viewCtRecipient = sealTo(req.recipientAuditorPubkey, encodeDisclosure(disclosure));

    // Note ciphertexts: one to recipient's vk (for the recipient output) and
    // one to the sender's own vk (for the change output).
    const noteCtRecipient = sealTo(req.recipientViewingPubkey, encodeNotePayload(recipientOut, req.recipientAuditorPubkey));
    const noteCtChange = sealTo(this.viewingKey.publicKey, encodeNotePayload(changeOut, senderAuditorPubkey));

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
    const note = this.notes.find((n) => n.note.amount === req.amount);
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
    const viewCt = sealTo(note.auditorPubkeyBytes, encodeDisclosure(disclosure));
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

  private findTransferInputs(amount: bigint): [DiscoveredNote, DiscoveredNote] | null {
    for (let i = 0; i < this.notes.length; i++) {
      for (let j = i + 1; j < this.notes.length; j++) {
        const a = this.notes[i];
        const b = this.notes[j];
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

function randomField(): Field {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return new Field(BigInt("0x" + hex(bytes)));
}

function hex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

function pubkeyToField(pk: Uint8Array): Field {
  if (pk.length !== 32) throw new Error("pubkey must be 32 bytes");
  return new Field(BigInt("0x" + hex(pk)));
}

function deriveX25519Pub(priv: Uint8Array): Uint8Array {
  return x25519.getPublicKey(priv);
}

function sameBytes(a: Uint8Array | undefined, b: Uint8Array | undefined): boolean {
  if (!a || !b || a.length !== b.length) return false;
  return a.every((x, i) => x === b[i]);
}
