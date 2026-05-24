import { x25519 } from "@noble/curves/ed25519";
import {
  Field,
  commitNote,
  computeNullifier,
  encodeDisclosure,
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

export interface WalletConfig {
  /** Seed bytes (e.g. NEAR-wallet-sign-in-derived). Used to derive sk and vk. */
  seed: Uint8Array;
  /** USDC FT contract account id, used in tx envelopes. */
  usdcTokenAccountId: string;
  /** The shielded pool contract account id. */
  poolAccountId: string;
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
  private notes: DiscoveredNote[] = [];

  constructor(private readonly config: WalletConfig) {
    if (config.seed.length < 32) {
      throw new Error("seed must be >= 32 bytes");
    }
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
    const noteCt = sealTo(this.viewingKey.publicKey, encodeNote(note));
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
    // Pick a single input note that covers the amount (v0: exact match).
    // A production splitter would handle change as a second output; here we
    // emit a 2-out structure where the second output carries the change back
    // to the sender.
    const input = this.notes.find((n) => n.note.amount >= req.amount);
    if (!input) {
      throw new Error(`no unspent note >= ${req.amount} (have: ${this.balance()})`);
    }

    const senderAuditorField = input.note.auditorPubkey;
    const nullifier = computeNullifier(this.spendingKey, input.commitment, input.leafIndex);

    const recipientAuditorField = pubkeyToField(req.recipientAuditorPubkey);
    const recipientOut: Note = {
      amount: req.amount,
      ownerPubkey: req.recipientOwnerPubkey,
      auditorPubkey: recipientAuditorField,
      blinding: randomField(),
    };
    const changeOut: Note = {
      amount: input.note.amount - req.amount,
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
    const viewCtSender = sealTo(fieldToPubkey(senderAuditorField), encodeDisclosure(disclosure));
    const viewCtRecipient = sealTo(req.recipientAuditorPubkey, encodeDisclosure(disclosure));

    // Note ciphertexts: one to recipient's vk (for the recipient output) and
    // one to the sender's own vk (for the change output).
    const noteCtRecipient = sealTo(req.recipientViewingPubkey, encodeNote(recipientOut));
    const noteCtChange = sealTo(this.viewingKey.publicKey, encodeNote(changeOut));

    return {
      method: "transfer",
      publicInputs: {
        nullifier: nullifier.toHex(),
        commitmentRecipient: c_recipient.toHex(),
        commitmentChange: c_change.toHex(),
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
    // We don't know the auditor's pubkey bytes here; use the field form.
    const auditorField = note.note.auditorPubkey;
    const viewCt = sealTo(
      fieldToPubkey(auditorField),
      encodeDisclosure(disclosure)
    );
    return {
      method: "withdraw",
      publicInputs: {
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

/**
 * Reduces a 32-byte pubkey to a Field for in-circuit use. The inverse is lossy
 * (the field is mod p, not full 32-byte space) so we keep a separate
 * `fieldToPubkey` that simply re-emits the field bytes; the caller is expected
 * to track the pubkey bytes out-of-band where round-trip fidelity matters.
 */
function fieldToPubkey(f: Field): Uint8Array {
  return f.toBytesBE();
}

function deriveX25519Pub(priv: Uint8Array): Uint8Array {
  return x25519.getPublicKey(priv);
}

function encodeNote(n: Note): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({
      amount: n.amount.toString(),
      ownerPubkey: n.ownerPubkey.toHex(),
      auditorPubkey: n.auditorPubkey.toHex(),
      blinding: n.blinding.toHex(),
    })
  );
}
