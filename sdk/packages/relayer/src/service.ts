/**
 * Relayer service - the stateless gas-payer that submits withdrawal proofs
 * on behalf of users in exchange for a fee taken out of the withdrawal amount.
 *
 * The relayer's NEAR account and fee are PUBLIC INPUTS to the zk proof. A
 * malicious relayer cannot tamper with the proof's payload (recipient, amount,
 * fee, relayer account) - the on-chain verifier will reject any modification.
 * This means there is zero trust gradient between relayers.
 */

export interface RelayerConfig {
  /** The NEAR account that will submit transactions and receive the fee. */
  nearAccountId: string;
  /** Flat fee in USDC base units (6 decimals). v0 uses a flat fee. */
  feeUsdcBase: bigint;
}

export interface Quote {
  relayer: string;
  feeUsdcBase: string; // decimal string for JSON
  validUntil: number;  // unix seconds
}

export interface SubmitRequest {
  proof: Uint8Array;
  merkleRoot: string;
  nullifier: string;
  recipient: string;
  amount: string;             // decimal string, USDC base units
  auditorPubkey: string;
  viewCt: string;             // base64 or hex - opaque to relayer
  relayer: string;            // must match this relayer's account id
  relayerFee: string;         // must match the quote
}

export interface SubmitResult {
  txHash: string;
}

export class RelayerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RelayerError";
  }
}

/**
 * Abstract NEAR transaction submitter. Production swaps in a real NEAR JSON-RPC
 * client; tests inject a mock that records inputs and returns a canned hash.
 */
export interface NearTxSubmitter {
  submitWithdraw(req: SubmitRequest): Promise<string>;
}

export class RelayerService {
  constructor(
    private readonly config: RelayerConfig,
    private readonly submitter: NearTxSubmitter,
    private readonly quoteValiditySeconds = 60
  ) {}

  quote(): Quote {
    return {
      relayer: this.config.nearAccountId,
      feeUsdcBase: this.config.feeUsdcBase.toString(),
      validUntil: Math.floor(Date.now() / 1000) + this.quoteValiditySeconds,
    };
  }

  async submit(req: SubmitRequest): Promise<SubmitResult> {
    if (req.relayer !== this.config.nearAccountId) {
      throw new RelayerError(
        `relayer mismatch: request says ${req.relayer}, this relayer is ${this.config.nearAccountId}`
      );
    }
    // Parse caller-supplied amounts defensively: bad input must surface as a
    // RelayerError, not an uncaught BigInt SyntaxError.
    const fee = parseBaseUnits(req.relayerFee, "relayerFee");
    const amount = parseBaseUnits(req.amount, "amount");
    if (fee !== this.config.feeUsdcBase) {
      throw new RelayerError(
        `fee mismatch: request says ${req.relayerFee}, quoted ${this.config.feeUsdcBase}`
      );
    }
    if (fee > amount) {
      throw new RelayerError("relayer_fee exceeds amount");
    }
    if (!req.recipient || req.recipient.length === 0) {
      throw new RelayerError("recipient must not be empty");
    }
    if (!req.proof || req.proof.length === 0) {
      throw new RelayerError("proof must not be empty");
    }
    const txHash = await this.submitter.submitWithdraw(req);
    return { txHash };
  }
}

/** Parses a non-negative base-units decimal string; RelayerError on bad input. */
function parseBaseUnits(s: string, field: string): bigint {
  let v: bigint;
  try {
    v = BigInt(s);
  } catch {
    throw new RelayerError(`${field} is not a valid integer: ${JSON.stringify(s)}`);
  }
  if (v < 0n) {
    throw new RelayerError(`${field} must be non-negative: ${s}`);
  }
  return v;
}
