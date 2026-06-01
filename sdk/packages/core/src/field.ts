/**
 * BN254 scalar field (the curve order Noir's `Field` uses).
 *
 * This is the same field as `ark_bn254::Fr` in the Rust contract. Values are
 * stored as native bigints and reduced mod p on construction; the on-the-wire
 * representation is 32 bytes big-endian (matching `Field::to_bytes_be` on the
 * Rust side, which is what gets fed into Poseidon and the contract).
 */
export const BN254_MODULUS =
  0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;

export class Field {
  readonly value: bigint;

  constructor(v: bigint) {
    let x = v % BN254_MODULUS;
    if (x < 0n) x += BN254_MODULUS;
    this.value = x;
  }

  static zero(): Field {
    return new Field(0n);
  }

  static fromU64(x: bigint | number): Field {
    return new Field(BigInt(x));
  }

  /** Parses a 0x-prefixed 64-hex-char big-endian field element. */
  static fromHex(s: string): Field {
    const t = s.startsWith("0x") ? s.slice(2) : s;
    if (t.length !== 64) throw new Error(`field hex must be 64 chars, got ${t.length}`);
    return new Field(BigInt("0x" + t));
  }

  /** 32-byte big-endian encoding. */
  toBytesBE(): Uint8Array {
    const out = new Uint8Array(32);
    let v = this.value;
    for (let i = 31; i >= 0; i--) {
      out[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    return out;
  }

  toHex(): string {
    return "0x" + Array.from(this.toBytesBE())
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  equals(other: Field): boolean {
    return this.value === other.value;
  }

  /** Reads `bytes` little-endian (byte 0 = LSB) into a Field. Accepts any
   *  length; values whose magnitude exceeds the BN254 modulus are reduced
   *  (Field's constructor handles that). Matches Rust
   *  `contract::poseidon::Field::from_bytes_le`. */
  static fromBytesLe(bytes: Uint8Array): Field {
    let v = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) {
      v = (v << 8n) | BigInt(bytes[i]);
    }
    return new Field(v);
  }
}
