import { poseidon2 as p2, poseidon4 as p4 } from "poseidon-lite";
import { Field } from "./field.js";

/**
 * BN254 Poseidon hash, parameter-compatible with `light-poseidon::new_circom`
 * on the Rust contract side. Test vectors in `sdk/test-vectors/poseidon.json`
 * are the source of truth — both sides must match bit-for-bit.
 */
export function poseidon2(a: Field, b: Field): Field {
  return new Field(p2([a.value, b.value]));
}

export function poseidon4(a: Field, b: Field, c: Field, d: Field): Field {
  return new Field(p4([a.value, b.value, c.value, d.value]));
}
