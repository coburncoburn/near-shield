import { Field, poseidon2 } from "@shielded-near/core";

export const TREE_DEPTH = 20;

export class MerkleTree {
  private leaves: Field[] = [];
  private readonly zeros: Field[] = MerkleTree.computeZeros();

  private static computeZeros(): Field[] {
    const z = [Field.zero()];
    for (let i = 1; i <= TREE_DEPTH; i++) z.push(poseidon2(z[i - 1], z[i - 1]));
    return z; // length TREE_DEPTH + 1, indices 0..TREE_DEPTH
  }

  append(commitment: Field): number {
    this.leaves.push(commitment);
    return this.leaves.length - 1;
  }

  size(): number {
    return this.leaves.length;
  }

  root(): Field {
    if (this.leaves.length === 0) return this.zeros[TREE_DEPTH];
    let level = this.leaves.slice();
    for (let d = 0; d < TREE_DEPTH; d++) level = this.nextLevel(level, d);
    return level[0];
  }

  pathFor(leafIndex: bigint): Field[] {
    let idx = Number(leafIndex);
    if (idx >= this.leaves.length) throw new Error(`leaf ${idx} not present`);
    const path: Field[] = [];
    let level = this.leaves.slice();
    for (let d = 0; d < TREE_DEPTH; d++) {
      const isRight = idx % 2 === 1;
      const siblingIdx = isRight ? idx - 1 : idx + 1;
      path.push(siblingIdx < level.length ? level[siblingIdx] : this.zeros[d]);
      level = this.nextLevel(level, d);
      idx = Math.floor(idx / 2);
    }
    return path;
  }

  private nextLevel(level: Field[], depth: number): Field[] {
    const out: Field[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : this.zeros[depth];
      out.push(poseidon2(left, right));
    }
    return out;
  }
}
