import { describe, it, expect } from "vitest";
import { Field, poseidon2 } from "@shielded-near/core";
import { MerkleTree, TREE_DEPTH } from "./merkle-tree.js";

function zeros(): Field[] {
  const z = [Field.zero()];
  for (let i = 1; i < TREE_DEPTH; i++) z.push(poseidon2(z[i - 1], z[i - 1]));
  return z;
}

describe("MerkleTree", () => {
  it("leaf0 root folds against zero siblings (matches empty_path_for_leaf0)", () => {
    const leaf = Field.fromU64(123n);
    const t = new MerkleTree();
    t.append(leaf);
    const z = zeros();
    let cur = leaf;
    for (let i = 0; i < TREE_DEPTH; i++) cur = poseidon2(cur, z[i]);
    expect(t.root().toHex()).toBe(cur.toHex());
    expect(t.pathFor(0n).map((f) => f.toHex())).toEqual(z.map((f) => f.toHex()));
  });

  it("two leaves: path0[0]=leaf1, path1[0]=leaf0 (matches tree_with_two_leaves)", () => {
    const a = Field.fromU64(60n), b = Field.fromU64(40n);
    const t = new MerkleTree();
    t.append(a); t.append(b);
    expect(t.pathFor(0n)[0].toHex()).toBe(b.toHex());
    expect(t.pathFor(1n)[0].toHex()).toBe(a.toHex());
  });

  it("empty tree root equals zeros[TREE_DEPTH]", () => {
    const z = [Field.zero()];
    for (let i = 1; i <= TREE_DEPTH; i++) z.push(poseidon2(z[i - 1], z[i - 1]));
    const t = new MerkleTree();
    expect(t.root().toHex()).toBe(z[TREE_DEPTH].toHex());
  });

  it("three leaves: pathFor(2n) has zeros[0] sibling at level 0", () => {
    const a = Field.fromU64(7n), b = Field.fromU64(8n), c = Field.fromU64(9n);
    const t = new MerkleTree();
    t.append(a); t.append(b); t.append(c);
    const p = t.pathFor(2n);
    const z = zeros();
    // c's level-0 sibling is the zero leaf (frontier)
    expect(p[0].toHex()).toBe(z[0].toHex());
    // level-1 sibling is poseidon2(a, b)
    expect(p[1].toHex()).toBe(poseidon2(a, b).toHex());
  });
});
