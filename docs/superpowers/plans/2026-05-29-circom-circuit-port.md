# Circom Circuit Port Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers-extended-cc:subagent-driven-development (if subagents available) or superpowers-extended-cc:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the three arkworks Groth16 circuits (deposit/transfer/withdraw) to Circom + circomlib, proving byte-for-byte equivalence with the deployed contract/SDK hashing and reproducing every soundness constraint, so the mature snarkjs trusted-setup ceremony can run over them (Sub-project A of 3).

**Architecture:** A new `circom/` pnpm workspace package holds the circuits, shared templates, and a vitest test suite. Circuits use circomlib (Poseidon, Num2Bits, Switcher, comparators). The existing arkworks `tools/prover` and the hand-rolled TS hashing in `@shielded-near/core` stay as the independent equivalence oracle — `core`'s `poseidon2`/`poseidon4`/`commitNote`/`computeNullifier` and the client `MerkleTree` are pinned to `sdk/test-vectors/poseidon.json` and are what the deployed contract agrees with. A Poseidon parity **kill-gate** (Task 1) runs before any circuit work; if circomlib's Poseidon does not match the locked vectors, we stop.

**Tech Stack:** circom 2.1.9 (cargo-built binary), circomlib 2.0.5, snarkjs 0.7.x, circom_tester 0.0.20, vitest 2.x, TypeScript, pnpm workspace, Node 22. Spec: `docs/superpowers/specs/2026-05-29-circom-circuit-port-design.md`.

**Conventions for every task:** follow @superpowers-extended-cc:test-driven-development (red→green→commit) and @superpowers-extended-cc:verification-before-completion (paste real command output before claiming a step passed). Public-input order in every circuit's `main { public [...] }` MUST match the contract verifier order exactly.

---

### Task 0: Toolchain + `circom/` workspace scaffold

**Files:**
- Create: `circom/package.json`
- Create: `circom/tsconfig.json`
- Create: `circom/vitest.config.ts`
- Create: `circom/.gitignore`
- Create: `circom/README.md`
- Create: `circom/scripts/build.sh`
- Modify: `pnpm-workspace.yaml` (add `circom` to `packages`)

- [ ] **Step 1: Install the circom compiler (pinned)**

Run:
```bash
git clone https://github.com/iden3/circom.git /tmp/circom-build \
  && cd /tmp/circom-build && git checkout v2.1.9 \
  && cargo build --release && cargo install --path circom
circom --version
```
Expected: `circom compiler 2.1.9`. (circom is a Rust binary; it is intentionally not an npm dep.)

- [ ] **Step 2: Create the workspace package manifest**

Create `circom/package.json`:
```json
{
  "name": "@shielded-near/circom",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "build": "bash scripts/build.sh",
    "test": "vitest run"
  },
  "dependencies": {
    "circomlib": "2.0.5",
    "snarkjs": "^0.7.4"
  },
  "devDependencies": {
    "@shielded-near/core": "workspace:*",
    "@shielded-near/client": "workspace:*",
    "@types/node": "^22.0.0",
    "circom_tester": "0.0.20",
    "typescript": "^5.5.0",
    "vitest": "^2.1.0"
  }
}
```

- [ ] **Step 3: Add config + ignore + build script**

Create `circom/tsconfig.json` (mirror `sdk/packages/core/tsconfig.json`'s compiler options; `"module": "ESNext"`, `"moduleResolution": "Bundler"`, `"strict": true`).

Create `circom/vitest.config.ts`:
```ts
import { defineConfig } from "vitest/config";
// Circuit compilation + witness calc is slow; raise the per-test timeout.
export default defineConfig({ test: { testTimeout: 120_000, hookTimeout: 120_000 } });
```

Create `circom/.gitignore`:
```
build/
*.wtns
*.zkey
*.ptau
*_js/
```

Create `circom/scripts/build.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p build
for c in deposit transfer withdraw; do
  echo "== compiling $c =="
  circom "circuits/$c.circom" --r1cs --wasm -l node_modules -o build
done
```
`chmod +x circom/scripts/build.sh`.

Create `circom/README.md`: one paragraph stating this package is Sub-project A, that `tools/prover` (arkworks) + `@shielded-near/core` are the equivalence oracle and are retained until Sub-project B, and that all keys produced here are DEV-only (real keys come from the Sub-project C ceremony).

- [ ] **Step 4: Register the workspace and install**

Modify `pnpm-workspace.yaml` — add `- "circom"` under `packages:`.

Run:
```bash
cd /Users/coburnberry/X/hip4 && pnpm install
pnpm --filter @shielded-near/circom exec snarkjs --version
```
Expected: install succeeds; snarkjs prints its version.

- [ ] **Step 5: Commit**
```bash
git add -f circom pnpm-workspace.yaml pnpm-lock.yaml
git commit -m "build(circom): scaffold circom workspace package + toolchain"
```

---

### Task 1: Poseidon parity kill-gate (BLOCKS everything)

> If this task fails, **stop and escalate** — the design's "no cascade into contract/SDK" premise is false and the approach must be re-evaluated. The locked vectors live in `sdk/test-vectors/poseidon.json`.

**Files:**
- Create: `circom/circuits/test/poseidon2_test.circom`
- Create: `circom/circuits/test/poseidon4_test.circom`
- Create: `circom/test/helpers.ts`
- Create: `circom/test/poseidon-parity.test.ts`

- [ ] **Step 1: Write the two test-wrapper circuits**

`circom/circuits/test/poseidon2_test.circom`:
```circom
pragma circom 2.1.6;
include "circomlib/circuits/poseidon.circom";
template P2() { signal input a; signal input b; signal output out;
  component h = Poseidon(2); h.inputs[0] <== a; h.inputs[1] <== b; out <== h.out; }
component main = P2();
```
`circom/circuits/test/poseidon4_test.circom`:
```circom
pragma circom 2.1.6;
include "circomlib/circuits/poseidon.circom";
template P4() { signal input in[4]; signal output out;
  component h = Poseidon(4); for (var i=0;i<4;i++){ h.inputs[i] <== in[i]; } out <== h.out; }
component main = P4();
```

- [ ] **Step 2: Write the circom_tester helper**

`circom/test/helpers.ts`:
```ts
import { wasm as wasmTester } from "circom_tester";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

// circom_tester compiles the circuit (needs `circom` in PATH and -l node_modules).
export async function load(relCircuitPath: string) {
  return wasmTester(path.join(root, "circuits", relCircuitPath), {
    include: [path.join(root, "node_modules")],
  });
}
```

- [ ] **Step 3: Write the failing parity test**

`circom/test/poseidon-parity.test.ts`:
```ts
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { load } from "./helpers.js";

const vectors = JSON.parse(
  readFileSync(
    path.resolve(fileURLToPath(import.meta.url), "../../../sdk/test-vectors/poseidon.json"),
    "utf8",
  ),
);
const toBig = (hex: string) => BigInt(hex); // "0x..." parses directly

describe("poseidon parity kill-gate", () => {
  it("circomlib Poseidon(2) matches all locked poseidon2 vectors", async () => {
    const c = await load("test/poseidon2_test.circom");
    for (const v of vectors.poseidon2) {
      const w = await c.calculateWitness({ a: v.inputs[0], b: v.inputs[1] }, true);
      await c.assertOut(w, { out: toBig(v.expected) });
    }
  });

  it("circomlib Poseidon(4) matches all locked poseidon4 vectors", async () => {
    const c = await load("test/poseidon4_test.circom");
    for (const v of vectors.poseidon4) {
      const w = await c.calculateWitness({ in: v.inputs }, true);
      await c.assertOut(w, { out: toBig(v.expected) });
    }
  });
});
```

- [ ] **Step 4: Run the gate**

Run: `pnpm --filter @shielded-near/circom test -- poseidon-parity`
Expected: **PASS** — both `Poseidon(2)([1,2]) == 0x115cc0…189a` and `Poseidon(4)([1,2,3,4]) == 0x299c86…0465` (plus the other vectors). If it FAILS, STOP and escalate (see banner above).

- [ ] **Step 5: Commit**
```bash
git add -f circom/circuits/test circom/test
git commit -m "test(circom): Poseidon parity kill-gate against locked vectors"
```

---

### Task 2: Shared library templates (commit / nullifier / merkle / range) + parity corpus

**Files:**
- Create: `circom/circuits/lib/commit.circom`
- Create: `circom/circuits/lib/range.circom`
- Create: `circom/circuits/lib/merkle.circom`
- Create: `circom/circuits/test/{commit_test,owner_test,nullifier_test,merkle_test}.circom`
- Create: `circom/test/lib-parity.test.ts`

- [ ] **Step 1: Write the templates**

`circom/circuits/lib/commit.circom`:
```circom
pragma circom 2.1.6;
include "circomlib/circuits/poseidon.circom";

// commit_note = Poseidon([amount, ownerPubkey, auditorPubkey, blinding])
template CommitNote() {
  signal input amount; signal input ownerPubkey; signal input auditorPubkey; signal input blinding;
  signal output out;
  component h = Poseidon(4);
  h.inputs[0] <== amount; h.inputs[1] <== ownerPubkey; h.inputs[2] <== auditorPubkey; h.inputs[3] <== blinding;
  out <== h.out;
}
// owner_pubkey = Poseidon([spendingKey, 0])
template OwnerPubkey() {
  signal input spendingKey; signal output out;
  component h = Poseidon(2); h.inputs[0] <== spendingKey; h.inputs[1] <== 0; out <== h.out;
}
// nullifier = Poseidon([spendingKey, Poseidon([commitment, leafIndex])])
template Nullifier() {
  signal input spendingKey; signal input commitment; signal input leafIndex; signal output out;
  component inner = Poseidon(2); inner.inputs[0] <== commitment; inner.inputs[1] <== leafIndex;
  component outer = Poseidon(2); outer.inputs[0] <== spendingKey; outer.inputs[1] <== inner.out;
  out <== outer.out;
}
```

`circom/circuits/lib/range.circom`:
```circom
pragma circom 2.1.6;
include "circomlib/circuits/bitify.circom";

// Enforce in < 2^n.
template RangeCheck(n) { signal input in; component bits = Num2Bits(n); bits.in <== in; }

// Enforce a >= b as 64-bit unsigned (mirrors arkworks enforce_u64_geq:
// bound a, b, and a-b to 64 bits).
template U64Geq() {
  signal input a; signal input b;
  component ra = Num2Bits(64); ra.in <== a;
  component rb = Num2Bits(64); rb.in <== b;
  component rd = Num2Bits(64); rd.in <== a - b;
}
```

`circom/circuits/lib/merkle.circom`:
```circom
pragma circom 2.1.6;
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/switcher.circom";

// Depth-DEPTH inclusion. indexBits are LE bits of leafIndex.
// Switcher: sel==0 -> outL=L,outR=R ; sel==1 -> swapped.
// Matches arkworks: bit==0 keeps current on the left (current=L, sibling=R).
template MerkleInclusion(DEPTH) {
  signal input leaf; signal input root;
  signal input indexBits[DEPTH]; signal input pathElements[DEPTH];
  component sw[DEPTH]; component h[DEPTH];
  signal cur[DEPTH + 1]; cur[0] <== leaf;
  for (var i = 0; i < DEPTH; i++) {
    sw[i] = Switcher();
    sw[i].sel <== indexBits[i]; sw[i].L <== cur[i]; sw[i].R <== pathElements[i];
    h[i] = Poseidon(2); h[i].inputs[0] <== sw[i].outL; h[i].inputs[1] <== sw[i].outR;
    cur[i + 1] <== h[i].out;
  }
  root === cur[DEPTH];
}
```

- [ ] **Step 2: Write test-wrapper circuits**

`commit_test.circom` → `component main = CommitNote();`
`owner_test.circom` → `component main = OwnerPubkey();`
`nullifier_test.circom` → `component main = Nullifier();`
`merkle_test.circom` → `component main = MerkleInclusion(20);`
(each with the matching `pragma` + `include "../lib/<file>.circom";`).

- [ ] **Step 3: Write the failing parity corpus test**

`circom/test/lib-parity.test.ts` — use `@shielded-near/core` (`poseidon2`, `poseidon4`, `commitNote`, `computeNullifier`) and `@shielded-near/client` (`MerkleTree`) as the oracle. Convert each core `Field` to a bigint for `assertOut` via its public readonly `.value` property (e.g. `expected.value` — there is no accessor method/helper). Cases:
- `CommitNote(amount, owner, auditor, blinding)` over ~5 randomized field tuples == `commitNote({...})`.
- `OwnerPubkey(sk)` == `poseidon2(sk, 0)`.
- `Nullifier(sk, commitment, leafIndex)` == `computeNullifier(...)`.
- `MerkleInclusion(20)`: build a `MerkleTree`, `append(commitment)` the leaves, take a real `leafIndex` + path (via `MerkleTree.pathFor(...)`) + `root()`, decompose `leafIndex` into 20 LE bits in TS, assert `calculateWitness` succeeds and `checkConstraints` passes.

```ts
// shape:
const c = await load("test/commit_test.circom");
const expected = commitNote({ amount, ownerPubkey, auditorPubkey, blinding }); // core oracle
const w = await c.calculateWitness({ amount, ownerPubkey, auditorPubkey, blinding }, true);
await c.assertOut(w, { out: fieldToBig(expected) });
```

- [ ] **Step 4: Run**

Run: `pnpm --filter @shielded-near/circom test -- lib-parity`
Expected: PASS — circom templates produce identical hashes/roots to the SDK oracle.

- [ ] **Step 5: Commit**
```bash
git add -f circom/circuits/lib circom/circuits/test circom/test/lib-parity.test.ts
git commit -m "feat(circom): commit/nullifier/merkle/range templates + parity corpus"
```

---

### Task 3: `deposit.circom` + equivalence tests

**Files:**
- Create: `circom/circuits/deposit.circom`
- Create: `circom/test/deposit.test.ts`

- [ ] **Step 1: Write the circuit**
```circom
pragma circom 2.1.6;
include "lib/commit.circom";

template Deposit() {
  // public (contract order): commitment, amount, auditorPubkey, viewCtHash
  signal input commitment; signal input amount; signal input auditorPubkey; signal input viewCtHash;
  // private
  signal input ownerPubkey; signal input blinding; signal input viewCtHashWitness;

  component c = CommitNote();
  c.amount <== amount; c.ownerPubkey <== ownerPubkey; c.auditorPubkey <== auditorPubkey; c.blinding <== blinding;
  c.out === commitment;
  viewCtHash === viewCtHashWitness;
}
component main { public [commitment, amount, auditorPubkey, viewCtHash] } = Deposit();
```
> Faithful-port note: deposit has **no** amount range check, matching `tools/prover/src/circuits/deposit.rs`. Do not add one (flagged for Gate-3 review).

- [ ] **Step 2: Write the failing tests** (`circom/test/deposit.test.ts`)
Mirror `deposit.rs` tests using `commitNote` oracle for the honest commitment:
- `honest deposit → calculateWitness succeeds + checkConstraints passes`.
- `wrong amount (commitment built for 100, amount=200) → calculateWitness rejects` (`await expect(c.calculateWitness({...}, true)).rejects.toThrow()`).
- `view_ct_hash != witness → calculateWitness rejects`.

- [ ] **Step 3: Build + run**

Run: `pnpm --filter @shielded-near/circom test -- deposit`
Expected: PASS (honest satisfiable; both tampered cases rejected).

- [ ] **Step 4: Commit**
```bash
git add -f circom/circuits/deposit.circom circom/test/deposit.test.ts
git commit -m "feat(circom): deposit circuit + equivalence/negative tests"
```

---

### Task 4: `transfer.circom` + equivalence tests (the heavy one)

**Files:**
- Create: `circom/circuits/transfer.circom`
- Create: `circom/test/transfer.test.ts`

- [ ] **Step 1: Write the circuit**
```circom
pragma circom 2.1.6;
include "lib/commit.circom";
include "lib/merkle.circom";
include "lib/range.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

template Transfer(DEPTH) {
  // public (contract order, 9):
  signal input merkleRoot;
  signal input nullifier0; signal input nullifier1;
  signal input commitmentOut0; signal input commitmentOut1;
  signal input auditorPubkey; signal input recipientAuditorPubkey;
  signal input viewCtHashSender; signal input viewCtHashRecipient;
  // private:
  signal input in0Amount; signal input in0Owner; signal input in0Blinding; signal input in0LeafIndex; signal input in0Path[DEPTH];
  signal input in1Amount; signal input in1Owner; signal input in1Blinding; signal input in1LeafIndex; signal input in1Path[DEPTH];
  signal input spendingKey;
  signal input out0Amount; signal input out0Owner; signal input out0Blinding;
  signal input out1Amount; signal input out1Owner; signal input out1Blinding;
  signal input viewCtHashSenderWitness; signal input viewCtHashRecipientWitness;

  // input commitments
  component cin0 = CommitNote(); cin0.amount <== in0Amount; cin0.ownerPubkey <== in0Owner; cin0.auditorPubkey <== auditorPubkey; cin0.blinding <== in0Blinding;
  component cin1 = CommitNote(); cin1.amount <== in1Amount; cin1.ownerPubkey <== in1Owner; cin1.auditorPubkey <== auditorPubkey; cin1.blinding <== in1Blinding;

  // ownership: owner = Poseidon(sk,0) must equal both input owners
  component own = OwnerPubkey(); own.spendingKey <== spendingKey;
  own.out === in0Owner; own.out === in1Owner;

  // nullifiers
  component n0 = Nullifier(); n0.spendingKey <== spendingKey; n0.commitment <== cin0.out; n0.leafIndex <== in0LeafIndex; n0.out === nullifier0;
  component n1 = Nullifier(); n1.spendingKey <== spendingKey; n1.commitment <== cin1.out; n1.leafIndex <== in1LeafIndex; n1.out === nullifier1;

  // distinctness: nullifier0 != nullifier1
  component eqn = IsEqual(); eqn.in[0] <== nullifier0; eqn.in[1] <== nullifier1; eqn.out === 0;

  // leaf indices bound to exactly DEPTH bits, bits reused for inclusion
  component idx0 = Num2Bits(DEPTH); idx0.in <== in0LeafIndex;
  component idx1 = Num2Bits(DEPTH); idx1.in <== in1LeafIndex;
  component m0 = MerkleInclusion(DEPTH); m0.leaf <== cin0.out; m0.root <== merkleRoot; m0.indexBits <== idx0.out; m0.pathElements <== in0Path;
  component m1 = MerkleInclusion(DEPTH); m1.leaf <== cin1.out; m1.root <== merkleRoot; m1.indexBits <== idx1.out; m1.pathElements <== in1Path;

  // output commitments (under recipient auditor)
  component co0 = CommitNote(); co0.amount <== out0Amount; co0.ownerPubkey <== out0Owner; co0.auditorPubkey <== recipientAuditorPubkey; co0.blinding <== out0Blinding; co0.out === commitmentOut0;
  component co1 = CommitNote(); co1.amount <== out1Amount; co1.ownerPubkey <== out1Owner; co1.auditorPubkey <== recipientAuditorPubkey; co1.blinding <== out1Blinding; co1.out === commitmentOut1;

  // 128-bit range checks on all amounts (mint-exploit guard)
  component r0 = RangeCheck(128); r0.in <== in0Amount;
  component r1 = RangeCheck(128); r1.in <== in1Amount;
  component r2 = RangeCheck(128); r2.in <== out0Amount;
  component r3 = RangeCheck(128); r3.in <== out1Amount;

  // value conservation
  in0Amount + in1Amount === out0Amount + out1Amount;

  // view bindings
  viewCtHashSender === viewCtHashSenderWitness;
  viewCtHashRecipient === viewCtHashRecipientWitness;
}
component main { public [merkleRoot, nullifier0, nullifier1, commitmentOut0, commitmentOut1, auditorPubkey, recipientAuditorPubkey, viewCtHashSender, viewCtHashRecipient] } = Transfer(20);
```

- [ ] **Step 2: Write a TS witness builder + failing tests** (`circom/test/transfer.test.ts`)
Build an `honestTransfer()` helper in TS mirroring `transfer.rs::honest()` using the `core`/`client` oracle (build a depth-20 `MerkleTree` with the two input commitments, derive owner/nullifiers/roots/paths). Then mirror every arkworks `transfer.rs` test:
- `honest → calculateWitness + checkConstraints pass`.
- `value_violation (out0=150) → rejects`.
- `wraparound_mint (out0 = 2^130-ish, out1 = 100 - out0 in field) → rejects` (the 128-bit RangeCheck catches it).
- `forged_merkle_path → rejects`.
- `same_input_note (both inputs identical, n0==n1) → rejects` (the `IsEqual ... === 0` makes witness calc throw).
- `leaf_index_above_depth (in0LeafIndex = 2^20, nullifier recomputed for it) → rejects` (Num2Bits(20) overflow).

- [ ] **Step 3: Build + run**

Run: `pnpm --filter @shielded-near/circom test -- transfer`
Expected: PASS — honest satisfiable; all five attacks rejected.

- [ ] **Step 4: Commit**
```bash
git add -f circom/circuits/transfer.circom circom/test/transfer.test.ts
git commit -m "feat(circom): transfer circuit + full negative-case corpus"
```

---

### Task 5: `withdraw.circom` + equivalence tests

**Files:**
- Create: `circom/circuits/withdraw.circom`
- Create: `circom/test/withdraw.test.ts`

- [ ] **Step 1: Write the circuit**
```circom
pragma circom 2.1.6;
include "lib/commit.circom";
include "lib/merkle.circom";
include "lib/range.circom";
include "circomlib/circuits/bitify.circom";

template Withdraw(DEPTH) {
  // public (contract order, 8):
  signal input merkleRoot; signal input nullifier; signal input recipient; signal input amount;
  signal input relayer; signal input relayerFee; signal input auditorPubkey; signal input viewCtHash;
  // private:
  signal input noteAmount; signal input noteOwner; signal input noteAuditor; signal input noteBlinding;
  signal input spendingKey; signal input leafIndex; signal input merklePath[DEPTH]; signal input viewCtHashWitness;

  component c = CommitNote(); c.amount <== noteAmount; c.ownerPubkey <== noteOwner; c.auditorPubkey <== noteAuditor; c.blinding <== noteBlinding;
  component own = OwnerPubkey(); own.spendingKey <== spendingKey; own.out === noteOwner;
  component nf = Nullifier(); nf.spendingKey <== spendingKey; nf.commitment <== c.out; nf.leafIndex <== leafIndex; nf.out === nullifier;

  noteAmount === amount;
  noteAuditor === auditorPubkey;

  // amount >= relayerFee (u64)
  component geq = U64Geq(); geq.a <== amount; geq.b <== relayerFee;

  viewCtHash === viewCtHashWitness;

  // leaf index bound to DEPTH bits, bits reused for inclusion
  component idx = Num2Bits(DEPTH); idx.in <== leafIndex;
  component m = MerkleInclusion(DEPTH); m.leaf <== c.out; m.root <== merkleRoot; m.indexBits <== idx.out; m.pathElements <== merklePath;

  // Bind recipient & relayer into the proof so a relayer cannot tamper with them.
  // (relayerFee is already bound by U64Geq, so it gets NO extra trivial constraint —
  // matches withdraw.rs:81-82 where only recipient/relayer use enforce_equal(x,x).)
  signal recipientSq <== recipient * recipient;
  signal relayerSq <== relayer * relayer;
}
component main { public [merkleRoot, nullifier, recipient, amount, relayer, relayerFee, auditorPubkey, viewCtHash] } = Withdraw(20);
```

- [ ] **Step 2: Write witness builder + failing tests** (`circom/test/withdraw.test.ts`)
Mirror `withdraw.rs::honest()` and its tests via the oracle:
- `honest → pass`.
- `wrong_spending_key → rejects`.
- `forged_merkle_path → rejects`.
- `fee_exceeds_amount (relayerFee=101, amount=100) → rejects` (U64Geq's `a-b` Num2Bits(64) overflows).
- `leaf_index_above_depth (leafIndex=2^20, nullifier recomputed) → rejects`.

- [ ] **Step 3: Build + run**

Run: `pnpm --filter @shielded-near/circom test -- withdraw`
Expected: PASS — honest satisfiable; all four attacks rejected.

- [ ] **Step 4: Commit**
```bash
git add -f circom/circuits/withdraw.circom circom/test/withdraw.test.ts
git commit -m "feat(circom): withdraw circuit + equivalence/negative tests"
```

---

### Task 6: DEV keys + snarkjs prove→verify roundtrip + ptau sizing

**Files:**
- Create: `circom/scripts/dev-setup.sh`
- Create: `circom/test/prove-verify.test.ts`
- Modify: `circom/README.md` (record measured constraint counts + chosen ptau power)

- [ ] **Step 1: Measure constraint counts**

Run: `pnpm --filter @shielded-near/circom build` then inspect circom's per-circuit "non-linear constraints" output (transfer is largest).
Record the numbers in `README.md`. Choose dev ptau power `P = ceil(log2(maxConstraints))` (e.g. ~13–15k constraints → `P=14`; if transfer measures above 16384, use `P=15`, and `P=16` if above 32768 — re-pin from the real count, don't guess). Pin `P` in `dev-setup.sh`.

- [ ] **Step 2: Write the DEV-only setup script**

`circom/scripts/dev-setup.sh` — clearly labeled DEV (single contribution, deterministic entropy is acceptable here because these keys are never shipped; the Sub-project B fingerprint guard will block them and Sub-project C produces real keys):
```bash
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"
P=15   # ptau power, sized to transfer constraint count (see README)
SNARKJS="pnpm exec snarkjs"
mkdir -p build/keys
$SNARKJS powersoftau new bn128 "$P" build/keys/pot_0.ptau -v
echo "dev-entropy-A" | $SNARKJS powersoftau contribute build/keys/pot_0.ptau build/keys/pot_1.ptau --name=dev -v
$SNARKJS powersoftau prepare phase2 build/keys/pot_1.ptau build/keys/pot_final.ptau -v
for c in deposit transfer withdraw; do
  $SNARKJS groth16 setup "build/${c}.r1cs" build/keys/pot_final.ptau "build/keys/${c}_0.zkey"
  echo "dev-entropy-${c}" | $SNARKJS zkey contribute "build/keys/${c}_0.zkey" "build/keys/${c}_dev.zkey" --name=dev -v
  $SNARKJS zkey export verificationkey "build/keys/${c}_dev.zkey" "build/keys/${c}_vk.json"
done
```
`chmod +x circom/scripts/dev-setup.sh`.

- [ ] **Step 3: Write the prove→verify test**

`circom/test/prove-verify.test.ts` — for each circuit, run `snarkjs.groth16.fullProve(honestInput, wasmPath, devZkeyPath)` then `snarkjs.groth16.verify(vk, publicSignals, proof)` and assert `true`. Reuse the honest-input builders from the Task 3–5 tests (export them). Gate this test to skip with a clear message if `build/keys/*_dev.zkey` is absent (so the suite still runs pre-setup).

- [ ] **Step 4: Run setup + test**

Run:
```bash
pnpm --filter @shielded-near/circom build
bash circom/scripts/dev-setup.sh
pnpm --filter @shielded-near/circom test -- prove-verify
```
Expected: full proof generated and verified `true` for all three circuits.

- [ ] **Step 5: Commit**
```bash
git add -f circom/scripts/dev-setup.sh circom/test/prove-verify.test.ts circom/README.md
git commit -m "feat(circom): DEV ptau/zkey setup + prove→verify roundtrip"
```

---

## Done criteria for Sub-project A

- `pnpm --filter @shielded-near/circom test` is green: Poseidon parity gate, lib parity corpus, all three circuits' honest + negative cases, and the prove→verify roundtrip.
- Circom circuits reproduce every arkworks constraint and every soundness negative test, and compute byte-identical commitments/nullifiers/roots to `@shielded-near/core` (hence to the deployed contract).
- DEV keys exist for local proving; they are loudly labeled and unshippable (the fingerprint guard is Sub-project B).
- Public-input ordering matches the contract verifier in all three `main { public [...] }` declarations (full contract-roundtrip verification is Sub-project B).

## Handoff to Sub-project B

B swaps the SDK/relayer/demo prover to snarkjs, writes the snarkjs-VK→EIP-196/197 adapter, adds the dev-key fingerprint guard to `scripts/check-production-readiness.sh`, deletes the arkworks `tools/prover`, and verifies a real proof through `contract/src/groth16.rs`.
