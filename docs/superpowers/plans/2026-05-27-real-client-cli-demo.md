# Real-client CLI demo — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers-extended-cc:subagent-driven-development (if subagents available) or superpowers-extended-cc:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `pnpm` CLI demo that drives a full deposit→transfer→withdraw shielded-pool flow with real Groth16 proofs and a real NEP-141 token against a local near-workspaces sandbox, using the TypeScript SDK as a real client would.

**Architecture:** A new reusable package `@shielded-near/client` provides the NEAR connection layer the SDK lacks — submitting calls, parsing the contract's NEP-297 events to feed `wallet.scan()`, and reconstructing the Merkle tree client-side (the contract has no inclusion-path view). The chain transport is an injected `NearCaller` interface so the same client works against a near-workspaces sandbox now and testnet later. A narrated `demo/run-demo.ts` stands up the sandbox, deploys a vendored NEP-141 + the real `groth16-verifier` pool, and runs two wallets (Alice, Bob) plus the relayer through the flow. A prerequisite SDK fix aligns `view_ct_hash` with the bytes the contract hashes.

**Tech Stack:** TypeScript (ESM, vitest), pnpm workspaces, `near-api-js` (client transport adapter), `near-workspaces` (demo sandbox), Rust + `near-contract-standards` (vendored NEP-141), the existing `shielded-prover` Rust CLI.

**Spec:** `docs/superpowers/specs/2026-05-27-real-client-cli-demo-design.md`

---

## Key facts the implementer must know

- **No root `package.json`.** The workspace is defined by `pnpm-workspace.yaml` (`packages: sdk/packages/*`). Commands run via `pnpm --filter <pkg> <script>` or `pnpm -r`. The demo is run with `pnpm --filter @shielded-near/demo demo`. **You must add `demo` to the workspace globs.**
- **Canonical hashing.** `@shielded-near/core` exports `hashBytesToField(Uint8Array)`, `poseidon2(Field, Field)`, `Field` (`Field.zero()`, `Field.fromHex`, `Field.fromU64`, `.toHex()`, `.equals()`, `new Field(bigint)`). These are byte-for-byte locked to the Rust contract via `sdk/test-vectors/`.
- **Contract init:** `new(owner, usdc_token, vk_deposit, vk_transfer, vk_withdraw)` where the vks are `Vec<u8>` read from `target/sp-keys/{deposit,transfer,withdraw}.vk` (produced by `shielded-prover setup`).
- **Deposit path:** production deposit is `ft_transfer_call` on the token with a JSON `DepositArgs` in `msg`; the token then calls the pool's `ft_on_transfer`. The direct `deposit()` is gated out of deployable builds.
- **Events (NEP-297 JSON in `env::log_str`):** `{"standard":"shielded-pool","event":"deposit","data":{commitment, leaf_index, view_ct, note_ct}}` and `event:"transfer"` with `data:{merkle_root, nullifiers[2], commitments[2], leaf_indices[2], view_cts[2], note_cts[2]}`. See `contract/src/events.rs`.
- **`view_ct`/`note_ct` on the wire** are `"0x"+hex(sealedBytes)` (see `encodeCt` in `sdk/packages/sdk/src/envelopes.ts:201`). The contract binds them into the proof via `hash_bytes_to_field(view_ct.as_bytes())` — i.e. it hashes the *bytes of that `"0x…"` string*.
- **The bug being fixed:** `Wallet.buildDepositProved/buildTransferProved/buildWithdrawProved` compute `view_ct_hash` as `hashBytesToField(viewCt)` over the **raw sealed `Uint8Array`** (`wallet.ts` ~lines 332, 426–427, 526). That does not equal what the contract hashes, so a real proof's `view_ct_hash` public input will be rejected. Fix: hash the bytes of the encoded string instead.
- **Build prerequisites** (the demo must check these and error with guidance, mirroring `contract/tests/e2e_real_proofs.rs`):
  ```
  cargo build -p shielded-pool --target wasm32-unknown-unknown --release --no-default-features --features groth16-verifier
  wasm-opt --enable-bulk-memory --llvm-memory-copy-fill-lowering <in> -o target/wasm32-unknown-unknown/release/shielded_pool.opt.wasm
  cargo build -p shielded-prover --release
  cargo run -p shielded-prover --release -- setup --out-dir target/sp-keys
  cargo build -p mock-ft --target wasm32-unknown-unknown --release --no-default-features   # new (Task 1) — strips near-sdk unit-testing helpers
  ```
  (The exact opt-wasm command already lives in `scripts/check-production-readiness.sh` — reuse it.)

---

## File Structure

| File | Responsibility |
|------|----------------|
| `sdk/packages/sdk/src/envelopes.ts` (modify) | Export `encodeCiphertext` (was private `encodeCt`) so the wallet hashes the exact submitted bytes. |
| `sdk/packages/sdk/src/wallet.ts` (modify) | All three proved-builders compute `view_ct_hash` over `encodeCiphertext(...)` bytes. |
| `sdk/packages/sdk/src/wallet.viewcthash.test.ts` (create) | Binding test: proved-tx `view_ct_hash` PI == `hashBytesToField(utf8(encodeCiphertext(ct)))`. |
| `contracts/mock-ft/Cargo.toml`, `src/lib.rs` (create) | Vendored NEP-141 FT (near-contract-standards) for the sandbox. |
| `Cargo.toml` (modify) | Add `contracts/mock-ft` to workspace members. |
| `pnpm-workspace.yaml` (modify) | Add `demo` to package globs. |
| `sdk/packages/client/{package.json,tsconfig.json}` (create) | New `@shielded-near/client` package. |
| `sdk/packages/client/src/near-caller.ts` (create) | `NearCaller` interface + `NearApiJsCaller` adapter. |
| `sdk/packages/client/src/merkle-tree.ts` (create) | Append-only depth-20 Poseidon tree → `{root, path}`. |
| `sdk/packages/client/src/events.ts` (create) | Parse NEP-297 logs → typed deposit/transfer event data. |
| `sdk/packages/client/src/pool-client.ts` (create) | Submit calls, fetch events as `NoteCiphertext[]`, track leaves, `merkleRoot()`. |
| `sdk/packages/client/src/near-submitter.ts` (create) | `NearTxSubmitter` impl over `NearCaller` for the relayer. |
| `sdk/packages/client/src/index.ts` (create) | Public exports. |
| `sdk/packages/client/src/*.test.ts` (create) | Unit tests for merkle-tree, events, near-submitter. |
| `demo/package.json`, `tsconfig.json` (create) | `@shielded-near/demo`; deps: near-workspaces, client, sdk, core, relayer. |
| `demo/src/workspaces-caller.ts` (create) | `NearCaller` adapter over a near-workspaces `Account`. |
| `demo/src/prereqs.ts` (create) | Verify wasm/binary/keys exist; throw actionable errors. |
| `demo/src/run-demo.ts` (create) | Narrated two-wallet flow entrypoint. |

---

## Task 0: Fix `view_ct_hash` derivation in the Wallet (prerequisite)

Maps to native task #11. **Blocks Tasks 4 and 6** (real proofs won't verify until this lands).

**Files:**
- Modify: `sdk/packages/sdk/src/envelopes.ts` (export the encoder)
- Modify: `sdk/packages/sdk/src/wallet.ts` (3 proved-builders)
- Create: `sdk/packages/sdk/src/wallet.viewcthash.test.ts`

**Why:** The contract computes the proof's `view_ct_hash` public input as `hash_bytes_to_field(view_ct.as_bytes())` where `view_ct` is the `"0x"+hex` string the SDK submits. The wallet must commit to the *same* value, i.e. hash the encoded-string bytes — not the raw sealed bytes.

- [ ] **Step 1: Export the ciphertext encoder.** In `sdk/packages/sdk/src/envelopes.ts`, rename the private `encodeCt` to an exported `encodeCiphertext` (keep behavior identical) and update its internal callers in that file.

```ts
/** Ciphertexts cross the JSON boundary as "0x"+hex. The contract treats the
 *  resulting string as opaque and hashes its bytes into the proof's public
 *  input, so any code deriving view_ct_hash MUST hash these same bytes. */
export function encodeCiphertext(b: Uint8Array): string {
  return "0x" + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}
```

- [ ] **Step 2: Write the failing binding test.** Create `wallet.viewcthash.test.ts`. Use a capturing stub prover that records `publicInputs` and returns 256 zero bytes. Assert the deposit `view_ct_hash` PI equals `hashBytesToField(new TextEncoder().encode(encodeCiphertext(viewCt)))`. Because the wallet does not expose the raw `viewCt`, assert the equivalent property: the captured PI must NOT equal `hashBytesToField(rawSealedBytes)` and MUST equal the hash over the re-encoded string of the emitted `viewCiphertexts[0]`.

```ts
import { describe, it, expect } from "vitest";
import { Wallet } from "./wallet.js";
import { encodeCiphertext } from "./envelopes.js";
import { hashBytesToField } from "@shielded-near/core";
import type { Prover, ProveRequest } from "./prover.js"; // Prover/ProveRequest live in the sdk package, not core

class CapturingProver {
  public last?: ProveRequest;
  async prove(req: ProveRequest): Promise<Uint8Array> { this.last = req; return new Uint8Array(256); }
}

const DEPOSIT_PI_INDEX_VIEW_CT_HASH = 3; // PI order: commitment, amount, auditor, view_ct_hash

describe("view_ct_hash binding", () => {
  it("deposit proves the hash of the encoded ciphertext bytes", async () => {
    const seed = new Uint8Array(64).fill(7);
    const auditorPubkey = new Uint8Array(32).fill(9);
    const prover = new CapturingProver();
    const w = new Wallet({ seed, usdcTokenAccountId: "usdc.test", poolAccountId: "pool.test" });
    const tx = await w.buildDepositProved({ amount: 100n, auditorPubkey }, prover as any);
    const expected = hashBytesToField(
      new TextEncoder().encode(encodeCiphertext(tx.viewCiphertexts[0]))
    ).toHex();
    expect(prover.last!.publicInputs[DEPOSIT_PI_INDEX_VIEW_CT_HASH]).toBe(expected);
  });
});
```

- [ ] **Step 3: Run the test, verify it FAILS.** `pnpm --filter @shielded-near/sdk test -- wallet.viewcthash` → FAIL (PI is the raw-bytes hash, not the encoded-string hash).

- [ ] **Step 4: Fix the three proved-builders.** In `wallet.ts`, import `encodeCiphertext` from `./envelopes.js`. Replace each `hashBytesToField(viewCt...)` used for a `view_ct_hash` with a hash over the encoded string. There are three sites:
  - `buildDepositProved`: `const viewCtHashHex = hashBytesToField(new TextEncoder().encode(encodeCiphertext(viewCt))).toHex();`
  - `buildTransferProved`: same transform for both `viewCtHashSenderHex` (from `viewCtSender`) and `viewCtHashRecipientHex` (from `viewCtRecipient`).
  - `buildWithdrawProved`: same transform for `viewCtHashHex` (from `viewCt`).
  Add one module-level helper to avoid repetition:

```ts
import { encodeCiphertext } from "./envelopes.js";
function viewCtHash(sealed: Uint8Array): string {
  return hashBytesToField(new TextEncoder().encode(encodeCiphertext(sealed))).toHex();
}
```
  Then each site becomes `const viewCtHashHex = viewCtHash(viewCt);` etc. The witness field (`viewCtHashWitness` / `viewCtHashSenderWitness` / `viewCtHashRecipientWitness`) reuses the same value (unchanged — they already mirror the PI).

- [ ] **Step 5: Run the new test + the full sdk suite, verify PASS.** `pnpm --filter @shielded-near/sdk test` → all PASS (existing wallet tests assert proof length / PI counts, not the hash value, so they remain green).

- [ ] **Step 6: Commit.**
```bash
git add sdk/packages/sdk/src/envelopes.ts sdk/packages/sdk/src/wallet.ts sdk/packages/sdk/src/wallet.viewcthash.test.ts
git commit -m "fix(sdk): derive view_ct_hash from submitted ciphertext bytes"
```

---

## Task 1: Vendor a NEP-141 mock-ft contract

Maps to native task #12. Independent of Task 0. **Blocks Task 6.**

**Files:**
- Create: `contracts/mock-ft/Cargo.toml`, `contracts/mock-ft/src/lib.rs`
- Modify: `Cargo.toml` (workspace members)

**Why:** The repo has no token contract; the Rust e2e fakes USDC and tolerates the payout failing. A real NEP-141 lets the demo assert `ft_balance_of(Bob)` after withdrawal. This is a test/demo fixture only — it is never part of the deployable pool artifact.

- [ ] **Step 1: Add the crate to the workspace.** In root `Cargo.toml`, change `members = ["contract", "tools/prover"]` to `members = ["contract", "tools/prover", "contracts/mock-ft"]`. Add to `[workspace.dependencies]`: `near-contract-standards = "5.5"`.

- [ ] **Step 2: Write `contracts/mock-ft/Cargo.toml`.**
```toml
[package]
name = "mock-ft"
version.workspace = true
edition.workspace = true
license.workspace = true

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
near-sdk.workspace = true
near-contract-standards.workspace = true
```

- [ ] **Step 3: Write `contracts/mock-ft/src/lib.rs`** — a standard NEP-141 with metadata, storage management, and an init that mints the full supply to a given owner. Use `near_contract_standards::fungible_token::FungibleToken` plus the `FungibleTokenCore`, `FungibleTokenResolver`, `StorageManagement`, and `FungibleTokenMetadataProvider` impls via the `near_contract_standards` impl macros. (Reference the near-contract-standards FT example for the exact macro wiring; mint to `owner_id` in `new` and register that account.)

- [ ] **Step 4: Build to wasm, verify it compiles.**
Run: `cargo build -p mock-ft --target wasm32-unknown-unknown --release`
Expected: produces `target/wasm32-unknown-unknown/release/mock_ft.wasm`.

- [ ] **Step 5: Sanity unit test.** Add a `#[cfg(test)]` mod using `near_sdk::test_utils` asserting `new` mints total supply to the owner and `ft_balance_of(owner)` returns it.
Run: `cargo test -p mock-ft` → PASS.

- [ ] **Step 6: Commit.**
```bash
git add Cargo.toml contracts/mock-ft
git commit -m "test(mock-ft): vendor a NEP-141 fungible token for the demo sandbox"
```

---

## Task 2: Scaffold `@shielded-near/client`

Maps to native task #6. Depends on nothing. **Blocks Tasks 3, 4, 5.**

**Files:**
- Create: `sdk/packages/client/package.json`, `sdk/packages/client/tsconfig.json`, `sdk/packages/client/src/index.ts`
- Create: `sdk/packages/client/src/near-caller.ts`

- [ ] **Step 1: Write `package.json`** (mirror `@shielded-near/sdk`):
```json
{
  "name": "@shielded-near/client",
  "version": "0.1.0",
  "type": "module",
  "main": "./src/index.ts",
  "types": "./src/index.ts",
  "exports": { ".": "./src/index.ts" },
  "scripts": { "build": "tsc", "test": "vitest run" },
  "dependencies": {
    "@shielded-near/core": "workspace:*",
    "@shielded-near/sdk": "workspace:*",
    "near-api-js": "^5.0.0"
  },
  "devDependencies": {
    "@types/node": "^22.0.0",
    "typescript": "^5.5.0",
    "vitest": "^2.1.0"
  }
}
```

- [ ] **Step 2: Write `tsconfig.json`** — copy `sdk/packages/sdk/tsconfig.json` verbatim.

- [ ] **Step 3: Write `near-caller.ts`** — the injected transport interface + a near-api-js adapter:
```ts
import type { Account } from "near-api-js";

/** Minimal NEAR transport the client needs. Injected so the same client works
 *  against a near-workspaces sandbox (demo) and testnet (near-api-js). */
export interface NearCaller {
  /** AccountId of the signer. */
  accountId(): string;
  /** Change-method call. Returns flattened receipt logs + the tx hash so callers can assert it landed. */
  call(contractId: string, method: string, args: Record<string, unknown>,
       opts?: { gas?: bigint; attachedDeposit?: bigint }): Promise<{ logs: string[]; transactionHash: string }>;
  /** View-method call, JSON-decoded. */
  view<T>(contractId: string, method: string, args?: Record<string, unknown>): Promise<T>;
}

/** Adapter over a near-api-js Account (testnet / mainnet path). */
export class NearApiJsCaller implements NearCaller {
  constructor(private readonly account: Account) {}
  accountId(): string { return this.account.accountId; }
  async call(contractId: string, method: string, args: Record<string, unknown>,
             opts?: { gas?: bigint; attachedDeposit?: bigint }) {
    const outcome = await this.account.functionCall({
      contractId, methodName: method, args,
      gas: (opts?.gas ?? 100_000_000_000_000n) as unknown as bigint,
      attachedDeposit: (opts?.attachedDeposit ?? 0n) as unknown as bigint,
    } as any);
    const logs = outcome.receipts_outcome.flatMap((r) => r.outcome.logs);
    return { logs };
  }
  async view<T>(contractId: string, method: string, args: Record<string, unknown> = {}) {
    return (await this.account.viewFunction({ contractId, methodName: method, args })) as T;
  }
}
```

- [ ] **Step 4: Write a placeholder `index.ts`** exporting `NearCaller`, `NearApiJsCaller` (more added later).

- [ ] **Step 5: Install + typecheck.**
Run: `pnpm install` then `pnpm --filter @shielded-near/client build`
Expected: resolves in the workspace and compiles.

- [ ] **Step 6: Commit.**
```bash
git add sdk/packages/client pnpm-lock.yaml
git commit -m "feat(client): scaffold @shielded-near/client with injectable NearCaller"
```

---

## Task 3: Client-side Merkle reconstruction (`merkle-tree.ts`)

Maps to native task #7. Depends on Task 2.

**Files:**
- Create: `sdk/packages/client/src/merkle-tree.ts`
- Test: `sdk/packages/client/src/merkle-tree.test.ts`

**Why:** The contract has no inclusion-path view. To prove transfer/withdraw, the client rebuilds the tree from observed commitments and produces the 20-deep sibling path.

- [ ] **Step 1: Write the failing test.** Mirror the Rust e2e helpers (`empty_path_for_leaf0`, `tree_with_two_leaves`) so vectors are shared truth.
```ts
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
});
```

- [ ] **Step 2: Run, verify FAIL.** `pnpm --filter @shielded-near/client test -- merkle-tree` → FAIL (module not found).

- [ ] **Step 3: Implement `merkle-tree.ts`.** Append-only tree storing leaves; `root()`/`pathFor()` recompute level-by-level using precomputed zero siblings. (Demo scale is tiny, so recompute-on-demand is fine; no incremental caching needed — YAGNI.)
```ts
import { Field, poseidon2 } from "@shielded-near/core";

export const TREE_DEPTH = 20;

export class MerkleTree {
  private leaves: Field[] = [];
  private readonly zeros: Field[] = MerkleTree.computeZeros();

  private static computeZeros(): Field[] {
    const z = [Field.zero()];
    for (let i = 1; i < TREE_DEPTH; i++) z.push(poseidon2(z[i - 1], z[i - 1]));
    return z;
  }

  append(commitment: Field): number {
    this.leaves.push(commitment);
    return this.leaves.length - 1;
  }
  size(): number { return this.leaves.length; }

  root(): Field {
    let level = this.leaves.slice();
    if (level.length === 0) return this.foldEmpty(0);
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
    return out.length ? out : [this.zeros[depth + 1] ?? Field.zero()];
  }

  private foldEmpty(_d: number): Field { return this.zeros[TREE_DEPTH - 1]; }
}
```
  (If the empty-root branch is never exercised by the demo, keep it minimal; the leaf0/two-leaf tests are the real coverage.)

- [ ] **Step 4: Run, verify PASS.** `pnpm --filter @shielded-near/client test -- merkle-tree` → PASS.

- [ ] **Step 5: Export from `index.ts`** (`MerkleTree`, `TREE_DEPTH`).

- [ ] **Step 6: Commit.**
```bash
git add sdk/packages/client/src/merkle-tree.ts sdk/packages/client/src/merkle-tree.test.ts sdk/packages/client/src/index.ts
git commit -m "feat(client): client-side Merkle tree reconstruction"
```

---

## Task 4: Event parsing + `PoolClient`

Maps to native task #8. Depends on Tasks 2, 3, and 0.

**Files:**
- Create: `sdk/packages/client/src/events.ts`, `sdk/packages/client/src/events.test.ts`
- Create: `sdk/packages/client/src/pool-client.ts`
- Modify: `sdk/packages/client/src/index.ts`

- [ ] **Step 1: Write the failing event-parsing test.** Cover deposit (one leaf) and transfer (two leaves/indices). Use literal NEP-297 log strings exactly as `events.rs` emits.
```ts
import { describe, it, expect } from "vitest";
import { parseShieldedEvents } from "./events.js";

const depositLog = JSON.stringify({
  standard: "shielded-pool", event: "deposit",
  data: { commitment: "0x01", leaf_index: 0, view_ct: "0xaa", note_ct: "0xbb" },
});
const transferLog = JSON.stringify({
  standard: "shielded-pool", event: "transfer",
  data: { merkle_root: "0x0", nullifiers: ["0x1","0x2"], commitments: ["0x03","0x04"],
          leaf_indices: [1,2], view_cts: ["0xc1","0xc2"], note_cts: ["0xcc","0xdd"] },
});

describe("parseShieldedEvents", () => {
  it("extracts deposit leaf + note_ct", () => {
    const ev = parseShieldedEvents([depositLog]);
    expect(ev.commitments).toEqual([{ leafIndex: 0n, commitment: "0x01" }]);
    expect(ev.noteCiphertexts).toEqual([{ leafIndex: 0n, noteCtHex: "0xbb" }]);
  });
  it("extracts BOTH transfer outputs in leaf_index order", () => {
    const ev = parseShieldedEvents([transferLog]);
    expect(ev.commitments).toEqual([
      { leafIndex: 1n, commitment: "0x03" }, { leafIndex: 2n, commitment: "0x04" },
    ]);
    expect(ev.noteCiphertexts.map((n) => n.noteCtHex)).toEqual(["0xcc", "0xdd"]);
  });
  it("ignores non-shielded and EVENT_JSON-prefixed noise gracefully", () => {
    expect(parseShieldedEvents(["random", "EVENT_JSON:" + depositLog]).commitments.length).toBe(1);
  });
});
```

- [ ] **Step 2: Run, verify FAIL.**

- [ ] **Step 3: Implement `events.ts`.** Strip an optional `EVENT_JSON:` prefix, `JSON.parse`, filter `standard==="shielded-pool"`, and flatten deposit/transfer into `{ commitments: {leafIndex,commitment}[], noteCiphertexts: {leafIndex, noteCtHex}[] }` sorted by `leafIndex`. Decode `noteCtHex` ("0x…") to bytes only at the `NoteCiphertext` boundary (Step 5).

- [ ] **Step 4: Run, verify PASS.**

- [ ] **Step 5: Implement `pool-client.ts`.** Wraps a `NearCaller` + pool/token ids + an internal `MerkleTree`. Uses the SDK envelopes for arg shaping.
```ts
import { MerkleTree } from "./merkle-tree.js";
import { parseShieldedEvents } from "./events.js";
import type { NearCaller } from "./near-caller.js";
import { Field, type NoteCiphertext } from "@shielded-near/core";
import {
  toFtTransferCallArgs, toTransferCall, type BuiltTx,
} from "@shielded-near/sdk"; // all re-exported by sdk/src/index.ts (verified). withdraw goes via the relayer submitter, so toWithdrawCall is NOT needed here.

const ONE_YOCTO = 1n;

export class PoolClient {
  readonly tree = new MerkleTree();
  private seenLeaves = new Set<bigint>();

  constructor(
    private readonly caller: NearCaller,
    private readonly poolId: string,
    private readonly tokenId: string,
  ) {}

  /** Deposit via ft_transfer_call on the token; returns emitted note ciphertexts. */
  async deposit(tx: BuiltTx): Promise<NoteCiphertext[]> {
    const call = toFtTransferCallArgs(tx, this.tokenId, this.poolId);
    const { logs } = await this.caller.call(call.contractId, call.methodName, call.args,
      { gas: BigInt(call.gas), attachedDeposit: ONE_YOCTO });
    return this.ingest(logs);
  }
  async transfer(tx: BuiltTx): Promise<NoteCiphertext[]> {
    const call = toTransferCall(tx, this.poolId);
    const { logs } = await this.caller.call(call.contractId, call.methodName, call.args,
      { gas: BigInt(call.gas) });
    return this.ingest(logs);
  }
  async merkleRoot(): Promise<string> {
    return await this.caller.view<string>(this.poolId, "merkle_root");
  }

  /** Parse logs, grow the local tree (asserting it matches chain), return note cts. */
  private async ingest(logs: string[]): Promise<NoteCiphertext[]> {
    const ev = parseShieldedEvents(logs);
    for (const { leafIndex, commitment } of ev.commitments) {
      if (this.seenLeaves.has(leafIndex)) continue;
      // events are ascending; demo deposits/transfers append in order
      this.tree.append(Field.fromHex(commitment));
      this.seenLeaves.add(leafIndex);
    }
    return ev.noteCiphertexts.map((n) => ({
      leafIndex: n.leafIndex, sealed: hexToBytes(n.noteCtHex),
    }));
  }

  /** Cross-check: local root must equal the contract's. Throws on drift. */
  async assertRootMatchesChain(): Promise<void> {
    const local = this.tree.root().toHex();
    const chain = await this.merkleRoot();
    if (local !== chain) throw new Error(`merkle root drift: local ${local} != chain ${chain}`);
  }

  pathFor(leafIndex: bigint): string[] { return this.tree.pathFor(leafIndex).map((f) => f.toHex()); }
}

function hexToBytes(h: string): Uint8Array {
  const s = h.startsWith("0x") ? h.slice(2) : h;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}
```
  Note: `withdraw` is submitted through the relayer (Task 5), not `PoolClient`. `@shielded-near/sdk/index.ts` already re-exports `toFtTransferCallArgs`, `toTransferCall`, `toWithdrawCall`, and `type BuiltTx` (verified), so no change to the sdk package is needed.

- [ ] **Step 6: Run full client suite, verify PASS.** `pnpm --filter @shielded-near/client test`

- [ ] **Step 7: Export `PoolClient` + event types from `index.ts`. Commit.**
```bash
git add sdk/packages/client/src/events.ts sdk/packages/client/src/events.test.ts sdk/packages/client/src/pool-client.ts sdk/packages/client/src/index.ts
git commit -m "feat(client): PoolClient submit + NEP-297 event ingestion + root cross-check"
```

---

## Task 5: `NearTxSubmitter` for the relayer (`near-submitter.ts`)

Maps to native task #9. Depends on Task 2.

**Files:**
- Create: `sdk/packages/client/src/near-submitter.ts`, `sdk/packages/client/src/near-submitter.test.ts`
- Modify: `sdk/packages/client/src/index.ts`

**Why:** Routes a real withdraw on-chain through `RelayerService.submit()`. The submitter reconstructs the `withdraw` call from the `SubmitRequest` and signs with the relayer's `NearCaller`.

- [ ] **Step 1: Write the failing test** with a fake `NearCaller` capturing the call. The submitter must call `poolId.withdraw` with all 9 args from `SubmitRequest` (merkle_root, nullifier, recipient, amount, auditor_pubkey, view_ct, relayer, relayer_fee, proof). Assert the captured args + that `proof` is sent as a number array.

- [ ] **Step 2: Run, verify FAIL.**

- [ ] **Step 3: Implement `near-submitter.ts`.**
```ts
import type { NearCaller } from "./near-caller.js";
import type { NearTxSubmitter, SubmitRequest } from "@shielded-near/relayer";

export class NearCallerSubmitter implements NearTxSubmitter {
  constructor(private readonly caller: NearCaller, private readonly poolId: string) {}
  async submitWithdraw(req: SubmitRequest): Promise<string> {
    await this.caller.call(this.poolId, "withdraw", {
      merkle_root: req.merkleRoot, nullifier: req.nullifier, recipient: req.recipient,
      amount: req.amount, auditor_pubkey: req.auditorPubkey, view_ct: req.viewCt,
      relayer: req.relayer, relayer_fee: req.relayerFee, proof: Array.from(req.proof),
    }, { gas: 300_000_000_000_000n, attachedDeposit: 1n }); // 1 yocto covers storage-staking margin per e2e
    return "sandbox-tx"; // sandbox has no externally meaningful hash; demo reads state, not hash
  }
}
```
  Add `@shielded-near/relayer` as a dependency in the client `package.json`. Confirm `SubmitRequest.viewCt` is the encoded ciphertext string the contract expects (it is — same `encodeCiphertext` output the withdraw envelope uses).

- [ ] **Step 4: Run, verify PASS.**

- [ ] **Step 5: Export `NearCallerSubmitter` from `index.ts`. Commit.**
```bash
git add sdk/packages/client/src/near-submitter.ts sdk/packages/client/src/near-submitter.test.ts sdk/packages/client/src/index.ts sdk/packages/client/package.json
git commit -m "feat(client): NearTxSubmitter routing relayer withdraws on-chain"
```

---

## Task 6: Narrated demo (`demo/run-demo.ts`)

Maps to native task #10. Depends on Tasks 0, 1, 4, 5.

**Files:**
- Modify: `pnpm-workspace.yaml` (add `demo` glob)
- Create: `demo/package.json`, `demo/tsconfig.json`
- Create: `demo/src/workspaces-caller.ts`, `demo/src/prereqs.ts`, `demo/src/run-demo.ts`

This is the integration artifact; it is exercised by running it, not by unit tests (it needs the sandbox + prover + wasm).

- [ ] **Step 1: Add `demo` to the workspace.** In `pnpm-workspace.yaml`, set:
```yaml
packages:
  - "sdk/packages/*"
  - "demo"
```

- [ ] **Step 2: Write `demo/package.json`.**
```json
{
  "name": "@shielded-near/demo",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": { "demo": "tsx src/run-demo.ts" },
  "dependencies": {
    "@shielded-near/core": "workspace:*",
    "@shielded-near/sdk": "workspace:*",
    "@shielded-near/client": "workspace:*",
    "@shielded-near/relayer": "workspace:*",
    "near-workspaces": "^4.0.0"
  },
  "devDependencies": { "@types/node": "^22.0.0", "tsx": "^4.0.0", "typescript": "^5.5.0" }
}
```

- [ ] **Step 3: Write `demo/src/workspaces-caller.ts`** — a `NearCaller` over a near-workspaces `Account`:
```ts
import type { NearCaller } from "@shielded-near/client";
import type { NearAccount } from "near-workspaces";

export class WorkspacesCaller implements NearCaller {
  constructor(private readonly account: NearAccount) {}
  accountId(): string { return this.account.accountId; }
  async call(contractId: string, method: string, args: Record<string, unknown>,
             opts?: { gas?: bigint; attachedDeposit?: bigint }) {
    const res = await this.account.callRaw(contractId, method, args, {
      gas: (opts?.gas ?? 100_000_000_000_000n).toString(),
      attachedDeposit: (opts?.attachedDeposit ?? 0n).toString(),
    });
    // near-workspaces TransactionResult exposes a flattened `.logs` getter that
    // concatenates receipt logs. Use it directly; do NOT use `res.result.logs`.
    // `.result.transaction_outcome.id` is the canonical tx hash on the v4 result.
    return { logs: res.logs, transactionHash: res.result.transaction_outcome.id };
  }
  async view<T>(contractId: string, method: string, args: Record<string, unknown> = {}) {
    return await this.account.view<T>(contractId, method, args);
  }
}
```
  **Verify before relying on it:** near-workspaces `TransactionResult.logs` is a getter returning all receipt logs flattened. If on the installed version logs are only under `res.result.receipts_outcome[*].outcome.logs`, flatten those instead. The demo silently ingests zero events (and `assertRootMatchesChain` will throw on the first deposit) if this returns nothing — so confirm logs are non-empty after the first deposit during Step 6 of Task 6.

- [ ] **Step 4: Write `demo/src/prereqs.ts`** — `assertPrereqs()` that checks the four artifacts exist (`target/wasm32-unknown-unknown/release/shielded_pool.opt.wasm`, `.../mock_ft.wasm`, `target/release/shielded-prover`, `target/sp-keys/{deposit,transfer,withdraw}.vk`) and throws a single message listing the exact build commands (from the "Key facts" block) for any that are missing.

- [ ] **Step 5: Write `demo/src/run-demo.ts`.** Structure:
  1. `await assertPrereqs()`.
  2. `Worker.init()`; `root = worker.rootAccount`.
  3. Deploy token: `const token = await root.devDeploy(MOCK_FT_WASM)`, call `new` minting supply to a freshly created `alice` (or to a `minter` then transfer). Register storage (`storage_deposit`) for the pool, alice, bob, relayer.
  4. Deploy pool: `const pool = await root.devDeploy(POOL_OPT_WASM)`; call `pool.new({ owner: pool.accountId, usdc_token: token.accountId, vk_deposit, vk_transfer, vk_withdraw })` reading vks from `target/sp-keys`.
  5. Build wallets: `new Wallet({ seed, usdcTokenAccountId: token.accountId, poolAccountId: pool.accountId, prover: new SubprocessProver(PROVER_BIN, repoRoot) })` for Alice and Bob (distinct seeds). Bob shares his `address()` (ownerPubkey + viewingPubkey) and an auditor pubkey out-of-band. **One shared `PoolClient`** is used for chain I/O and tree state (the Merkle tree is global to the pool); both wallets `scan()` the ciphertexts it returns.
  6. **Deposit TWO notes** (REQUIRED — a transfer consumes two input notes; `Wallet.findTransferInputs` needs two unspent notes with the *same* auditor, see `wallet.ts`). Alice deposits 60 then 40, both with the same `auditorPubkey`:
     - for each `amt` of `[60n, 40n]`: `const tx = await alice.buildDepositProved({ amount: amt, auditorPubkey }, alice.prover); const cts = await pool.deposit(tx); alice.scan(cts);`
     - `await pool.assertRootMatchesChain()`; the two deposits land at leaf indices 0 and 1; print Alice balance = 100.
  7. **Transfer 60 to Bob:** `const merkleRoot = await pool.merkleRoot();` build `TransferMerkleInputs { merkleRoot, merklePath0: pool.pathFor(0n), merklePath1: pool.pathFor(1n) }`; `const tx = await alice.buildTransferProved({ amount: 60n, recipientOwnerPubkey, recipientAuditorPubkey, recipientViewingPubkey }, alice.prover, merkleInputs);` `const cts = await pool.transfer(tx);` then `bob.scan(cts)` (Bob picks up the 60 note) and `alice.scan(cts)` (Alice picks up the 40 change note). Mark Alice's two spent inputs: `alice.markSpent(0n); alice.markSpent(1n);`. Print balances: Alice 40, Bob 60.
  8. **Bob withdraws his 60 note:** the transfer's two outputs are at leaf indices 2 (recipient→Bob) and 3 (change→Alice); Bob's note is the one his scan discovered (`leafIndex` from the `DiscoveredNote`). `const merkleRoot = await pool.merkleRoot(); const tx = await bob.buildWithdrawProved({ amount: 60n, recipientNearAccount: bobNear.accountId, relayer: relayerNear.accountId, relayerFee, merkleRoot, merklePath: pool.pathFor(bobNoteLeafIndex) }, bob.prover);` (note `buildWithdraw` is whole-note: `amount` must equal Bob's note amount exactly — 60). Build `RelayerService({ nearAccountId: relayerNear.accountId, feeUsdcBase: relayerFee }, new NearCallerSubmitter(relayerCaller, pool.accountId))`; map `tx` → `SubmitRequest` (`proof, merkleRoot, nullifier, recipient=bobNear.accountId, amount:"60", auditorPubkey, viewCt=encodeCiphertext(tx.viewCiphertexts[0]), relayer=relayerNear.accountId, relayerFee:String(relayerFee)`); `await relayerService.submit(req)`. The pool's payout `ft_transfer` credits `bobNear` with `60 - relayerFee` and `relayerNear` with the fee.
  9. Assert `await token.view("ft_balance_of", { account_id: bobNear.accountId })` increased by `60 - relayerFee` and `relayerNear`'s by `relayerFee`. (Both accounts must be `storage_deposit`-registered on the token — Step 3 — or the payout falls into the pool's recovery book instead of crediting them.)
  10. `await worker.tearDown()` in a `finally`.
  Print a clear narration line before each step (commitments, nullifiers, roots, proof byte length, balances).

  **Account-id note:** `bobNear`/`relayerNear` are the on-chain NEAR accounts used as the withdraw `recipient`/`relayer` public inputs (hashed via `fieldFromAccountId` = `hashBytesToField(utf8(accountId))`, which matches the contract's `hash_bytes_to_field(recipient.as_bytes())`). They are distinct from Bob's shielded `address()` keys. Ensure both are storage-registered and that the depositor account holds enough minted token for the two deposits.

- [ ] **Step 6: Build everything, then run the demo.**
```bash
# one-time prereqs (see Key facts for the exact opt-wasm flags / reuse scripts/check-production-readiness.sh)
cargo build -p shielded-pool --target wasm32-unknown-unknown --release --no-default-features --features groth16-verifier
cargo build -p mock-ft --target wasm32-unknown-unknown --release --no-default-features
cargo build -p shielded-prover --release
cargo run -p shielded-prover --release -- setup --out-dir target/sp-keys
pnpm install
pnpm --filter @shielded-near/demo demo
```
Expected: narrated deposit→transfer→withdraw completes; final assertion confirms Bob's on-chain token balance rose by `60 - relayerFee`. Exit code 0.

- [ ] **Step 7: Commit.**
```bash
git add pnpm-workspace.yaml demo
git commit -m "feat(demo): narrated two-wallet shielded-pool flow against a sandbox"
```

---

## Task 7: Wire-up verification + docs

Depends on all prior tasks.

**Files:**
- Modify: `README.md` (add a "Try the demo" subsection)

- [ ] **Step 1: Full regression.** Run `pnpm -r test` (core/sdk/auditor/relayer/client) and `cargo test -p mock-ft` → all PASS. Confirm Task 0 did not regress `cargo test -p shielded-pool --lib` (it shouldn't — pure TS change) by running it once.
- [ ] **Step 2: Run the demo once more end-to-end** to confirm reproducibility from a clean `target/sp-keys`.
- [ ] **Step 3: Add a short README "Try the demo" block** with the prereq build commands and `pnpm --filter @shielded-near/demo demo`. Note it is sandbox-only and reuses the production-readiness build artifacts.
- [ ] **Step 4: Commit.**
```bash
git add README.md
git commit -m "docs: document the real-client sandbox demo"
```

---

## Verification (use superpowers-extended-cc:verification-before-completion)

- `pnpm -r test` green; `cargo test -p mock-ft` green; `cargo test -p shielded-pool --lib` unchanged-green.
- `pnpm --filter @shielded-near/demo demo` runs through the **deposit step** end-to-end with real proofs (Bob's `assertRootMatchesChain` cross-check passes, real Groth16 verification succeeds on-chain — the value of the `view_ct_hash` fix). The transfer step is currently blocked by a contract-level gas issue surfaced by this demo; see "Follow-ups" below.
- No new dependency leaked into the deployable pool build: `cargo tree -p shielded-pool` must not list `near-contract-standards`.

## Follow-ups (discovered during implementation, out of scope for this plan)

1. **Contract `hash_bytes_to_field` gas blowup with real-size view ciphertexts.** The pool's `transfer` (and likely `withdraw` with realistic payloads) exceeds NEAR's 300 Tgas per-tx cap because `hash_bytes_to_field` is invoked on the hex-encoded ciphertext string and Poseidons it in 31-byte chunks in pure WASM. A typical sealed `ViewDisclosure` is ~351 bytes → 704-char hex → 23 chunks → 22 `poseidon2` folds per view_ct; transfer hashes both sender + recipient view_cts plus 40 tree-insert hashes ≈ 84 `poseidon2` calls ≈ 340–420 Tgas (over the 300 Tgas cap). The Rust e2e (`contract/tests/e2e_real_proofs.rs`) never hit this because it used 10-char synthetic strings. **Options:**
   - Hash the raw sealed bytes instead of the hex string (~half the chunk count).
   - Replace the bound `view_ct_hash` with a smaller commitment computed off-chain (e.g. hash on TS, contract stores/checks the commitment).
   - Move the view_ct to event-only (don't bind it into the proof) and trust the SDK encoding.
   Any of these requires touching the contract's `hash_bytes_to_field` call sites and the SDK's `view_ct_hash` derivation (in lockstep with Task 0's helper). This is its own task and may also need a soundness re-review.

2. **SDK envelope defaults were wrong.** `toTransferCall` / `toWithdrawCall` defaulted to `attachedDeposit: "0"` and 100 Tgas, both insufficient. Fixed in Task 6 to 1 NEAR and 300 Tgas to match `contract/src/storage.rs` (`TRANSFER_BYTES`/`WITHDRAW_BYTES` × `YOCTO_PER_BYTE`) and the Rust e2e. `PoolClient.transfer` also wasn't forwarding the envelope's `attachedDeposit`. Both fixed in Task 6's commit (`d9b734d`).

3. **`mock-ft` wasm needs bulk-memory lowering**, same as the pool. The demo prereqs require `mock_ft.opt.wasm` produced by `wasm-opt --enable-bulk-memory --llvm-memory-copy-fill-lowering`, not the raw cargo output.

4. **`near-workspaces` ships an older neard.** `near-workspaces@4.0.0`'s bundled `near-sandbox@0.1.5` is neard 2.6.2 (protocol 77), missing the `promise_batch_action_use_global_contract` host fn that `near-sdk 5.5` imports. The demo requires `SANDBOX_ARTIFACT_URL=...near-sandbox 2.7.0...` to be set when installing. Worth documenting in the README and either pinning a newer near-workspaces or providing an install script.
