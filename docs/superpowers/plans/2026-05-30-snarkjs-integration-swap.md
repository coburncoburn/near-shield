# snarkjs Integration Swap Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers-extended-cc:subagent-driven-development (if subagents available) or superpowers-extended-cc:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make snarkjs the only Groth16 proving path end-to-end — an in-process `SnarkjsProver` + pure VK/proof adapters in the SDK, snarkjs-derived VKs at contract init, the demo + Rust tests on real snarkjs proofs, and the arkworks `tools/prover` deleted (Sub-project B of 3).

**Architecture:** Pure browser-safe adapters convert snarkjs `vk.json`/proof JSON to the contract's EIP-196/197 little-endian bytes. A per-circuit input-mapper turns the SDK's `ProveRequest` (big-endian hex publicInputs + arkworks-named witness) into a circom flat input (applying a small key-rename map). `SnarkjsProver` ties them to `snarkjs.groth16.fullProve`. Committed snarkjs fixtures (from Sub-project A's honest-input builders) drive a Rust `verify_groth16` gate, a converted Rust e2e, and a drift guard; the live TS demo is the full-flow integration test.

**Tech Stack:** snarkjs 0.7.x (new SDK dep), circom 2.1.9 + DEV keys from Sub-project A (`circom/build`), vitest, near-workspaces (demo + e2e), Rust/cargo (contract tests). Spec: `docs/superpowers/specs/2026-05-30-snarkjs-integration-swap-design.md`.

**Conventions:** follow @superpowers-extended-cc:test-driven-development and @superpowers-extended-cc:verification-before-completion (paste real command output before claiming pass). The contract verifier (`contract/src/groth16.rs`) and the soon-deleted `tools/prover/src/keys.rs` are the byte-layout ground truth: G1 = `x_LE(32) ‖ y_LE(32)`; G2 = `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1` (each 32 LE); proof = `A(64) ‖ B(128) ‖ C(64)` with A un-negated; VK = `alpha_g1 ‖ beta_g2 ‖ gamma_g2 ‖ delta_g2 ‖ IC[0..n]`.

---

### Task 0: SDK snarkjs dependency + adapter/mapper module scaffolding

**Files:**
- Modify: `sdk/packages/sdk/package.json` (add `snarkjs` dep)
- Create: `sdk/packages/sdk/src/groth16-adapter.ts` (stubs + types)
- Create: `sdk/packages/sdk/src/snarkjs-prover.ts` (stubs + types)
- Modify: `sdk/packages/sdk/src/index.ts` (export the new public symbols)

- [ ] **Step 1: Add snarkjs dep + install**
Add `"snarkjs": "^0.7.4"` to `dependencies` in `sdk/packages/sdk/package.json`. Run `pnpm install` from repo root. (snarkjs ships no first-class types; import as `import * as snarkjs from "snarkjs"` and add a minimal `declare module "snarkjs"` if `tsc` complains, or `// @ts-expect-error` at the import with a comment.)

- [ ] **Step 2: Create typed stubs**
`groth16-adapter.ts`: define `SnarkjsVk`, `SnarkjsProof` interfaces (G1 = `[string,string,string]`, G2 = `[[string,string],[string,string],[string,string]]`) and export `vkJsonToContractBytes(vk: SnarkjsVk): Uint8Array` and `snarkjsProofToBytes(proof: SnarkjsProof): Uint8Array` throwing "not implemented".
`snarkjs-prover.ts`: export `CircuitName` type, `ArtifactProvider` type, `proveRequestToCircomInput(req)` stub, `SnarkjsProver implements Prover` stub.

- [ ] **Step 3: Verify build + commit**
Run: `pnpm --filter @shielded-near/sdk exec tsc --noEmit` → passes (stubs typecheck).
```bash
git add -f sdk/packages/sdk/package.json sdk/packages/sdk/src/groth16-adapter.ts sdk/packages/sdk/src/snarkjs-prover.ts sdk/packages/sdk/src/index.ts pnpm-lock.yaml
git commit -m "build(sdk): add snarkjs dep + adapter/prover scaffolding"
```

---

### Task 1: VK + proof adapters (pure) + structural unit tests

**Files:**
- Modify: `sdk/packages/sdk/src/groth16-adapter.ts`
- Create: `sdk/packages/sdk/src/groth16-adapter.test.ts`

- [ ] **Step 1: Write failing structural tests** (`groth16-adapter.test.ts`)
Using a small hand-written `SnarkjsVk`/`SnarkjsProof` (decimal strings), assert: `snarkjsProofToBytes(proof).length === 256`; `vkJsonToContractBytes(vk).length === 64 + 128*3 + 64*IC.length`; a known small field value (e.g. `"5"`) serializes to 32-byte little-endian (`out[0]===5`, rest 0); a point-at-infinity (`z==="0"`) → all-zero segment. Run → FAIL.

- [ ] **Step 2: Implement the adapters**
```ts
const FR = 32;
function decToLe(dec: string): Uint8Array {
  let v = BigInt(dec); const out = new Uint8Array(FR);
  for (let i = 0; i < FR; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}
// G1 [x,y,z]; z==="1" affine, z==="0" infinity → zeros.
function g1(p: readonly string[]): Uint8Array {
  const o = new Uint8Array(64);
  if (p[2] === "0") return o;
  o.set(decToLe(p[0]), 0); o.set(decToLe(p[1]), 32); return o;
}
// G2 [[x.c0,x.c1],[y.c0,y.c1],[z..]]. NOTE: snarkjs↔arkworks Fp2 order — see Task 2 gate.
function g2(p: readonly (readonly string[])[]): Uint8Array {
  const o = new Uint8Array(128);
  if (p[2][0] === "0" && p[2][1] === "0") return o;
  o.set(decToLe(p[0][0]), 0); o.set(decToLe(p[0][1]), 32);   // x.c0, x.c1
  o.set(decToLe(p[1][0]), 64); o.set(decToLe(p[1][1]), 96);  // y.c0, y.c1
  return o;
}
export function snarkjsProofToBytes(pr: SnarkjsProof): Uint8Array {
  const o = new Uint8Array(256);
  o.set(g1(pr.pi_a), 0); o.set(g2(pr.pi_b), 64); o.set(g1(pr.pi_c), 192);
  return o;
}
export function vkJsonToContractBytes(vk: SnarkjsVk): Uint8Array {
  const parts = [g1(vk.vk_alpha_1), g2(vk.vk_beta_2), g2(vk.vk_gamma_2), g2(vk.vk_delta_2), ...vk.IC.map(g1)];
  const total = parts.reduce((a, p) => a + p.length, 0);
  const o = new Uint8Array(total); let off = 0;
  for (const p of parts) { o.set(p, off); off += p.length; }
  return o;
}
```
> The G2 `c0/c1` order above is the *first attempt*. Its semantic correctness is unknown until the Task 2 contract roundtrip — do NOT consider the adapters done until that gate is green.

- [ ] **Step 3: Run + commit**
Run: `pnpm --filter @shielded-near/sdk exec vitest run groth16-adapter` → PASS (structural).
```bash
git add -f sdk/packages/sdk/src/groth16-adapter.ts sdk/packages/sdk/src/groth16-adapter.test.ts
git commit -m "feat(sdk): snarkjs VK/proof → contract-bytes adapters (structural)"
```

---

### Task 2: Fixtures generation + the `verify_groth16` contract gate (pins G2 ordering)

> This is B's kill-gate: a real snarkjs proof + adapted VK must verify on the contract's `verify_groth16`. If it returns false, the adapter's G2 `Fp2` order is wrong — swap `c0`/`c1` in `g2()` (and re-run) until true.

**Files:**
- Create: `circom/scripts/regen-fixtures.sh`
- Create: `circom/scripts/gen-fixtures.ts` (TS: prove + adapt + write bytes)
- Create: `circom/fixtures/{deposit,transfer,withdraw}/` (proof.json, public.json, vk.json, proof.bin, vk.bin) + `circom/fixtures/meta.json`
- Create: `contract/tests/snarkjs_verify_fixture.rs`

- [ ] **Step 1: Write the fixture generator** (`gen-fixtures.ts`)
Import the honest-input builders from `circom/test/fixtures.ts` (circom-named, so NO rename needed here). For each circuit: `snarkjs.groth16.fullProve(input, build/<c>_js/<c>.wasm, build/keys/<c>_dev.zkey)` → `{proof, publicSignals}`; `snarkjs.zKey.exportVerificationKey(build/keys/<c>_dev.zkey)` → vk; write `proof.json`, `public.json`, `vk.json`, plus `proof.bin = snarkjsProofToBytes(proof)` and `vk.bin = vkJsonToContractBytes(vk)` (import the Task 1 adapters from `@shielded-near/sdk`). Write `circom/fixtures/meta.json` mapping each circuit → sha256 of `build/<c>.r1cs`.

- [ ] **Step 2: regen-fixtures.sh** wraps it: `pnpm --filter @shielded-near/circom build` → ensure `build/keys` (run `dev-setup.sh` if absent) → `pnpm --filter @shielded-near/circom exec tsx scripts/gen-fixtures.ts`. `chmod +x`. Run it; commit the generated fixtures.

- [ ] **Step 3: Write the failing Rust gate** (`contract/tests/snarkjs_verify_fixture.rs`)
For each circuit: read `circom/fixtures/<c>/vk.bin` + `proof.bin` + `public.json` (parse public signals → `Field`s in contract order). Construct the contract `VerifyingKey`/`Proof` from bytes and call `groth16::verify_groth16(&vk, &proof, &inputs)`; assert `true`. (Mirror how `contract/src/groth16.rs` tests construct these; the verifier is feature-gated — run under the same features the existing `groth16_proof.rs` test uses.)
Run: `cargo test -p shielded-pool --test snarkjs_verify_fixture <features>` → expected FAIL initially if G2 order is wrong.

- [ ] **Step 4: Make the gate pass**
If verify is false, swap `c0`/`c1` in `groth16-adapter.ts` `g2()` (`o.set(decToLe(p[0][1]),0); o.set(decToLe(p[0][0]),32); …`), re-run `regen-fixtures.sh`, re-run the Rust test. Iterate until all three circuits verify `true`. **Document the final correct ordering with a comment in `g2()`.**

- [ ] **Step 5: Commit**
```bash
git add -f circom/scripts/regen-fixtures.sh circom/scripts/gen-fixtures.ts circom/fixtures sdk/packages/sdk/src/groth16-adapter.ts contract/tests/snarkjs_verify_fixture.rs
git commit -m "feat: snarkjs fixtures + verify_groth16 contract gate (pins G2 ordering)"
```

---

### Task 3: ProveRequest → circom input mapper + exact-signal-set test

**Files:**
- Modify: `sdk/packages/sdk/src/snarkjs-prover.ts`
- Create: `sdk/packages/sdk/src/snarkjs-prover.test.ts`

- [ ] **Step 1: Write the failing mapper test**
For each circuit, build a representative `ProveRequest` (publicInputs of the right length as `0x` hex; witness with the wallet's actual keys — for transfer include `in0OwnerPubkey` etc., for withdraw `noteOwnerPubkey`/`noteAuditorPubkey`). Assert `Object.keys(proveRequestToCircomInput(req)).sort()` **exactly equals** the circuit's declared circom input signal set (hardcode the expected sets from `circom/circuits/*.circom`). Expected **object-key** counts (note `in0Path`/`in1Path`/`merklePath` are single array-valued keys, NOT flattened per element): deposit = 4 public + 3 witness = **7**; transfer = 9 public + 19 witness = **28**; withdraw = 8 public + 8 witness = **16**. Run → FAIL.

- [ ] **Step 2: Implement the mapper**
```ts
const PUBLIC_NAMES: Record<CircuitName, string[]> = {
  deposit: ["commitment","amount","auditorPubkey","viewCtHash"],
  transfer: ["merkleRoot","nullifier0","nullifier1","commitmentOut0","commitmentOut1",
    "auditorPubkey","recipientAuditorPubkey","viewCtHashSender","viewCtHashRecipient"],
  withdraw: ["merkleRoot","nullifier","recipient","amount","relayer","relayerFee","auditorPubkey","viewCtHash"],
};
const RENAME: Record<CircuitName, Record<string,string>> = {
  deposit: {},
  transfer: { in0OwnerPubkey:"in0Owner", in1OwnerPubkey:"in1Owner", out0OwnerPubkey:"out0Owner", out1OwnerPubkey:"out1Owner" },
  withdraw: { noteOwnerPubkey:"noteOwner", noteAuditorPubkey:"noteAuditor" },
};
const conv = (v: unknown): string | string[] =>
  Array.isArray(v) ? v.map((x) => BigInt(x as string).toString()) : BigInt(v as string).toString();
export function proveRequestToCircomInput(req: ProveRequest): Record<string, string | string[]> {
  const names = PUBLIC_NAMES[req.circuit as CircuitName];
  if (req.publicInputs.length !== names.length)
    throw new Error(`${req.circuit}: expected ${names.length} public inputs, got ${req.publicInputs.length}`);
  const input: Record<string, string | string[]> = {};
  names.forEach((n, i) => { input[n] = conv(req.publicInputs[i]); });
  const rename = RENAME[req.circuit as CircuitName];
  for (const [k, v] of Object.entries(req.witness)) input[rename[k] ?? k] = conv(v);
  return input;
}
```
> Big-endian hex → bigint (value-preserving) here; the Task 1 adapter does bigint → little-endian bytes. Keep these two endianness concerns in their separate functions.

- [ ] **Step 3: Run + commit**
Run: `pnpm --filter @shielded-near/sdk exec vitest run snarkjs-prover` → PASS.
```bash
git add -f sdk/packages/sdk/src/snarkjs-prover.ts sdk/packages/sdk/src/snarkjs-prover.test.ts
git commit -m "feat(sdk): ProveRequest→circom input mapper + exact-signal test"
```

---

### Task 4: `SnarkjsProver` + node artifact provider

**Files:**
- Modify: `sdk/packages/sdk/src/snarkjs-prover.ts`
- Modify: `sdk/packages/sdk/src/snarkjs-prover.test.ts`
- Create: `sdk/packages/sdk/src/node-artifacts.ts` (node-only helper)

- [ ] **Step 1: Implement `SnarkjsProver`**
```ts
export type ArtifactProvider = (c: CircuitName) => Promise<{ wasm: Uint8Array; zkey: Uint8Array }>;
export class SnarkjsProver implements Prover {
  constructor(private readonly artifacts: ArtifactProvider) {}
  async prove(req: ProveRequest): Promise<Uint8Array> {
    const input = proveRequestToCircomInput(req);
    const { wasm, zkey } = await this.artifacts(req.circuit as CircuitName);
    const { proof } = await snarkjs.groth16.fullProve(input, wasm, zkey);
    return snarkjsProofToBytes(proof);
  }
}
```
(snarkjs `fullProve` accepts `Uint8Array` wasm/zkey buffers — confirm; if it needs file paths in node, the node provider can pass paths and the browser path uses buffers, but prefer the buffer API so the class stays env-agnostic.)
`node-artifacts.ts`: `export function nodeArtifactProvider(buildDir: string): ArtifactProvider` returning `readFileSync` of `<buildDir>/<c>_js/<c>.wasm` and `<buildDir>/keys/<c>_dev.zkey` as `Uint8Array`. Keep this in a separate file (node `fs`) so the browser never imports it.

- [ ] **Step 2: Write the prove test**
For each circuit, use `nodeArtifactProvider("circom/build")` + a `ProveRequest` built from the same honest values as `circom/test/fixtures.ts` but **in wallet/ProveRequest shape** (publicInputs hex + wallet-named witness incl. `in0OwnerPubkey` etc.), call `prover.prove(req)`, assert the result is 256 bytes. (Gate the test to skip with a message if `circom/build/keys` is absent, like A's prove-verify test.) Run → PASS.

- [ ] **Step 3: Commit**
```bash
git add -f sdk/packages/sdk/src/snarkjs-prover.ts sdk/packages/sdk/src/snarkjs-prover.test.ts sdk/packages/sdk/src/node-artifacts.ts sdk/packages/sdk/src/index.ts
git commit -m "feat(sdk): in-process SnarkjsProver + node artifact provider"
```

---

### Task 5: Convert the Rust e2e to fixtures + drift guard; delete the CLI-roundtrip test

**Files:**
- Modify: `contract/tests/e2e_real_proofs.rs` (replace prover shell-out with fixture reads)
- Delete: `contract/tests/prover_cli_roundtrip.rs`

- [ ] **Step 1: Add the drift guard helper**
In the e2e test setup, read `circom/fixtures/meta.json`, recompute sha256 of the current `circom/build/<c>.r1cs` (or require the build present), and `assert!` they match — fail with "fixtures stale: run circom/scripts/regen-fixtures.sh". (If `circom/build` isn't present in CI, skip the recompute but still assert the fixture files exist **and assert `vk.bin`/`proof.bin` have the expected non-zero lengths** — 256 for proof, `64+128*3+64*IC.len` for vk — so a truncated/empty committed fixture can't silently pass; document the tradeoff.)

- [ ] **Step 2: Replace proof generation with fixture reads**
Delete the `prove()` shell-out and `PROVER_BIN`/`KEY_DIR` usage. Read `circom/fixtures/<c>/proof.bin` for proofs and `vk.bin` for the init VKs. Align the test's public inputs / note values / merkle state to the fixtures' honest scenario (the same values `circom/test/fixtures.ts` uses — document them as constants). Keep the full deposit→(transfer)→withdraw entrypoint assertions (leaf insertion, nullifier spent, payout).

- [ ] **Step 3: Run + delete the CLI test**
Run: `cargo test -p shielded-pool --test e2e_real_proofs <same features as before>` → PASS. Then `git rm contract/tests/prover_cli_roundtrip.rs`.

- [ ] **Step 4: Commit**
```bash
git add -f contract/tests/e2e_real_proofs.rs
git rm contract/tests/prover_cli_roundtrip.rs
git commit -m "test(contract): drive e2e from snarkjs fixtures + r1cs drift guard"
```

---

### Task 6: Demo cutover to snarkjs

**Files:**
- Modify: `demo/src/prereqs.ts` (build circom + dev keys, not the arkworks binary)
- Modify: `demo/src/run-demo.ts` (SnarkjsProver + vkJsonToContractBytes)
- Modify: `demo/package.json` if needed (ensure it can import `@shielded-near/sdk` adapters + `@shielded-near/circom` build path; add `tsx`/snarkjs only if not transitively available)

- [ ] **Step 1: prereqs.ts** — replace the `shielded-prover` binary + `sp-keys` checks with: `circom/build/<c>.r1cs` + `<c>_js/<c>.wasm` (build via `pnpm --filter @shielded-near/circom build`) and `circom/build/keys/<c>_dev.zkey` + `<c>_vk.json` (via `circom/scripts/dev-setup.sh`).

- [ ] **Step 2: run-demo.ts** — replace `SubprocessProver(PROVER_BIN, REPO_ROOT)` with `new SnarkjsProver(nodeArtifactProvider(resolve(REPO_ROOT,"circom/build")))`. Replace the `readFileSync(<c>.vk)` VK init with `Array.from(vkJsonToContractBytes(JSON.parse(readFileSync(circom/build/keys/<c>_vk.json))))` for `vk_deposit/transfer/withdraw`. Drop `PROVER_KEY_DIR`.

- [ ] **Step 3: Run the demo** (full sandbox flow)
Run: `pnpm --filter @shielded-near/circom build && bash circom/scripts/dev-setup.sh && pnpm --filter @shielded-near/demo demo` → expect `ALL ASSERTIONS PASSED` (deposit→transfer→withdraw with snarkjs proofs against the contract). Paste the tail.

- [ ] **Step 4: Commit**
```bash
git add -f demo/src/prereqs.ts demo/src/run-demo.ts demo/package.json
git commit -m "feat(demo): cut over to in-process SnarkjsProver + snarkjs VKs"
```

---

### Task 7: Delete arkworks prover + SubprocessProver; Cargo/README; fingerprint guard

**Files:**
- Delete: `tools/prover/` (whole crate, incl. `tests/verify_via_contract.rs`)
- Modify: `Cargo.toml` (remove `tools/prover` from workspace members)
- Modify: `sdk/packages/sdk/src/prover.ts` (remove `SubprocessProver`) + `sdk/packages/sdk/src/prover.test.ts` + `index.ts`
- Modify: `scripts/check-production-readiness.sh` (DEV-VK fingerprint denylist)
- Modify: `README.md`

- [ ] **Step 1: Remove SubprocessProver**
Delete the `SubprocessProver` class + its `defaultSpawn` helper from `prover.ts`, remove its tests from `prover.test.ts`, drop the export from `index.ts`. Keep `StubProver` + the `Prover`/`ProveRequest` interfaces. Run `pnpm --filter @shielded-near/sdk exec vitest run` → green.

- [ ] **Step 2: Delete the arkworks crate**
`git rm -r tools/prover`. Remove `"tools/prover"` from `Cargo.toml` `[workspace] members`. Run `cargo build -p shielded-pool --target wasm32-unknown-unknown --release --no-default-features --features groth16-verifier` and `cargo test -p shielded-pool --test e2e_real_proofs --test snarkjs_verify_fixture <features>` → green (they no longer depend on the crate).

- [ ] **Step 3: Fingerprint guard**
In `scripts/check-production-readiness.sh`, add a step: compute sha256 of each `circom/fixtures/<c>/vk.bin` (the DEV VKs) into a `DEV_VK_FINGERPRINTS` denylist, and fail if any VK destined for deployment matches. For B (no production deploy config yet) implement the mechanism + register the current DEV fingerprints, with a comment that Sub-project C wires the actual deploy-VK comparison. Run the script → still exits 0 (DEV keys are not "being deployed" yet, just registered).

- [ ] **Step 4: README + final full check**
Update `README.md` build/run instructions: circom build + `dev-setup.sh` replace the arkworks-binary steps; note the prover is now in-process snarkjs. Run the whole relevant suite: `pnpm --filter @shielded-near/sdk exec vitest run` + `pnpm --filter @shielded-near/circom exec vitest run` + `cargo test -p shielded-pool <features>` → all green.

- [ ] **Step 5: Commit**
```bash
git add -f Cargo.toml sdk/packages/sdk/src/prover.ts sdk/packages/sdk/src/prover.test.ts sdk/packages/sdk/src/index.ts scripts/check-production-readiness.sh README.md
git rm -r tools/prover
git commit -m "chore: delete arkworks prover + SubprocessProver; dev-VK fingerprint guard"
```

---

## Done criteria for Sub-project B

- The Task 2 gate is green: real snarkjs proofs + adapted VKs verify on the contract's `verify_groth16` for all three circuits (G2 ordering pinned).
- `SnarkjsProver` produces accepted 256-byte proofs in-process; the input-mapper produces exactly each circuit's signal set (rename map applied).
- The demo runs the full deposit→transfer→withdraw flow on a sandbox with snarkjs proofs; the Rust e2e runs from fixtures with a drift guard; the focused `verify_groth16` fixture test passes.
- `tools/prover` and `SubprocessProver` are gone; the dev-VK fingerprint guard is in `check-production-readiness.sh`; README updated.
- All SDK + circom + contract suites are green.

## Handoff to Sub-project C

C runs the real multi-party ceremony (Perpetual PoT + per-circuit Phase-2 MPC + beacon + runbook), replaces the DEV `*_dev.zkey`/VKs with ceremony output, regenerates fixtures from the real keys, and wires the deploy-VK comparison into the fingerprint guard. Mainnet also remains gated on the independent circuit soundness review + external audit.
