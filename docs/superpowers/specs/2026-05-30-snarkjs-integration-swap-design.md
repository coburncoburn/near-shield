# snarkjs integration swap (full cutover) — design

**Date:** 2026-05-30
**Status:** design approved; spec-review loop + plan pending
**Sub-project:** B of 3 (see "Initiative context")

## Why this exists

Sub-project A ported the three shielded-pool circuits to Circom and proved them
equivalent to the deployed contract/SDK hashing, with DEV Groth16 keys and a
prove→verify roundtrip (spec `docs/superpowers/specs/2026-05-29-circom-circuit-port-design.md`,
plan `…/plans/2026-05-29-circom-circuit-port.md`). Sub-project B makes snarkjs the
**only** proving path end to end: the SDK generates snarkjs proofs, the contract is
initialized with snarkjs-derived verifying keys, the demo/tests run against real proofs,
and the arkworks `tools/prover` is deleted. Sub-project C (the real trusted-setup ceremony)
then replaces the DEV keys with ceremony output.

**Decision: full cutover** (not a parallel path) — one prover, no dead arkworks code heading
into the audit.

## Initiative context — three sequential sub-projects

| | Sub-project | Status |
|---|---|---|
| A | Circom circuit port + equivalence validation | **DONE** (branch `feat/real-groth16-prover`) |
| **B (this spec)** | Integration swap: snarkjs prove path, VK/proof adapters, fingerprint guard, cutover | design approved |
| C | The ceremony (Perpetual PoT + per-circuit Phase-2 MPC + beacon + runbook) | pending |

Mainnet with real funds remains gated on C **plus** the independent circuit soundness review
and external audit. B is sandbox/DEV-key only.

## Key facts grounding the design

- The SDK already has a clean proving seam: `interface Prover { prove(req: ProveRequest):
  Promise<Uint8Array> }` returning the 256-byte `A‖B‖C` (EIP-196/197). Implementations today:
  `StubProver` (mock) and `SubprocessProver` (shells out to the arkworks binary). The wallet's
  `build*Proved(req, prover)` methods take a `Prover`.
- `ProveRequest` = `{ circuit, publicInputs: string[] (32-byte big-endian 0x-hex, contract
  order), witness: Record<string,unknown> }`. The wallet's `witness` keys mostly match the circom
  private signal names, **but not entirely** — there is a per-circuit rename table (verified
  against `wallet.ts` and the circom circuits):
  - **deposit:** all match (`ownerPubkey`, `blinding`, `viewCtHashWitness`). No renames.
  - **transfer:** wallet emits `in0OwnerPubkey/in1OwnerPubkey/out0OwnerPubkey/out1OwnerPubkey`;
    circom declares `in0Owner/in1Owner/out0Owner/out1Owner`. 4 renames. All other keys match
    (`in0Amount`, `in0Blinding`, `in0LeafIndex`, `in0Path`, `spendingKey`, `out0Amount`,
    `out0Blinding`, `viewCtHashSenderWitness`, `viewCtHashRecipientWitness`, …).
  - **withdraw:** wallet emits `noteOwnerPubkey/noteAuditorPubkey`; circom declares
    `noteOwner/noteAuditor`. 2 renames. Others match (`noteAmount`, `noteBlinding`, `spendingKey`,
    `leafIndex`, `merklePath`, `viewCtHashWitness`).

  The circom circuits are frozen by Sub-project A, so the rename lives in the mapping layer (§3),
  not in the circuits. **A name mismatch fails at `snarkjs.groth16.fullProve` (witness generation
  rejects an unknown signal / missing input) — *before* any proof exists — so the §4 contract
  roundtrip does NOT catch it.** The mapping must therefore be exhaustive and have its own direct
  test (every required circom input present, no extras).
- The contract takes verifying keys as **init parameters**: `new(…, vk_deposit, vk_transfer,
  vk_withdraw: Vec<u8>)` in EIP-196/197 bytes (`contract/src/lib.rs`). VKs are **not** hardcoded
  in WASM — so no contract code change is needed; B only needs the adapter that produces those
  bytes from snarkjs `vk.json`, fed at init.
- The **relayer does not generate proofs** — it forwards pre-built proof bytes
  (`sdk/packages/relayer/src/service.ts`). No relayer changes.
- The on-chain verifier (`contract/src/groth16.rs`) is generic standard Groth16 over BN254
  `alt_bn128`; it negates A itself, so it expects the standard un-negated A (snarkjs `pi_a`).

## Components

### 1. Adapters (pure, environment-agnostic) — `sdk/packages/sdk/src/groth16-adapter.ts`

The risk-bearing core. Two pure functions (no fs → browser-safe):

- `vkJsonToContractBytes(vk)` → `alpha_g1(64) ‖ beta_g2(128) ‖ gamma_g2(128) ‖ delta_g2(128) ‖
  IC[0..n](64 each)`, each field coordinate serialized as **32-byte little-endian**, matching
  the `VerifyingKey` byte layout in `contract/src/groth16.rs`. Mirror the exact ordering from
  `tools/prover/src/keys.rs` (`build_vk_bytes`/`g1_to_eip196`/`g2_to_eip197`) **before** that
  crate is deleted.
- `snarkjsProofToBytes(proof)` → 256 bytes `A_g1(64) ‖ B_g2(128) ‖ C_g1(64)`, A **un-negated**.

**The single highest-risk detail is the G2 `Fp2` component ordering** (snarkjs represents Fp2
as `[c0, c1]`; EIP-197 expects a specific `c0/c1` order, and the two are a frequent silent-swap
bug). This is pinned by the roundtrip test in §4 (a real snarkjs proof must verify on the
contract's `verify_groth16`).

### 2. `SnarkjsProver` (in-process, browser + node) — `sdk/packages/sdk/src/snarkjs-prover.ts`

Implements `Prover`. Constructor takes an **artifact provider**:
`(circuit: "deposit"|"transfer"|"withdraw") => Promise<{ wasm: Uint8Array; zkey: Uint8Array }>`
— **bytes, not filesystem paths**, so it runs in a browser (fetch) and in node. A small node-only
helper (e.g. `nodeArtifactProvider(buildDir)`) loads from the `circom/build` outputs for
demo/tests; browsers supply their own.

`prove(req)`:
1. Map `req` → a circom flat input (see §3).
2. `const { proof } = await snarkjs.groth16.fullProve(input, wasm, zkey)`.
3. `return snarkjsProofToBytes(proof)`.

snarkjs becomes a runtime dependency of the `sdk` package. `StubProver` stays (mock-verifier
tests). `SubprocessProver` is **removed** (its only consumer was the arkworks binary).

### 3. ProveRequest → circom input mapping — in `snarkjs-prover.ts`

Per circuit, two hardcoded tables: (a) an ordered public-signal-name list matching each circuit's
`main { public [...] }` declaration (deposit 4, transfer 9, withdraw 8), and (b) the
**witness key-rename map** from the Key-facts section (deposit: none; transfer: 4 `…OwnerPubkey
→ …Owner`; withdraw: `noteOwnerPubkey→noteOwner`, `noteAuditorPubkey→noteAuditor`). Build the
circom input as `{ …namedPublicInputs, …renamedWitness }`, converting every `0x…` hex string
(and arrays thereof, e.g. `merklePath`/`in0Path`) to `bigint`. **Endianness note:** `publicInputs`
and `witness` hex are 32-byte *big-endian* (per `prover.ts`); the §1 adapter serializes contract
VK/proof coordinates 32-byte *little-endian*. The input-mapper (hex→bigint, value-preserving) and
the adapter (bigint→LE bytes) handle endianness in opposite directions — an easy place to introduce
a swap bug, so keep the two concerns in separate, separately-tested functions. The mapping must
produce **exactly** the circom input signal set (a missing/extra key fails `fullProve`), so it has
a dedicated test independent of the contract roundtrip.

### 4. Fixtures + regen + drift guard, and the three test layers

- **Fixtures:** `circom/fixtures/{deposit,transfer,withdraw}/` with `proof.json`, `public.json`,
  `vk.json`, and the adapter outputs (contract VK bytes + 256-byte proof). Generated from the
  Sub-project A honest-input builders (`circom/test/fixtures.ts`).
- **Regen:** `circom/scripts/regen-fixtures.sh` rebuilds circuits, ensures DEV keys, generates a
  proof per circuit, exports vk + proof + public, and writes a `meta.json` containing each
  circuit's compiled **`.r1cs` sha256**.
- **Drift guard:** a check (in the Rust e2e setup and/or `check-production-readiness.sh`) fails if
  the current build's `.r1cs` sha256 differs from the fixtures' `meta.json` — so a circuit change
  cannot silently pass against a stale proof.
- **Three test layers:**
  1. `demo/src/run-demo.ts` swapped to the live `SnarkjsProver` — full deposit→transfer→withdraw
     on a near-workspaces sandbox (highest fidelity: real SDK→prover→contract path).
  2. `contract/tests/e2e_real_proofs.rs` converted to consume the committed fixtures — full
     entrypoint flow (deposit/transfer/withdraw → nullifier set, merkle insertion, state) in
     `cargo test`, deterministic, no Node/circom toolchain needed.
  3. A focused Rust test: `verify_groth16(fixture proof, fixture vk)` == true — fastest
     deterministic regression gate.
- **First milestone / gate:** one circuit's DEV proof+vk through the adapters →
  `verify_groth16` on the contract returns **true**. Until this passes the adapters are unproven;
  this is B's analog of A's Poseidon kill-gate.

### 5. Dev-key fingerprint guard — `scripts/check-production-readiness.sh`

Add a denylist of known **DEV VK fingerprints** (sha256 of the dev vk bytes — the fixtures are
those dev keys). The readiness check fails if a VK destined for deployment matches the denylist.
Forward-looking protection so Sub-project C's real ceremony keys can't be accidentally replaced by
DEV keys at deploy time.

### 6. Cutover & deletions

- **demo** (`demo/src/run-demo.ts`, `demo/src/prereqs.ts`): build circuits + DEV keys, initialize
  the contract via `vkJsonToContractBytes`, and prove via `SnarkjsProver` + the node artifact
  provider. Remove the arkworks-binary build/prereq steps.
- **Delete:** the entire `tools/prover` crate, `contract/tests/prover_cli_roundtrip.rs`,
  `tools/prover/tests/verify_via_contract.rs`, and `SubprocessProver` (+ its test); update the root
  `Cargo.toml` workspace members and the README build/run instructions.
- **relayer:** unchanged.

## Testing

- Adapter unit tests (`groth16-adapter` round-trips a known snarkjs vk/proof to bytes and back where
  meaningful; structural assertions on lengths/offsets).
- Input-mapper unit test: for each circuit, the ProveRequest→circom mapping produces **exactly** the
  set of signal names the circuit declares (no missing, no extra), with the rename map applied —
  catches the §3 name-mismatch class before it reaches `fullProve`.
- `SnarkjsProver` test: produces a 256-byte proof for each circuit from the honest fixtures, and the
  bytes `verify_groth16`-on-contract (the §4 gate).
- Drift-guard test: tampering the fixture `meta.json` r1cs hash makes the guard fail.
- The three test layers in §4.
- Existing SDK suites (`@shielded-near/core`, `client`, `sdk`) continue to pass.

## Risks

- **G2 Fp2 component ordering** in the adapters → gated by the §4 contract roundtrip.
- **Fixture staleness** → addressed by the r1cs-hash drift guard.
- **snarkjs browser bundle size / wasm loading** → acknowledged; not optimized in B.
- **Witness/public-input name or order mismatch** → handled by the explicit per-circuit rename map
  + public-name list (§3), pinned to each circuit's signals. A name mismatch fails at `fullProve`
  (witness generation), *not* at the §4 verify gate, so the mapping has its own exhaustive test
  (exact required-signal set, no extras). A public-input *order* error (names right, order wrong)
  would be caught by the §4 contract roundtrip (proof would not verify).

## Out of scope for B

- The real multi-party ceremony, Perpetual-PoT import, Phase-2 tooling, beacon, participant runbook
  (Sub-project C).
- Browser bundle-size optimization of snarkjs.
- Any change to the circom circuits themselves (frozen by Sub-project A) or the contract verifier
  logic (only its init VK bytes change, via the adapter).
