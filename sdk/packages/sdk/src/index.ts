export {
  Wallet,
  type BuiltTx,
  type DepositRequest,
  type TransferRequest,
  type WalletConfig,
  type WithdrawRequest,
} from "./wallet.js";
export {
  StubProver,
  SubprocessProver,
  type Prover,
  type ProveRequest,
} from "./prover.js";
export {
  encodeCiphertext,
  toDepositArgs,
  toFtTransferCallArgs,
  toTransferArgs,
  toTransferCall,
  toWithdrawArgs,
  toWithdrawCall,
  type DepositArgs,
  type NearFunctionCall,
  type TransferArgs,
  type WithdrawArgs,
} from "./envelopes.js";
export {
  vkJsonToContractBytes,
  snarkjsProofToBytes,
  type G1,
  type G2,
  type SnarkjsProof,
  type SnarkjsVk,
} from "./groth16-adapter.js";
export {
  SnarkjsProver,
  proveRequestToCircomInput,
  type CircuitName,
  type ArtifactProvider,
} from "./snarkjs-prover.js";
// WARNING: Node-only — imports node:fs. Browser consumers must NOT import this
// symbol; supply a custom ArtifactProvider instead. Tree-shaking bundlers can
// drop this via "sideEffects": false in package.json.
export { nodeArtifactProvider } from "./node-artifacts.js";
