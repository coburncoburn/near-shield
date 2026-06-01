// Public API for @shielded-near/deploy

export { run, CANONICAL_WASM, MAINNET_CHECKLIST, type RunOpts, type RunResult } from "./deploy.js";
export { assembleInitArgs, type InitArgs, type AssembleResult } from "./assemble.js";
export {
  assertNotDevKey,
  assertVkLength,
  DEV_VK_FINGERPRINTS,
  type Circuit,
} from "./gates.js";
