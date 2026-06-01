import { defineConfig } from "vitest/config";
// Circuit compilation + witness calc is slow; raise the per-test timeout.
export default defineConfig({ test: { testTimeout: 120_000, hookTimeout: 120_000 } });
