import { describe, expect, it } from "vitest";
import { VERSION } from "./index.js";

describe("core", () => {
  it("exposes a semver version constant", () => {
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
