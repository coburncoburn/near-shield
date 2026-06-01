import { describe, it, expect } from "vitest";
import { loadConfig } from "./config.js";

describe("loadConfig", () => {
  it("loads sandbox config from file", () => {
    const cfg = loadConfig("sandbox");
    expect(cfg.network).toBe("sandbox");
    expect(cfg.account).toBe("pool.test.near");
    expect(cfg.owner).toBe("pool.test.near");
    expect(cfg.usdcToken).toBe("usdc.test.near");
  });

  it("overrides win over file values", () => {
    const cfg = loadConfig("sandbox", { account: "override.near", usdcToken: "other-usdc.near" });
    expect(cfg.account).toBe("override.near");
    // owner still comes from file
    expect(cfg.owner).toBe("pool.test.near");
    expect(cfg.usdcToken).toBe("other-usdc.near");
  });

  it("throws when usdcToken is missing (mainnet, no file, no override)", () => {
    expect(() =>
      loadConfig("mainnet", { account: "x", owner: "y" })
    ).toThrow(/usdcToken.*required/i);
  });

  it("throws when account is missing", () => {
    expect(() =>
      loadConfig("mainnet", { owner: "y", usdcToken: "usdc.near" })
    ).toThrow(/account.*required/i);
  });

  it("throws when owner is missing", () => {
    expect(() =>
      loadConfig("mainnet", { account: "x", usdcToken: "usdc.near" })
    ).toThrow(/owner.*required/i);
  });

  it("accepts all fields via overrides (no config file needed)", () => {
    const cfg = loadConfig("mainnet", {
      account: "pool.near",
      owner: "dao.near",
      usdcToken: "usdc.near",
    });
    expect(cfg.network).toBe("mainnet");
    expect(cfg.account).toBe("pool.near");
    expect(cfg.owner).toBe("dao.near");
    expect(cfg.usdcToken).toBe("usdc.near");
  });
});
