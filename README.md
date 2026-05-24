# NEAR Shielded USDC Pool

Privacy-preserving USDC pool on NEAR with per-user auditor view keys.

See `docs/superpowers/specs/2026-05-24-near-shielded-pool-design.md` for the design and `docs/superpowers/plans/2026-05-24-near-shielded-pool.md` for the implementation plan.

## Layout
- `circuits/` — Noir zk circuits (deposit, transfer, withdraw)
- `contract/` — NEAR Rust contract
- `sdk/` — TypeScript SDK, relayer, auditor indexer, CLI
