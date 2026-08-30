# Concepts

Three ideas define `ghst`'s security model:

- [The permission ceiling](permission-ceiling.md) is the intersection enforced by GitHub, narrowed
  further by local policy.
- [Profiles and tokens](profiles-and-tokens.md) separate reusable authority from delegated access
  and give each credential an issuer-defined lifetime.
- [Credential and sandbox boundaries](security-boundaries.md) explain what `ghst` controls and
  what a separate process sandbox must control.

These are short operational introductions. The [Security model](../security/index.md) contains the
full threat analysis and trust assumptions behind them.
