# Security model

`ghst` reduces the GitHub authority and credential lifetime that a trusted human operator delegates
to a less-trusted local process. Its security claims depend on both GitHub's platform controls and
the operator preserving specific local and administrative boundaries.

This section documents the reasoning behind those claims, not only the commands used to enforce
them:

- [Threat model and trust assumptions](threat-model.md) define whom `ghst` protects and whom it
  deliberately trusts.
- [Authority and permission intersection](authority-model.md) explains why a scoped request can
  narrow access but cannot widen it.
- [Device Flow and human authorization](device-flow.md) describes the phishing boundary created by
  a public client ID and human approval.
- [Client secrets and private keys](app-credentials.md) explains why those credentials have
  fundamentally different consequences.
- [Credential consequences and lifetimes](credential-consequences.md) analyzes what an attacker can
  do with each credential and with combinations of credentials.
- [Local state and process isolation](local-boundaries.md) separates `ghst`'s storage protections
  from the guarantees only a process sandbox can provide.

The claims require a dedicated GitHub App with expiring user access tokens, Device Flow, minimum
permissions and repositories, and **no private keys**. The operator must approve only Device Flows
that they personally initiated in a trusted terminal. Start with the
[required App configuration](../getting-started/github-app.md).

If credentials may already be exposed, go directly to
[credential incident response](../troubleshooting/incident-response.md).
