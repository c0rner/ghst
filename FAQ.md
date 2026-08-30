# Frequently Asked Questions (FAQ)

The topics previously covered in this FAQ are now maintained in the **[ghst User Manual](https://c0rner.github.io/ghst/)** (source in [`docs/src/`](docs/src/)).

Find answers to common questions by following the links below:

## Background & Concepts
- **What problem does `ghst` solve?** → [Introduction](https://c0rner.github.io/ghst/introduction.html)
- **Why not just use fine-grained Personal Access Tokens (PATs)?** → [Permission Ceiling](https://c0rner.github.io/ghst/concepts/permission-ceiling.html)
- **How does `ghst` differ from GitHub Actions OIDC / Workload Identity Federation?** → [Introduction](https://c0rner.github.io/ghst/introduction.html)
- **How do token lifetimes and proactive renewal work?** → [Profiles and Token Lifetimes](https://c0rner.github.io/ghst/concepts/profiles-and-tokens.html)

## Security & Threat Model
- **Is `ghst` a process sandbox?** → [Credential and Sandbox Boundaries](https://c0rner.github.io/ghst/concepts/security-boundaries.html) and [Local State & Process Isolation](https://c0rner.github.io/ghst/security/local-boundaries.html)
- **Why does `profiles.toml` store a `client_secret`? Is that safe?** → [Client Secrets and Private Keys](https://c0rner.github.io/ghst/security/app-credentials.html) and [Credential Consequences](https://c0rner.github.io/ghst/security/credential-consequences.html)
- **Why are GitHub App Private Keys strictly forbidden?** → [No Private Keys](https://c0rner.github.io/ghst/getting-started/github-app.html#no-private-keys) and [Client Secrets and Private Keys](https://c0rner.github.io/ghst/security/app-credentials.html)
- **What happens to OAuth refresh tokens?** → [Device Flow and Human Authorization](https://c0rner.github.io/ghst/security/device-flow.html)
- **Can a trusted operator bypass `ghst` using the App's public client ID?** → [Threat Model and Trust Assumptions](https://c0rner.github.io/ghst/security/threat-model.html)
- **Full security architecture and threat analysis** → [Security Model](https://c0rner.github.io/ghst/security/) and [Credential Consequences](https://c0rner.github.io/ghst/security/credential-consequences.html)

## AI Agents & Tooling Workflows
- **Which tools work with `ghst`?** → [AI-Agent Workflows](https://c0rner.github.io/ghst/recipes/ai-agents.html)
- **How to confine AI agents with sandboxes or MicroVMs?** → [Process Sandboxing & MicroVMs](https://c0rner.github.io/ghst/recipes/sandboxing.html)
- **Can I run background daemons with `ghst run`?** → [`run` Command Reference](https://c0rner.github.io/ghst/commands/run.html)
- **Multi-repository workflows and CLI overrides** → [Multi-Repository Setups](https://c0rner.github.io/ghst/recipes/multi-repository.html)

## Troubleshooting & Incident Response
- **Why does scoped token creation fail with HTTP 403?** → [Common Failures](https://c0rner.github.io/ghst/troubleshooting/common-failures.html)
- **What happens after a crash, kill, power loss, or network interruption?** → [Cleanup and Recovery](https://c0rner.github.io/ghst/troubleshooting/cleanup.html)
- **How to respond to credential or configuration exposure?** → [Credential Incident Response](https://c0rner.github.io/ghst/troubleshooting/incident-response.html)

