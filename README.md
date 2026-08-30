# ghst - GitHub Scoped Tokens

`ghst` (pronounced "ghost") mints short-lived, least-privilege GitHub user access tokens for AI
coding agents and developer tools. Instead of granting a broad Personal Access Token (PAT) or
ambient workstation credentials, `ghst` provides ephemeral, user-attributed tokens narrowed by a
dedicated GitHub App and local permission profile.

```bash
# Run an AI agent with the default scoped profile and repository selection
ghst run -- codex

# Select an explicit least-privilege profile
ghst run --profile reader -- aider

# Confine the local process with a kernel sandbox (ghst outside, sandbox inside)
ghst run -- nono run --allow . -- claude
```

## Security Warning & Requirements

> [!IMPORTANT]
> `ghst` requires a **dedicated GitHub App** configured with:
>
> - Only the minimum permissions and repositories needed
> - **Device Flow** enabled and **expiring user access tokens** enabled
> - **No private keys** (private keys bypass human authorization and are strictly forbidden)
> - An optional client secret (only needed for scoped profiles or remote revocation)
>
> `ghst` controls credential authority and lifetime; **it is not a process sandbox**. Always deny
> less-trusted tools access to `~/.config/ghst/`, `~/.cache/ghst/`, GitHub CLI state, and SSH keys.
> See the [Security Model](https://c0rner.github.io/ghst/security/) for full threat analysis.

## User Manual

Comprehensive, searchable documentation is available in the **[ghst User Manual](https://c0rner.github.io/ghst/)**
(source in [`docs/src/`](docs/src/)):

| Section | Description |
|---|---|
| **[Getting Started](https://c0rner.github.io/ghst/getting-started/)** | [Installation](https://c0rner.github.io/ghst/getting-started/installation.html), [Required GitHub App Setup](https://c0rner.github.io/ghst/getting-started/github-app.html), and [Quickstart](https://c0rner.github.io/ghst/getting-started/quickstart.html) |
| **[Concepts](https://c0rner.github.io/ghst/concepts/)** | [Permission Ceiling](https://c0rner.github.io/ghst/concepts/permission-ceiling.html), [Profiles & Token Lifetimes](https://c0rner.github.io/ghst/concepts/profiles-and-tokens.html), and [Security Boundaries](https://c0rner.github.io/ghst/concepts/security-boundaries.html) |
| **[Security Model](https://c0rner.github.io/ghst/security/)** | [Threat Model](https://c0rner.github.io/ghst/security/threat-model.html), [Authority Intersection](https://c0rner.github.io/ghst/security/authority-model.html), [Device Flow Safety](https://c0rner.github.io/ghst/security/device-flow.html), [Credentials](https://c0rner.github.io/ghst/security/app-credentials.html), and [Consequences Matrix](https://c0rner.github.io/ghst/security/credential-consequences.html) |
| **[Configuration](https://c0rner.github.io/ghst/configuration/)** | [Global Options](https://c0rner.github.io/ghst/configuration/global.html), [App Profiles](https://c0rner.github.io/ghst/configuration/app-profiles.html), [Scoped Profiles](https://c0rner.github.io/ghst/configuration/scoped-profiles.html), and [Repository Resolution](https://c0rner.github.io/ghst/configuration/repositories.html) |
| **[Commands](https://c0rner.github.io/ghst/commands/)** | [`edit`](https://c0rner.github.io/ghst/commands/edit.html), [`login`](https://c0rner.github.io/ghst/commands/login.html), [`token`](https://c0rner.github.io/ghst/commands/token.html), [`profiles`](https://c0rner.github.io/ghst/commands/profiles.html), [`status`](https://c0rner.github.io/ghst/commands/status.html), [`run`](https://c0rner.github.io/ghst/commands/run.html), [`prune`](https://c0rner.github.io/ghst/commands/prune.html), [`revoke`](https://c0rner.github.io/ghst/commands/revoke.html) |
| **[Recipes](https://c0rner.github.io/ghst/recipes/)** | [AI Agents](https://c0rner.github.io/ghst/recipes/ai-agents.html), [Process Sandboxing & MicroVMs](https://c0rner.github.io/ghst/recipes/sandboxing.html), and [Multi-Repository Workflows](https://c0rner.github.io/ghst/recipes/multi-repository.html) |
| **[Troubleshooting](https://c0rner.github.io/ghst/troubleshooting/)** | [Common Failures](https://c0rner.github.io/ghst/troubleshooting/common-failures.html), [Cleanup & Recovery](https://c0rner.github.io/ghst/troubleshooting/cleanup.html), and [Incident Response](https://c0rner.github.io/ghst/troubleshooting/incident-response.html) |

## Quick Installation

```bash
# Cargo (recommended if Rust toolchain is installed)
cargo install --locked ghst

# Or download prebuilt release binaries
# https://github.com/c0rner/ghst/releases
```

## Reporting Security Vulnerabilities

Please do not report security vulnerabilities in public issues. Use the private
[GitHub Security Advisory form](https://github.com/c0rner/ghst/security/advisories/new) or see
[SECURITY.md](SECURITY.md).

## Development

```bash
cargo check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
mdbook build docs
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

