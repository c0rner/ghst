# Introduction

`ghst` (pronounced “ghost”) mints short-lived, least-privilege GitHub user access tokens for local developer tools and AI coding agents.

Rather than granting child processes broad, long-lived credentials (such as Personal Access Tokens or ambient workstation state), `ghst` provides ephemeral, user-attributed access constrained by an administrative ceiling, a local profile, and repository selection.

```console
# Execute an AI agent with read-only access confined to the current repository
$ ghst run --profile reader -- claude
```

---

## Authority & Delegation Model

Access granted by `ghst` is governed by three intersecting boundaries:

1. **The Authority Ceiling (Dedicated GitHub App)**  
   The GitHub App defines the maximum allowable permissions and accessible repositories. A child token cannot exceed the App's permissions, even if the authorizing human has full administrative rights across the organization.
2. **The Base Token (`ghst login`)**  
   The operator authenticates via GitHub OAuth Device Flow. `ghst` holds an expiring base token and never persists the OAuth refresh token to disk.
3. **The Scoped Profile & Run Token (`ghst run`)**  
   A local profile specifies the exact permissions (`read`, `write`) and repositories required for a specific task. `ghst` mints a short-lived **run token**, injects it into `GH_TOKEN` and `GITHUB_TOKEN` for a single foreground command, and immediately requests revocation when the command exits.

---

## The Delegation Lifecycle

```
┌────────────────────────────────────────────────────────┐
│ 1. Dedicated GitHub App (Administrative Ceiling)       │
│    - Hard upper bound on permissions and repositories  │
│    - Device Flow enabled; Expiring user tokens enabled │
│    - Private keys strictly forbidden                   │
└───────────────────────────┬────────────────────────────┘
                            ▼
┌────────────────────────────────────────────────────────┐
│ 2. Human Authentication (`ghst login`)                 │
│    - OAuth Device Flow verified in trusted browser     │
│    - Expiring base token cached in ~/.cache/ghst/      │
│    - Refresh tokens are never persisted to disk        │
└───────────────────────────┬────────────────────────────┘
                            ▼
┌────────────────────────────────────────────────────────┐
│ 3. Scoped Profile Narrowing                            │
│    - Downscopes permissions (e.g. issues = "read")     │
│    - Downscopes repository target (e.g. repo = "auto") │
└───────────────────────────┬────────────────────────────┘
                            ▼
┌────────────────────────────────────────────────────────┐
│ 4. Foreground Execution & Revocation (`ghst run`)      │
│    - Mints ephemeral run token                         │
│    - Injected via GH_TOKEN and GITHUB_TOKEN            │
│    - Immediate revocation request upon child exit      │
└────────────────────────────────────────────────────────┘
```

---

## Security Boundaries & Process Isolation

`ghst` controls **credential lifetime and authorization scope**; it is not an OS process sandbox.

> [!IMPORTANT]
> `ghst` protects against credential over-privilege and credential retention, but it cannot prevent a running child process from accessing other files on the host system.
>
> When executing less-trusted tools or autonomous AI agents, combine `ghst` with host isolation (such as a [kernel sandbox or MicroVM](recipes/sandboxing.md)) to deny access to:
> - `~/.config/ghst/` and `~/.cache/ghst/`
> - Ambient GitHub CLI tokens (`~/.config/gh/`)
> - SSH keys (`~/.ssh/`)
> - Git credential helpers and global config files

---

## Operational Guarantees & Stability

- **Zero-Storage Refresh Tokens**: `ghst` never writes OAuth refresh tokens to persistent storage. Base tokens expire naturally.
- **Fail Closed**: In pre-1.0 releases, configuration and cache files must match current schemas. Malformed or outdated state immediately fails closed rather than performing automatic migrations or fallback parsing.

---

## Next Steps

- [Required GitHub App Setup](getting-started/github-app.md) — Configure the administrative ceiling before authenticating.
- [Quickstart Guide](getting-started/quickstart.md) — Initialize configuration, authenticate, and run your first tool.
- [Concepts](concepts/index.md) — Learn about permission ceilings, profile inheritance, and token lifetimes.
- [Security Model](security/index.md) — Read the complete threat model, trust boundaries, and credential consequence matrix.

