# ghst - GitHub Scoped Tokens

`ghst` (pronounced "ghost") is a local, developer-focused CLI tool that issues short-lived GitHub App user access tokens for humans and AI coding tools. It replaces long-lived personal access credentials with user-attributed, strictly scoped access tokens.

---

## Features & Core Principles

- **Security First & Least Privilege:** Mint derived tokens scoped to specific repositories (`owner/repo` or `auto`) and permission subsets (e.g. `contents=read`, `pull_requests=write`). GitHub's root user token remains the authority ceiling.
- **User Attribution:** All tokens are minted via GitHub App User Access Token flows. Actions taken by AI tools remain attributable to the authorizing human user.
- **Refresh Token Destruction:** Refresh tokens are destroyed immediately in memory upon receipt. Credentials issued to AI tools can never be extended or renewed.
- **Cross-Platform Browser Auth:** Automatically launches host system browser to base authorization URLs (`https://github.com/login/device`), with configurable `--no-browser` options for headless/SSH environments.

---

## Ephemeral Command Execution with `ghst run`

`ghst run` puts a credential lifetime around one foreground command. Each invocation mints a fresh
token from a derived profile, sets `GH_TOKEN` and `GITHUB_TOKEN`, and launches the command directly
without a shell. When the command exits, `ghst` revokes the token and returns the command's exit
result.

This avoids exporting a reusable token into a shell or giving an AI tool access to the broader
authority of a root profile:

```bash
ghst run --profile contributor --repo auto -- codex
```

`ghst run` controls GitHub authority and credential lifetime; it is not a sandbox. Combine it with
a kernel sandbox such as [nono](https://nono.sh/) to also restrict filesystem, network, and host
access:

```bash
ghst run --profile contributor --repo auto -- \
  nono run --allow . -- codex
```

The ordering is deliberate: `ghst` owns the complete foreground invocation, while `nono` confines
the AI tool and its process tree. The sandbox should deny access to `ghst` configuration and cache
files, as well as fallback credentials such as GitHub CLI storage, Git credential helpers, and SSH
keys.

> [!WARNING]
> `ghst run` is not suitable for commands that daemonize, run in the background, or detach their
> sandbox session. The token lease belongs to the top-level command invocation, not to arbitrary
> descendants. When that command exits, `ghst` revokes the token even if a descendant is still
> running. Keep the workload in the foreground; for example, do not use `nono run --detached` here
> or consider using `ghst token` for more control.

Before handing off the token, `ghst` records a private recovery entry. If a crash, power loss, or
GitHub failure prevents immediate cleanup, `ghst prune` retries abandoned run tokens. Active
recorded processes are skipped conservatively.

---

## Security Model & Risk Architecture

### 1. `client_secret` Storage & Filesystem Security
Root profiles reference configured GitHub Apps. A `client_secret` is optional; it enables derived-token minting and remote revocation.
- **Filesystem Permissions:** `profiles.toml` must be restricted to `0600` permissions (`chmod 600 ~/.config/ghst/profiles.toml`).
- **Access Limits:** Possession of `client_secret` alone does **not** grant repository access. Initial user authority requires interactive GitHub Device Flow authorization; creating a scoped token also requires an existing non-scoped user token and can only narrow it.

### 2. Phishing Protection & Anti-Phishing Invariants
OAuth Device Flow uses the public `client_id`, not the `client_secret`, so anyone who knows the App identity can initiate a flow. The user must authorize only a code produced by a `ghst login` invocation they personally started. `ghst` provides explicit mitigations:
- **Interactive Verification Banner:** `ghst` prints a prominent `DEVICE AUTHORIZATION REQUIRED` banner showing the configured target account and user code. Users are warned to verify the expected App on GitHub and the local authorization context before approving it.
- **Prohibition of Pre-filled Verification URLs:** `ghst` **never** opens or outputs pre-filled verification URLs containing `?user_code=...`. The browser strictly navigates to `https://github.com/login/device`, forcing the user to manually copy and enter the user code. This removes a one-click authorization path from `ghst` itself, but cannot protect a user who approves an out-of-bound flow.

> [!IMPORTANT]
> Please take time to read [SECURITY.md](SECURITY.md) before deploying in large scale. 

---

## Configuration (`profiles.toml`)

Configuration is stored at `~/.config/ghst/profiles.toml` (or custom path via `-c`/`--config`).

```toml
version = 1
default_profile = "reader"
# no_browser = true # Optional global toggle

# Root Profiles (Backed directly by GitHub Apps)
[profile.developer]
description = "Full developer privilege ceiling"
github_app.account = "acme-corp"
github_app.client_id = "Iv1.8888888888888888"
github_app.client_secret = "secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Secretless root (Device Flow login and raw root tokens only)
[profile.automation]
github_app.account = "acme-corp"
github_app.client_id = "Iv1.9999999999999999"

# Derived Profiles (Scoped subsets of root profiles)
[profile.reader]
source = "developer"
description = "Read-only access to contents, pull requests, and issues"
repo = "auto"
permissions = { contents = "read", pull_requests = "read", issues = "read" }
```

Profile type is inferred from its fields: roots define `github_app`, while derived profiles define `source`. Profiles cannot mix both shapes or declare a separate `kind` field. Unknown fields are rejected.

Root profiles cannot define `repo`: they represent the GitHub App's complete authority ceiling and are cached under `profile|all`. Derived profiles may reference only roots with a configured client secret.

A derived profile's `repo` value is its default selection. Repeated CLI `--repo` values replace that default. `all` means “apply no additional repository narrowing”; it never widens the permissions or repositories GitHub allows for the source profile. Explicit repositories must use `owner/repository`, and every owner must match the source root profile's `github_app.account`.

> [!TIP]
> See [SECURITY.md](SECURITY.md#permission-ceiling-and-scope-intersection) for details on GitHubs permission model.

#### Common Scopes

Permission | Values | Description
------|--------|------------
actions | read, write | View and manage GitHub Actions workflows, workflow runs, and artifacts.
checks | read, write | View and manage checks on code.
contents | read, write | View and manage contents, commits, branches, downloads, releases, and merges.
issues | read, write | View and manage issues and related comments, assignees, labels, and milestones.
packages | read, write | View and manage packages published to GitHub Packages.
pull_requests | read, write | View and manage pull requests and related comments, assignees, labels, milestones, and merges.
security_events | read, write | View and manage security events like code scanning alerts.

For a full list see `permissions` on GitHub's [scoped-token endpoint](https://docs.github.com/en/rest/apps#create-a-scoped-access-token)

### Independent Token Lifetimes

GitHub issues a derived (scoped) token as a separate user access token with its own `expires_at`. A derived token may remain valid after the root token used to mint it has expired or been individually revoked. An expired root may validate an already-cached child but cannot mint a new one.

Root-token expiration or individual revocation must not be treated as revoking its children. `ghst revoke --all` attempts to revoke every cached live root, derived, and run token when its root client secret is available before removing its cache entry. A live secretless root is deleted locally, reported as potentially active remotely, and makes `revoke` return nonzero. See GitHub's [scoped-token endpoint](https://docs.github.com/en/rest/apps/apps#create-a-scoped-access-token) and [single-token revocation endpoint](https://docs.github.com/en/rest/apps/oauth-applications#delete-an-app-token).

---

## CLI Reference

```bash
# List configured profiles
ghst profiles          # Concise summary
ghst profiles -v       # Detailed profile inspection

# Authenticate a root profile via OAuth Device Flow
ghst login [--profile name] [--no-browser]

# Mint or retrieve a scoped token
ghst token [--profile name] [--repo all|auto|owner/repo]... [--format text|json|env]

# Display active token status
ghst status

# Revoke all cached credentials and remove their local entries
ghst revoke --all

# Run one command with a fresh derived token
ghst run [--profile name] [--repo all|auto|owner/repo]... -- <command> [args...]

# Recover abandoned run tokens and remove issuer-expired entries
ghst prune
```

---

## Development

```bash
# Run tests
cargo test

# Run linter & formatter checks
cargo clippy
cargo fmt -- --check
```

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
