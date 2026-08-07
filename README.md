# ghst (GitHub Scoped Tokens)

`ghst` (pronounced "ghost") is a local, developer-focused CLI tool that issues short-lived GitHub App user access tokens for humans and AI coding tools. It replaces long-lived personal access credentials with user-attributed, strictly scoped access tokens.

---

## Features & Core Principles

- **Security First & Least Privilege:** Mint derived tokens scoped to specific repositories (`owner/repo` or `auto`) and permission subsets (e.g. `contents=read`, `pull_requests=write`). GitHub's root user token remains the authority ceiling.
- **User Attribution:** All tokens are minted via GitHub App User Access Token flows. Actions taken by AI tools remain attributable to the authorizing human user.
- **Refresh Token Destruction:** Refresh tokens are destroyed immediately in memory upon receipt. Credentials issued to AI tools can never be extended or renewed.
- **Cross-Platform Browser Auth:** Automatically launches host system browser to base authorization URLs (`https://github.com/login/device`), with configurable `--no-browser` options for headless/SSH environments.

---

## Security Model & Risk Architecture

### 1. `client_secret` Storage & Filesystem Security
Root profiles reference configured GitHub Apps. A `client_secret` is optional; it enables derived-token minting and remote revocation.
- **Filesystem Permissions:** `profiles.toml` must be restricted to `0600` permissions (`chmod 600 ~/.config/ghst/profiles.toml`).
- **Access Limits:** Possession of `client_secret` alone does **not** grant repository access or token minting privileges. Token issuance always requires interactive human user authorization via GitHub OAuth Device Flow.

### 2. Phishing Protection & Anti-Phishing Invariants
If a `client_secret` were exposed, an attacker could attempt to initiate OAuth Device Flows. `ghst` enforces explicit mitigations:
- **Interactive Verification Banner:** `ghst` prints a prominent `DEVICE AUTHORIZATION REQUIRED` banner explicitly showing the target GitHub App name. Users are warned to verify the App name before authorizing.
- **Prohibition of Pre-filled Verification URLs:** `ghst` **never** opens or outputs pre-filled verification URLs containing `?user_code=...`. The browser strictly navigates to `https://github.com/login/device`, forcing the user to manually copy and enter the user code. This prevents 1-click phishing attacks.

### 3. One-Off Command Tokens and Sandboxing

`ghst run` always mints a fresh token from a derived profile and launches one command directly,
without a shell. It sets both `GH_TOKEN` and `GITHUB_TOKEN`, removes the GitHub Enterprise token
variables, and preserves all other environment variables and command arguments. The token is
revoked after the command exits. Cleanup never replaces the command's exit result.

The token is recorded in a private recovery entry before the child can use it. If the wrapper or
GitHub fails during cleanup, `ghst prune` retries abandoned tokens; active recorded processes are
skipped conservatively. `ghst run` is a credential-lifetime tool, not a sandbox. Use a kernel
sandbox separately to restrict configuration/cache access and fallback credentials such as GitHub
CLI storage, Git credential helpers, and SSH keys.

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

Root profiles cannot define `repo`: they represent the GitHub App's complete authority ceiling and are cached under `profile|all`. A root token can be printed in text, JSON, or environment format only by calling `ghst token` without `--repo`. Derived profiles may reference only roots with a configured client secret. Removing a secret therefore also requires removing every derived profile that references that root.

A derived profile's `repo` value is its default selection. Repeated CLI `--repo` values replace that default. `all` means “apply no additional repository narrowing”; it never widens the permissions or repositories GitHub allows for the root token. Explicit repositories must use `owner/repository`, and every owner must match the source root profile's `github_app.account`.

### Independent Token Lifetimes

GitHub issues a scoped token as a separate user access token with its own `expires_at`. `ghst` takes this GitHub-issued expiry at face value and only requires the token to remain usable beyond its 30-second safety margin; it does not impose a local maximum lifetime. A scoped token may remain valid after the root token used to mint it has expired or been individually revoked. An expired root may validate an already-cached child but cannot mint a new one.

Root-token expiration or individual revocation must not be treated as revoking its children. `ghst revoke --all` attempts to revoke every cached live root, derived, and run token when its root client secret is available before removing its cache entry. A live secretless root is deleted locally, reported as potentially active remotely, and makes `revoke` return nonzero. See GitHub's [scoped-token endpoint](https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#create-a-scoped-access-token) and [single-token revocation endpoint](https://docs.github.com/en/rest/apps/oauth-applications?apiVersion=2022-11-28#delete-an-app-token).

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

`run` accepts derived profiles only and never reuses the token returned by `ghst token`. After
handoff, a normal child exit is returned unchanged and Unix signal termination maps to
`128 + signal`. Pre-handoff `ghst` failures return `1`. Revocation failures print a redacted warning,
leave the entry in `cleanup_pending`, and still return the child's result. `prune` processes global
recovery explicitly; post-run cleanup targets only that run.

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
