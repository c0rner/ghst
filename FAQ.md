# Frequently Asked Questions (FAQ)

This document answers common questions regarding `ghst`'s security architecture, usage with AI coding tools, enterprise deployments, and credential isolation practices.

---

## 🧭 General & Motivation

### What problem does `ghst` solve?
Modern AI coding tools (such as Claude Code, Codex, Aider, OpenCode, and Cursor) often require GitHub access to read issues, inspect code, create branches, or open pull requests. Typically, developers hand these tools broad Personal Access Tokens (PATs) or rely on ambient GitHub CLI credentials (`gh auth login`).

If an autonomous tool hallucinates, executes a malicious prompt injection, or runs a rogue script, an overprivileged credential can compromise private repositories or entire GitHub organizations. `ghst` addresses this by minting short-lived, least-privilege tokens narrowed to the repositories and permissions selected by a derived profile. With `repo = "auto"`, that repository selection resolves from the current Git remote. For `ghst run`, the token is tied to the foreground invocation and remote revocation is requested when the command exits.

### Why not just use GitHub Fine-Grained Personal Access Tokens (PATs)?
Fine-grained PATs improve repository scoping, but they do not solve the automated developer workflow problem:
1. **No process lifecycle binding:** A fine-grained PAT cannot be minted on the fly by a CLI launcher and automatically submitted for revocation when the child process exits or receives `SIGINT` (`Ctrl+C`).
2. **Minimum 1-day expiration:** GitHub's web interface enforces a minimum 1-day lifetime for fine-grained PATs. They cannot be set to expire in minutes or hours.
3. **Manual management overhead:** Developers must manually generate, copy, paste, and rotate tokens through the GitHub web UI.

`ghst` automates short-lived scoping directly in your terminal without manual web clicks.

### How is `ghst` different from GitHub Actions OIDC / Workload Identity Federation?
Workload Identity Federation and GitHub Actions OIDC tokens are designed for automated CI/CD runners and cloud environments (AWS, GCP, Azure). They are not built for interactive local developer workstations running desktop AI coding agents. `ghst` brings ephemeral, user-attributed, scoped credential leases to local development machines.

---

## 🛡️ Security & Threat Model

### Is `ghst` a process sandbox?
**No.** `ghst` manages **GitHub authority and credential lifetime**; it is not a host process sandbox.

If an untrusted child process has unrestricted filesystem access, it could inspect local files or environment variables on the machine. Pair `ghst` with an OS kernel sandbox (such as [`nono`](https://nono.sh/), Linux Landlock / Bubblewrap, or macOS Seatbelt) to restrict its access to host resources:

```bash
# ghst scopes GitHub authority; nono confines the local process
ghst run --profile contributor --repo auto -- \
  nono run --allow . -- claude
```

### Why does `profiles.toml` store a `client_secret`? Is that safe?
Under `ghst`'s required App configuration, possession of the `client_secret` alone does **not grant repository access** and **cannot mint installation tokens**.

Here is why:
- The GitHub App configuration **strictly forbids private keys**.
- Minting a scoped token requires **both** the client secret and an **active, human-authorized user access token** acquired via interactive Device Flow.
- Device Flow requires explicit human authorization on GitHub.
- The `client_secret` is only used to access GitHub's App-authenticated endpoints (the scoped-token endpoint and remote revocation endpoint).

The configuration file must be protected with `0600` permissions inside a `0700` directory (`~/.config/ghst/`).

See [Why Client-Secret Exposure Is Bounded](SECURITY.md#why-client-secret-exposure-is-bounded) for the exact boundary and the consequences when the secret is combined with other credentials.

### Why are GitHub App Private Keys strictly forbidden?
A GitHub App **private key** can sign App JWTs and mint *installation access tokens*. Installation tokens act with the full permissions of the App installation, bypass the authorizing user's permissions, and do not attribute actions to an accountable human.

`ghst` operates exclusively with human-authorized *User Access Tokens* (UATs) via Device Flow to preserve user attribution and enforce least-privilege intersections.

See [No Private Keys](SECURITY.md#no-private-keys) for the required App configuration and rationale.

### What happens to OAuth refresh tokens?
GitHub issues a refresh token alongside expiring user access tokens during Device Flow. **`ghst` destroys refresh tokens in memory after parsing and never persists them to disk.**

This ensures that credentials issued to local tools cannot be silently renewed or extended beyond their initial lease.

### How does `ghst` prevent OAuth Device Flow phishing?
Anyone who knows a public GitHub App `client_id` can initiate a Device Flow. An attacker could attempt to trick a user into approving an unauthorized device code.

`ghst` mitigates this by:
1. **Never opening pre-filled URLs:** `ghst` never opens or prints URLs with `?user_code=...`. The browser is strictly directed to `https://github.com/login/device`.
2. **Explicit Verification Banners:** `ghst` prints a prominent terminal banner displaying the expected target account and one-time code, prompting the user to verify the context before authorizing.

The [Device Flow and Human Authorization](SECURITY.md#device-flow-and-human-authorization) section defines the complete approval procedure and threat boundary.

---

## 🤖 AI Agents & CLI Tooling

### Which tools work with `ghst`?
Tools that honor the standard GitHub authentication environment variables (`GH_TOKEN` or `GITHUB_TOKEN`) work without a `ghst`-specific integration. This includes:
- AI coding tools: Claude Code, Codex, Aider, OpenCode, Cursor CLI, etc.
- Developer CLI tools: GitHub CLI (`gh`), `git-credential-manager`, custom scripts, and build tools.

### What happens if my AI agent crashes or is killed with `Ctrl+C` (`SIGINT`)?
`ghst run` handles termination signals (`SIGINT`, `SIGTERM`, `SIGHUP`) and requests revocation of the active run token before exiting. If remote cleanup cannot complete, the private recovery entry remains available for a later `ghst prune` retry.

### What if my machine loses power or loses network connectivity during a run?
Before handing a token to the child process, `ghst` writes a private recovery entry in `~/.cache/ghst/`. If a crash or power loss prevents immediate remote revocation, running:

```bash
ghst prune
```

will identify abandoned run leases and revoke them with GitHub once network connectivity is restored.

### Can I run background daemons with `ghst run`?
**No.** `ghst run` is designed for foreground process invocations. When the launcher command finishes, `ghst` requests revocation of the token on GitHub. If you launch a detached daemon (e.g. `nono run --detached`), it should not rely on that token remaining available after the parent exits. For long-running or detached workloads, use `ghst token` and manage the token lifecycle manually.

---

## 🏢 Enterprise & Team Deployments

### Can an enterprise security team deploy a shared GitHub App?
**Yes.** An organization admin can register a single dedicated GitHub App at the organization level with an approved permissions ceiling. The admin distributes the App's `client_id` (and optionally `client_secret`) to developers via standard workstation configuration profiles (`profiles.toml`).

Each developer still performs their own `ghst login` using their individual GitHub account, ensuring all actions in audit logs remain attributable to that specific engineer.

### What if our security policy prohibits distributing `client_secret` to developers?
You can use a **Secretless Multi-App Architecture**:
1. Org admins register separate GitHub Apps for different roles (e.g., `acme-ghst-reader` with read-only permissions, and `acme-ghst-writer` with pull request permissions).
2. Developers configure these as secretless root profiles in `profiles.toml` using only `client_id` (no `client_secret` required).
3. Developers log in to the desired profile (`ghst login --profile reader`).

While secretless profiles cannot dynamically derive finer-grained sub-tokens or invoke App-authenticated remote revocation endpoints, they still provide expiring (~8 hour) user access tokens bound to the specific App's permission boundary without requiring any secret on developer disks.

### Does `ghst` send telemetry or talk to third-party servers?
**No.** `ghst` does not collect telemetry or use a project-operated service. Its network operations communicate directly with GitHub's REST and OAuth endpoints (`api.github.com` and `github.com`); it has no metrics collector or proxy relay.

---

## 🧼 Credential Hygiene & Best Practices

### Should I log out of GitHub CLI (`gh auth logout`)?
**Yes, this is strongly recommended.**

Many AI coding agents and git helpers check for existing ambient credentials on your machine (such as `~/.config/gh/hosts.yml`, Git credential helpers, or SSH keys) if an environment token lacks permissions. If broad credentials exist on disk, an agent running without a sandbox might fall back to them.

**Recommended Daily Workflow:**
1. Log out of ambient GitHub CLI sessions:
   ```bash
   gh auth logout
   ```
2. Authenticate with `ghst` at the start of your workday:
   ```bash
   ghst login --profile developer
   ```
   *(This gives you an ~8-hour human-authorized root token ceiling).*
3. Run your AI tools inside ephemeral leases:
   ```bash
   ghst run --profile reader -- aider
   ghst run --repo auto -- claude
   ```
4. Block access to host SSH keys and dotfiles by combining `ghst` with a sandbox (e.g., [`nono`](https://nono.sh/)).
5. At the end of the day or when switching contexts, clean up all cached tokens:
   ```bash
   ghst revoke --all
   ```
