# Credential and sandbox boundaries

`ghst` constrains the **authority and lifetime** of the GitHub token it issues. It is **not** a process sandbox.

---

## 1. Child Environment & Ambient Credentials

When `ghst run` executes a foreground command:
- It injects the fresh run token into `GH_TOKEN` and `GITHUB_TOKEN`.
- It unsets GitHub Enterprise variables (`GH_ENTERPRISE_TOKEN`, `GITHUB_ENTERPRISE_TOKEN`).
- The rest of the host environment, filesystem, and user credentials remain accessible unless restricted by a separate isolation tool.

Without an operating system sandbox, an unconfined child process running under your user account can potentially discover:

| Ambient Asset | Risk if Unrestricted |
|---|---|
| **GitHub CLI State** (`~/.config/gh/`) | Access to broad, personal OAuth tokens stored by `gh` |
| **Git Credential Helpers** | Ambient credentials for HTTPS Git operations |
| **SSH Keys & Agents** (`~/.ssh/`, `$SSH_AUTH_SOCK`) | Persistent credentials for Git operations or remote server access |
| **Local `ghst` State** (`~/.config/ghst/`, `~/.cache/ghst/`) | Cached base tokens or client secrets |
| **Workspace Secrets** (`.env`, build configs) | Statically configured tokens or API keys |

---

## 2. Layering with Kernel Sandboxes

For semi-autonomous tools and AI coding agents, enforce defense-in-depth by placing a kernel sandbox inside the `ghst` execution boundary:

```console
# ghst mints the scoped token; nono confines local filesystem access
$ ghst run --profile reader -- nono run --allow . -- claude
```

### Essential Sandbox Rules
- **Deny credential stores:** Explicitly block read access to `~/.config/ghst/`, `~/.cache/ghst/`, `~/.config/gh/`, and `~/.ssh/`.
- **Restrict filesystem access:** Grant access only to the target repository workspace.
- **Isolate environment variables:** Avoid passing sensitive host environment variables to child processes.

> [!NOTE]
> Logging out of other GitHub tools reduces accidental fallback if a token expires, but it is **not a substitute** for OS-level process isolation.

---

## 3. Local Storage Protections & Limits

`ghst` hardens its local state against accidental exposure and race conditions:
- **Strict File Modes:** The configuration directory is private (`0700`) and configuration files are created with `0600` permissions.
- **Safe Persistence:** Persistent cache entries use atomic file writes, reject symlinks, and refuse to open FIFOs or unsafe paths.
- **Fail Closed:** Insecure file modes, ownership mismatches, or malformed schemas immediately trigger errors.

> [!WARNING]
> **Unix permissions are not a boundary against the same user.**  
> File permissions (`0600`) and advisory file locks protect against *other* local user accounts, but they cannot prevent another process running with your same UID from reading your files. True process isolation requires a kernel sandbox.

---

## 4. Secret Redaction & Exposure Vectors

`ghst` follows strict zero-leak logging principles:
- **Redacted Logging:** `ghst` never writes access tokens, client secrets, device codes, or refresh tokens to `tracing` logs (which default to `WARN` on `stderr`).
- **No Refresh Token Persistence:** Refresh tokens returned during Device Flow are destroyed immediately.

### Intentional Output Vectors
`ghst` deliberately exposes credentials only through two dedicated channels:
1. `ghst token` prints the requested token directly to `stdout` for caller consumption.
2. `ghst run` injects the run token directly into the child process environment (`GH_TOKEN`, `GITHUB_TOKEN`).

Be aware of external disclosure paths outside `ghst`'s control, such as shell history, CI logs, process environment inspection (`/proc/$PID/environ`), and child crash reports.

---

## Related Security Analysis

- [Threat model and trust assumptions](../security/threat-model.md) — Trust boundaries, phishing resistance, and operator responsibilities.
- [Local state and process isolation](../security/local-boundaries.md) — Technical invariants for directory permissions and cache locks.
- [Process sandboxing & MicroVMs](../recipes/sandboxing.md) — Practical guide to pairing `ghst` with OS sandboxing and MicroVMs.

