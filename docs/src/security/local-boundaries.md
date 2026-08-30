# Local state and process isolation

`ghst` strictly controls file modes, metadata, and transaction locks on the local filesystem, while separating credential persistence from process isolation boundaries.

---

## Local Filesystem Permission Model

`ghst` enforces strict Unix permissions to prevent unauthorized access from other user accounts on multi-user systems:

| Path | Required Ownership & Mode | Invariants & Protection |
|---|---|---|
| **Config Directory** (`~/.config/ghst/`) | User-owned, directory, **`0700`** | Non-symlink; private directory traversal |
| **Config File** (`profiles.toml`) | User-owned, regular file, **`0600`** | Single hard-link; contains optional client secrets |
| **Cache Directory** (`~/.cache/ghst/`) | User-owned, directory, **`0700`** | Non-symlink; holds private token slots |
| **Cache Entries & Lock** (`*.json`, `.lock`) | User-owned, regular files, **`0600`** | Atomic writes; symlinks and FIFOs rejected |

### Storage Integrity & Fail-Closed Behavior
- **No Symlink Traversal:** `ghst` verifies path descriptors and refuses to open or follow symlinks in configuration and cache paths.
- **Atomic Operations:** Cache replacements write to temporary files before atomic rename, preventing torn reads under concurrency.
- **Fail Closed:** Insecure file permissions, ownership mismatches, or malformed data cause commands to error immediately rather than falling back to unverified defaults.

> [!WARNING]
> **Unix Permissions Do Not Isolate Processes with the Same UID**  
> Mode `0600` and advisory file locks coordinate cooperating `ghst` processes and block *other* user accounts on the machine. However, any process running under your same user account (such as an unconfined AI agent) can still read your files.

---

## Child Process Exposure & Secret Redaction

- **Deliberate Outputs:** `ghst token` writes tokens to `stdout` for caller scripting. `ghst run` injects tokens into `GH_TOKEN` and `GITHUB_TOKEN` for the child process.
- **Zero-Leak Logging:** `ghst` structured diagnostics (`tracing` on `stderr`) never log access tokens, client secrets, device codes, or refresh tokens.
- **External Disclosure Vectors:** Redaction inside `ghst` cannot prevent external leaks outside its control, such as shell tracing (`set -x`), CI console logs, process environment inspection (`/proc/$PID/environ`), or crash reports.

---

## Why Kernel Sandboxing Is Required

Because an unconfined child process running as your user ID has ambient access to your home directory, it could potentially discover:
- `ghst` configuration and cached base tokens (`~/.config/ghst/`, `~/.cache/ghst/`)
- Ambient GitHub CLI credentials (`~/.config/gh/`)
- Git credential helpers and stored HTTPS tokens
- SSH private keys and active agent sockets (`~/.ssh/`, `$SSH_AUTH_SOCK`)
- Statically configured API keys in `.env` files

```console
# Correct pattern: ghst outside, sandbox inside
$ ghst run --profile contributor --repo auto -- \
    nono run --allow . -- your-agent
```

For operational sandboxing guides covering kernel sandboxes, containers, and MicroVMs, see the [sandboxing recipe](../recipes/sandboxing.md).

