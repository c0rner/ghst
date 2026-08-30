# `prune`

Purge expired cache files and recover abandoned foreground runs without disrupting active workloads.

```text
ghst prune
```

---

## What `ghst prune` Does

`prune` inspects all entries in `~/.cache/ghst/` under a cache-wide transaction lock:

| Cache Entry Type | Condition | Action Taken |
|---|---|---|
| **Expired Tokens** (Base, Scoped, Run) | Issuer expiration timestamp has elapsed | Safely deleted locally |
| **Interrupted Runs** (`cleanup_pending`) | Process exited but remote revocation failed | Retries remote revocation with GitHub |
| **Abandoned Runs** (`pending`, `running`) | Neither the recorded wrapper nor child PID is alive | Revokes token remotely and deletes recovery entry |
| **Active Runs** (`running`) | Child process or wrapper PID is currently running | **Skipped** (left untouched) |
| **Uncertain Liveness / Permission Errors** | Unable to verify whether PID is alive | **Skipped** (conservative fail-safe) |
| **Invalid / Incompatible State** | Malformed or unsupported cache schema | **Retained** for inspection (fails closed) |

---

## Exit Codes & Output Report

`prune` always prints a structured summary of actions taken:
- Count of expired local entries deleted
- Count of abandoned run tokens revoked remotely (or confirmed inactive by GitHub)
- Count of active runs skipped
- Count of retained entries and failures

### Exit Status
- **`0` (Success):** All eligible entries were cleanly purged or revoked; no recoverable state was left behind.
- **`1` (Incomplete):** One or more entries could not be cleanly processed (e.g. network failure contacting GitHub, or missing client secret). A warning is printed to stderr.

---

## When to Use `prune` vs. `revoke --all`

- Use **`ghst prune`** for routine recovery after crashes, disconnects, or dead terminal sessions. It will never interrupt running commands.
- Use **[`ghst revoke --all`](revoke.md)** for emergency containment or deliberate cache reset. `revoke --all` is unconditional and will revoke active tokens even if processes are currently using them.

