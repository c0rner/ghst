# Cleanup and recovery

`ghst` provides built-in mechanisms to recover abandoned tokens, handle unexpected crashes, and perform safe cache cleanup.

---

## 1. Interrupted Runs & Crash Recovery (`ghst prune`)

If a child process crashes, the machine loses power, or a network failure prevents immediate token revocation, `ghst` retains private recovery state in `~/.cache/ghst/`.

To recover and clean up abandoned tokens:

```console
$ ghst prune
```

### How `ghst prune` Works
- **Retries Revocation:** Automatically attempts remote revocation for unexpired runs left in `cleanup_pending` state.
- **Deletes Expired State:** Safely purges issuer-expired base, scoped, and run cache files locally.
- **Protects Active Workloads:** Inspects recorded PIDs and skips any runs whose wrapper or child processes are still alive. If process liveness is uncertain or permissions prevent verification, `prune` errs on the side of caution and leaves the entry intact.
- **Reports Incomplete Cleanup:** Returns exit code `0` only when all eligible entries are cleaned up. A non-zero exit code indicates that some recovery state could not be cleaned and was retained for a future retry.

---

## 2. Full Routine Cleanup & Pre-Upgrade (`ghst revoke --all`)

Before performing software upgrades or resetting a development environment, unconditionally revoke all locally cached tokens:

```console
# 1. Inspect current cache entries and lease statuses
$ ghst status

# 2. Unconditionally revoke and purge all cached credentials
$ ghst revoke --all
```

> [!IMPORTANT]
> **Keep Client Secret Configured During Revocation**  
> `ghst` requires the configured GitHub App client secret to perform remote token revocation. If the client secret is removed before running `ghst revoke --all`, `ghst` can only delete the local cache files, reports incomplete cleanup with exit status 1, and warns that the tokens may remain active remotely until their natural expiration.

---

## 3. Why Manual Cache Deletion Is Dangerous

> [!CAUTION]
> **Never run `rm -rf ~/.cache/ghst` as a first response.**  
>
> Manually deleting cache files from disk:
> 1. **Erases Token Copies Needed for Remote Revocation:** Without the cached token material, `ghst` cannot contact GitHub to revoke the active credential.
> 2. **Destroys Recovery Metadata:** Erases the PID and process state needed to determine whether background tasks are still running.
> 3. **Leaves Remote Tokens Active:** The tokens will remain fully functional and authorized on GitHub until their issuer lifetime expires.
>
> Always run `ghst revoke --all` or `ghst prune` first. Only delete residual cache files manually if a format is completely obsolete and remote tokens have already been revoked.
