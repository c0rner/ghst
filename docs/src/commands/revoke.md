# `revoke`

Revoke individual cached credentials by status ID, or unconditionally revoke all locally known credentials.

```text
ghst revoke <id>
ghst revoke --all
```

---

## Command Modes

You must specify exactly one revocation target:

### 1. Targeted Single-Token Revocation (`ghst revoke <id>`)
Revokes the credential currently occupying the specified cache slot:

```console
# Revoke a single token identified by its status ID
$ ghst revoke 3a8f1b2
```

- `<id>` must be a 7-to-64 character hexadecimal prefix copied from [`ghst status`](status.md).
- Ambiguous or non-existent prefixes fail immediately without modifying cache state.

### 2. Cache-Wide Unconditional Revocation (`ghst revoke --all`)
Selects and revokes **every** locally known base, scoped, and run token:

```console
$ ghst revoke --all
```

> [!WARNING]
> **Revoking Base Tokens Alone Is Incomplete**  
> Because scoped tokens are independent user access tokens with separate lifecycles, revoking only a base token does **not** invalidate already-minted scoped or run tokens.
>
> During a security incident or when resetting credentials, always run `ghst revoke --all` to ensure every child token is submitted for remote revocation.

---

## Revocation Lifecycle & Concurrency

`ghst` executes revocation across three distinct phases, ensuring the cache lock is never held during remote network calls:

1. **Phase A: Snapshot & Epoch Advance (Locked):**
   Under an exclusive cache lock, `ghst` inspects matching cache entries and advances the cache issuance epoch. Advancing the epoch invalidates any in-flight token issuance or renewal that began before revocation started. Valid entries and malformed/unsupported files are classified into a snapshot before releasing the lock.
2. **Phase B: Remote API Revocation (Lockless):**
   With the cache lock released, `ghst` contacts GitHub's OAuth application revocation endpoint concurrently or sequentially for each live credential:
   - **Active Tokens:** If the token has more than the 30-second handoff safety margin remaining and valid app credentials (client ID and secret) are available, `ghst` requests remote deletion from GitHub. If GitHub reports HTTP 404 (already inactive), this is treated as successfully revoked.
   - **Near-Expiry & Expired Tokens:** Tokens already expired or within the 30-second handoff margin (`expires_at <= now + 30s`) skip the remote API call and proceed directly to local cleanup.
   - **Local Fallback (Missing Secret or Mismatched Authority):** If no client secret is configured or authority cannot be validated against current configuration, `ghst` marks the record for local-only deletion, noting that the token may remain live remotely until its natural expiration.
3. **Phase C: Conditional Exact Local Deletion (Locked):**
   Under a brief lock per record, `ghst` compares the on-disk file with the Phase A snapshot:
   - If the file matches exactly, it is removed from the cache.
   - If the file was concurrently replaced (e.g. by a newer token minted under the new epoch), the replacement is preserved intact, and a failure is reported.
   - If remote revocation failed (e.g., due to a network or server error), the cached record is retained for retry.

### Retention of Malformed & Invalid Files
Malformed JSON, inconsistent metadata, or unsupported schema files are **never** silently deleted during revocation. They fail closed, are retained on disk for operator inspection, and are reported as failures in the summary report.

---

## Summary Report & Exit Status

`revoke` prints a structured accounting of results:
- **Remotely revoked / confirmed inactive:** Tokens successfully revoked via GitHub's API or confirmed already inactive (HTTP 404).
- **Deleted locally only (remote status uncertain):** Live tokens whose local files were removed, but remote revocation could not be performed due to missing secrets, mismatched authority, or near-expiry handoff margins.
- **Retained entries (failures):** Files left on disk due to remote API errors, malformed/unsupported formats, or concurrent record replacement.

### Exit Codes
- **`0`:** The report contains no failures. Every live token requiring remote cleanup was revoked or confirmed inactive, and any eligible local deletion completed cleanly.
- **`1`:** The report contains one or more failures. This includes malformed or unsupported cache files retained on disk, live tokens deleted only locally due to missing credentials or mismatched authority, remote API errors, filesystem I/O errors, or concurrent record replacement during exact deletion.
