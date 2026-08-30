# `status`

Inspect locally cached tokens and lease states without making network requests.

```text
ghst status
```

---

## Example Output

```console
$ ghst status
Cached token(s):
* reader [scoped]
    Permissions: contents=read, pull_requests=read
    ID:          3a8f1b2
    Lifetime:    Usable
    Repo Scope:  example-org/service
    Expires:     2026-08-30 23:59:00 UTC (in 2 hours)

  developer [app]
    ID:          9c7e4a1
    Lifetime:    Usable
    Repo Scope:  all (app authority)
    Expires:     2026-08-31 02:00:00 UTC (in 4 hours)
```

---

## Token Lifecycle States

`status` evaluates each token's local validity and expiration against the current clock:

| Lifetime Status | Meaning | Operational Action |
|---|---|---|
| **`Usable`** | Token is valid and more than 30 seconds from expiration | Safe to use for commands or minting |
| **`Expiring`** | Token is within the 30-second handoff window | `ghst` will mint a fresh token or request login |
| **`Expired`** | Token lifetime has elapsed | Safe to clean up with `ghst prune` |
| **`Invalid`** | Malformed or schema-mismatched cache file | Retained for audit; requires investigation |

### Run Token States
For active or recently terminated `ghst run` sessions, `status` additionally reports:
- **`Pending`**: Run token minted and awaiting process handoff.
- **`Running`**: Foreground process is currently executing (displays child PID and executed command).
- **`Cleanup pending`**: Command exited but network revocation was interrupted; retained for `ghst prune`.

---

## Understanding Cache Slot IDs

- **Hexadecimal Prefixes:** The `ID` shown in the output (e.g. `3a8f1b2`) is an abbreviated, unique prefix of the cache key.
- **Targeted Revocation:** You can pass this ID directly to `ghst revoke <id>` to revoke that specific token.
- **Slot Identity:** An ID identifies a profile and repository scope slot rather than a token generation. If a token is proactively renewed, the ID remains the handle for the new token occupying that slot.

---

## Offline Guarantees & Privacy

- **Zero Network Traffic:** `ghst status` operates entirely offline by inspecting local cache descriptors.
- **No Secret Printing:** Token bearer strings and client secrets are never printed to stdout or logs.
- **Independent Lifetimes:** A scoped token may appear `Usable` even if its parent base token has expired, because GitHub treats issued user access tokens as separate credentials.
