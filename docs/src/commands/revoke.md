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

## Remote Revocation & Fallback Behavior

`ghst` executes revocation under an exclusive cache-wide lock:

- **Remote API Revocation:** If the source app profile and client secret are available, `ghst` contacts GitHub's OAuth application revocation endpoint. If GitHub reports the token was already inactive, it is treated as successfully revoked.
- **Local Fallback (Missing Secret or Mismatched Authority):** If no client secret is configured or authority cannot be validated, `ghst` deletes the local cache entry, reports that the token may remain live remotely until its natural expiration, and returns exit status 1 for incomplete cleanup.
- **Expired Tokens:** Tokens that have already expired locally are deleted immediately without making redundant network requests.

---

## Summary Report & Exit Status

`revoke` prints a structured accounting of results:
- **Remotely revoked / confirmed inactive**
- **Deleted locally only (remote status uncertain)**
- **Retained entries (failures)**

### Exit Codes
- **`0`:** The report contains no failures. Every live token requiring remote cleanup was revoked or confirmed inactive, and any eligible local-only deletion completed.
- **`1`:** The report contains one or more failures. This includes a live token deleted only locally because its client secret is unavailable or its authority cannot be validated, as well as network, permission, and filesystem failures.
