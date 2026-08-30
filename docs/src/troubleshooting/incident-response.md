# Credential incident response

If a token, client secret, or host workstation is compromised, follow this containment playbook immediately.

> [!CAUTION]
> **Emergency First Steps**
> 1. **Stop approving Device Flows:** Do not approve any pending device codes on `https://github.com/login/device`.
> 2. **Never post secrets publicly:** Do not share tokens, client secrets, device codes, or raw debug logs in public GitHub issues, chats, or forums.

---

## Containment Escalation Levels

Apply the narrowest containment tier that fully isolates the exposure:

```
┌─────────────────────────────────────────────────────────────┐
│ Level 1: Workstation Containment                            │
│ `ghst revoke --all` (Revokes local base, scoped, run tokens)│
└──────────────────────────────┬──────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Level 2: User Authorization Revocation                      │
│ User revokes App in GitHub Settings -> Authorized Apps      │
└──────────────────────────────┬──────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Level 3: App Installation Suspension                        │
│ Suspend or uninstall App in Organization / Account Settings │
└──────────────────────────────┬──────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Level 4: Global App Kill Switch                             │
│ "Revoke all user tokens" in GitHub App Developer Settings   │
└─────────────────────────────────────────────────────────────┘
```

### Level 1: This Workstation (`ghst revoke --all`)
While the configured client secret remains valid, execute:

```console
$ ghst revoke --all
```

- **Scope:** Selects and attempts remote revocation for all locally known base, scoped, and run tokens.
- **Verification:** Treat any non-zero exit code as incomplete (e.g., due to network interruptions or revoked credentials).
- **Limitation:** Only revokes tokens recorded in the local cache on this machine.

### Level 2: Single User Account
If a specific user's credentials or workstation are compromised:
1. **Revoke App Authorization:** The user navigates to **GitHub Settings → Applications → Authorized GitHub Apps → [Your Dedicated App] → Revoke**.
2. **Revoke Org Access:** If the user account itself is compromised, disable the account or remove it from the organization and repositories.

### Level 3: Single Installation
If an entire repository or organization's access must be halted without affecting other installations:
1. Navigate to **Organization Settings → GitHub Apps** (or **Installed GitHub Apps**).
2. Select **Configure** on the dedicated App.
3. Click **Suspend** (temporary freeze) or **Uninstall** (permanent removal).

### Level 4: Global Kill Switch ("Revoke all user tokens")
If an OAuth Device Flow refresh token was exfiltrated or tokens exist outside local workstation caches, use GitHub's App-wide revocation kill switch:

1. Go to **GitHub Developer settings → GitHub Apps → [Your App]**.
2. Scroll to the **Danger zone** at the bottom of the App settings page.
3. Click **"Revoke all user tokens"**.

> [!WARNING]
> **Break-Glass Emergency Action**  
> The **"Revoke all user tokens"** button immediately invalidates **all** active user access tokens and refresh tokens across all users and installations for that App.
>
> Every user will be required to re-authenticate with `ghst login`. Verify in audit logs or test tokens to confirm that previous credentials no longer function. (See [GitHub Community Discussion #173651](https://github.com/orgs/community/discussions/173651)).

---

## Specific Credential Compromises

### Client Secret Compromised
- **Action:** Go to the GitHub App settings page, generate a new client secret, update `profiles.toml`, and delete the old secret.
- **Security Reality:** Rotating a client secret is necessary, but **it does not revoke existing user access tokens or refresh tokens** (Device Flow refresh does not require the client secret). Always combine client secret rotation with Level 1 or Level 4 token revocation.

### Private Key Discovered
- **Action:** **Delete the private key immediately.**
- **Security Reality:** A private key allows generating installation access tokens that completely bypass the human authorizing-user boundary. Review all installation activity and audit logs, suspend or uninstall the App during investigation, and re-establish the required **no-private-keys** policy before resuming use.

---

## Reporting Vulnerabilities & Account Compromise

- **`ghst` Vulnerabilities:** Report security vulnerabilities privately using the repository's [GitHub Security Advisory form](https://github.com/c0rner/ghst/security/advisories/new).
- **Active Account Takeover:** Follow GitHub's official account and organization incident procedures and contact [GitHub Support](https://support.github.com/).
- **Threat Reference:** See [Credential consequences and lifetimes](../security/credential-consequences.md) for full risk analysis of each credential combination.

