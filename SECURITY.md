# Security Architecture & Threat Model

`ghst` is a credential isolation and scoped token minting tool designed to issue short-lived GitHub App user access tokens to humans and AI coding agents. Because `ghst` handles sensitive access credentials, security is its primary design goal.

---

## Security Invariants

All architectural decisions in `ghst` strictly enforce five core security invariants:

1. **`ghst` Never Exposes Refresh Tokens to Downstream Tools**
   Refresh tokens received during authentication are discarded immediately in memory. They
   are never cached, logged, transmitted through the proxy, or returned to any caller. Tokens
   delivered through `ghst` cannot be refreshed by the tools that receive them. Derived tokens
   also cannot be reset or used to create further scoped tokens.
2. **Every Token is User-Attributed**  
   Tokens are minted via GitHub App User Access Token flows. Actions taken by AI tools remain attributable to the authorizing human user.
3. **Every Derived Token is a Strict Subset**  
   Child tokens minted via scoping endpoints can only narrow permissions and repository boundaries relative to the root token.
4. **No Operation Can Increase Privilege**  
   Privilege escalation is impossible. A requested profile or token scope can never exceed the intersection of user permissions and root app boundaries.
5. **Every Token Has an Explicit, Bounded Lifetime**  
   Root and derived tokens have separate GitHub-issued lifetimes (maximum 8 hours).

---

## Trusted Operator Assumption

`ghst` protects a trusted human operator's GitHub authority from less-trusted processes
running on the same machine. It does not attempt to prevent the operator themselves from
bypassing local profiles or directly invoking the GitHub API.

**Trusted:** The human operating `ghst`, the host-side `ghst proxy`, the root-profile
configuration, and the GitHub App registration.

**Less trusted:** AI coding agents, agent-invoked shell commands, build tools and repository
scripts, sandboxed subprocesses, and any tokens exposed inside an agent environment.

A developer who uses the public `client_id` to run the Device Flow independently — bypassing
`ghst` — is the trusted operator choosing to step outside their
own protection. This is analogous to a developer running `gh auth token` and handing the
result directly to an agent. No local tool can prevent a workstation owner from
intentionally dismantling their own security boundary while they control all the underlying
credentials.

> [!NOTE]
> **Enterprise applicability:** Local `ghst` is appropriate where developers are already
> trusted with GitHub repository access and the organization's goal is to constrain
> authority delegated to AI tools. It is not an insider-resistant policy boundary — the
> workstation owner controls the local configuration and OAuth client credentials. A
> deployment that must constrain the operator themselves requires a centrally managed
> credential broker.

---

## Permission Ceiling & Scope Intersection

Every token is constrained by two layers enforced by GitHub's API. Derived tokens add a third layer enforced by `ghst`.

### Layer 1 — GitHub App Installation Grant (Absolute Ceiling)

A GitHub App is granted a specific set of permissions when an organization administrator installs it. This installation grant is the **absolute permission ceiling**. Any token produced through that App — regardless of what a profile or caller requests — can never carry permissions beyond what the administrator approved. This constraint is enforced by GitHub's API; `ghst` cannot override it.

### Layer 2 — Authenticating User's Repository Access

GitHub intersects a GitHub App user token's authority with the **authorizing user's own access rights**. When `ghst` requests a derived token through the scoped token endpoint (`POST /applications/{client_id}/token/scoped`), the same user boundary continues to apply. The [GitHub API documentation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-with-a-github-app-on-behalf-of-a-user) states explicitly:

> *"The app can only access resources that the user has access to. If a user does not have access to a repository, your app cannot access that repository on their behalf even if the app is installed on that repository… A token cannot grant additional access capabilities to a user."*

This is a platform-level guarantee from GitHub, enforced independently of any `ghst` configuration.

### Layer 3 — Profile Declaration (Local Narrowing)

On top of both GitHub-enforced layers, `ghst` further narrows the token request to the permission subset and repository selection declared in the derived profile. Profile configuration is validated locally before the API call is made and can only narrow — never widen — what is requested.

### Effective Scope

Root and derived tokens have different effective-scope formulas:

```
Root scope = GitHub App installation grant
           ∩ Authenticating user's repository access       (GitHub-enforced)

Derived scope = Root scope
              ∩ Profile-declared permission and repo subset
```

Even a misconfigured or compromised profile cannot produce a token that exceeds either GitHub-enforced ceiling.

---

## Client Secret Deployment Modes

Each root profile may contain a client secret or omit it. Neither mode is universally safer; they place the least-privilege boundary in different locations.

| Mode | Security boundary | Capabilities | Tradeoffs |
| --- | --- | --- | --- |
| **Secret-bearing root** | GitHub App grant, user access, and local derived profiles | Repository and permission narrowing; remote token revocation | The secret must be isolated. A party holding both it and a live non-scoped root token can request a scoped token with an independent lifetime. |
| **Secretless root** | GitHub App grant and user access | Device Flow login and bounded root-token delivery | No derived profiles and no App-authenticated remote revocation. Live tokens removed locally may remain active until GitHub invalidates them or they are manually revoked. |

An enterprise that does not want to distribute client secrets can provide multiple narrowly configured GitHub Apps for different roles or repository sets and distribute only their public client IDs. This moves policy enforcement into GitHub App installation grants. It increases App administration and loses the flexibility of local derived profiles, but avoids placing App client secrets on developer workstations.

Where derived profiles are needed, the strongest architecture is to keep the client secret and root token behind `ghst proxy` and expose only derived tokens to less-trusted tools.

Removing a client secret also requires removing every derived profile that references that root; configuration loading otherwise fails closed.

---

## Filesystem & Local Storage Security

> [!WARNING]
> Configuration files may store sensitive `client_secret` credentials for your GitHub Apps. Restrict access permissions on configuration and cache directories.

- **Configuration Directory:** `~/.config/ghst/`  
  Configuration file `~/.config/ghst/profiles.toml` must be set to `0600` permissions (`chmod 600 ~/.config/ghst/profiles.toml`).
- **Runtime Cache Directory:** `~/.cache/ghst/`  
  Directory permissions are enforced at `0700`.
- **Cache Files & Lock Files:** `~/.cache/ghst/*.json` and `~/.cache/ghst/.cache.lock`  
  File permissions are strictly enforced at `0600`.
- **Atomic Operations & Symlink Protection:**  
  Cache entries are written atomically using tempfiles (`0600`) and directory syncing. Hard links and symlinks are explicitly rejected.
- **Platform Support:**  
  Token caching requires Unix private permission semantics. Non-Unix platforms fail closed rather than storing tokens insecurely.

---

## Device Flow and Anti-Phishing Preparations

GitHub's Device Flow is a public-client flow: anyone who knows the App's public client ID can initiate it. If a user authorizes an attacker's flow, the initiating party receives both an eight-hour access token and a refresh token. For Device-Flow credentials, GitHub permits refresh with the client ID and refresh token; the client secret is not required. A successful out-of-band authorization can therefore provide renewable access even when no client secret is distributed. See GitHub's documentation for [generating](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app) and [refreshing](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens) user access tokens.

`ghst` destroys every refresh token it receives, but it cannot control a Device Flow initiated by another party. It provides explicit prompts to reduce accidental authorization:

> [!IMPORTANT]
> Always verify that the GitHub App name displayed on `https://github.com/login/device` matches your expected App account before authorizing.

1. **Interactive Verification Banner:** `ghst` displays a prominent `DEVICE AUTHORIZATION REQUIRED` banner in stdout/stderr displaying the target GitHub App account and user code.
2. **Prohibition of Pre-filled URLs:** `ghst` **never** opens or outputs pre-filled verification URLs containing `?user_code=...`. The browser navigates strictly to `https://github.com/login/device`, requiring the user to manually copy and enter the code. This removes a one-click authorization path but cannot prevent a user from authorizing a convincing out-of-band request.

---

## Threat Model & Risk Matrix

| Risk Vector | Assessment | Mitigation Architecture |
| --- | --- | --- |
| **Out-of-Band Device Flow** | High; interactive | The public client ID is sufficient to initiate Device Flow. If the user authorizes it, the initiator receives the refresh token and can renew without a client secret. Users must treat unexpected device codes as phishing and verify the context as well as the App identity. |
| **`client_secret` Exposure Alone** | Bounded | The secret alone grants no repository access and is not needed for Device Flow. Restrict `profiles.toml`, rotate exposed secrets, and prefer secretless profiles where their App installation grants are sufficiently narrow. |
| **Root Token + Client Secret Exposure** | Extended but not widened | Together they can request a scoped token with an independent lifetime. The result cannot exceed the root authority, and a scoped token cannot create another scoped token. Isolate both credentials behind the proxy when using derived profiles. |
| **Refresh Token Exposure** | Renewable access | A Device-Flow refresh token can be exchanged using the public client ID without the client secret. `ghst` destroys refresh tokens immediately and never persists or returns them. |
| **Trusted Operator Bypass** | Out of scope in local mode | A developer who controls the machine can extract credentials, bypass `ghst`, or use another GitHub authentication path. This is accepted risk under the trusted-operator model. Insider-resistant enforcement requires a managed broker. See [Trusted Operator Assumption](#trusted-operator-assumption). |
| **Derived Token Exfiltration** | Capped impact | The token is bounded by its repository scope, permission subset, and fixed GitHub-issued lifetime. It has no refresh token and cannot mint another token. |
| **Root Token Exfiltration** | Capped unless paired with another credential | The token is bounded by the App/user intersection and its remaining lifetime. Without a refresh token it cannot use the refresh grant; pairing it with the client secret permits scoped-token creation. |
| **Untrusted AI Agent Sandbox Escape** | High Impact | Host IPC Proxy Mode (`ghst proxy`) isolates secrets behind a Unix domain socket (`GHST_SOCKET`), completely denying sandboxed AI agents access to `~/.config/ghst/`. |

---

## Credential Isolation & Sandboxing (`ghst proxy`)

When running untrusted AI tools inside kernel sandboxes (e.g., `nono`, `landlock`, or container namespaces):

```
                        HOST SYSTEM (Trusted Zone)
+-------------------------------------------------------------------+
|   `ghst proxy` Daemon                                            |
|   - Reads ~/.config/ghst/profiles.toml (0600)                    |
|   - Listens on Unix Domain Socket (/tmp/ghst.sock, 0600)         |
|   - Enforces host privilege ceilings (--allow-profile)            |
+-------------------------------------------------------------------+
                                 ^
                                 | Local IPC Boundary (Unix Socket)
                                 v
+-------------------------------------------------------------------+
|                `nono` KERNEL SANDBOX (Restricted Zone)            |
|   - DENIED access to ~/.config/ghst/ and ~/.cache/ghst/         |
|   - ALLOWED connection to /tmp/ghst.sock                         |
|   - `ghst token --profile reader` receives scoped token over IPC  |
+-------------------------------------------------------------------+
```

- Sandboxed processes are **denied read/write access** to `~/.config/ghst/` and `~/.cache/ghst/`.
- The host user runs `ghst proxy` in the trusted zone, serving scoped tokens over IPC without exposing refresh tokens, `client_secret`s, or parent credentials.

---

## Reporting a Security Vulnerability

If you discover a potential security vulnerability in `ghst`, please do not report it in public GitHub issues. Please report security concerns privately to the maintainers or via repository security advisories.
