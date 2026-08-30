# Required GitHub App setup

Use a dedicated GitHub App for `ghst`. Do not share the App with a server, automation system, or
other integration that needs a private key or a callback-based OAuth flow.

Configure it as follows:

| GitHub App setting | Required value | Security reason |
|---|---|---|
| **Permissions** | Only the repository, organization, and account permissions that `ghst` users need | The App permissions are a platform-enforced ceiling. Scoped profiles can narrow this ceiling but cannot repair an unnecessarily broad installation. |
| **Installation repositories** | Only the repositories that may be accessed through this App | A token cannot access repositories outside the App installation, but `all` in a scoped profile applies no further repository narrowing. |
| **Enable Device Flow** | Enabled | `ghst login` uses only GitHub's Device Flow. GitHub documents this as the flow intended for CLI and headless applications. |
| **Request user authorization (OAuth) during installation** | Disabled | `ghst` does not use install-time or callback-based web authorization. Keep other OAuth workloads on a separate App. |
| **Callback URL** | Empty | Device Flow does not use a redirect URI. An empty callback configuration prevents this dedicated App from also serving a web application flow. |
| **Expire user authorization tokens** / **User-to-server token expiration** | Enabled | GitHub then returns an expiring user access token and a refresh token. `ghst` requires the access-token expiry and destroys the refresh token. |
| **Client secret** | Generate only if scoped profiles or remote revocation are needed | The secret enables scoped-token and revocation endpoints but is not used by Device Flow. It must remain private even though exposure alone has bounded authority. |
| **Private keys** | **None** | A private key can authenticate as the App and mint installation access tokens, bypassing the authorizing-user intersection on which `ghst` relies. |
| **Webhooks** | Disabled | `ghst` does not consume webhooks. A workload that needs them should use a separate App. |

GitHub exposes Device Flow and install-time OAuth as separate settings. “Device Flow only” in this
threat model means that Device Flow is enabled, install-time OAuth is disabled, and no other
callback-based OAuth client shares this App. GitHub notes that the callback URL is ignored when an
App uses Device Flow. See GitHub's guides to [registering a GitHub App](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app),
[modifying its authorization settings](https://docs.github.com/en/apps/maintaining-github-apps/modifying-a-github-app-registration),
and [choosing minimum permissions](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app).

After saving the registration, verify that the **Private keys** list is empty, install the App only
on the intended account and repositories, and copy its client ID into the app profile. Generate a
client secret only when scoped profiles or remote revocation are required, store it in the `0600`
configuration file, and set `github_app.account` to the target account that owns the permitted
repositories. A secretless app profile can perform Device Flow login but cannot mint scoped tokens or
remotely revoke tokens through the App-authenticated endpoints.

## No Private Keys

> A GitHub App used by `ghst` must never have a private key. If the App's **Private keys** list is
> non-empty, it does not satisfy this threat model. Delete every key, and use a different GitHub App
> for any workload that must authenticate as an App installation.

A client secret and a private key are not interchangeable:

- A **client secret** authenticates the App at OAuth application endpoints. The scoped-token
  endpoint still requires an existing non-scoped user access token, and Device Flow still requires
  an explicit human authorization.
- A **private key** signs an App JWT. A holder can use that JWT to request an installation access
  token without a human authorizing a user flow. Unless the request narrows it, that installation
  token receives all permissions and repositories granted to the installation.
- Installation-token authorization depends on the App installation, not on a particular user's
  access. Actions are attributed to the App rather than to the accountable human operator.
- GitHub App private keys do not expire automatically. They remain useful until manually deleted.

GitHub documents that a JWT signed by an App private key can mint an
[installation access token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app),
and explicitly recommends user access tokens for actions performed on behalf of users in its
[GitHub App security guidance](https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/best-practices-for-creating-a-github-app).

## Device Flow safety

Authorize only a Device Flow that you personally started in a trusted terminal and that is still
waiting locally. Manually enter its displayed code at `https://github.com/login/device`, and verify
that GitHub displays the expected dedicated App. Never approve a code delivered through chat,
email, an issue, an AI tool, or another person's terminal.

`ghst` opens only GitHub's verification URI and requires manual code entry; it never presents a
pre-filled `?user_code=...` link.

The [Security model](../security/index.md) explains why each requirement exists, including the
[threat model and trust assumptions](../security/threat-model.md), [authority model](../security/authority-model.md),
[Device Flow phishing boundary](../security/device-flow.md), and [app credentials](../security/app-credentials.md).
