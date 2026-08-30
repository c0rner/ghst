# Client secrets and private keys

A GitHub App client secret and private key are both sensitive, but they authenticate different
things and have very different consequences.

## Client secret

The client secret authenticates the OAuth application at endpoints used to create scoped user
tokens and revoke individual tokens. It is not used to start or complete `ghst` Device Flow.

Under the required App configuration, possession of the client secret **alone** does not represent
a user or App installation, does not grant repository API access, and cannot mint an installation
access token. Creating a scoped user token additionally requires a live non-scoped user access
token; the result cannot exceed that token's App/user authority.

This is a bounded-consequence claim, not permission to disclose the secret. Store it only in the
private configuration file, deny it to less-trusted processes, rotate it after exposure, and
investigate whether it was exposed together with a base token or other authorization material.

## Private key

A private key signs a GitHub App JWT. A JWT can authenticate as the App and request an installation
access token without a human Device Flow. Unless narrowed at issuance, that token receives the
installation's permissions and repository access, without the authorizing-user intersection.

Private keys also do not expire automatically; they remain valid until manually deleted. GitHub's
[private-key documentation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps)
describes their use for App JWT and installation-token authentication.

> A GitHub App used by `ghst` must have **no private keys**. If the App's Private keys list is
> non-empty, it is outside this threat model. Delete every key and use a separate GitHub App for
> any server or automation workload that requires App installation authentication.

## Why a dedicated App is required

Using a dedicated GitHub App solely for `ghst` is essential for auditability, maintaining an uncompromised trust chain, and strict permission hygiene:

- **Auditability and Attribution:** When an App is dedicated exclusively to `ghst`, security logs and GitHub audit events (`integration.*`) have unambiguous provenance. Administrators know with certainty that any activity associated with the App originates from interactive, human-authorized `ghst` sessions rather than background jobs or automated server integrations.
- **Preventing Permission Scope Creep:** Multi-use or shared Apps are vulnerable to scope creep. If a shared App is granted elevated permissions (such as `administration: write`, `secrets`, or `workflows: write`) for a server bot or CI service, those permissions immediately raise the ceiling for *all* `ghst` tokens. Users or AI agents could then mint tokens with permissions never intended for interactive developer delegation, breaking the trust chain.
- **Eliminating Alternative Authentication Vectors:** Reusing an App that serves web applications or webhook consumers introduces redirect URLs, install-time OAuth flows, and potential private keys into the trust boundary. A dedicated App disables webhooks and install-time OAuth, keeps the callback URL empty, and operates purely through Device Flow.
- **Containing Incident Blast Radius:** If credentials are exposed or token revocation is necessary, suspending the App or triggering emergency token revocation affects only `ghst` CLI workflows, without disrupting production infrastructure, server automations, or unrelated web services.

The complete required settings and their operational setup are listed under
[Required GitHub App setup](../getting-started/github-app.md).

