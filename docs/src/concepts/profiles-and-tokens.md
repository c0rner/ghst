# Profiles and token lifetimes

## Profiles

An **app profile** names a GitHub App client ID and target account. Its cached credential is a
**base token**, obtained through OAuth Device Flow. A secretless app profile supports login and
base-token output only.

A **scoped profile** names one app profile as its `source`, plus repositories and permissions to
request. It cannot source another scoped profile, and its app profile must have a client secret.

## Tokens

| Token | How it is obtained | Stored? | Used for |
|---|---|---|---|
| Base token | Device Flow for an app profile | Yes | App-profile output and minting narrower tokens |
| Scoped token | Scoped-token API for a scoped profile | Yes | Reusable `ghst token` output |
| Run token | Fresh scoped-token API request | Recovery entry only | One `ghst run` child |
| Refresh token | May accompany Device Flow response | **Never** | Destroyed immediately; never used |

Base, scoped, and run token lifetimes come from GitHub. A base response must contain a usable
`expires_in`; scoped and run responses must contain a valid RFC 3339 `expires_at`. `ghst` rejects a
new token that is not more than 30 seconds from expiry and never synthesizes a lifetime.

A scoped or run token is a separate user access token with an independent expiry. It may remain
live after its source base token expires or is revoked. Removing a local cache file is not remote
revocation.

## Reuse and renewal

`ghst token` reuses a provenance-compatible cached token while safe. Scoped tokens enter a
10-minute proactive renewal window. If a usable base token is available, `ghst` mints and
atomically stores a replacement, then revokes the displaced token. If the base token cannot mint a
replacement, a matching scoped token may still be returned until it reaches the 30-second handoff
margin.

Changing the source app authority, repository selection, permissions, or parent base-token
generation invalidates scoped cache reuse. Only current cache schemas are accepted; unsupported,
malformed, or insecure entries are retained and rejected rather than silently deleted or treated
as misses.

`ghst run` never reuses a scoped token. It creates a distinct recovery entry before handing the
fresh run token to a child and deletes that entry after successful cleanup.

See [Credential consequences and lifetimes](../security/credential-consequences.md) for the impact
of exposing each token type or combining a base token with App credentials.
