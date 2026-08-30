# Credential consequences and lifetimes

Credential risk depends on what material is exposed together. The client ID is public; every other
credential must be treated as sensitive.

| Material held by an attacker | Consequence |
|---|---|
| Public client ID only | Can initiate Device Flow and attempt to socially engineer a user into approving it |
| Client secret only | Can authenticate the OAuth application at applicable endpoints, but has no user or installation authority for repository APIs |
| Live base token only | Can act within the App/user intersection until revoked or expired |
| Client secret plus live base token | Can mint independently expiring scoped user tokens, never broader than the base-token ceiling |
| Scoped token | Can act within its repository/permission scope until revoked or expired |
| Run token | Has the same bearer-token risk as a scoped token; `ghst` additionally attempts revocation when its foreground lease ends |
| Device Flow refresh token | Can rotate into a new user access token and refresh token without the client secret |
| Private key | Can sign App JWTs and mint installation access tokens without a user intersection |
| App administration access | Can change permissions, installations, OAuth settings and secrets, or generate a private key |

## Issuer-defined lifetimes

`ghst` never invents or extends a token lifetime. It requires GitHub to return `expires_in` for a
base token and a valid RFC 3339 `expires_at` for scoped and run tokens. A newly issued token must be
more than 30 seconds from expiry before `ghst` hands it to a caller.

GitHub currently documents an eight-hour user access token and a six-month refresh token when
expiring GitHub App user tokens are enabled. Successful refresh rotates both credentials; six
months is therefore the lifetime of one unused refresh token, not a guaranteed maximum lifetime
for an authorization that is continuously refreshed. The implementation relies on the lifetime
returned by GitHub rather than hard-coding those documented durations. See
[Refreshing user access tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens).

## Independent tokens

A scoped token is a separate GitHub user access token with its own expiry. Expiring or revoking its
source base token is not assumed to revoke an already-created scoped or run token. Consequently:

- a cached scoped token may remain valid after the base token expires;
- revoking only base-token cache slots is not complete incident cleanup;
- deleting a local cache entry does not revoke its remote token; and
- `ghst revoke --all` must select every locally known base, scoped, and run token when full local
  cleanup is required.

`ghst` stores base and reusable scoped tokens in private cache entries. A run token is briefly
stored in a private recovery entry because remote cleanup cannot be retried after a crash without
the token being revoked. Refresh tokens, device codes, and authorization codes are never persisted.

## Residual risk after delegation

Any process receiving a token can copy and exfiltrate it. Revocation at child exit reduces its
useful lifetime but cannot retract actions already performed, guarantee instantaneous remote
invalidation, or prevent use before GitHub processes revocation. The permission intersection,
issuer expiry, sandbox boundary, and cleanup mechanisms work together; none is sufficient alone.
