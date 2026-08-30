# Authority and permission intersection

GitHub Apps can authenticate in several different identities. `ghst` intentionally uses user
access tokens: their actions are performed on behalf of an accountable user, and GitHub evaluates
both App and user permissions. It never uses installation access tokens.

| `ghst` term | GitHub meaning |
|---|---|
| App profile | Local configuration identifying one GitHub App and target account |
| Base token | Non-scoped GitHub App user access token obtained through Device Flow |
| Scoped profile | Local request for repository and permission restrictions |
| Scoped token | Separate scoped user access token returned by GitHub's scoped-token endpoint |
| Run token | Fresh scoped token whose cleanup lease belongs to one foreground invocation |
| Installation access token | App-attributed credential minted through private-key/JWT authentication; never used by `ghst` |

## The intersection

Effective access is the intersection of five inputs:

| Boundary | What it limits | Who enforces it |
|---|---|---|
| App registration | Permission categories the App may request | GitHub |
| App installation | Accounts and repositories available to the App | GitHub |
| Authorizing user | Operations and repositories available to that user | GitHub |
| Scoped-profile permissions | Permission names and `read`/`write` levels requested for the child | `ghst` request, enforced by GitHub |
| Resolved repository selection | `all` or the explicit repositories requested for the child | `ghst` validation and GitHub |

The first three form the **base-token ceiling**. The last two can only narrow it. For example, App
write permission plus user read permission yields read access, not write. A scoped request for
write cannot repair the user's missing authority. Conversely, a user with broad organization
access receives no access to repositories outside the App installation.

GitHub documents that a user-token request depends on both App and user permissions, while an
installation-token request depends on the App's permissions. See
[Choosing permissions for a GitHub App](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app).

## Meaning of `all`

`repo = "all"` means that `ghst` asks for no additional repository narrowing. It does not mean all
repositories on GitHub, all repositories visible to the user, or all repositories in an
organization. The App installation and user intersection still applies.

Likewise, a permission name in a scoped profile is a request, not a grant. GitHub rejects the
request if it is invalid or exceeds available authority. This is why scoped profiles cannot repair
an unnecessarily broad App: the App remains the maximum authority available to every token created
through it.

## Why installation tokens are excluded

An installation access token is attributed to the App installation rather than to the individual
human authorization. A private-key holder can mint one without Device Flow, and its authorization
does not include the user's permission boundary. That is a valid GitHub App model for servers and
automation, but it contradicts `ghst`'s user-attributed delegation model. The required
no-private-key configuration removes that alternative credential path from the dedicated App.
