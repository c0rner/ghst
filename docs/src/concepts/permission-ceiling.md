# Permission ceiling

No `ghst` profile can create authority that GitHub has not already granted. Understanding access in
`ghst` requires understanding how GitHub layers permissions across the App, the human user, and the
scoped token request.

## 1. The GitHub App as the Absolute Ceiling

The dedicated GitHub App forms the absolute upper bound for all permissions and repository access:

- **App Registration Permissions:** Sets the maximum categories (e.g., `contents`, `pull_requests`,
  `issues`) and maximum levels (`read` or `write`) the App is ever allowed to request.
- **App Installation Repositories:** Sets the exact repository list the App is permitted to touch.

No token issued through the App can ever exceed what the App registration and installation allow.

## 2. The Base Token: App ∩ User Intersection

When a human operator signs in using `ghst login`, GitHub performs OAuth Device Flow and issues a
**base token**. GitHub evaluates effective access as the intersection of the App ceiling and the
authorizing user's personal access:

```text
GitHub App ceiling
        ∩
Authorizing user access
        │
        ▼
Base-token authority
```

- **Permission Intersection:** If the App has `contents: write` but the authorizing user only has
  read access to a repository, the base token receives only `read` access.
- **Repository Intersection:** If the user has access to 50 repositories in an organization, but the
  GitHub App is installed on only 2 repositories, the base token can only access those 2 repositories.

The base token represents the maximum authority available for that App/user pair.

## 3. Scoped Profiles: Narrowing the Base Token

A **scoped profile** applies additional, local restrictions to narrow the base token for specific
tasks or tools:

```text
Base-token authority
        ∩
Scoped-profile request
        │
        ▼
Scoped-token authority
```

- **Narrowing Permissions:** A scoped profile can request a subset of the base token's permissions
  (e.g., `contents = "read"` instead of write).
- **Narrowing Repositories:** A scoped profile can restrict access to explicit repositories or the
  current repository (`repo = "auto"`).
- **Meaning of `repo = "all"`:** Setting `repo = "all"` does *not* grant access to all repositories
  on GitHub or across an organization. It simply asks for no additional repository narrowing beyond
  what the base token already permits (i.e. all repositories within the App installation that the
  user can access).

## 4. The Gotcha: A Scoped Request Can Fail (HTTP 403)

A crucial detail of the GitHub scoped-token model is that permissions and repositories in a scoped
profile are **explicit API requests**, not local fallback filters or permissions grants:

> [!WARNING]
> **HTTP 403 commonly indicates an authority-ceiling mismatch.**
> A permission (e.g. `issues = "write"`) or repository (e.g. `owner/other-repo`) requested outside
> the GitHub App installation or authorizing user's available authority is a likely cause. GitHub's
> response does not identify which boundary caused the rejection, so treat this as a diagnosis to
> verify rather than a guaranteed interpretation of every 403 response.

A scoped profile cannot grant, expand, or repair missing authority. If your command fails with
HTTP 403 during token minting, verify that:

1. The GitHub App registration includes the requested permission.
2. The GitHub App is installed on the target repository.
3. Your authorizing GitHub user account has sufficient permissions on that repository.

See
[Common Failures](../troubleshooting/common-failures.md#scoped-token-request-returns-http-403-forbidden)
for troubleshooting steps, and
[Authority and permission intersection](../security/authority-model.md) for the complete security
analysis.
