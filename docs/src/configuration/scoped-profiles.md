# Scoped profiles

A scoped profile is a local policy for minting a narrower user access token.

```toml
[profile.contributor]
description = "Write code and update pull requests"
source = "developer"
repo = "auto"
permissions = { contents = "write", pull_requests = "write", issues = "write" }
```

Fields:

| Field | Required | Meaning |
|---|---:|---|
| `description` | no | Human-readable text shown by `profiles --verbose` |
| `source` | yes | Name of one app profile with a client secret |
| `repo` | no | `all`, `auto`, one `owner/repository`, or an array of selections; defaults to `auto` |
| `permissions` | yes | Non-empty inline map from GitHub permission name to `read` or `write` |

The source must exist, must be an app profile, and must have a client secret. Chaining scoped
profiles is rejected. Unknown fields, an empty permissions map, unsupported permission levels, and
mixed app/scoped fields are rejected.

The requested permissions are bounded by the source App and authorizing user's access. `ghst`
passes configured permission names to GitHub; a name or level that GitHub does not accept causes
the API request to fail.

Removing a client secret while scoped profiles still reference that app profile makes the whole
configuration invalid. Change profiles and credentials deliberately, then validate with
`ghst edit` or `ghst profiles`.
