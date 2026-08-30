# App profiles

An app profile defines the GitHub authority ceiling and the credentials used at OAuth application
endpoints.

```toml
[profile.developer]
description = "Developer authority ceiling"
github_app.account = "example-org"
github_app.client_id = "<github-app-client-id>"
github_app.client_secret = "<github-app-client-secret>"
```

Fields:

| Field | Required | Meaning |
|---|---:|---|
| `description` | no | Human-readable text shown by `profiles --verbose` |
| `github_app.account` | yes | Target GitHub organization or user account |
| `github_app.client_id` | yes | Dedicated GitHub App client ID |
| `github_app.client_secret` | no | Enables scoped-token creation and remote revocation |

The account and client ID must not be empty. A configured client secret must not be empty or only
whitespace. Unknown fields are rejected.

Profile type is inferred from its fields: `github_app` makes this an app profile. Do not add a
`kind` field, and do not mix `source`, `repo`, or `permissions` into an app profile.

A secretless app profile can authenticate and cache a base token. `ghst token --profile <app>` can
return that base token, but the profile cannot be the source of a scoped profile. Live tokens from
a secretless profile cannot be remotely revoked by `ghst`; cleanup deletes the local copy and
reports that the credential may remain active until GitHub expires it.

See [Required GitHub App setup](../getting-started/github-app.md) before using either shape.
