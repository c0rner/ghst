# Global fields

The file-level fields are:

| Field | Required | Meaning |
|---|---:|---|
| `version` | yes | Must be the integer `1` |
| `default_profile` | no | Profile used when neither CLI nor environment selects one |
| `no_browser` | no | Boolean; disables automatic browser opening during login |
| `profile` | no | TOML tables keyed by profile name |

Example:

```toml
version = 1
default_profile = "reader"
no_browser = false
```

If set, `default_profile` must name a configured profile. `no_browser` defaults to `false`; the
`login --no-browser` switch also disables browser opening for that invocation.

On Unix, the default directory must be a non-symlink directory owned by the effective user with
mode `0700`. The file must be a regular, single-link file owned by that user with mode `0600`.
Unsafe ownership, link state, or permissions fail closed. `ghst edit` restores private modes after
an editor returns, but it does not turn an unsafe replacement target into a trusted file.

App client secrets are stored in this file when configured. Never commit it, paste it into issue
reports, or make it readable to an AI-agent sandbox.
