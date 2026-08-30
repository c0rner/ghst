# `token`

Return a reusable base or scoped token.

```text
ghst token [-p <name> | --profile <name>]
           [-r <selection> | --repo <selection>]...
           [-f <format> | --format <format>]
```

`format` is `text` (the default), `json`, or `env`, case-insensitively. Repository selections are
`all`, `auto`, or `owner/repository`; repeated CLI selections replace the profile's configured
selection.

For an app profile, omit every `--repo`. The command validates and returns the cached base token;
it never starts Device Flow automatically. For a scoped profile, it validates the source base
token and cached scoped-token provenance, then reuses or mints a scoped token. A missing usable
base token produces login guidance.

Exact output shapes are:

```text
<access-token>
```

```sh
export GH_TOKEN='<access-token>' GITHUB_TOKEN='<access-token>'
```

```json
{"expires_at":1785434400,"id":"3a8f1b2","profile":"reader","repo":"example-org/service","token":"<access-token>"}
```

The env format uses POSIX single-quote escaping. JSON is one compact object followed by a newline;
`expires_at` is a Unix timestamp in seconds, `repo` is the canonical scope (`all` or a
comma-separated sorted repository list), and `id` is the cache-slot prefix accepted by
`ghst revoke <id>`.

Every format writes a live credential to stdout. Avoid terminal scrollback, shell tracing,
command substitution visible in diagnostics, shared files, and CI logs. Prefer [`ghst run`](run.md)
when a token is needed by one foreground process.
