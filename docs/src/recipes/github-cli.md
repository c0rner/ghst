# GitHub CLI with temporary credentials

A normal `gh auth login` stores a GitHub CLI OAuth credential locally. If you prefer to keep
GitHub CLI signed out, `ghst` can instead supply a GitHub-issued, typically eight-hour App user
access token to a trusted interactive shell. The actual lifetime is set by GitHub and reported by
`ghst`.

The workflow creates two deliberate trust levels:

- The human-operated shell receives an expiring base token for ordinary `gh` commands.
- Each less-trusted foreground command receives a fresh token narrowed to selected repositories
  and permissions.

## 1. Remove GitHub CLI's stored authentication

```console
$ gh auth logout --hostname github.com
```

[`gh auth logout`](https://cli.github.com/manual/gh_auth_logout) removes the selected account's
authentication configuration locally; it does not revoke the OAuth token remotely. Revoke the
GitHub CLI OAuth authorization separately in GitHub settings if the old token must also become
invalid.

## 2. Authenticate the base App profile

```console
$ ghst login --profile base-profile
```

Complete Device Flow from a trusted terminal and browser. `ghst` caches the expiring base token
and immediately destroys the refresh token. This step does not export a credential into the shell.

## 3. Export the base token into a trusted shell

```console
$ eval "$(ghst token --profile base-profile --format env)"
```

Keep the command substitution quoted. The `env` format emits shell-quoted exports for both
`GH_TOKEN` and `GITHUB_TOKEN`. GitHub CLI gives these variables precedence over stored
credentials, so ordinary commands now use the base App token:

```console
$ gh auth status
$ gh repo view example-org/application
```

The token remains bounded by the intersection of the App installation and the authorizing user's
access. It remains in the shell environment until it is removed, although GitHub will reject it
after its issuer-provided expiry:

```console
$ unset GH_TOKEN GITHUB_TOKEN
```

## 4. Run a child command with narrower authority

Use a scoped profile whenever a tool should receive less authority than the trusted shell:

```console
$ ghst run --profile scoped-profile -- some-command
```

`ghst run` replaces `GH_TOKEN` and `GITHUB_TOKEN` in the direct child's environment with a fresh
scoped token. The parent shell retains its base token, and `ghst` requests revocation of the run
token when the command exits. This preserves the normal GitHub CLI experience for the human while
preventing the child from inheriting the base token through those environment variables.
