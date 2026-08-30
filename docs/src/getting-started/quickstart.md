# Quickstart

Create and open a starter configuration:

```console
$ ghst edit --init
```

Replace its placeholders with your dedicated App's target account, client ID, and client secret.
Keep a narrow scoped profile as the default:

```toml
version = 1
default_profile = "reader"

[profile.developer]
description = "Developer authority ceiling"
github_app.account = "example-org"
github_app.client_id = "<github-app-client-id>"
github_app.client_secret = "<github-app-client-secret>"

[profile.reader]
description = "Read-only access to the current repository"
source = "developer"
repo = "auto"
permissions = { contents = "read", pull_requests = "read", issues = "read" }
```

Authenticate the app profile, not the scoped profile:

```console
$ ghst login --profile developer
```

Complete the Device Flow in a trusted browser. Then run a foreground tool with a fresh token:

```console
$ ghst run --profile reader -- your-tool
```

`auto` resolves the current Git repository's GitHub `origin`. The child receives the same fresh
run token in `GH_TOKEN` and `GITHUB_TOKEN`. When it exits, `ghst` requests revocation and returns
the child's exit code.

Inspect the setup and cached state with:

```console
$ ghst profiles --verbose
$ ghst status
```

For an AI agent or other less-trusted command, continue with the
[sandboxing recipe](../recipes/sandboxing.md).
