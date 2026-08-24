# ghst - GitHub Scoped Tokens

`ghst` (pronounced "ghost") puts a secure credential lifetime around AI coding agents and
developer CLI tools. Instead of handing a tool a broad, long-lived Personal Access Token (PAT) or
letting it discover reusable credentials on the host, `ghst` gives the tool a short-lived,
user-attributed GitHub token narrowed by the selected profile and repository scope.

```bash
# Run an AI agent with the default derived profile and repository selection.
ghst run -- codex

# Select an explicit least-privilege profile.
ghst run --profile reader -- aider

# Also confine the process with a kernel sandbox.
ghst run -- nono run --allow . -- claude
```

## How it works

1. `ghst login` uses GitHub OAuth Device Flow to obtain an expiring user access token. GitHub
   limits that token to the intersection of the dedicated App installation and the authorizing
   user's access.
2. `ghst run` asks GitHub for a fresh token narrowed to the repositories and permissions in a
   derived profile, then supplies it to the foreground child through `GH_TOKEN` and `GITHUB_TOKEN`.
3. When the child exits, `ghst` requests remote revocation. A private recovery entry lets
   `ghst prune` retry if a crash, power loss, or GitHub failure interrupts cleanup.

GitHub may return a refresh token during login. `ghst` destroys it in memory and never persists or
passes it to a child process, so delegated access cannot be renewed by the recipient.

## Requirements

`ghst` supports Linux and macOS, where it can enforce Unix ownership, file-permission, and
file-descriptor guarantees. It requires a dedicated GitHub App configured with:

- only the permissions and repositories users need;
- Device Flow and expiring user access tokens enabled;
- a client secret when derived profiles or remote revocation are required; and
- **no private keys**.

> [!IMPORTANT]
> The exact App settings are part of the security boundary. Follow the
> [required GitHub App configuration](SECURITY.md#required-github-app-configuration) before logging
> in. In particular, never generate a private key for an App used by `ghst`.

## Installation

### GitHub Releases

Prebuilt archives for macOS and glibc-based Linux (`x86_64` and `aarch64` / Apple Silicon) are
available on [GitHub Releases](https://github.com/c0rner/ghst/releases). Each archive has a matching
`.sha256` file, and each release includes a combined `sha256.sum`. Download the archive and its
checksum before extracting it, then verify them with `sha256sum --check` on Linux or
`shasum --algorithm 256 --check` on macOS.

These checksums detect corruption or a mismatch between files downloaded from the release. Because
the checksums and archives are published together, they do not provide independent authentication
of the release publisher.

### Cargo

With a Rust toolchain installed:

```bash
cargo install --locked ghst
```

This builds the published crate and its locked dependency graph locally. As with other Cargo
installations, the build may execute code from build dependencies and build scripts.

### Shell installer (convenience)

Releases also include a generated `ghst-installer.sh` that selects and downloads the appropriate
prebuilt archive. It verifies the embedded SHA-256 checksum when `sha256sum` is installed, but
warns and continues without verification when that command is unavailable. The installer is
remotely supplied shell code, so use it only if that bootstrap trust model is acceptable. It is
provided as a convenience, not as the recommended installation method.

```bash
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/c0rner/ghst/releases/latest/download/ghst-installer.sh | sh
```

## Configure and run

The default configuration is `~/.config/ghst/profiles.toml`. Create and open a private starter
configuration with:

```bash
ghst edit --init
```

The command creates the directory with mode `0700` and the file atomically with mode `0600`, then
opens the file using `VISUAL`, `EDITOR`, or an available `nano`, `vim`, or `vi`. On editor exit,
`ghst` securely reopens a regular configuration file without following links, restores private
permissions, and rejects a target that cannot be safely opened and identified instead of repairing
it through its path. After a successful editor exit, `ghst` validates the complete configuration.
Edit the starter root profile for the dedicated App and the derived profiles for the authority to
delegate:

```toml
version = 1
default_profile = "reader"

[profile.developer]
description = "Developer authority ceiling"
github_app.account = "acme-corp"
github_app.client_id = "Iv1.8888888888888888"
github_app.client_secret = "secret_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

[profile.reader]
source = "developer"
description = "Read-only repository access"
repo = ["acme-corp/application", "acme-corp/shared-library", "auto"]
permissions = { contents = "read", pull_requests = "read", issues = "read" }
```

Then authenticate the root profile and start the tool:

```bash
ghst login --profile developer
ghst run -- codex
```

During login, authorize only a Device Flow that you personally started in a trusted terminal and
that is still waiting locally. Manually enter the displayed code at
`https://github.com/login/device` and verify that GitHub shows the expected dedicated App. Never
approve a code received through chat, email, an issue, an AI agent, or another person's terminal.

See the repository's [example configuration](profiles.toml) for additional profiles.

### Profiles and repository scope

A root profile identifies the dedicated GitHub App whose installation/user intersection becomes
the authority ceiling. A derived profile is a local scoping recipe: its
`source` names one root, while `repo` and `permissions` describe the narrower token to request.

`repo` accepts one selection as a string or several selections as a TOML array. `auto` resolves the
current Git remote, an explicit `owner/repository` selects that repository, and `all` applies no
additional repository narrowing. For example, a profile can combine stable dependencies with the
current repository:

```toml
repo = ["acme-corp/application", "acme-corp/shared-library", "auto"]
```

After resolving `auto`, `ghst` sorts and deduplicates explicit repositories and requires every
owner to match the source root profile's configured account. `all` cannot be combined with another
selection. When one or more `--repo` options are supplied, they replace the complete configured
selection rather than adding to it; repeated CLI values may still mix explicit repositories and
`auto`. None of these choices can widen the repositories or permissions granted by GitHub to the
App and authorizing user. Choose the narrowest useful default profile, then override it only when a
task genuinely needs a different repository set. The complete authority model is documented under
[Permission Ceiling and Scope Intersection](SECURITY.md#permission-ceiling-and-scope-intersection).

## Common commands

```bash
ghst edit                                  # Edit, secure, and validate the configuration
ghst token --profile reader --format env   # Emit a reusable token as environment assignments
ghst profiles -v                           # Inspect configured profiles
ghst status                                # Inspect cached token status and lifetimes
ghst prune                                 # Retry abandoned-run cleanup and remove expired entries
ghst revoke --all                          # Revoke all locally cached credentials
```

Run `ghst --help` or `ghst <command> --help` for the complete command-line interface.
If you suspect refresh tokens outside the local cache, follow the App-level controls in
[Responding to Credential or Configuration Exposure](SECURITY.md#responding-to-credential-or-configuration-exposure).

## Security boundaries

`ghst` controls GitHub authority and credential lifetime; **it is not a process sandbox**. A
less-trusted process with unrestricted host access may find GitHub CLI credentials, SSH keys,
credential helpers, or `ghst` configuration and cache files. Combine `ghst` with a kernel sandbox
when those resources must be inaccessible:

```bash
ghst run --profile contributor --repo auto -- \
  nono run --allow . -- codex
```

Keep the workload in the foreground. The token lease belongs to the top-level command invocation;
when that command exits, `ghst` requests revocation even if a detached descendant is still
running. See the [FAQ](FAQ.md#can-i-run-background-daemons-with-ghst-run) for detached workloads
and the [sandboxing guidance](SECURITY.md#sandboxing-less-trusted-tools) for the complete host
credential boundary.

## Further reading

- [FAQ](FAQ.md) answers practical questions about alternatives, AI tools, failure recovery, and
  team deployment.
- [Security Architecture & Threat Model](SECURITY.md) defines the required App configuration,
  security assumptions, credential consequences, and incident response.

## Development

```bash
cargo check
cargo clippy
cargo fmt -- --check
cargo test
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
