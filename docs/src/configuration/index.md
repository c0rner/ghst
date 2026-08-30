# Configuration

`ghst` uses TOML configuration schema version 1. The default file is
`profiles.toml` under the platform's `ghst` user configuration directory (normally
`~/.config/ghst/profiles.toml` on Linux).

Configuration path precedence is:

1. the global `--config <path>` or `-c <path>` option;
2. `GHST_CONFIG`;
3. the platform default.

For example, the global option comes before the command:

```console
$ ghst --config ./profiles.toml profiles --verbose
```

Profile-name precedence for `login`, `token`, and `run` is:

1. `--profile <name>` or `-p <name>`;
2. a non-empty, trimmed `GHST_PROFILE` value;
3. `default_profile` in the configuration.

If none supplies a name, the command fails. A supplied name must exist and be a supported profile
kind for the command.

Unknown fields and mixed profile shapes are rejected. Only schema version 1 is supported; there is
no fallback parser or migration.

See the repository's [`profiles.toml`](https://github.com/c0rner/ghst/blob/main/profiles.toml) for a
complete placeholder example.
