# Troubleshooting

Start with [`ghst status`](../commands/status.md) for local state and
[`ghst profiles --verbose`](../commands/profiles.md) for the validated policy. Neither command
contacts GitHub.

Set `RUST_LOG=debug` for more decision-path diagnostics:

```console
$ RUST_LOG=debug ghst token --profile reader --repo example-org/service
```

Diagnostics go to stderr. `ghst` redacts access tokens, client secrets, device codes, refresh
tokens, and authorization headers from its own structured values, but always review output before
sharing it. Never share the stdout of `ghst token`.

Continue with [common failures](common-failures.md), [cleanup and recovery](cleanup.md), or the
[credential incident procedure](incident-response.md).
