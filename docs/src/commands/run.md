# `run`

Run one foreground command with a fresh run token.

```text
ghst run [-p <name> | --profile <name>]
         [-r <selection> | --repo <selection>]... -- <command> [arguments...]
```

The selected profile must be scoped. Repository resolution matches `token`, but `run` always mints
a new token; it does not reuse the scoped-token cache.

Before exposure, `ghst` writes a unique private recovery entry in `pending` state. It starts the
command directly without a shell, sets identical `GH_TOKEN` and `GITHUB_TOKEN` values, removes
`GH_ENTERPRISE_TOKEN` and `GITHUB_ENTERPRISE_TOKEN`, records the direct child's PID, and marks the
entry `running`.

On Unix, `SIGINT`, `SIGTERM`, `SIGHUP`, and `SIGQUIT` are forwarded to the direct child. Normal
child exit codes are returned unchanged; a signal maps to `128 + signal`. Once the running state is
durable, cleanup failure does not replace the child's result. Instead, a warning says recovery
state was retained for `ghst prune`.

When the child exits, `ghst` claims the exact run entry, requests remote revocation, and deletes the
entry on success or when GitHub reports the token inactive. Failure leaves it `cleanup_pending`.
Keep the workload in the foreground: cleanup begins when the top-level child exits even if it left
detached descendants running.

This wrapper controls a GitHub credential lease, not filesystem, process, or network access. See
the [sandboxing recipe](../recipes/sandboxing.md).
