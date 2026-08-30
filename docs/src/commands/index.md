# Commands

The top-level syntax is:

```text
ghst [-c <path> | --config <path>] <command> [options]
```

Commands are `edit`, `login`, `token`, `profiles`, `status`, `run`, `prune`, and `revoke`. Run
`ghst --help` or `ghst <command> --help` for generated help.

Except for `run`, success returns exit status 0 and a command error prints `Error: ...` to stderr
and returns 1. `run` returns its foreground child's exit status after handoff; on Unix, a child
signal becomes `128 + signal`. A `run` failure before successful handoff returns 1.

Diagnostics use `tracing` on stderr. `RUST_LOG` controls filtering and defaults to `WARN`.
Machine-readable token output is stdout-only, but it is intentionally secret. Do not combine
stdout and stderr into logs that others can read.
