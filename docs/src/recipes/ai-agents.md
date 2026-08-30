# AI-agent workflows

Tools and coding agents that honor standard `GH_TOKEN` or `GITHUB_TOKEN` environment variables (such as Claude Code, Aider, Codex, GitHub CLI, etc.) work with `ghst` out of the box without special plugins.

---

## 1. Principle of Least Privilege

Configure a narrow, read-only profile as your default in `profiles.toml`. Only elevate permissions when a specific task requires write access:

```console
# Routine: Run with read-only permissions on the current repository
$ ghst run -- your-agent

# Elevated: Explicitly select a write-enabled profile when creating PRs or editing issues
$ ghst run --profile contributor -- your-agent
```

---

## 2. Command-Line Repository Overrides

You can override which repositories a token can access directly from the command line using `--repo` (or `-r`):

```console
# Restrict token access specifically to 'example-org/service'
$ ghst run --profile reader --repo example-org/service -- your-agent

# Grant access to multiple specific repositories
$ ghst run --profile reader -r example-org/service -r example-org/shared-lib -- your-agent
```

> [!NOTE]
> **Overrides Replace Configured Repositories**  
> Passing `--repo` on the command line **completely replaces** the repository list defined in `profiles.toml` rather than appending to it. This ensures that the exact target scope granted to the agent is explicit and visible in your terminal history and process arguments, with no hidden repositories inherited from configuration.

---

## 3. Passing Agent Arguments (`--`)

`ghst run` executes commands directly without an intermediate shell. Always use the standard `--` argument separator so `ghst` does not confuse the agent's flags with its own:

```console
$ ghst run --profile reader -- your-agent --model claude-3-7-sonnet --verbose
```

---

## 4. Foreground Execution vs. Background Daemons

`ghst run` binds token lifetime to a **single foreground process**:

- **Immediate Revocation:** When the child process terminates, `ghst` immediately requests remote token revocation from GitHub.
- **Do Not Detach/Daemonize:** If an agent launcher forks a background daemon and exits immediately, `ghst` will revoke the token while the background daemon is still running.
- **Detached Workflows:** If you must run a long-lived background service, use `ghst token` to fetch a token, but you become responsible for token storage, lifetime monitoring, and revocation.
