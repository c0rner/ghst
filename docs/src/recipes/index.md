# Recipes

These recipes compose supported commands without changing their security boundaries:

- [AI-agent workflows](ai-agents.md) use a fresh foreground lease.
- [GitHub CLI with temporary credentials](github-cli.md) uses an expiring base token for a trusted
  shell and scoped run tokens for child commands.
- [Process sandboxing & MicroVMs](sandboxing.md) blocks fallback access to host credentials.
- [Multi-repository setups](multi-repository.md) define and override repository sets.

Use placeholders for accounts, repositories, and credentials when adapting examples for shared
documentation or issue reports.
