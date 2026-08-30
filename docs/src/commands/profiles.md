# `profiles`

List all configured app and scoped profiles after validating configuration integrity.

```text
ghst profiles [-v | --verbose]
```

---

## Output Modes

### 1. Standard View (`ghst profiles`)
Displays a concise summary of profile names, types (`[app]` or `[scoped]`), descriptions, and an asterisk `* (default)` marking the default profile:

```console
$ ghst profiles
  developer [app] - Developer authority ceiling
* reader [scoped] (default) - Read-only access to repository contents, PRs, and issues
  contributor [scoped] - Write access to code and pull requests
```

### 2. Verbose View (`ghst profiles --verbose`)
Displays detailed capability matrices, target accounts, repository scopes, and requested permission maps:

```console
$ ghst profiles --verbose
Configured Profiles:

  developer [app]
    Account:      example-org
    Repo Scope:   all (app authority)
    Capabilities: base tokens, scoped tokens, remote revocation
    Description:  Developer authority ceiling

* reader [scoped] (default)
    Source:       developer
    Repo Scope:   auto
    Permissions:  contents=read, issues=read, pull_requests=read
    Description:  Read-only access to repository contents, PRs, and issues
```

---

## Security & Privacy Guarantees

- **No Secret Leaks:** `ghst profiles` never outputs client IDs, client secrets, or active token values.
- **Offline Validation:** Profile capabilities are inferred strictly from local configuration structure without making network calls.

