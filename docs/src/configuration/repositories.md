# Repository selection and resolution

Scoped profiles restrict token access to specific repositories. `ghst` supports single repository targets, arrays, dynamic resolution via Git (`"auto"`), and full App-wide scope (`"all"`).

---

## Configuration Syntax

| Target Format | Example in TOML | Meaning & Behavior |
|---|---|---|
| **Explicit Repository** | `repo = "org/service"` | Restricts token to the named repository |
| **Current Git Origin** | `repo = "auto"` *(default)* | Resolves the repository from local Git `origin` |
| **Multi-Repo Array** | `repo = ["org/app", "auto"]` | Grants access to both `org/app` and the current repo |
| **All App Repositories** | `repo = "all"` | No repository narrowing beyond the App installation ceiling |

---

## How `"auto"` Resolves Git Remotes

When `"auto"` is evaluated, `ghst` traverses the current directory and its parent folders to locate a Git repository, queries Git for the `origin` remote, and parses the GitHub repository name.

### Supported Remote URL Formats
| Git Remote Format | Example URL | Resolved Target |
|---|---|---|
| **HTTPS** | `https://github.com/org/repo.git` | `org/repo` |
| **SCP-style SSH** | `git@github.com:org/repo.git` | `org/repo` |
| **SSH URL** | `ssh://git@github.com/org/repo.git` | `org/repo` |

> [!NOTE]
> **Git Rewrite Rules Honored**  
> Because `ghst` resolves the remote URL through Git before parsing, URL rewrite rules (e.g. `url."git@github.com:".insteadOf "https://github.com/"`) in your global or local `.gitconfig` are automatically respected.
>
> Non-GitHub remotes, missing `origin` remotes, or unparseable URLs fail closed with a descriptive error.

---

## Validation & Canonicalization Rules

1. **Owner Matching:** Every repository owner must case-insensitively match the `github_app.account` configured in the source app profile.
2. **Character Set:** Repository owners allow ASCII letters, digits, and `-`. Repository names allow letters, digits, `-`, `_`, and `.`.
3. **Canonical Sorting:** Repository names are normalized to lowercase, deduplicated, and sorted alphabetically. This ensures consistent cache identities across profiles.
4. **The `"all"` Constraint:** `"all"` cannot be combined with `"auto"` or explicit repositories.

---

## Command-Line Overrides

Passing `--repo` (or `-r`) flags on the command line **completely replaces** the repository selection defined in the configuration file:

```console
# Overrides any configured repo in the profile and grants access only to service-a and service-b
$ ghst token --profile reader \
    --repo example-org/service-a \
    --repo example-org/service-b
```

