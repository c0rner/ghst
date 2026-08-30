# Multi-repository setups

Many developer workflows and AI coding tools require access to multiple repositories simultaneously (e.g. an application, a shared microservice, and a common utility library).

`ghst` allows profiles to target multiple repositories with automatic deduplication, canonical sorting, and command-line override capabilities.

---

## 1. Multi-Repository Array Configuration

Configure an array of repository strings in `profiles.toml`. You can combine explicit repository names with `"auto"` (which resolves the current Git working tree's `origin`):

```toml
[profile.workspace-reader]
description = "Read the application, shared library, and current repository"
source = "developer"
repo = ["example-org/application", "example-org/shared-library", "auto"]
permissions = { contents = "read", pull_requests = "read" }
```

### Canonical Resolution & Cache Identity

- **Owner Consistency:** Every repository owner in the array must match the `github_app.account` defined in the source app profile.
- **Normalization:** `ghst` resolves `"auto"`, converts names to lowercase, deduplicates entries, and sorts them alphabetically.
- **Cache Identity:** Within one named profile, repository selections that resolve to the same
  canonical set use the same reusable cache slot regardless of their ordering in TOML. Different
  profile names use different slots, and reuse still requires compatible source authority,
  permissions, and base-token provenance.

---

## 2. Dynamic Command-Line Overrides

To target a different set of repositories for a single command invocation, specify repeated `--repo` (or `-r`) flags:

```console
$ ghst run --profile workspace-reader \
    --repo example-org/application \
    --repo example-org/docs -- your-tool
```

> [!NOTE]
> **Overrides Are Non-Additive**  
> Specifying `--repo` on the command line **completely replaces** the repository list defined in the profile. In the example above, the token will grant access *only* to `example-org/application` and `example-org/docs` — it will not include `shared-library` or `auto`.

---

## 3. The `repo = "all"` Scope & Ceiling Constraints

When a task genuinely needs access across all repositories within the GitHub App installation:

```toml
[profile.org-auditor]
description = "Audit issues across all installed repositories"
source = "developer"
repo = "all"
permissions = { issues = "read" }
```

### Constraints on `all`
- **Cannot Be Combined:** `"all"` cannot be mixed with `"auto"` or explicit `owner/repo` entries in an array.
- **Respects the App Ceiling:** `repo = "all"` does *not* grant access to every repository on GitHub or in your organization. It only requests access to all repositories where the dedicated GitHub App is installed and where your authorizing user account has permissions.

---

## Best Practice: Named Profiles vs. Ad-hoc Overrides

For routine tasks with different repository requirements, define distinct **named profiles** in `profiles.toml` rather than typing long `--repo` overrides repeatedly. Named profiles are auditable, version-controllable, and self-documenting.
