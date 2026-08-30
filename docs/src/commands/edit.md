# `edit`

Safely open, initialize, repair file permissions, and validate `profiles.toml`.

```text
ghst edit [--init]
```

---

## Usage & Workflows

### 1. Initialize a New Configuration (`--init`)
If no configuration file exists, `--init` safely creates `~/.config/ghst/profiles.toml` (with private `0700`/`0600` permissions) populated with a commented starter template, then launches your editor:

```console
$ ghst edit --init
```

If the file already exists, `--init` opens the existing file without overwriting it.

### 2. Edit Existing Configuration
Opens your active configuration file in your preferred text editor:

```console
$ ghst edit
```

---

## Editor Selection & Security Invariants

`ghst` selects the editor using the following precedence:
1. `$VISUAL` environment variable
2. `$EDITOR` environment variable
3. The first available executable among `nano`, `vim`, or `vi` on `$PATH`

### Automatic Permission Repair & Validation
When the editor process exits:
- **Private Permission Restoration:** `ghst` immediately restores directory mode `0700` and file mode `0600`.
- **Atomic Validation:** `ghst` re-reads the file from disk and parses the entire TOML configuration.
- **Fail-Closed Feedback:** If the syntax is invalid, unknown fields exist, or permission chains are broken, `edit` prints the exact validation error and exits with code `1`.
- **Success Confirmation:** On valid configuration, `edit` prints `Configuration is valid.` and exits `0`.

---

## Custom Configuration Paths

You can pass the global `--config` option to edit an alternate configuration file:

```console
$ ghst --config ./custom-profiles.toml edit --init
```

