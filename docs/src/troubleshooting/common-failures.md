# Common failures

## No profile specified

**Symptom:** `ghst` errors with `no profile specified`.

**Remedy:**
- Pass an explicit profile flag: `ghst run --profile <name> -- <cmd>`
- Set the environment variable: `export GHST_PROFILE=<name>`
- Configure a default in `profiles.toml`: `default_profile = "<name>"`
- List available profiles with `ghst profiles`.

---

## Configuration is rejected

**Symptom:** `ghst` fails on startup parsing `profiles.toml`.

**Remedy:**
- **Unknown fields or syntax errors:** Only `version = 1` and supported fields are allowed. Malformed files fail closed.
- **Insecure file permissions:** `~/.config/ghst/` must be owned by the user and mode `0700`. `profiles.toml` must be mode `0600` and not a symlink.
- Use `ghst edit` to safely initialize or repair configuration and file permissions.

---

## No valid base token

**Symptom:** `ghst run` reports no valid base token is cached.

**Remedy:**
- Authenticate the source **app profile** (never authenticate a scoped profile directly):
  ```console
  $ ghst login --profile <app-profile-name>
  ```
- An expired base token requires a new Device Flow. Refresh tokens are intentionally never persisted to disk.

---

## Scoped token request returns HTTP 403 Forbidden

**Symptom:** Token minting fails with HTTP 403 from GitHub.

**Remedy:**
A requested permission or repository outside the available authority ceiling is a likely cause,
but a 403 response does not identify the precise policy boundary. Inspect the reported GitHub error
and verify that:

1. The GitHub App registration includes every permission listed in your scoped profile.
2. The GitHub App is installed on the target repository.
3. Your authorizing human GitHub user account has access to the target repository.

---

## Repository resolution fails

**Symptom:** `repo = "auto"` fails to determine the target repository.

**Remedy:**
- Ensure the current working directory is inside a Git repository with a GitHub remote: `git remote get-url origin`.
- Verify the repository owner matches `github_app.account` in the app profile.
- Or override explicitly: `ghst run --profile <name> --repo owner/repo -- <cmd>`.

---

## Device Flow expires or is denied

**Symptom:** `ghst login` exits with an authorization timeout or access denied error.

**Remedy:**
- Re-run `ghst login` and complete the browser verification prompt before the timer expires.
- Verify that **Device Flow** and **Expiring user access tokens** are enabled in your GitHub App settings.
- Ensure the authorizing user clicked "Authorize" and not "Cancel".

---

## Headless or Remote SSH environments

**Symptom:** `ghst login` attempts to launch a GUI browser in a headless shell or container, printing `xdg-open` warnings.

**Remedy:**
- Suppress browser launch on the command line:
  ```console
  $ ghst login --profile <name> --no-browser
  ```
- Or permanently disable automatic browser launching in `profiles.toml`:
  ```toml
  no_browser = true
  ```
- Copy the verification URL (`https://github.com/login/device`) and enter the user code in any trusted browser.

---

## Cache schema or corrupted cache error

**Symptom:** `ghst` rejects entries in `~/.cache/ghst/`.

**Remedy:**
- `ghst` fails closed on malformed, expired, or schema-mismatched cache files and never performs silent migrations.
- Revoke active tokens remotely (via GitHub or a working version of `ghst revoke --all`) before manually removing obsolete cache files.
