# `login`

Authenticate one app profile through GitHub OAuth Device Flow.

```text
ghst login [-p <name> | --profile <name>] [--no-browser]
```

Profile selection follows [the normal precedence](../configuration/index.md). A scoped profile is
rejected with guidance to log in to its source app profile.

If a provenance-compatible base token remains more than 30 seconds from expiry, `login` reuses it
without starting Device Flow. Otherwise it requests a device code, displays GitHub's verification
URL and code, optionally opens the URL, and polls until authorization, denial, or expiry.
`--no-browser` disables automatic opening; global `no_browser = true` does the same.

The operator must manually enter the code and verify the expected App. `ghst` does not use a
prefilled completion URL. Device codes are shown to the operator but never stored.

GitHub must return an expiring base token with a lifetime beyond the 30-second handoff margin.
`ghst` caches the base token and GitHub user name, destroys any refresh token in memory, and prints
the user/profile and expiration time. It never prints the access token from this command.
