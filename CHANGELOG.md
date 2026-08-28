# Changelog

All notable changes to `ghst` are documented in this file.

## [Unreleased]

### Breaking

- Adopt app/scoped terminology for profiles and base/scoped terminology for tokens throughout the CLI, cache, diagnostics, configuration model, and documentation. This is a breaking cache change: reusable entries now use schema version 5 and the `base` and `scoped` kind tags. Unsupported or malformed cache artifacts fail closed.

## [0.5.2] - 2026-08-26

### Added

- Show cache slot IDs in `ghst status` and accept `ghst revoke <id>` to revoke one cached credential ([#46]).
- Display child process ID and executed command line in `ghst status` output for running sessions ([#44]).

### Fixed

- Evict cached base token on permanent GitHub authorization rejection (HTTP 401/404) during scoped-token minting ([#43]).
- Display token expiry timestamps in the system local timezone (with UTC fallback) and normalize base token expiry to whole-second precision ([#42]).

## [0.5.1] - 2026-08-25

### Added

- Support multiple repositories in scoped profiles via TOML arrays and CLI overrides ([#39]).
- Add actionable debug and trace logging across token acquisition, cache lookups, refresh flows, and child process execution ([#38]).
- Add `ghst config edit` command to securely edit configuration files with editor discovery, descriptor permission validation, and nonblocking validation before saving ([#34]).

### Fixed

- Export both `GH_TOKEN` and `GITHUB_TOKEN` from `ghst token --format env`, so an
  existing higher-precedence `GH_TOKEN` cannot override the scoped token
  ([#29]).

## [0.5.0] - 2026-08-21

- First public release.

[Unreleased]: https://github.com/c0rner/ghst/compare/v0.5.2...HEAD
[0.5.2]: https://github.com/c0rner/ghst/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/c0rner/ghst/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/c0rner/ghst/releases/tag/v0.5.0
[#29]: https://github.com/c0rner/ghst/pull/29
[#34]: https://github.com/c0rner/ghst/pull/34
[#38]: https://github.com/c0rner/ghst/pull/38
[#39]: https://github.com/c0rner/ghst/pull/39
[#42]: https://github.com/c0rner/ghst/pull/42
[#43]: https://github.com/c0rner/ghst/pull/43
[#44]: https://github.com/c0rner/ghst/pull/44
[#46]: https://github.com/c0rner/ghst/pull/46
