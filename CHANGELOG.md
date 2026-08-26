# Changelog

All notable changes to `ghst` are documented in this file.

## [Unreleased]

### Added

- Show cache slot IDs in `ghst status` and accept `ghst revoke <id>` to revoke one cached credential.

## [0.5.1] - 2026-08-25

### Added

- Support multiple repositories in derived profiles via TOML arrays and CLI overrides ([#39]).
- Add actionable debug and trace logging across token acquisition, cache lookups, refresh flows, and child process execution ([#38]).
- Add `ghst config edit` command to securely edit configuration files with editor discovery, descriptor permission validation, and nonblocking validation before saving ([#34]).

### Fixed

- Export both `GH_TOKEN` and `GITHUB_TOKEN` from `ghst token --format env`, so an
  existing higher-precedence `GH_TOKEN` cannot override the scoped token
  ([#29]).

## [0.5.0] - 2026-08-21

- First public release.

[Unreleased]: https://github.com/c0rner/ghst/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/c0rner/ghst/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/c0rner/ghst/releases/tag/v0.5.0
[#29]: https://github.com/c0rner/ghst/pull/29
[#34]: https://github.com/c0rner/ghst/pull/34
[#38]: https://github.com/c0rner/ghst/pull/38
[#39]: https://github.com/c0rner/ghst/pull/39
