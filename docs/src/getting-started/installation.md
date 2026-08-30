# Installation

`ghst` supports Linux and macOS, where it can enforce the Unix ownership, permission, and
file-descriptor checks required for persistent token caching.

## Release archives

Prebuilt archives for macOS and glibc-based Linux on `x86_64` and `aarch64` are published on
[GitHub Releases](https://github.com/c0rner/ghst/releases). Download the archive and its matching
`.sha256` file, then verify before extracting:

```console
$ sha256sum --check ghst-<version>-<target>.tar.xz.sha256
```

On macOS, use `shasum --algorithm 256 --check`. Release checksums detect corruption or a mismatch
between files downloaded together; they are not an independent signature from the publisher.

## Cargo

With a Rust toolchain installed:

```console
$ cargo install --locked ghst
```

This builds the published crate and locked dependency graph locally. Cargo builds may execute code
from dependencies and build scripts.

## Shell installer

Each release also includes `ghst-installer.sh`. It is a convenience bootstrap, not the recommended
installation method: the downloaded script executes immediately, and it warns and continues if
`sha256sum` is unavailable.

```console
$ curl --proto '=https' --tlsv1.2 -LsSf \
    https://github.com/c0rner/ghst/releases/latest/download/ghst-installer.sh | sh
```

After installation, use `ghst --help` to confirm the command is available.
