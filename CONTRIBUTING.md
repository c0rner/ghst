# Contributing

Thank you for considering contributing to this project!

## Development Setup

1. Install [Rust](https://rustup.rs/) (the toolchain is managed by [`rust-toolchain.toml`](rust-toolchain.toml)).
2. Clone the repository and run `cargo build`.

## Before Submitting a PR

Please make sure the following pass locally — they are the same checks CI runs:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo doc --no-deps --all-features
mdbook build docs
```

### Building the User Manual

The user manual is built with [mdBook](https://rust-lang.github.io/mdBook/) 0.5.4. To build or serve the manual locally:

```sh
# Build the book into docs/book/
mdbook build docs

# Or serve locally with live reloading
mdbook serve docs
```

## Commit Messages

Use clear, descriptive commit messages. Consider following the [Conventional Commits](https://www.conventionalcommits.org/) specification.

