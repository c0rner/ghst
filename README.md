# template-rust

<!-- TODO: Replace with your project description -->

A Rust project scaffolded from [template-rust](https://github.com/OWNER/template-rust).

## Prerequisites

- [Rust](https://rustup.rs/) (stable, edition 2024)

The required toolchain and components are declared in [`rust-toolchain.toml`](rust-toolchain.toml) and will be installed automatically by `rustup` on first use.

## Getting Started

```sh
cargo build
cargo run
```

## Development

```sh
# Run tests
cargo test

# Run linter
cargo clippy

# Format code
cargo fmt
```

Lint configuration lives in [`Cargo.toml`](Cargo.toml) under `[lints]`, not in CI flags.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
