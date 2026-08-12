# Contributing to iPhoneLoadly

iPhoneLoadly is experimental. Please report bugs with redacted logs, your
Debian version, iOS version, and the smallest reproducible steps; never include
Apple credentials, two-factor codes, pairing records, UDIDs, or private keys.

For local development, install the Rust toolchain, then run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build --workspace --release
```

Keep pull requests focused, document user-facing behavior, and include tests
where practical. Do not weaken localhost binding, credential handling, or
systemd hardening without explaining the security impact.
