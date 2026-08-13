# iPhoneLoadly

Self-hosted IPA signing, Wi-Fi installation, and refresh support for a trusted
iPhone from a Debian server.

> Self-host IPA signing and installation for your iPhone, then check for refreshes over Wi-Fi before the typical 7-day free-signing period expires.

[![Version](https://img.shields.io/badge/version-0.2.0--alpha.1-blue)](VERSION)
[![Rust](https://img.shields.io/badge/rust-2024-orange)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![CI](https://github.com/lemehavit/iPhoneLoadly/actions/workflows/ci.yml/badge.svg)](https://github.com/lemehavit/iPhoneLoadly/actions/workflows/ci.yml)

> [!WARNING]
> iPhoneLoadly is experimental alpha software. Apple’s services and iOS device
> protocols can change without notice; expect breaking changes and do not rely
> on it as your only sideloading solution.

## Features

- Self-hosted Rust service for Debian 13 amd64
- Local Apple-ID signing session and interactive two-factor authentication
- One-time USB trust/pairing, followed by trusted Wi-Fi device transport
- Responsive Swedish/English browser dashboard with installation progress,
  history, signing validity and managed-app/device overview
- IPA upload validation, SHA-256 inspection, and signing/install job tracking
- Hourly retry check for apps whose last successful install is about six days old
- Optional encrypted Apple credential storage for sign-in restoration
- Systemd deployment, host diagnostics, backup, and recovery tools

## How it works

1. iPhoneLoadly runs on a Debian 13 amd64 server.
2. You connect and unlock the iPhone over USB once, then accept its Trust prompt.
3. The host creates a local pairing record, which is sensitive device-access material.
4. Wi-Fi connections are enabled; later app work uses the trusted network path.
5. You sign into Apple through the local dashboard and complete 2FA when asked.
6. iPhoneLoadly discovers trusted iPhones on Wi-Fi, then signs and installs an
   uploaded IPA for the selected phone.
7. Its systemd timer checks whether a successful installation is about six days old
   and queues a refresh when the Apple signing session and phone are available.

An Apple ID is required because Apple provisioning, certificates, and device
registration are part of signing. Passwords stay in memory unless the user
explicitly enables encrypted credential storage. Two-factor responses are never
persisted, and Apple may still request 2FA after a restart. Pairing records,
uploaded IPAs, encrypted credentials, local keys and backups are sensitive data.

## Install iPhoneLoadly

Follow the single beginner path in [docs/INSTALL.md](docs/INSTALL.md). It starts
with an empty Debian 13 host, uses a GitHub Release archive when one is available,
and finishes at the local dashboard. Source builds are documented as an advanced
option. The API deliberately stays on `127.0.0.1:8080`. For normal LAN use,
configure authenticated `https://iphoneloadly.local` using the
[Caddy LAN proxy guide](docs/operations/caddy-lan.md). An SSH tunnel remains an
alternative for administrators. Never expose Apple credential endpoints directly.

Detailed material remains available under [docs/](docs/), including host Wi-Fi
pairing, systemd operations, architecture, and test-IPA guidance.

## Security and licensing

Read [SECURITY.md](SECURITY.md) before deployment. iPhoneLoadly’s own source is
licensed under the [MIT License](LICENSE). Host tooling and dependencies retain
their own licenses; see [third-party notices](deploy/host/THIRD_PARTY_NOTICES.md).
The `isideload` Git dependency is intentionally pinned to its
`apple-codesign-quick` branch because published releases do not yet include the
signing backend this project uses; Cargo.lock records the resolved revision.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Suggested GitHub topics: `iphone`,
`ios`, `ipa`, `sideloading`, `ios-sideloading`, `rust`, `self-hosted`, and
`debian`.

## Support

If iPhoneLoadly helps you, support is welcome but never expected:

<a href="https://buymeacoffee.com/lemehavit">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" height="50" alt="Buy Me a Coffee">
</a>

<a href="https://paypal.me/lemehavit">
  <img src="https://img.shields.io/badge/PayPal-Support%20me-0070BA?logo=paypal&logoColor=white" height="50" alt="PayPal">
</a>
