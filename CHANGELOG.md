# Changelog

All notable changes to iPhoneLoadly are documented here. The project follows
Semantic Versioning while remaining experimental alpha software.

## [0.2.0-alpha.2] - 2026-08-14

### Added

- Configurable automatic refresh on day 1–6 after the latest successful
  installation, stored persistently on the server with day 6 as the default.
- Bonjour/mDNS publication of `iphoneloadly.local` using the Debian host's
  active LAN address.
- Optional helper for creating an iOS configuration profile containing only
  Caddy's public local root certificate.
- Illustrated English dashboard user guide with English UI screenshots.

### Changed

- Refresh warnings now follow the configured automatic-refresh day.
- LAN access guidance now covers iPhone/iPad name resolution, certificate
  warnings and trusted-certificate installation.

### Fixed

- Avoided Avahi reverse-record collisions when publishing the dashboard alias.
- Direct LAN access no longer depends on manually configured client host files
  when Bonjour/mDNS is available on the network.

## [0.2.0-alpha.1] - 2026-08-13

### Added

- Trusted iPhone discovery and installation over Wi-Fi after one USB trust step.
- Optional encrypted Apple credential storage and sign-in restoration after a
  service restart, with explicit removal from the dashboard.
- Swedish and English dashboard languages.
- Installation progress, history, redacted diagnostics and refresh warnings.
- Remaining free-signing days per successful IPA/device installation.
- Paired-device overview that lists only apps installed through iPhoneLoadly.
- Authenticated `https://iphoneloadly.local` deployment guidance using Caddy.

### Changed

- Refreshed responsive dashboard navigation and layout.
- Automatic refresh checks now retry hourly when an eligible phone is offline.
- Release archives now contain version, license, security policy, changelog and
  the complete documentation tree.

### Security

- Apple credentials are saved only when the user opts in and are encrypted with
  a root-only local key.
- The API remains bound to loopback; LAN access must be protected by an
  authenticated reverse proxy.
- Release packaging excludes runtime state, uploaded IPAs, pairing records,
  credentials and backups.

## [0.1.0] - 2026-08-08

- Initial experimental release structure and Debian 13 host tooling.
