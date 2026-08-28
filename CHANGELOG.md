# Changelog

All notable changes to iPhoneLoadly are documented here. The project follows
Semantic Versioning while remaining experimental alpha software.

## [0.3.0-alpha.2] - 2026-08-28

### Fixed

- Debian self-updates stop the API before replacing its executable, avoiding
  `ETXTBSY` failures during systemd restarts.
- Upgrade startup now retries health checks within a bounded timeout and
  requires the exact package version.
- Failed upgrades safely restore the previous runtime and restart the API
  without changing persistent application state.

## [0.3.0-alpha.1] - 2026-08-28

### Added

- Five app views: Overview, Apps, Install, Activity and Settings.
- Responsive desktop/mobile navigation with iPhone safe-area-aware bottom tabs.
- Adaptive light/dark appearance, clearer spacing and a more deliberate visual hierarchy.

### Changed

- Added visible pressed, focus and busy states with consistent loading, empty, success, warning and error feedback.
- Added meaningful activity text and determinate upload/install progress.
- Replaced browser prompt/confirm workflows with accessible in-app dialogs and sheets.
- Consolidated device management, IPA Library, GitHub sources, installation readiness, Activity history and Settings.
- Completed Swedish and English localization across the dashboard.
- Single-job and history responses now share canonical install-job serialization, including `progressPercent`.

### Security

- `Remove from management` does not uninstall or unpair an iPhone; installation history is retained.
- No true phone-unpairing, physical uninstall, native iOS app, or private GitHub source support is provided.

### Upgrade

- After publication, users on `v0.2.0-alpha.3` can update from **Settings → Software update**.

## [0.2.0-alpha.3] - 2026-08-27

### Added

- Official GitHub release update discovery and a constrained systemd updater.
- IPA upload progress, readable names, parsed versions and rename support.
- Stale managed app/device removal without deleting history or uninstalling apps.
- Stage-specific safe installation diagnostics with app name/version history snapshots.
- Public GitHub IPA sources with deterministic asset selection and manual download.
- Opt-in automatic source synchronization with an explicit supply-chain warning.

### Changed

- Source-linked IPA replacement preserves logical app identity and installation history.
- Deleting a server IPA disables its linked source automation.

### Security

- Self-update accepts only verified artifacts from `lemehavit/iPhoneLoadly`.
- Third-party downloads are bounded, structurally validated and bundle-ID checked.
- Automatic third-party downloads are disabled by default and never immediately install.


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
