# Changelog

All notable changes to iPhoneLoadly are documented here. The project follows
Semantic Versioning while remaining experimental alpha software.

## [Unreleased]

## [0.3.0-alpha.6] - 2026-10-26

### Fixed

- Normal RSD installs and refreshes can register an iPhone that is missing from
  the selected Apple team's device list, matching the existing installation
  behavior. Already registered devices are reused. The isolated first-install
  diagnostic still requires an existing registration.
- RSD jobs now report signing and transfer progress instead of remaining at
  "Signing IPA 1%" while uploading files.
- The RSD device picker uses model and OS-version metadata from the existing
  handshake when available, rather than always reporting `unknown`.
- File-heavy RSD installs no longer share the diagnostic's 15-minute limit.
  Normal installs and refreshes have a 60-minute total budget; the isolated
  first-install diagnostic retains its 15-minute limit.
- Each AFC request has a 90-second deadline. A connection that times out is
  discarded for further commands, preventing a late response from being used
  as the response to a subsequent command. Existing scoped cleanup and
  installed-bundle verification remain in place.

### Added

- Bounded registration-match counts, upload planning and transfer counters,
  and pending/timed-out AFC-operation diagnostics, without raw UDIDs, file
  paths or payload contents.
- Regression coverage for registration policy, transfer progress, optional
  device metadata, delayed and unanswered AFC requests, and timeout budgets.

### Upgrade notes

- A large app with many small files can still take more than 15 minutes over
  RSD. Keep the device reachable until Activity reports the final result.
  A hardware installation with 12,308 entries and about 312 MB of signed app
  data completed successfully in 29 minutes 51 seconds with this fix.
- Restarting the service may require completing Apple two-factor sign-in in
  the dashboard before the next install or refresh.

## [0.3.0-alpha.5] - 2026-10-20

### Added

- Experimental Apple TV support behind `IPHONELOADLY_APPLE_TV=on` (requires
  `IPHONELOADLY_RSD_INSTALL=on`). Settings gets an Apple TV card that finds an
  Apple TV showing "Remote App and Devices" and pairs with the PIN it shows.
  The paired Apple TV appears in the device list and installs, refreshes and
  lists apps over the same RSD path as the iPhone. Signing registers the Apple
  TV and requests tvOS provisioning profiles on its first install.
- Install jobs refuse an iOS-only IPA on an Apple TV and a tvOS IPA on an
  iPhone before any Apple account work starts.
- Apple TV discovery logs what it saw (found, resolved and rejected services),
  and install jobs log why signing failed (the bounded signing error and, when
  present, the signing diagnostic).

### Changed

- The install picker calls the target a device instead of an iPhone, since it
  also lists the Apple TV.

### Fixed

- The API service may now use netlink (`AF_NETLINK` in
  `RestrictAddressFamilies`). Without it mDNS could not list network
  interfaces, so Apple TV discovery and RSD discovery of the iPhone found
  nothing.
- Apple TV discovery waits 10 seconds, like the iPhone's RSD discovery.
- The 2FA dialog no longer reopens after a submitted code while Apple is still
  checking it.
- The GitHub sources, managed installations and validity lists keep their list
  layout after a loading or error message, instead of squeezing each row into a
  narrow column.
- IPAs with small, highly compressed files (such as NuvioTV's silent audio
  file) are no longer rejected by the compression-ratio check on upload or
  GitHub download; the check now applies to entries of 1 MiB or more.
- An app whose IPA file is missing on the server no longer reports "The IPA
  could not be signed". Install jobs fail with a clear message, the app can
  still be removed, and "Download latest" restores the file even when the
  release is unchanged.

## [0.3.0-alpha.4] - 2026-10-20

### Added

- Wireless installs over RSD for an iPhone paired with remote pairing. With
  `IPHONELOADLY_RSD_INSTALL=on` the paired iPhone appears in the device list,
  and install and refresh jobs to it go over RSD, upgrading an app that is
  already installed. A job only succeeds after the install is verified on the
  device and records the team-suffixed bundle identifier.
- The installed-apps list for the RSD iPhone is read over RSD.
- Install responses can carry a bounded `signingDiagnostic` (stage, error
  class, HTTP status, Apple code, local I/O kind) without raw error text.

### Fixed

- Apple sign-in after GrandSlam error -80045: anisette client info and URL bag
  handling backported from upstream; GrandSlam keeps pinned Apple trust while
  Developer Services uses public PKI.
- App ID and app group names are stripped of characters Apple rejects (result
  code 35), so apps such as `hello_world` can be signed.

## [0.3.0-alpha.3] - 2026-08-31

### Changed

- Overview no longer duplicates the Wi-Fi success presentation; selected-device information and controls remain available.
- Settings no longer duplicates the persistent “Up to date” presentation; manual update checks still show clear feedback.
- GitHub sources show the current local IPA version separately from the exact GitHub release tag, refresh app and source metadata after successful downloads, and provide clearer status and failure feedback.

### Fixed

- Activity history preserves each installation job’s recorded app version when the server IPA is later replaced.
- Repeated GitHub checks keep a pending source update available until the new release asset is downloaded or otherwise authoritatively resolved; release tags and IPA internal versions remain separate authorities.
- Dashboard hash navigation is retained with regression coverage.

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
