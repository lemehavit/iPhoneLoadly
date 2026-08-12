# iPhoneLoadly

buymeacoffee.com/lemehavit

Self-hosted Debian service for Apple-ID IPA signing and trusted Wi-Fi installation.
It includes a localhost-only dashboard, locally hosted anisette, systemd deployment,
and a daily refresh check that re-installs apps only when about one day remains of
the seven-day signing period.

Apple passwords and two-factor codes are never written to disk. An Apple login is
therefore required after an API or host restart.

## Installation

For a ready-to-install server use the [quick-start guide](docs/operations/quick-start.md).
To build a release archive yourself, run:

```bash
bash deploy/release/build-release.sh
```

For host prerequisites and the one-time iPhone pairing ceremony use the complete
[from-scratch guide](docs/operations/from-scratch.md). Existing hosts should use
the [systemd operations guide](docs/operations/api-systemd.md).

The dashboard is deliberately bound to `127.0.0.1:8080`; access it through an SSH
tunnel, or use the documented [Caddy LAN proxy](docs/operations/caddy-lan.md).

- [Technical feasibility and architecture assessment](docs/architecture-assessment.md)
- [Version 0.1 implementation and test plan](docs/mvp-v0.1-plan.md)
- [Debian 13.6 host preparation runbook](docs/operations/debian13-host-preparation.md)
- [Test IPA strategy](docs/operations/test-ipa-strategy.md)
- [From-scratch installation](docs/operations/from-scratch.md)
- [Quick start from a release archive](docs/operations/quick-start.md)
- [API and refresh operations](docs/operations/api-systemd.md)
- [Caddy LAN proxy](docs/operations/caddy-lan.md)

The short conclusion is: build a new headless Rust service around the MIT-licensed `idevice` and `isideload` libraries used by iLoader; use USB only for the initial iPhone trust/pairing ceremony; and make Wi-Fi discovery, local Apple-account provisioning/signing, transfer, installation, and eventual automatic refresh mandatory acceptance criteria. Signing happens locally on the server and does not itself use a device transport.
