# iPhoneLoadly

Planning repository for a lightweight, self-hosted iOS IPA installation and refresh service.

No application has been implemented yet. The current milestone is the architecture decision and the smallest viable Version 0.1 plan:

- [Technical feasibility and architecture assessment](docs/architecture-assessment.md)
- [Version 0.1 implementation and test plan](docs/mvp-v0.1-plan.md)
- [Debian 13.6 host preparation runbook](docs/operations/debian13-host-preparation.md)
- [Test IPA strategy](docs/operations/test-ipa-strategy.md)

The short conclusion is: build a new headless Rust service around the MIT-licensed `idevice` and `isideload` libraries used by iLoader; use USB only for the initial iPhone trust/pairing ceremony; and make Wi-Fi discovery, transfer, installation, and eventual automatic refresh mandatory acceptance criteria. Signing happens locally on the server and does not itself use a device transport.
