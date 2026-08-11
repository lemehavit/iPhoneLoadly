# iPhoneLoadly technical feasibility and architecture assessment

Status: proposed  
Research date: 2026-08-10  
Revised: 2026-08-10 — Wi-Fi installation is a hard requirement  
Scope: architecture through Version 0.1 only; no application implementation

## Executive decision

The project is technically feasible, including local Apple-account provisioning/signing and installation over the local Wi-Fi network after a one-time USB pairing. Version 0.1 accepts an unsigned or re-signable IPA, provisions it for the selected iPhone, signs it locally, and installs the resulting IPA over Wi-Fi. Apple private developer APIs, 2FA, free-account seven-day limits, unattended account sessions, and wireless reachability are hard acceptance gates rather than deferred concerns.

Build a new headless Rust backend. Reuse the same two MIT-licensed libraries that current iLoader uses:

- [`jkcoxson/idevice`](https://github.com/jkcoxson/idevice) for usbmuxd, lockdownd, AFC, installation proxy, pairing, TCP and modern iOS services.
- [`nab138/isideload`](https://github.com/nab138/isideload) for Apple authentication, 2FA, developer services, certificates, App IDs, provisioning, IPA manipulation and signing in Version 0.2.

Do not fork iLoader as the server foundation. Its useful backend code is coupled to Tauri commands, windows, events and desktop keyrings. Its dependency selection and MIT-licensed implementation are valuable, but the headless service should call the libraries directly and adapt only small, attributed pieces where the libraries do not yet expose the required API.

USB is permitted only for the initial trust/pairing ceremony and for enabling Wi-Fi device connections. After the cable is removed, device discovery, AFC staging, installation-proxy installation, and later refresh reinstalls must use Wi-Fi. Run Debian `usbmuxd` for onboarding and current `netmuxd` v0.4.3 as a network-discovery shim on a separate compatible Unix socket. The container sees only the shim socket. Direct `idevice::TcpProvider` plus host mDNS discovery is the fallback design.

## Feasibility by capability

| Capability | Recommended implementation | Confidence | Notes |
|---|---|---:|---|
| Device detection | Host `netmuxd` plus `idevice` `UsbmuxdConnection` | Medium-high | The production device must be returned with connection type `Network`; USB entries are onboarding-only. |
| Device information | `idevice` lockdownd client | High | Read `DeviceName`, `ProductType`, `ProductVersion`, and identifiers. |
| Initial pairing | Host mux daemon plus `idevicepair`; later `idevice` pairing API | High over USB | This is the only normal workflow that requires a cable. Requires unlocked phone, Trust confirmation, and passcode. |
| Pair-record ownership | Host mux daemon, `/var/lib/lockdown` | High | The container receives scoped mux access, not a mount of the pairing directory. The direct-TCP fallback needs an encrypted imported copy. |
| Wi-Fi discovery/transport | Avahi/mDNS plus current `netmuxd`; fallback `idevice::TcpProvider` | Medium-high, hardware-gated | Required in Version 0.1. The phone and Debian VM must share working multicast/LAN reachability. |
| IPA validation/metadata | Rust `zip` plus `plist`, strict application-level checks | High | Validation must defend against traversal and archive bombs. |
| Apple login, 2FA, developer resources, provisioning and signing | `isideload` behind an internal `SigningProvider` adapter | Medium, hardware/account-gated | Use a dedicated Apple Account; request 2FA interactively; keep passwords in memory only; persist encrypted session state only when supported and validated. |
| Signed IPA install | `idevice` AFC plus installation proxy over a network provider; reuse/adapt isideload's MIT install path | Medium-high, hardware-gated | Stage the locally signed IPA to a unique `PublicStaging` path over Wi-Fi, invoke install, stream status, then clean up. A USB install does not satisfy Version 0.1. |
| Installation progress | Installation proxy status callback -> job events/SSE | High | Preserve raw diagnostic data but show a translated error. |
| Apple authentication and 2FA | `isideload::auth::apple_account` | Medium-high | Implemented and used by iLoader, but private API behavior can change. |
| Anisette | `isideload` remote v3 provider; self-hosted provider later | Medium | Pin the selected provider and make it replaceable. Do not silently send credentials to an unknown service. |
| Developer teams/certificates/App IDs | `isideload::dev` APIs | Medium-high | Current iLoader exercises these APIs. Free-account quotas need explicit handling. |
| Provisioning and signing | `isideload` signing pipeline, which uses a modified Apple signing implementation | Medium | Entitlement edge cases remain an upstream TODO; test complex IPAs. |
| Independent code-sign inspection | `apple-codesign`/`rcodesign` where useful | Medium-high | MPL-2.0; useful as a verifier or replaceable signer, not a provisioning solution. |
| Expiration detection | Parse `embedded.mobileprovision` CMS/plist | High | Does not require contacting Apple. |
| Persistent metadata/jobs | SQLite | High | One database is sufficient at this scale. |
| Auto-refresh scheduling | In-process Tokio scheduler with DB leases | High after signing works | No Redis, Celery, or separate queue is needed. |

## Upstream assessment

### iLoader

[`nab138/iloader`](https://github.com/nab138/iloader) is the closest architectural reference and is actively developed. Its current Rust manifest identifies version 2.3.1 and depends on `idevice` 0.1.57 plus `isideload` 0.3.17 from an `apple-codesign-quick` branch. The repository is MIT for source code, but its name, logos, and media have separate branding restrictions.

What can be reused directly:

- The `idevice` and `isideload` dependency choices and feature set.
- The device enumeration flow in `src-tauri/src/device.rs`: get devices from usbmuxd, construct a provider, and query lockdownd for name/version.
- The pairing flow in `src-tauri/src/pairing.rs`, including reading the host lockdown record, enabling Wi-Fi debugging, and generating/caching the iOS 17.4+ remote-pairing record.
- The Apple login/2FA and `SideloaderBuilder` integration in `account.rs` as a behavior reference.
- The error taxonomy and operation/progress concepts.
- The application installation pipeline available through `isideload`.

What should not be reused unchanged:

- Tauri command signatures, `AppHandle`, `Window`, desktop event listeners, and global mutex state.
- The React/Tauri desktop UI.
- The desktop keyring abstraction as the server secret store.
- iLoader's optional saved-password path. Current iLoader can put the Apple password in the OS keyring and logs in again after restart. This conflicts with this project's rule that the Apple password must not be retained.
- Branding assets or the iLoader name.

Important limitation: current `isideload::AppleAccount` holds the decrypted SPD/session data in memory but does not expose a documented, stable session export/import API. Unattended restart without saving the password therefore needs an upstream contribution or a small maintained fork of **isideload**, not a fork of the whole iLoader desktop application. This is a Version 0.2 gate.

### isideload

[`nab138/isideload`](https://github.com/nab138/isideload) is an MIT Rust library explicitly intended for Apple-ID-based sideloading and used by iLoader. Its modules already separate anisette, Apple authentication, developer-service APIs, application processing, signing, and installation. This is the best long-term integration point.

Risks:

- Its README still lists entitlement handling, dependency reduction, and performance/caching work as TODOs.
- iLoader currently consumes a Git branch rather than only a crates.io release. Production builds must pin an audited commit and record it in the software bill of materials.
- Session persistence suitable for a passwordless unattended daemon is not currently a public capability.

Recommended upstream work before Version 0.2:

1. Add encrypted-caller-controlled export/import of the minimum Apple session state, with expiry metadata.
2. Add zeroization/secret wrappers for transient password and token buffers.
3. Expose a public `install_already_signed_ipa` operation, including progress and cleanup, if the lower-level install module is not already public enough.
4. Make progress and 2FA interactions callback/channel based without any UI assumptions.

### idevice

[`jkcoxson/idevice`](https://github.com/jkcoxson/idevice) is an MIT, pure-Rust library designed to be embedded in applications and server programs. It includes feature-gated usbmuxd, TCP, pairing, AFC, installation proxy, CoreDevice, remote pairing and tunnel support. Its own README warns that point releases can contain breaking changes before 0.2.0. Pin an exact version/commit behind an internal adapter.

This is preferable to binding directly to C for the product backend because it matches the future signing stack and avoids an FFI layer. Keep the adapter narrow so a libimobiledevice or pymobiledevice3 fallback remains possible.

### libimobiledevice, usbmuxd and ideviceinstaller

[`libimobiledevice`](https://github.com/libimobiledevice/libimobiledevice) is the mature C protocol library. It supports Wi-Fi-sync network devices, device services, provisioning and app management. Version 1.4.0 was released in October 2025. The library is LGPL-2.1; bundled utilities have their applicable GPL terms.

[`usbmuxd`](https://github.com/libimobiledevice/usbmuxd) is the correct Linux host daemon. It owns USB access, exposes `/var/run/usbmuxd` (normally the same socket as `/run/usbmuxd`), and manages pairing records in `/var/lib/lockdown`. The daemon is GPL-3.0.

[`ideviceinstaller`](https://github.com/libimobiledevice/ideviceinstaller) is a useful diagnostic and fallback CLI. It supports `install`, `upgrade`, progress, a target UDID, and `--network`; it is GPL-2.0. Do not parse its human output as the primary product protocol if a native callback API is available. It remains an excellent independent Test 5 oracle.

### pymobiledevice3

[`doronz88/pymobiledevice3`](https://github.com/doronz88/pymobiledevice3) is currently the broadest and fastest-moving implementation of modern iOS services. It supports device discovery, application management, AFC, remote pairing, and modern iOS 17+ tunnels. Its July 2026 releases demonstrate active iOS 26 work. It is GPL-3.0.

Use it as:

- a diagnostic/reference implementation;
- a way to enable/test Wi-Fi connections and remote pairing;
- a compatibility fallback for newly changed Apple protocols while the Rust stack catches up.

Do not make it the main embedded backend unless Rust libraries fail a hardware spike. Embedding it would make the backend GPL-3.0 and add a larger Python dependency footprint. Invoking it as a separately installed host diagnostic tool is less coupled.

### Dadoum/Sideloader

[`Dadoum/Sideloader`](https://github.com/Dadoum/Sideloader) is a valuable implementation and reference for Apple private developer endpoints. It has a working cross-platform CLI covering accounts, certificates, App IDs, signing, and installation. It is written in D, depends on libimobiledevice/libplist/OpenSSL, and is GPL-3.0.

It should remain an alternative and test oracle, not the embedded core: its GPL license, D runtime/build chain, and CLI-oriented design fit this service less well than isideload. iLoader/isideload already credit it as a reference.

### SideStore

[`SideStore/SideStore`](https://github.com/SideStore/SideStore) is an AGPL-3.0 on-device application. It signs on the phone and uses a VPN/loopback technique plus Minimuxer to make the device communicate with its own lockdownd services. That architecture solves a different constraint: operation without a continuously available external server.

Reuse its source/feed concepts and operational lessons, not its on-device mux/VPN design. The Debian service can reach the iPhone through normal host-to-device transport and does not need to imitate SideStore's loopback trick.

### apple-codesign / rcodesign

[`indygreg/apple-platform-rs`](https://github.com/indygreg/apple-platform-rs) contains `apple-codesign` and the `rcodesign` CLI. Current crate metadata identifies version 0.29.0 and MPL-2.0. It is a strong pure-Rust implementation for Apple code-signing formats, but it does not replace Apple developer authentication, device registration, App ID creation, or profile generation. Use it behind the signing adapter or as an independent verifier where isideload's selected fork permits.

### netmuxd

[`jkcoxson/netmuxd`](https://github.com/jkcoxson/netmuxd) provides network-device discovery and a usbmuxd-compatible socket. Current v0.4.3 supports `--upstream-usbmuxd` shim mode and a separate `--socket-path`: USB/pair-record requests can be forwarded to Debian usbmuxd while network devices are added by netmuxd. It is LGPL-2.1. The iPhone still needs the one-time USB trust/pairing record before normal network access.

For the required Wi-Fi workflow, `netmuxd` is now a Version 0.1 host dependency candidate rather than an optional future experiment. Pin and test an exact release. If it cannot meet the reliability gate, keep `usbmuxd` for onboarding and implement host mDNS discovery plus `idevice::TcpProvider`, whose API accepts the phone IP address and pairing file directly. Do not run two daemons on the same Unix socket.

## License compatibility

Recommended license for original iPhoneLoadly code: Apache-2.0 OR MIT. This preserves flexibility while allowing the preferred MIT Rust dependencies.

| Component | License | Use | Compatibility action |
|---|---|---|---|
| iLoader source | MIT; separate branding terms | Reference or small attributed adaptations | Do not reuse name/logo/assets. Preserve copyright/license notices for copied code. |
| isideload | MIT | Linked Rust dependency | Compatible; pin commit and retain notices. |
| idevice | MIT | Linked Rust dependency | Compatible; pin exact version/commit. |
| apple-codesign | MPL-2.0 | Optional linked crate/tool | Compatible with a larger work, but modifications to MPL-covered files must remain MPL and source-available. |
| libimobiledevice | LGPL-2.1 | Host library/diagnostics | Dynamic linking is straightforward; preserve notices and relinking/source obligations when distributing. |
| netmuxd | LGPL-2.1 | Required host candidate for Wi-Fi transport | Distribute its license and corresponding source offer when shipping binaries/images. |
| usbmuxd | GPL-3.0 | Separate host daemon | Keep process boundary; comply with GPL if distributing a package/image containing it. |
| ideviceinstaller | GPL-2.0 | Separate diagnostic/fallback executable | Do not copy its source into a permissive backend; comply if bundled. |
| pymobiledevice3 | GPL-3.0 | Separate diagnostic/fallback | Embedding/importing would impose GPL obligations on the combined work. |
| Dadoum/Sideloader | GPL-3.0 | Reference/test oracle | Do not copy implementation into the permissive backend. |
| SideStore | AGPL-3.0 | Architectural reference | Do not copy code unless willing to comply with AGPL network-source obligations. |

This is an engineering compatibility assessment, not legal advice. Before a public binary or Docker image release, generate an SBOM and have the exact transitive dependency set reviewed. In particular, audit the dependency graph of the pinned isideload branch and its modified signing crate.

## Pairing and communication from Proxmox and Debian

### Hardware path

1. Pass the iPhone USB device or, preferably, its stable physical USB port from Proxmox to the Debian VM. Proxmox documents both vendor/product and bus/port host USB passthrough; physical port mapping is less likely to break when an Apple device re-enumerates with another product ID.
2. Confirm the device appears in the Debian guest with `lsusb`.
3. Install Avahi, Debian `usbmuxd`, and pinned `netmuxd` v0.4.3 on the host. Keep usbmuxd on `/run/usbmuxd`; run netmuxd in shim mode on `/run/iphoneloadly/mux.sock` with usbmuxd as its upstream.
4. Pair while the phone is unlocked. The user taps **Trust This Computer** and enters the phone passcode.
5. Enable Wi-Fi device connections during the same USB session. Store the lockdown pairing record under `/var/lib/lockdown` with restrictive permissions.
6. Disconnect the cable. Confirm `_apple-mobdev2._tcp.local` discovery and confirm the mux reports the phone as `Network`.
7. The backend container connects through the bind-mounted compatible Unix socket. It does not need the raw USB device, `/dev/bus/usb`, `--privileged`, host networking, or a mount of the pairing directory.

Host verification sequence:

```sh
lsusb | grep -i apple
systemctl status netmuxd
idevice_id -l
idevicepair pair
idevicepair validate
pymobiledevice3 lockdown wifi-connections on
# Disconnect USB before continuing.
avahi-browse -rt _apple-mobdev2._tcp
ideviceinfo --network -u <UDID> -k DeviceName
ideviceinfo --network -u <UDID> -k ProductVersion
```

If pairing fails, first check that USB passthrough is still attached to the VM, the phone is unlocked, the Trust dialog was accepted, and the VM clock is correct. Do not delete pairing records automatically; make record deletion an explicit recovery action because it forces a new trust ceremony.

### What a pairing record means

The lockdown pair record is effectively a host identity and client certificate that authorizes access to services on the device. Possession can permit sensitive device communication while the device is reachable. Treat it as a secret even though it is not an Apple-account credential.

For iOS 17.4+, remote-pairing/RSD records are a separate modern mechanism used by some developer services. iLoader already generates and caches an RPPairing file through `CoreDeviceProxy`. Normal AFC and installation-proxy work over the lockdown transport and do not require reproducing SideStore's on-device pairing scheme for Version 0.1.

## Mandatory installation over Wi-Fi

Yes, it is technically realistic, but it remains a hardware and network acceptance gate rather than a paper guarantee.

Evidence that the protocol path exists:

- libimobiledevice supports network devices with Wi-Fi sync enabled.
- current ideviceinstaller exposes `--network` for installation.
- pymobiledevice3 documents enabling Wi-Fi connections, Bonjour discovery of `_apple-mobdev2._tcp.local.`, and direct TCP/remote-pairing transports.
- iLoader's device model already distinguishes `USB` and `Network`, and its pairing code sets `EnableWifiDebugging`.

Conditions that can still break it:

- The open-source Linux `usbmuxd` daemon is fundamentally the USB mux. Network discovery generally needs direct TCP/mDNS handling or a companion such as netmuxd.
- Bonjour multicast must cross the Proxmox bridge and reach the Debian VM. Routed VLANs, Wi-Fi client isolation, firewalls and multicast filtering can prevent discovery.
- iOS may withdraw network services while asleep, locked, in low-power conditions, or after trust/network changes.
- Apple has changed remote-service and pairing behavior across iOS releases. iOS 17.0-17.3, 17.4+, and later releases do not all use identical modern tunnel paths.
- A scheduled refresh cannot succeed while the device is away from the LAN or unreachable; the scheduler must persist the pending job and retry while enough provisioning lifetime remains.

Required Version 0.1 transport test, before application work:

1. Over USB, enable Wi-Fi device connections with a supported tool.
2. Run Avahi on the Debian host and verify the phone advertises on the VM's L2 segment.
3. Remove the USB cable and verify the host mux reports a network device.
4. Test both `ideviceinfo --network -u <UDID>` and `ideviceinstaller --network -u <UDID> install <signed.ipa>` while USB remains disconnected.
5. Run the native Rust `idevice` spike over the same network path and require AFC staging plus installation-proxy progress.
6. Test locked/unlocked, screen-on/screen-off, phone sleep, server restart, VM restart, DHCP address change, Wi-Fi roam/reconnect, and 24-hour idle cases.
7. Record the exact iPhone model, iOS version, router/AP, VLAN, netmuxd/idevice commits and Debian package versions.

There is deliberately no USB installation fallback in the normal UI, scheduler, or completion criteria. If the phone is not reachable over Wi-Fi, the job stays pending/retrying and the UI explains why.

Signing itself is not transported over Wi-Fi: Apple authentication, provisioning and code signing execute locally on the Docker server. Wi-Fi is required for discovering the phone, staging the resulting signed IPA, installing it and verifying the installed application.

### Consequence for automatic seven-day refresh

The later scheduler must be presence-aware rather than assume that a scheduled timestamp means the phone is reachable:

1. Begin the refresh window early, for example at 72 hours remaining, with a configurable target to finish before 48 hours remain.
2. Prepare provisioning and sign the new IPA locally on the server. This work does not require the iPhone to be online.
3. If the paired phone is currently visible as `Network`, enqueue the Wi-Fi install immediately.
4. Otherwise persist `waiting_for_device`, retry with bounded backoff, and trigger an immediate retry when the mux reports that the phone has returned to the LAN.
5. Alert the administrator before the remaining validity reaches a configurable critical threshold.
6. Never silently switch the job to USB. A cable may be used only for an explicit re-pair/recovery ceremony.

The scheduler must also re-check the profile expiration and installed bundle/version immediately before installation so an old queued artifact is not installed after a newer refresh succeeded.

## Recommended Docker and host boundary

### Debian host

- Proxmox USB passthrough endpoint.
- Avahi/mDNS; required so the Debian VM can see `_apple-mobdev2._tcp.local` advertisements.
- Pinned `netmuxd` v0.4.3, managed by systemd, serving `/run/iphoneloadly/mux.sock` and discovering network devices.
- Debian `usbmuxd` and udev rules for one-time USB onboarding on `/run/usbmuxd`; netmuxd forwards upstream requests to it without sharing its socket path.
- Pair records in `/var/lib/lockdown`, readable only by the service account/root as required by the distribution.
- Caddy or another small reverse proxy for TLS and LAN/VPN access, if TLS is not terminated in the application.

### Docker

Use one application container initially:

- Rust HTTP API and job runner.
- React/Vite static assets served by the Rust process.
- SQLite and uploaded IPA data on one persistent volume.
- Bind mount only the selected mux socket (prefer a dedicated `/run/iphoneloadly/mux.sock` runtime directory), never all of `/run`. Socket ownership/mode and the container UID/GID control who can connect; a Docker `:ro` flag does not make an established Unix-socket connection read-only. Validate the exact mount with the selected runtime.
- Read-only root filesystem, tmpfs for `/tmp`, dropped Linux capabilities, `no-new-privileges`, non-root UID, and explicit memory/CPU limits.

Do not mount `/dev/bus/usb`, `/var/lib/lockdown`, the Docker socket, Avahi's system D-Bus socket, or the host root filesystem. Do not use host networking or `--privileged` for Version 0.1.

The chosen mux must run under systemd with a stable socket for the container lifetime. A bind mount of one socket inode can become stale if the daemon removes and recreates it; use a dedicated stable host-side proxy if the selected mux cannot preserve the socket. Add daemon-restart tests and do not solve the problem by mounting all of `/run`.

Conceptual deployment:

```text
iPhone --USB once--> Proxmox passthrough --> trust + pairing record
   |
   +--Wi-Fi/LAN--> Debian VM: Avahi + netmuxd + pair records
                                              |
                                  /run/iphoneloadly/mux.sock
                                              |
                              +---------------+----------------+
                              | iPhoneLoadly container         |
Browser --> TLS/auth -------->| Rust API + jobs + static UI    |
                              | SQLite + /data/apps            |
                              +--------------------------------+
```

## Recommended software architecture

Use a ports-and-adapters boundary around volatile Apple/device integrations:

```rust
trait DeviceTransport {
    async fn list_devices(&self) -> Result<Vec<Device>>;
    async fn device_info(&self, udid: &str) -> Result<Device>;
    async fn install_signed_ipa(
        &self,
        udid: &str,
        ipa: &Path,
        progress: ProgressSink,
    ) -> Result<InstallReceipt>;
}

trait SigningProvider {
    async fn sign(&self, request: SignRequest, progress: ProgressSink)
        -> Result<SignedArtifact>;
}

trait SecretStore {
    async fn put(&self, key: SecretKey, value: SecretBytes) -> Result<()>;
    async fn get(&self, key: SecretKey) -> Result<Option<SecretBytes>>;
}
```

Initial adapters:

- `IdeviceNetworkTransport`: Version 0.1 production adapter. It rejects USB connection entries for install jobs.
- `CommandDiagnosticTransport`: test-only adapter that invokes `ideviceinfo`/`ideviceinstaller` with fixed argument arrays and strict timeouts.
- `FakeDeviceTransport`: unit/integration tests without a phone.
- `IsideloadSigningProvider`: added only in Version 0.2.
- `IdeviceUsbOnboardingTransport`: setup-only adapter for trust, pairing and enabling Wi-Fi; never selected by install or refresh jobs.

Use Axum, Tokio, Serde, SQLx with SQLite, tracing, and rustls. A single Tokio process is sufficient for 2 vCPU and 1.5-2 GB RAM. Use bounded worker concurrency: one active device operation per UDID and a small global job limit.

## Security model

### Threat boundary

Assume the LAN is not inherently trusted. Require application authentication for every non-health endpoint and TLS even on the LAN where practical. Prefer access through a private VPN. Never expose Apple login, secrets, upload, or install endpoints directly to the public Internet.

### Application authentication

- One local administrator account is enough initially.
- Store only an Argon2id password hash with per-user salt.
- Use secure, HTTP-only, SameSite cookies and CSRF protection for state-changing requests.
- Rate-limit login, upload and Apple-account endpoints.
- Permit `/healthz` to disclose only liveness, not device/account details.

### Master key and encrypted records

- Generate a 256-bit master key at installation.
- Supply it as a Docker secret/file with mode `0400`, not in the image, database, Compose file, or command line.
- Encrypt each sensitive value independently with an AEAD such as XChaCha20-Poly1305, random nonce, record type/account ID as associated data, and an explicit key version.
- Store ciphertext and metadata in a separate `secrets` table or encrypted files; never put decrypted values in SQLite.
- Back up the master key separately. A data backup without the key should not reveal secrets; losing the key should make secrets unrecoverable.

Sensitive values include Apple session/SPD/app tokens, anisette machine state, certificate private keys, provisioning credentials and any copied remote-pairing records.

### Apple password lifecycle

- Accept the password only over an authenticated TLS request during interactive login.
- Hold it only in a secret/zeroizing memory type for the duration of login and 2FA.
- Never store it, include it in job arguments, retry payloads, panic reports, traces, metrics, or browser storage.
- Persist only encrypted renewable session state. If the selected library cannot resume a valid session after a process restart, mark the account `reauthentication_required`; do not fall back to saving the password.

This constraint means unattended refresh after a cold restart is blocked until isideload has a verified session import/export path.

### Certificates and pairing records

- Generate signing keys inside the service and encrypt private key material immediately at rest.
- Decrypt into memory only for a signing job and zeroize afterward.
- In the preferred netmuxd path, keep lockdown records only in `/var/lib/lockdown`; do not mount that directory or expose records through the API. If the direct `TcpProvider` fallback is selected, import only the required record during explicit USB onboarding, encrypt it immediately with the application master key, and delete/replace it on unpair or re-pair.
- The container's compatible mux-socket access is sensitive. Only the backend UID should have it, and no endpoint may act as a generic port proxy.

### IPA handling

- Ignore the client filename. Assign a UUID and store outside the web root.
- Stream upload to a newly created temporary file; apply configurable compressed and uncompressed size limits.
- Require ZIP structure with exactly one top-level `Payload/*.app`, a parseable `Info.plist`, a safe bundle ID/version, and no absolute paths, `..` traversal, symlinks or duplicate/conflicting paths.
- Cap file count, per-entry size, total expanded size and compression ratio before extraction.
- Do not trust or reuse any input `embedded.mobileprovision`. The signing adapter generates the profile for the selected device and the service parses only the resulting signed IPA's expiration for display. Installation remains the final signature/profile validity check because validity is device- and entitlement-dependent.
- Calculate SHA-256 while streaming. Deduplicate by checksum, not filename.
- Never pass user-controlled text through a shell. If a diagnostic CLI is used, call it with a fixed executable and argument array.

### Logging

Use structured JSON logs with timestamp, request ID, job ID, device internal ID, application ID, operation, phase, duration and result. Redact fields by type rather than by string pattern. Email may be masked; UDIDs should be hashed or shown only in authenticated diagnostics. Never log request bodies for login, secrets, certificates, profiles or pairing data.

## Proposed repository structure

```text
iphoneloadly/
  Cargo.toml                    # Rust workspace
  Cargo.lock                    # committed, reproducible dependency graph
  LICENSE-APACHE
  LICENSE-MIT
  README.md
  deny.toml                     # license/advisory policy
  crates/
    server/                     # Axum bootstrap, config, graceful shutdown
    domain/                     # devices, apps, jobs; no Apple-library types
    api/                        # REST models, auth, SSE
    persistence/                # SQLite migrations and repositories
    ipa/                        # upload, validation, metadata, checksum
    device-idevice/             # idevice network adapter + USB onboarding only
    signing-isideload/          # Version 0.2, absent from first MVP
    secrets/                    # AEAD secret-store adapter
  web/
    src/
    package.json
    vite.config.ts
  migrations/
  deploy/
    Dockerfile
    compose.yaml
    caddy.example
    systemd/
    host-setup.md
  docs/
    architecture-assessment.md
    mvp-v0.1-plan.md
    operations/
      pairing.md
      diagnostics.md
      backup-restore.md
    adr/
      0001-headless-rust.md
      0002-host-mux-and-wifi.md
  tests/
    fixtures/                   # synthetic/non-copyright IPA structures
```

This is the target structure, not a request to create all folders before they contain real code.

## Major technical risks

| Risk | Impact | Mitigation / gate |
|---|---|---|
| Apple changes private authentication/developer APIs | Login/signing stops | Pin dependencies, integration health test, adapter boundary, track iLoader/isideload upstream. |
| No passwordless resumable isideload session | Unattended restart/refresh blocked | Implement and upstream encrypted session export/import before Version 0.2 is accepted. |
| Free developer-account quotas and 7-day profiles | Refresh/certificate churn | Model quotas explicitly; never revoke certificates automatically without user confirmation/policy. |
| Entitlement or extension signing edge cases | Some IPAs fail | Corpus tests for extensions/frameworks; preserve original entitlements; compare against iLoader/Sideloader. |
| `idevice` pre-0.2 API churn | Build breaks | Internal adapter, exact commit pin, controlled upgrades. |
| iOS version changes | Detection/install regresses | Hardware matrix, pymobiledevice3/libimobiledevice diagnostic oracle, release qualification. |
| Wi-Fi discovery or reachability is unreliable | Core product cannot refresh automatically | This is a release blocker, not a degraded optional feature; qualify the real AP/VLAN/iOS matrix, add mDNS diagnostics, persistent retry windows and explicit alerts. |
| Phone is away/asleep until close to expiry | Refresh misses the seven-day deadline | Begin retrying before the final 48 hours, use bounded backoff, prioritize immediately on LAN presence, and notify while enough time remains for manual intervention. |
| USB passthrough/hotplug instability during onboarding | Initial trust/pairing cannot complete | Pass the physical port, check udev/mux logs, and use a known-good cable; USB is not part of recurring refresh. |
| Container socket permission mismatch | Backend cannot connect | Host setup creates a narrowly scoped group/GID; startup preflight reports exact socket problem. |
| mux daemon recreates a bind-mounted socket | Container retains a stale socket inode after restart | Keep the daemon/socket stable or use a dedicated host proxy; test mux and VM restart. |
| netmuxd regression or iOS network change | Required Wi-Fi transport stops | Pin a qualified release, retain direct `TcpProvider` adapter path, and use libimobiledevice/pymobiledevice3 as diagnostic oracles. |
| Malicious/huge IPA | Disk, memory or path compromise | Streaming limits, ZIP safety validation, per-job workspace, quotas, non-root/read-only container. |
| Secrets exposed by logs/backups | Account/device compromise | Typed redaction, AEAD per record, separate key backup, restore drill, no password retention. |
| Copyleft dependency accidentally linked/copied | Distribution obligations change | `cargo-deny`, SBOM, license review, keep GPL tools as separate diagnostics. |

## Fork decision

Do **not** fork iLoader for iPhoneLoadly. A fork would inherit a desktop/Tauri lifecycle, UI coupling, desktop credential assumptions, branding concerns and update-merge burden while still requiring a new REST API, database, scheduler and server secret store.

Preferred order:

1. Build the headless backend around published/pinned `idevice` and `isideload` dependencies.
2. Submit generic headless improvements upstream to isideload.
3. If upstream timing blocks the project, maintain a minimal isideload fork containing only session persistence, secret handling, install-progress hooks or signing fixes. Keep it rebased and document every delta.
4. Copy small MIT iLoader functions only when a reusable library API does not exist, with copyright/license attribution and tests.

## Architecture acceptance gates

Do not begin Version 0.2 until all Version 0.1 gates pass on the actual N100/Proxmox/Debian/iPhone path:

1. One-time USB trust/pairing succeeds and Wi-Fi device connections are enabled.
2. Pairing survives mux, VM and backend restarts without a new Trust prompt.
3. With the USB cable removed, mDNS sees the phone and the backend enumerates it as a network device.
4. Malformed, traversal and oversized IPA fixtures are rejected safely.
5. With the USB cable still removed, a safe unsigned or re-signable IPA is provisioned and signed locally, then installs over Wi-Fi with progress and an understandable result.
6. A deliberately invalid signature/profile sent over Wi-Fi fails with a useful translated error and retained technical diagnostics.
7. Network installation recovers after phone sleep, Wi-Fi reconnect, DHCP change, mux restart, backend restart and VM restart.
8. The service stays within the VM's memory/CPU budget and leaves no staged IPA behind after success/failure.
9. Authentication and log-redaction tests pass.

There is no optional USB-only completion path. Apple-account, 2FA, provisioning and signing are Version 0.1 gates. Automatic refresh remains deferred until a passwordless session-persistence proof-of-concept passes.

## Primary sources

- [iLoader repository and README](https://github.com/nab138/iloader)
- [iLoader Rust manifest](https://raw.githubusercontent.com/nab138/iloader/main/src-tauri/Cargo.toml)
- [iLoader device implementation](https://raw.githubusercontent.com/nab138/iloader/main/src-tauri/src/device.rs)
- [iLoader pairing implementation](https://raw.githubusercontent.com/nab138/iloader/main/src-tauri/src/pairing.rs)
- [iLoader account implementation](https://github.com/nab138/iloader/blob/main/src-tauri/src/account.rs)
- [isideload](https://github.com/nab138/isideload)
- [idevice](https://github.com/jkcoxson/idevice)
- [libimobiledevice](https://github.com/libimobiledevice/libimobiledevice)
- [usbmuxd](https://github.com/libimobiledevice/usbmuxd)
- [ideviceinstaller](https://github.com/libimobiledevice/ideviceinstaller)
- [ideviceinstaller source, including network/progress options](https://raw.githubusercontent.com/libimobiledevice/ideviceinstaller/master/src/ideviceinstaller.c)
- [pymobiledevice3](https://github.com/doronz88/pymobiledevice3)
- [pymobiledevice3 iOS 17+ tunnel guide](https://github.com/doronz88/pymobiledevice3/blob/master/docs/guides/ios17-tunnels.md)
- [Dadoum/Sideloader](https://github.com/Dadoum/Sideloader)
- [SideStore](https://github.com/SideStore/SideStore)
- [apple-platform-rs / apple-codesign](https://github.com/indygreg/apple-platform-rs)
- [apple-codesign crate manifest](https://raw.githubusercontent.com/indygreg/apple-platform-rs/main/apple-codesign/Cargo.toml)
- [netmuxd](https://github.com/jkcoxson/netmuxd)
- [netmuxd releases](https://github.com/jkcoxson/netmuxd/releases)
- [idevice TCP provider documentation](https://docs.rs/idevice/latest/idevice/provider/struct.TcpProvider.html)
- [pymobiledevice3 protocol layers and Wi-Fi discovery](https://github.com/doronz88/pymobiledevice3/blob/master/misc/understanding_idevice_protocol_layers.md)
- [Proxmox VE Administration Guide](https://pve.proxmox.com/pve-docs/pve-admin-guide.pdf)
