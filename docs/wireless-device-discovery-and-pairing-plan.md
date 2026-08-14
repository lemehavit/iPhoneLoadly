# Plan: automatic iPhone discovery and wireless pairing

## Decision summary

The work is divided into two separate product features:

1. **Automatic discovery of already trusted iPhones.** This is the stable,
   default path. It replaces manually configured UDIDs and fixed IP addresses
   and uses the current Wi-Fi/Lockdown transport after the initial USB pairing.
2. **Wireless first-time pairing.** This is a separate, feature-flagged iOS 27
   capability. Apple's public support starts with iOS/iPadOS 27 and Xcode 27
   Device Hub. The pinned `idevice` version contains building blocks for the
   same device-initiated RemotePairing flow, but the complete chain must be
   proven on real iPhone and Debian hardware before it is considered production
   support.

iOS 26 and earlier still require USB for the first connection. After that,
normal use, reinstallation, and refresh must work wirelessly without manual IP
configuration.

## Goals

- Automatically find every reachable, trusted iPhone on the local network.
- Support multiple phones and changing DHCP addresses.
- Clearly show online, offline, and pairing states in the web interface.
- Never install over USB accidentally; installation and refresh remain
  Wi-Fi-only operations.
- Give iOS 27 users a time-limited, user-initiated wireless first-pairing flow.
- Keep USB onboarding as a reliable fallback.
- Never expose UDIDs, pairing records, keys, or generic device tunnels through
  the API or logs.

## Non-goals

- Do not emulate the Apple TV PIN protocol on older iOS versions. Apple TV and
  iPhone use different onboarding behavior.
- Do not scan entire subnets or port 62078. Discovery must use DNS-SD/mDNS and
  `netmuxd`, not aggressive IP scanning.
- Do not pair automatically without an explicit administrator action and
  approval on the phone.
- Do not claim production support for iOS 27 before the phase 4 hardware gate.
- Do not expose a general-purpose TCP, usbmuxd, or RSD proxy through the web API.

## Current state and technical gaps

The current implementation:

- requires `IPHONELOADLY_DEVICE_ID`, `IPHONELOADLY_DEVICE_IP`, and
  `IPHONELOADLY_PAIRING_FILE`;
- creates one `DirectTcpTransport` with a fixed IP address;
- returns at most one phone from `GET /api/devices`;
- already includes Avahi, `netmuxd`, and a dedicated mux socket at
  `/run/iphoneloadly/mux.sock`;
- checks `_apple-mobdev2._tcp` and `idevice_id --network` during preflight but
  does not use that discovery in the API;
- lets `signing.rs` both sign and install and accepts only `TcpProvider`, which
  blocks an alternative RSD installation path; and
- treats device IDs as Rust `Uuid` values. An Apple UDID is a separate identifier
  type and must not be parsed or exposed as the application's internal UUID.

The first task is therefore not new protocol code. It is connecting the
existing `netmuxd` layer to the backend and introducing a real device registry.

## Support matrix

| Device state | Discovery | First pairing | Installation |
|---|---|---|---|
| Previously paired over USB, Wi-Fi enabled | Automatic through `netmuxd`/mDNS | Not applicable | Existing Lockdown path over Wi-Fi |
| Unpaired iPhone, iOS 26 or earlier | Must not appear as installable | USB required once | Wi-Fi after onboarding |
| Unpaired iPhone, iOS 27+ | Visible during an active pairing session | Experimental RemotePairing | Determined by hardware gate: Lockdown or RSD |
| Offline or sleeping, previously known | Shown as offline after timeout | Not applicable | Blocked until reachable |
| Visible only over USB | May appear as onboarding state | USB onboarding allowed | Installation over USB blocked |

## Intended user flow

### Previously paired phone

1. The user opens the dashboard.
2. The backend reads network devices from `netmuxd` and queries Lockdown for
   name, model, and iOS version with a short timeout.
3. The phone appears automatically as **Online via Wi-Fi**.
4. The user selects an IPA and phone and starts installation.
5. The backend resolves the phone's current mux entry again immediately before
   starting the job. It never trusts a stale IP address or UI snapshot.

### USB-based first onboarding

1. The UI shows **Add iPhone with USB** and step-by-step instructions.
2. The phone is connected and unlocked, and the user accepts **Trust This
   Computer**.
3. A setup tool pairs, validates, and enables Wi-Fi connections.
4. `netmuxd` restarts or reloads the pairing record.
5. USB is disconnected. Onboarding succeeds only after the same phone can be
   queried over the network.
6. The user never enters a UDID or IP address manually.

### Wireless first onboarding on iOS 27+

1. The administrator selects **Add iPhone wirelessly**.
2. The backend opens one time-limited pairing session and advertises a stable
   host identity as `_remotepairing-pairable-host._tcp.local`.
3. The iPhone finds the host. The exact menu and instructions are established
   during the hardware spike and documented per iOS version.
4. The phone connects to the pairing port and drives the RemotePairing flow.
5. The backend displays a six-digit one-time code in the authenticated dashboard.
6. The user enters the code on the phone and accepts the trust dialog.
7. The backend stores the RemotePairing identity and host `altIRK` encrypted,
   then stops advertising and closes the pairing port.
8. The backend proves a trusted transport and reads device information.
9. The phone is not marked **installable** until a signed test package has
   actually been installed over Wi-Fi.

## Recommended architecture

### 1. `DeviceRegistry`

Introduce a background service that owns the current view of all devices.

Responsibilities:

- read `ListDevices` from `/run/iphoneloadly/mux.sock`;
- filter for `idevice::usbmuxd::Connection::Network`;
- never use `Connection::Usb` for installation or refresh;
- query Lockdown for `DeviceName`, `ProductType`, and `ProductVersion`;
- update `last_seen_at`, status, and capabilities;
- map Apple UDIDs to internal, non-sensitive device IDs;
- keep real mux entries and UDIDs only in process memory;
- reconnect after `netmuxd` restarts and network changes;
- limit concurrent queries, for example to four devices; and
- use a per-device timeout so one sleeping phone cannot block the list.

The first implementation can poll every five seconds. Once stable, add
`UsbmuxdConnection::listen` for faster connect/disconnect events. Keep periodic
full resynchronization because daemon or socket restarts can lose events.

Proposed internal interfaces:

```rust
trait DeviceDiscovery: Send + Sync {
    async fn snapshot(&self) -> Result<Vec<DiscoveredDevice>, DiscoveryError>;
}

trait DeviceTransport: Send + Sync {
    async fn list_devices(&self) -> Result<Vec<Device>, TransportError>;
    async fn resolve(&self, id: DeviceId) -> Result<ResolvedDevice, TransportError>;
    async fn install_signed_ipa(
        &self,
        device: ResolvedDevice,
        ipa: PathBuf,
    ) -> Result<(), TransportError>;
}
```

`ResolvedDevice` is short-lived. It must verify the network connection type and
current trust session when a job starts and must not reuse an IP address from
the database.

### 2. Primary discovery adapter: `NetmuxDiscovery`

- Configure `IPHONELOADLY_MUX_SOCKET`, defaulting to
  `/run/iphoneloadly/mux.sock`.
- Connect with `idevice::usbmuxd::UsbmuxdAddr::UnixSocket`.
- Call `get_devices()` and keep only `Connection::Network`.
- Create a `UsbmuxdProvider` from the selected entry.
- Let `netmuxd` and the host pairing store provide Lockdown records through the
  mux protocol. The API process should not normally read plist files directly.
- Keep the existing `TcpProvider` only as a diagnostic fallback.

This removes the fixed-IP requirement and makes DHCP changes transparent.

### 3. Persistent device registry

Add a SQLite table through a versioned migration rather than more direct
`CREATE/ALTER` logic in `initialize`.

```sql
devices (
  id TEXT PRIMARY KEY,                 -- internal UUIDv7
  udid_hash TEXT NOT NULL UNIQUE,      -- HMAC-SHA256, never raw UDID
  display_name TEXT NOT NULL,
  product_type TEXT,
  ios_version TEXT,
  pairing_kind TEXT NOT NULL,          -- lockdown | remote_pairing
  onboarding_state TEXT NOT NULL,      -- trusted | experimental | revoked
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  last_network_seen_at TEXT
);
```

Rules:

- Use `id` in the API, jobs, and UI.
- Create `udid_hash` with a separate domain key and stable master key.
- Use raw UDIDs only for the current in-memory mux call.
- Do not store IP addresses.
- Previously known devices may appear offline, but installation requires a
  fresh registry entry.
- Existing jobs keep their internal UUIDs. Import a valid configured internal
  ID on first start; otherwise create a new ID and mark old jobs as legacy.

### 4. Separate signing from installation

Refactor `AppleSigningProvider::install_ipa(TcpProvider, ...)` into:

1. `SigningProvider::sign(...) -> SignedArtifact`;
2. `DeviceTransport::install_signed_ipa(...)`.

This is required because the same signed artifact must support classic
Lockdown and a possible RSD/CoreDevice path, while the signing layer must not
know about IP addresses, mux, or pairing records.

Implement the existing Lockdown/TCP installation first to preserve behavior.
Add an RSD adapter only if phase 4 proves it is necessary.

### 5. `PairingCoordinator`

Introduce a separate onboarding abstraction:

```rust
trait PairingCoordinator: Send + Sync {
    async fn start(&self, mode: PairingMode) -> Result<PairingSession, PairingError>;
    async fn status(&self, id: PairingSessionId) -> Result<PairingStatus, PairingError>;
    async fn cancel(&self, id: PairingSessionId) -> Result<(), PairingError>;
}
```

Allow only one active wireless pairing session initially. The session must:

- require an authenticated administrator and CSRF protection;
- expire after five minutes;
- allow no more than three PIN attempts;
- accept one phone and then close the listener;
- stop advertising on success, cancellation, timeout, or process exit; and
- never log PINs, pairing payloads, or private keys.

The first implementation may run in the API process because the current
deployment runs directly under systemd. Before container deployment, move the
LAN listener into a small host agent behind a private Unix socket. Do not solve
pairing-port and mDNS access with `--privileged` or host networking.

## iOS 27 prototype design

### Protocol building blocks

Pinned `idevice = 0.1.65` includes:

- `remote_pairing::PairableHost` for the device-initiated iOS 27 flow;
- `PairableHostInfo` and TXT records for
  `_remotepairing-pairable-host._tcp.local`;
- a six-digit PIN callback;
- `RpPairingFile`, `altIRK`, peer validation, and tunnel functions; and
- RSD and installation services behind separate Cargo features.

Do not enable the complete `full` feature. After the spike, enable only the
smallest verified feature set, likely `remote_pairing`, `mdns`, `rsd`, and the
installation service the test requires. Keep the exact version pinned and hide
protocol calls behind internal adapters.

### mDNS publication

The spike compares:

1. in-process DNS-SD through a small Rust library;
2. Avahi through a limited, typed integration.

Choose a solution that coexists with `avahi-daemon`, publishes correct TXT
records and IPv4/IPv6 addresses, stops deterministically, works with systemd
hardening, and can be tested without constructing shell commands.

Use a fixed, configurable high TCP port so the firewall rule remains narrow.
Listen only during an active session and reject routed WAN interfaces by default.

### Persistent secrets

- `RpPairingFile` for each wirelessly paired phone;
- the host's stable RemotePairing identifier;
- the host `altIRK`; and
- the master key for encryption and UDID HMAC.

Store this material encrypted with AEAD, owned by root or the service user, and
mode `0600`, using separate key domains. Include it in backups only as an
explicitly sensitive encrypted component. **Unpair** removes local pairing
state and marks that device revoked without deleting any other phone's records.

### Mandatory transport gate after pairing

RemotePairing success does not prove IPA installation. The spike must determine
which path works on iOS 27.

#### Path A: classic Lockdown becomes available

- The phone appears as a trusted `_apple-mobdev2._tcp`/`netmuxd` device.
- A Lockdown session starts without USB.
- The refactored existing installation adapter works.

This is the smallest and preferred product path when proven.

#### Path B: a separate RemotePairing/RSD transport is required

- Discover the phone's `_remotepairing._tcp` advertisement.
- Cryptographically match it to the saved RemotePairing identity.
- Establish a trusted userspace or system tunnel.
- Read device information through RSD.
- Install the signed IPA through a verified RSD/CoreDevice service.

If path B is required, implement it as `RsdDeviceTransport`; never smuggle a
tunnel address into `TcpProvider`. If RSD installation cannot be proven,
wireless pairing remains a lab feature even if the pairing dialog works.

## API proposal

### Devices

`GET /api/devices`

```json
[
  {
    "id": "019...",
    "displayName": "My iPhone",
    "productType": "iPhone17,1",
    "iosVersion": "27.0",
    "status": "online",
    "connectionType": "network",
    "pairingKind": "lockdown",
    "installEligible": true,
    "lastSeenAt": "2026-08-12T10:15:00Z"
  }
]
```

Stable product states are `online`, `offline`, `trustRequired`, `pairing`,
`unsupported`, and `revoked`. Raw Apple or library errors must not become the
API contract.

`POST /api/devices/rescan` requests an immediate resynchronization without
waiting for every phone. It should rarely be needed because the registry runs
in the background.

### Pairing sessions

- `POST /api/pairing-sessions` with `{ "mode": "wireless" }`.
- `GET /api/pairing-sessions/{id}` for initial UI polling.
- `DELETE /api/pairing-sessions/{id}` to cancel.

Example status:

```json
{
  "id": "019...",
  "phase": "awaitingDevice",
  "expiresAt": "2026-08-12T10:20:00Z",
  "setupCode": null,
  "publicMessage": "Open pairing on your iPhone."
}
```

When the phone connects, the phase becomes `awaitingCodeEntry` and `setupCode`
is shown only in the authenticated session. Final phases are
`verifyingTransport`, `ready`, `failed`, `cancelled`, and `expired`.

## UI plan

Replace the simple device select with device cards or a richer select showing:

- name, model, and iOS version;
- green **Online via Wi-Fi** or gray **Last seen ...** status;
- a disabled Install button when `installEligible` is false;
- **Scan again** for manual resynchronization;
- **Add iPhone**, with USB and feature-flagged wireless options;
- a step-by-step pairing dialog with countdown, PIN, and Cancel;
- a clear experimental label for iOS 27 until the hardware matrix passes; and
- no raw UDID, IP, HostID, or pairing-file path.

Handle these empty states separately: no known devices, known devices offline,
Bonjour available but trust missing, `netmuxd` unavailable, phone visible only
through USB, and iOS version without wireless first-pairing support.

## Security

- Start pairing only through an explicit administrator action.
- Keep the API bound to localhost behind the existing TLS proxy.
- Make the pairing port temporary, protocol-specific, and fail-safe.
- Cryptographically verify device identity before trust and every reconnect;
  never treat names or IP addresses as identity.
- Encrypt pairing state at rest and decrypt it only in memory.
- Log internal device ID and phase, never UDID, certificates, `altIRK`, PIN,
  pairing plist, or complete TXT records.
- Limit pairing attempts, session duration, and concurrency.
- Never interpolate user values into shell commands.
- Let `GET /healthz` report component health without listing devices or
  sensitive status.
- Verify backup and restore permissions and support restoring one phone without
  printing pairing material.

## Operations and configuration

After automatic discovery is implemented:

- add `IPHONELOADLY_MUX_SOCKET=/run/iphoneloadly/mux.sock`;
- remove production requirements for `IPHONELOADLY_DEVICE_IP` and
  `IPHONELOADLY_DEVICE_ID`;
- remove the API service `ExecStartPre` check for one pairing file;
- keep `/var/lib/lockdown` on the host and make `netmuxd` its normal reader;
- give the API user access only to the dedicated mux directory;
- run the API as a dedicated user after pairing/socket permissions are solved;
- add mux/discovery readiness to doctor and diagnostics; and
- document mDNS across VLANs, AP client isolation, IPv6, and pairing-port
  firewall requirements.

Feature flags:

```text
IPHONELOADLY_WIRELESS_PAIRING=off|experimental|on
IPHONELOADLY_PAIRING_PORT=<fixed high port>
IPHONELOADLY_PAIRING_INTERFACE=<empty or explicit LAN interface>
```

Allow `on` only after the production gate. Unknown or missing configuration
must behave as `off`.

## Delivery phases

### Phase 0: baseline and adapter boundaries

- Move device types and traits into separate modules.
- Introduce `DeviceId` around the internal UUID and private `AppleUdid` type.
- Move installation from `AppleSigningProvider` to the transport layer.
- Add `FakeDeviceDiscovery`, `FakeDeviceTransport`, versioned SQLite migrations,
  a `devices` table, and a regression test for current one-phone installation.

Acceptance: existing Wi-Fi installation is unchanged, Apple UDIDs are never
parsed as UUIDs, and tests simulate multiple devices without hardware.

### Phase 1: discover previously paired phones automatically

- Implement `NetmuxDiscovery` against the dedicated socket.
- Filter strictly for network connections.
- Add registry cache, timeouts, resync, reconnect, bounded parallel metadata
  queries, stable internal IDs, and persisted snapshots.
- Replace environment-variable transport in production startup while keeping
  fixed TCP configuration only for tests and diagnostics.

Acceptance: two paired phones appear automatically; no IP or UDID is entered;
DHCP changes, reconnect, sleep/wake, `netmuxd` restart, and host reboot require
no reconfiguration; USB-only devices cannot be selected for installation.

### Phase 2: multiple devices, API, and UI

- Extend `/api/devices` with status and capabilities.
- Add `/rescan`, offline history, device-aware empty states, and fresh device
  resolution at job start.
- Limit active jobs per device and globally.
- Make refresh skip offline devices with clear, redacted diagnostics.

Acceptance: jobs always target the correct phone during simultaneous connection
changes, offline devices cannot start jobs, and no raw identifiers reach API/UI.

### Phase 3: simplified USB onboarding

- Remove manual UDID/IP prompts from the installer.
- Identify the newly attached USB device unambiguously.
- Pair, validate, enable Wi-Fi, require USB disconnection, and approve onboarding
  only after a successful network query through the mux socket.
- Require explicit selection when multiple USB devices are connected.

Acceptance: a new iPhone is onboarded without copying UDID/IP, missed trust
approval has a concrete recovery path, and pairing records never appear in the
terminal.

### Phase 4: iOS 27 hardware spike

Build a separate test binary before integrating with the web API. In order:

1. advertise a pairable host with stable identity;
2. prove iPhone discovery on a Debian LAN;
3. complete PIN and trust;
4. reuse the RemotePairing record after process and host restart;
5. read name, UDID, and iOS version over trusted wireless transport;
6. determine installation path A or B;
7. sign and install a safe test IPA with USB physically disconnected;
8. repeat after sleep/wake, Wi-Fi change, and reboot;
9. test unpair and rejected/incorrect PIN; and
10. record model, exact iOS build, network, dependency commit, and log code.

Go only when the complete trust and installation chain works without USB on at
least two iPhone models and two iOS 27 builds, survives restart without a new
PIN, leaks no secrets, and uses reproducibly pinned upstream APIs. A no-go stops
phase 5 but does not block phases 1–3.

### Phase 5: experimental wireless pairing in the product

- Implement `PairingCoordinator`, time-limited mDNS, and pairing port.
- Add encrypted secret storage, pairing-session API/UI, verified Lockdown or RSD
  transport, cancel, timeout, rate limiting, cleanup, and unpair.
- Keep the feature behind `experimental`.

Acceptance: browser-to-iPhone onboarding works without terminal or cable;
cancellation leaves no port, advertisement, or partial state; unverified
transports are not installable; and USB fallback always remains available.

### Phase 6: hardening and general enablement

- Run the complete hardware matrix and long soak tests.
- Fuzz/property-test mDNS TXT and pairing-message parsing.
- Threat-model the LAN listener and secret store.
- Verify backup/restore, unpair, and iOS upgrades.
- Update installer, systemd, doctor, diagnostics, and user documentation.
- Move LAN pairing to a host agent before containerization if necessary.

Acceptance: at least 30 days of automatic reconnect/refresh tests without
manual re-pairing; upgrade and rollback preserve USB-paired devices; security
and log-redaction tests pass; support matrix and limitations are published.

## Test strategy

### Unit and integration tests without phones

- mux lists containing zero, one, or several network/USB devices;
- duplicate entries for the same UDID;
- device disappearance between listing and job start;
- malformed and non-UUID Apple UDIDs;
- timeout or broken pairing record for one of several phones;
- disappearing and returning `netmuxd` socket;
- stable internal ID mapping after restart;
- no IP, UDID, PIN, or keys in serialized API errors or logs;
- pairing state machine success, reject, timeout, cancel, and process stop;
- migration and rollback with an existing database; and
- refresh against online and offline targets.

### Hardware matrix

- one older iPhone on iOS 26 or earlier for USB onboarding and auto-discovery;
- at least two iOS 27 models for wireless pairing;
- a typical home network and a VLAN/mDNS-reflector network;
- IPv4, IPv6, and dual stack;
- AP client isolation as a negative test;
- locked, unlocked, sleeping, and rebooted phone states;
- host reboot, `netmuxd` restart, and DHCP lease change;
- two phones online simultaneously; and
- wrong PIN, rejected trust, timeout, and explicit unpair.

Record exact iOS build, model, Debian version, `idevice`/`netmuxd` versions, and
transport path while redacting UDIDs and pairing material.

## Observability and error model

Stable diagnostic codes:

- `discovery_mux_unavailable`
- `discovery_no_network_devices`
- `device_offline`
- `device_usb_only`
- `device_trust_required`
- `pairing_not_supported`
- `pairing_advertise_failed`
- `pairing_rejected`
- `pairing_expired`
- `pairing_transport_unverified`
- `install_transport_unavailable`

Log request/job/session ID, internal device ID, phase, duration, and code. Do not
log raw upstream errors until typed redaction has processed them.

Doctor checks mux socket and `netmuxd`, Avahi/mDNS, anonymous network-device
count, targeted Lockdown query by internal ID, feature flag and pairing port,
secret-store permissions, and that no pairing advertisement exists without an
active session.

## Migration and rollback

1. Ship database and adapter refactoring without removing legacy variables.
2. Prefer new discovery when healthy; allow an explicit legacy flag for one
   transition release.
3. Import the configured phone on its first successful network discovery.
4. Remove IP/UDID/pairing-file inputs from the default installer only after the
   phase 1 hardware gate.
5. Preserve pairing records during rollback and keep initial migrations additive.
6. Keep iOS 27 wireless pairing off by default and independently disableable.

## Main risks

| Risk | Impact | Mitigation |
|---|---|---|
| RemotePairing does not provide a transport usable by the installer | Pairing succeeds but IPA installation fails | Phase 4 requires a real installation; add a separate RSD adapter if needed |
| Private Apple protocol changes between iOS builds | Onboarding or reconnect breaks | Exact pinning, adapter boundary, hardware matrix, and feature flag |
| VLAN/AP blocks mDNS | Phones are not found | Clear doctor output, documented reflector/firewall, no subnet scan |
| Sleeping phone causes slow API calls | Dashboard and refresh stall | Cache, short timeout, bounded concurrency, and offline status |
| Wrong phone selected after a network change | Installation targets the wrong device | Cryptographic/UDID identity and resolution immediately before jobs |
| Pairing endpoint exposed on LAN | Attack surface and denial of service | Explicit five-minute session, rate limit, one client, fail-safe cleanup |
| Pairing state or UDID leaks | Persistent device access is exposed | AEAD, mode `0600`, typed redaction, no generic debug dumps |
| Pre-0.2 upstream `idevice` API breaks | Build or runtime failure | Exact version/commit and contract-tested internal adapter |

## Definition of done

### Automatic discovery

- Production configuration has no fixed iPhone IP.
- Users never copy UDIDs.
- Every trusted Wi-Fi device appears and updates automatically.
- Multiple phones, DHCP changes, sleep/wake, and daemon/host restarts are tested.
- Installation and refresh verify `Network` at job start.
- Raw identifiers and pairing records are never exposed.

### Wireless iOS 27 pairing

- Pairing starts and completes without USB.
- Pairing state survives controlled restart and supports unpair.
- The device is rediscovered and authenticated without a new PIN.
- A real safe test IPA is signed and installed over Wi-Fi.
- Negative tests leave no listener or partial pairing state.
- The feature can be disabled immediately without affecting USB fallback.

## Recommended first delivery

Deliver phases 0–3 together: dynamic `netmuxd` discovery, multiple phones, and
USB onboarding without manual IP/UDID. This provides the largest user benefit
with the lowest protocol risk.

Then run phase 4 as an isolated iOS 27 spike. Do not expose wireless pairing in
the dashboard until the same pairing record has produced a real IPA installation
with USB physically disconnected.

## References

- Apple: [Managing your simulated and physical devices in Device Hub](https://developer.apple.com/documentation/xcode/pairing-your-devices-with-your-mac)
- `pymobiledevice3`: [iOS 17+ tunnels](https://github.com/doronz88/pymobiledevice3/blob/master/docs/guides/ios17-tunnels.md)
- Pinned `idevice` 0.1.65: `remote_pairing::PairableHost`,
  `PairableHostInfo`, `RpPairingFile`, `mdns`, and `usbmuxd`
- Existing host design: [architecture-assessment.md](architecture-assessment.md)
- Existing delivery plan: [mvp-v0.1-plan.md](mvp-v0.1-plan.md)
