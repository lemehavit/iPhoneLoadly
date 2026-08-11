# Version 0.1: smallest implementation plan

Status: proposed  
Revised: 2026-08-10 — installation must use Wi-Fi  
Depends on: [architecture assessment](architecture-assessment.md)

## Goal and non-goals

Version 0.1 proves exactly this path on the real Debian VM and iPhone:

```text
Browser -> authenticated IPA upload -> persistent storage
        -> select a paired iPhone reachable on the home LAN
        -> provision and sign the IPA locally with the selected Apple account
        -> install the resulting IPA over Wi-Fi, with USB disconnected
        -> live progress -> useful success/failure diagnostics
```

USB is used only once for trust/pairing and enabling Wi-Fi connections. Version 0.1 authenticates to Apple interactively, handles 2FA, creates or reuses developer resources, provisions the selected device, signs the uploaded IPA locally, and installs it over Wi-Fi. It does not yet operate unattended, persist passwords, refresh automatically, or ingest sources. It **does** require working Wi-Fi discovery, staging and installation because these are prerequisites for the later automatic seven-day refresh workflow.

## Smallest deployable shape

One Rust service and one container:

- Axum HTTP API.
- React/Vite UI compiled to static files and served by Axum.
- SQLite database.
- `/data/apps` and `/data/jobs` persistent directories.
- Host Avahi plus a pinned network-capable mux, initially current `netmuxd`.
- Bind-mounted dedicated compatible mux socket, for example `/run/iphoneloadly/mux.sock`.
- No separate frontend container, Redis, message broker, scheduler service or privileged container.

For the first hardware spike, do not build the web UI. Pair and enable Wi-Fi once over USB, then remove the cable. Write a narrow Rust CLI/integration executable using the same `DeviceTransport` and `SigningProvider` adapters. It must authenticate an operator-supplied Apple account interactively, provision and sign one safe IPA for the selected device, then install it entirely over Wi-Fi. If any step fails, stop and resolve the Apple account, signing library, device library, mDNS, LAN or host boundary before building HTTP or React layers.

## Minimal data model

```sql
devices_snapshot(
  udid_hash TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  product_type TEXT,
  ios_version TEXT,
  connection_type TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
)

apps(
  id TEXT PRIMARY KEY,
  original_name TEXT NOT NULL,
  storage_name TEXT NOT NULL UNIQUE,
  sha256 TEXT NOT NULL UNIQUE,
  bundle_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  version TEXT,
  build_version TEXT,
  profile_expires_at TEXT,
  size_bytes INTEGER NOT NULL,
  uploaded_at TEXT NOT NULL
)

jobs(
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  app_id TEXT NOT NULL,
  target_udid_hash TEXT NOT NULL,
  state TEXT NOT NULL,
  phase TEXT NOT NULL,
  progress_percent INTEGER,
  public_message TEXT,
  diagnostic_code TEXT,
  diagnostic_detail TEXT,
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT
)

job_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  phase TEXT NOT NULL,
  progress_percent INTEGER,
  level TEXT NOT NULL,
  public_message TEXT NOT NULL,
  diagnostic_detail TEXT
)
```

Do not store full UDIDs in normal logs. The device adapter still needs the real UDID in memory to address the phone; store it encrypted if persistence is necessary, otherwise refresh it from the compatible mux and associate it with a keyed hash.

## Minimal API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/healthz` | Liveness only; no sensitive status. |
| `POST` | `/api/session` | Local administrator login. |
| `DELETE` | `/api/session` | Logout. |
| `GET` | `/api/devices` | Enumerate currently reachable paired devices. |
| `GET` | `/api/apps` | List uploaded validated IPAs. |
| `POST` | `/api/apps` | Multipart upload, validate, hash, persist, return metadata. |
| `DELETE` | `/api/apps/{id}` | Delete only when no active job references the app. |
| `POST` | `/api/install-jobs` | Body: `{ "appId": "...", "deviceId": "..." }`. |
| `GET` | `/api/jobs/{id}` | Current state and translated result. |
| `GET` | `/api/jobs/{id}/events` | Server-sent events for progress/log lines. |

SSE is sufficient because progress is server-to-browser. It is simpler than a WebSocket and reconnects using event IDs.

## Device install flow

The recommended Version 0.1 adapter uses `idevice` and follows the MIT isideload/iLoader installation approach over a network provider:

1. Get the target device from the network-capable mux by exact UDID; reject stale UI selections.
2. Require connection type `Network`. If only a USB entry exists, report that Wi-Fi is unavailable and do not install through the cable.
3. Construct an `IdeviceProvider` using the compatible mux socket. The fallback adapter constructs `idevice::TcpProvider` from the mDNS address and encrypted pairing record. The temporary environment-variable adapter is test-only and must never be enabled in a production container.
4. Start a lockdownd session using the host-managed pair record.
5. Open AFC and create a unique path such as `/PublicStaging/iphoneloadly-{job-id}.ipa`.
6. Stream the IPA over Wi-Fi in bounded chunks while reporting staging progress.
7. Connect to installation proxy and request installation of the staged package.
8. Convert installation-proxy status and percentage callbacks to job events.
9. On completion, verify that the returned status is complete. Optionally query the installed bundle ID as an additional check.
10. Remove the staged package on both success and failure, best effort.
11. Close all device services and release the per-device job lock.

Never shell out from a web request. All installs run as persisted background jobs with cancellation/timeout handling. A backend restart marks interrupted jobs as failed/interrupted and safely retries only after explicit user action in Version 0.1.

If the native Rust install spike exposes a blocking defect, the fallback is a fixed-argument `ideviceinstaller --network -u <UDID> install <server-generated-path>` adapter. Keep it isolated behind `DeviceTransport`, enforce a timeout, capture stdout/stderr separately, and document GPL distribution obligations. Do not use `shell=true` or interpolate a command string. A command without `--network` is diagnostic-only and cannot be the product fallback.

## Progress model

Expose these stable phases rather than raw Apple service names:

```text
queued
connecting
staging
installing
verifying
cleaning_up
succeeded | failed | canceled
```

Example public event:

```json
{
  "eventId": 17,
  "phase": "installing",
  "progressPercent": 62,
  "message": "Installing YouTubePlus on Fredriks iPhone"
}
```

Example failure response:

```json
{
  "state": "failed",
  "message": "The iPhone rejected this IPA's signature or provisioning profile.",
  "suggestions": [
    "Confirm that the profile includes this iPhone.",
    "Confirm that the profile has not expired.",
    "Upload an IPA signed for this device."
  ],
  "diagnostic": {
    "code": "ApplicationVerificationFailed",
    "detail": "...redacted low-level installation-proxy error..."
  }
}
```

Initial error translations:

| Technical class | User message |
|---|---|
| mux socket unavailable | Device service is unavailable on the server. Check netmuxd and the container socket mount. |
| device not found/disconnected | The iPhone is no longer connected. Reconnect it and keep it unlocked. |
| missing/invalid pair record | This iPhone is not trusted by the server. Pair it over USB and accept the Trust prompt. |
| passcode/device locked | Unlock the iPhone and try again. |
| signature/profile verification | The iPhone rejected the IPA's signature or provisioning profile. |
| profile device mismatch | The IPA is not provisioned for this iPhone. |
| profile expired | The IPA's provisioning profile has expired. |
| insufficient storage | The iPhone does not have enough free storage. |
| timeout | Communication with the iPhone timed out. Keep it connected/unlocked and retry. |

## Upload acceptance rules

Default configurable limits for the first build:

- 2 GiB maximum compressed upload.
- 4 GiB maximum total expanded size.
- 20,000 maximum archive entries.
- 200:1 maximum aggregate expansion ratio, with per-entry checks.
- Exactly one `Payload/<name>.app/Info.plist` main bundle.
- `CFBundleIdentifier` and at least one of display/bundle name present.
- `CFBundleShortVersionString` and `CFBundleVersion` parsed when present.
- An unsigned/re-signable input IPA is accepted only after strict archive and bundle metadata validation. Existing signing material is discarded or replaced only by the signing adapter in a private work directory.
- Reject encrypted ZIPs, absolute paths, drive prefixes, `..`, symlinks and conflicting duplicate paths.

Do not extract the full IPA merely to display metadata. Read only bounded selected entries from the ZIP. The actual installation adapter streams the original accepted IPA.

## Delivery increments

### Increment 0: host and hardware gate

Follow the [Debian 13.6 host preparation runbook](operations/debian13-host-preparation.md), then deliver command output proving one-time onboarding followed by cable-free operation:

```sh
lsusb | grep -i apple
idevicepair pair
idevicepair validate
pymobiledevice3 lockdown wifi-connections on
# Disconnect the USB cable here.
avahi-browse -rt _apple-mobdev2._tcp
ideviceinfo --network -u <UDID> -k DeviceName
ideviceinstaller --network -u <UDID> install signed.ipa
```

Pass condition: a known safe input IPA is provisioned and signed for the phone, then installs while USB is disconnected. The same network path still works after phone sleep/wake, Wi-Fi reconnect, mux restart and Debian VM reboot without a new Trust prompt or a stale container socket.

### Increment 1: native signing and device spike

- Create the Rust workspace and the `device-idevice` adapter.
- Enumerate network devices and print structured JSON including `connectionType: "network"`.
- Reject installation when the selected device is available only through USB.
- Perform Apple login and 2FA through a one-time terminal callback; never persist the password.
- Create or reuse developer resources and a provisioning profile that includes the selected iPhone.
- Sign one safe IPA in a private job directory, then install it over Wi-Fi with the cable removed.
- Emit phase/progress events to stdout.
- Add strict operation timeouts and best-effort staged-file cleanup.

Pass condition: an input IPA is signed for the selected iPhone and installs over Wi-Fi; an intentional invalid profile/signature failure produces a distinct, redacted result. USB must remain disconnected for both tests.

### Increment 2: safe IPA store

- Streaming upload/ingest library.
- ZIP safety validation and metadata/profile parsing.
- SHA-256 content-addressed storage.
- Unit tests with synthetic valid/invalid fixtures.

Pass condition: traversal, archive-bomb, malformed plist, multiple-app and missing-profile fixtures are rejected without leaving files.

### Increment 3: API, authentication, SQLite and jobs

- Local admin bootstrap/login.
- Device/app/job endpoints.
- One per-device semaphore and a small global worker pool.
- Persisted events and SSE.
- Typed error mapping and redacted tracing.

Pass condition: API tests run with `FakeDeviceTransport`; interrupted jobs recover to an explicit terminal state.

### Increment 4: minimal UI

One page with:

- current devices and transport;
- uploaded applications and metadata;
- upload action;
- device selector and Install button;
- progress timeline;
- public error plus expandable authenticated diagnostics.

Pass condition: the complete browser-to-phone flow works over Wi-Fi without using a terminal after the one-time host pairing.

### Increment 5: container and operations

- Multi-stage image with static UI and Rust binary.
- Non-root/read-only runtime and dedicated mux-socket GID setup.
- Compose file with persistent data, tmpfs and resource limits.
- Backup/restore and log-retention notes.
- End-to-end smoke script.

Pass condition: fresh deployment from documented steps works within the 1.5-2 GB / 2 vCPU VM budget.

## Independent diagnostic commands

Run these on the Debian host, not through the web application.

### Layer 1: Proxmox/USB

```sh
lsusb | grep -i apple
dmesg --follow
```

### Layer 2: USB onboarding and pairing

```sh
systemctl status netmuxd
journalctl -u netmuxd --since "10 minutes ago"
# If Debian usbmuxd is deliberately used for onboarding instead:
systemctl status usbmuxd
idevice_id -l
idevicepair pair
idevicepair validate
pymobiledevice3 lockdown wifi-connections on
```

Disconnect the USB cable before every remaining device command.

### Layer 3: mandatory Wi-Fi discovery and lockdownd

```sh
systemctl status avahi-daemon
systemctl status netmuxd
avahi-browse -rt _apple-mobdev2._tcp
ideviceinfo --network -u <UDID> -k DeviceName
ideviceinfo --network -u <UDID> -k ProductType
ideviceinfo --network -u <UDID> -k ProductVersion
```

### Layer 4: IPA structure

```sh
unzip -l signed.ipa | head -n 40
unzip -p signed.ipa 'Payload/*.app/Info.plist' | plutil -p -
unzip -p signed.ipa 'Payload/*.app/embedded.mobileprovision' > /tmp/profile.mobileprovision
openssl cms -inform DER -verify -noverify -in /tmp/profile.mobileprovision -out /tmp/profile.plist
plutil -p /tmp/profile.plist
```

The shell glob behavior varies; use a temporary isolated directory when manual inspection is awkward. Do not run these commands on untrusted uploads as the service user; the product parser must enforce its own limits.

### Layer 5: required Wi-Fi install oracle

```sh
ideviceinstaller --network -u <UDID> install signed.ipa
```

Exact command availability depends on the installed Debian package versions. Record package versions in every hardware test report.

## Test matrix

| Test | Expected result |
|---|---|
| Phone away from home LAN | Empty/offline device state; pending job is retained without a failure loop. |
| USB connected but Wi-Fi unavailable | Device may appear for onboarding, but install is refused because transport is not `Network`. |
| Network-visible but untrusted phone | Device/pairing error with USB onboarding instructions, no panic. |
| Trusted locked phone over Wi-Fi | Install succeeds if iOS permits it; otherwise show a clear unlock/retry state. |
| Valid unsigned/re-signable IPA | Local signing succeeds, Wi-Fi installation reaches success and staged file is removed. |
| Apple 2FA required | Job waits for a short-lived authenticated operator response; password is never persisted or logged. |
| Profile for another UDID | Install fails with device/profile guidance. |
| Expired profile | UI warns before install; device rejection remains available. |
| Wi-Fi loss during staging | Job becomes retryable/interrupted, resources close, and later LAN presence can resume with a fresh staging path. |
| Wi-Fi loss during installation | Job reaches a safe retryable/failed state; retry never assumes the partial installation succeeded. |
| Phone sleeps for 24 hours | Discovery/status remains understandable and reconnect works without USB. |
| DHCP address changes | mDNS/mux rediscovery replaces the stale address without changing device identity. |
| Duplicate IPA checksum | Return existing app or create a version record without duplicate blob. |
| Traversal/symlink/ZIP bomb fixture | Rejected before extraction, no out-of-root writes. |
| Two jobs for same phone | Second remains queued; never concurrent. |
| Backend restart during job | Job marked interrupted on startup. |
| netmuxd restart with container running | Backend reconnects through the stable socket/proxy; no container recreation or USB cable is required. |
| Unauthorized API request | `401/403`, including events and diagnostics. |
| Secret-like fixtures in errors | Redaction test proves they do not reach logs or API diagnostics. |

## Definition of done

Version 0.1 is done when a user can pair once over USB using documented host steps, remove the cable, and then use only the authenticated web UI to upload an unsigned or re-signable IPA, choose the iPhone discovered on the home LAN, complete Apple login/2FA, provision and sign the IPA locally, install it over Wi-Fi, watch real progress, and receive a useful success or failure result. The network install must survive routine Wi-Fi reconnects, phone sleep and service/VM restarts, meet upload safety checks, avoid privileged Docker access, and fit the target VM.

Auto-refresh and sources remain explicitly out of scope until this definition is met. No later phase may introduce USB installation as a fallback: it must sign locally, wait for the phone to be reachable on the home LAN, and install over Wi-Fi before the profile expires.
