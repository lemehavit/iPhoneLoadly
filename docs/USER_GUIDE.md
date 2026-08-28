# iPhoneLoadly user guide

This guide covers the normal workflow after the server, Caddy, and the initial
USB pairing have been configured. The dashboard is normally available at:

```text
https://iphoneloadly.local
```

A certificate warning may appear because Caddy uses a local certificate
authority. On a network you trust, you can continue past the browser warning or
install Caddy's public root certificate by following the
[Caddy LAN guide](operations/caddy-lan.md). Never expose the dashboard directly
to the Internet.

## 1. The five dashboard views

![Dashboard overview](images/dashboard-overview.png)

The dashboard is organized into five views:

- **Overview** shows signing readiness, the reachable trusted iPhone, installed
  iPhoneLoadly apps, signing validity, and refresh attention. Use the primary
  action to move to Install.
- **Apps** contains the IPA Library, file upload, app details, and GitHub IPA
  sources. Select an IPA row for rename, technical details, or deletion.
- **Install** is the guided installation flow. Choose an IPA and a reachable
  iPhone, resolve the readiness checklist, then select **Sign and install**.
- **Activity** separates active jobs from recent history. Expand a job for its
  safe public result, progress, and timestamps.
- **Settings** contains Apple signing, encrypted credential state, automatic
  refresh, software updates, certificate recovery, and language.

The language selector switches the complete interface between English and
Swedish. On an iPhone, the five views are available from the bottom tab bar;
on larger screens, navigation stays at the top.

## 2. Sign in with Apple

![Apple signing and IPA upload](images/dashboard-workflow.png)

1. Open **Settings → Apple signing**.
2. Enter the Apple ID email address and password.
3. Select **Save credentials encrypted on this server** only if you want the
   server to attempt to restore the session after a restart.
4. Select **Sign in** and enter the Apple 2FA code in the in-app dialog when
   requested.
5. Confirm that the signing badge reports **Ready**.

The password remains in memory only unless encrypted storage is explicitly
enabled. Two-factor authentication codes are never stored. Apple may still
require a new code after a server restart.

Use **Release an old development certificate** under **Advanced** only if Apple
explicitly reports that the certificate limit has been reached. Revoking a
certificate can make previously signed apps unavailable until they are signed
again.

## 3. Manage IPA files and GitHub sources

1. Open **Apps** and select **+ Add IPA**.
2. Choose **Upload file**, select an `.ipa`, optionally enter a display name,
   and select **Upload**.
3. Follow the determinate upload percentage and the subsequent **Validating
   IPA** state. The IPA appears in the library after successful validation.
4. Select an IPA row for its bundle ID, size, SHA-256, rename action, or
   **Delete from server** action.

Deleting removes the server IPA only. It does not uninstall an app already on
the iPhone, and deletion is blocked while an installation or refresh job uses
the file.

To use a GitHub source, select **Add source** in Apps. Enter only a public
`owner/repo` or canonical `https://github.com/owner/repo` repository, choose an
exact asset pattern such as `*.ipa`, and optionally link an existing IPA.
Preview the release before saving. The pattern must match exactly one IPA asset;
ambiguous releases are never guessed.

Use **Check latest** and **Download latest** for manual updates. A downloaded
IPA is validated like a browser upload. When linked to an existing app, its
bundle identifier must match and the logical app ID and history remain stable.
Downloading does not install the IPA on the phone.

Automatic downloads are off by default. Read and explicitly acknowledge the
security information before enabling automatic synchronization. Repository,
pattern, or prerelease changes disable the acknowledgement. Automatic sync
updates the server copy only; an enabled automatic refresh may use that copy
later.

## 4. Install and refresh a trusted iPhone

![Installation and history](images/dashboard-installation.png)

1. Open **Install**.
2. Confirm that Apple signing, an IPA, and a reachable iPhone are all marked
   ready in the checklist.
3. Choose the IPA and phone, then select **Sign and install**.
4. Follow the active job through queued, connecting, signing, transfer, and
   installation. The progress percentage is the persisted server job progress.
5. Use **Activity** for the active or completed result.

The phone may need to be unlocked. If it does not appear, select **Scan again**
from Overview. If it remains offline, check Wi-Fi, `iphoneloadly-netmuxd`, and
Bonjour.

**Refresh all previous installations** is a secondary action in Install. It
uses the configured refresh day and reports how many eligible jobs were queued.
Configure the day under **Settings → Automatic refresh**. Day 6 is the default
and recommended value because it normally leaves about one day before a free
seven-day signing expires. The setting is stored in the server database and
survives restarts.

## 5. Devices and management

Overview presents the reachable phone's name, model, iOS version, and **Online
via Wi-Fi** state. It also lists iPhoneLoadly-managed apps physically detected
on the selected phone and managed app/device records, including stale records.

Use **Remove from management** only to stop tracking and refreshing an
app/device pair that was deleted manually from the iPhone. The in-app dialog
explains that this action:

- does not uninstall anything from the phone;
- does not delete the server IPA;
- does not unpair or delete the trusted phone; and
- keeps installation history.

A later successful installation restores management automatically. True phone
unpairing is not provided by this dashboard.

## 6. Activity, validity, and updates

![Automatic refresh setting](images/dashboard-refresh-settings.png)

**Activity** shows the latest 20 jobs. Active jobs appear first with a spinner,
phase, and real progress where available. Completed and failed jobs show a
terminal icon and expandable safe diagnostics. Passwords, Apple sessions, and
complete phone identifiers are never displayed.

**Overview** shows remaining signing days for successful installations and
only shows refresh attention when an item needs action.

Under **Settings → Software update**, select **Check for updates**. If a
verified release is available, **Update now** shows the current and target
versions before requesting the update. During the verified download, install,
and API restart, the dashboard reports the reconnecting state. Success is
shown only after the service is reachable again at the expected version.

## Troubleshooting

- [Installation and common troubleshooting](INSTALL.md#troubleshooting)
- [Caddy and LAN access](operations/caddy-lan.md)
- [Debian, Bonjour, and Wi-Fi](operations/debian13-host-preparation.md)
- [Systemd, refresh, backup, and recovery](operations/api-systemd.md)
