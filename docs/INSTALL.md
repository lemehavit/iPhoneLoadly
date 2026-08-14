# Install iPhoneLoadly

This is the supported beginner path for a new host. It installs iPhoneLoadly on
**Debian 13 amd64** and keeps the dashboard private on the server at
`127.0.0.1:8080`. You need sudo access, Internet access for Debian packages and
the pinned host tool, an iPhone, and a USB cable for the first trust ceremony.

Do not run the installer on another Debian release or architecture. Do not put
Apple passwords, two-factor codes, pairing files, or UDIDs in shell history,
chat, or Git.

## 1. Download a release

When a release is published, download both the Linux amd64 archive and its
matching `.sha256` file from the [GitHub Releases page](https://github.com/lemehavit/iPhoneLoadly/releases).
The version in the two filenames must match.

```bash
mkdir -p ~/iphoneloadly-install && cd ~/iphoneloadly-install
# Copy the two downloaded release assets into this directory.
sha256sum -c iphoneloadly-v<VERSION>-linux-amd64.tar.gz.sha256
tar -xzf iphoneloadly-v<VERSION>-linux-amd64.tar.gz
cd iphoneloadly-v<VERSION>-linux-amd64
```

Expected checksum result:

```text
iphoneloadly-v<VERSION>-linux-amd64.tar.gz: OK
```

The current alpha package version is `v0.2.0-alpha.2`. If that release is unavailable,
use the advanced source-build instructions in
[from-scratch.md](operations/from-scratch.md); never substitute an unverified
archive from another site.

## 2. Start the local anisette service

Signing needs an anisette service. The current supported deployment builds the
upstream anisette service locally and binds it to localhost. Review the upstream
project before using it; it is an external component, not part of iPhoneLoadly.

```bash
sudo apt-get update
sudo apt-get install --yes docker.io
sudo systemctl enable --now docker
sudo docker build --pull --tag iphoneloadly-anisette:source https://github.com/Dadoum/anisette-v3-server.git
sudo docker run -d --name iphoneloadly-anisette-source --restart unless-stopped \
  --publish 127.0.0.1:6970:6969 \
  --volume iphoneloadly-anisette-source-libs:/home/Alcoholic/.config/anisette-v3/lib/ \
  iphoneloadly-anisette:source
curl --fail --silent http://127.0.0.1:6970/ >/dev/null && echo 'anisette: OK'
```

Expected: `anisette: OK`. The API and anisette service both remain localhost
only. This source-build step is manual because the upstream is not yet pinned by
an immutable, independently verified release artifact in this project.

## 3. Run the setup assistant

Connect and unlock the iPhone before starting. The assistant installs Debian
packages, verifies the pinned `netmuxd` archive and binary checksums, installs
the systemd units, performs the pairing ceremony, enables Wi-Fi connections,
creates safe configuration, starts the API and refresh timer, and runs a health
check. The source-install path installs iPhoneLoadly's isolated Rust 1.89.0
toolchain and Cargo needed to build the API; Debian's older Rust package is not
used. The installer explicitly selects that toolchain during the build. It does
not save Apple credentials or expose port 8080.

When the installer asks for the Trust This Computer confirmation, it waits up to
120 seconds for the iPhone response. Keep the phone connected and unlocked, then
tap **Trust** and enter the device passcode if iOS requests it.

```bash
sudo bash ./install.sh
```

During setup, connect and unlock exactly one iPhone, then accept **Trust This
Computer** on the phone. Disconnect USB when prompted. The installer identifies
that phone, enables Wi-Fi connections, and verifies the same trusted device over
the network before it continues; it never asks you to enter a UDID or IP address.
If that verification times out, keep USB disconnected and use the diagnostics
below before repeating the pairing ceremony.

## 4. Open the dashboard and install an IPA

For normal use on a trusted LAN, configure the authenticated Caddy endpoint by
following [caddy-lan.md](operations/caddy-lan.md), then open:

```text
https://iphoneloadly.local
```

An SSH tunnel remains available as an administrator fallback:

From your own computer, make an SSH tunnel to the Debian host:

```bash
ssh -N -L 8080:127.0.0.1:8080 YOUR_USER@YOUR_SERVER
```

Open the dashboard, sign in with your Apple ID, complete 2FA, upload an IPA,
select the discovered phone, and create an installation job. The password stays
in memory unless you explicitly select encrypted credential storage; 2FA is never
saved. Apple may still require 2FA after an API or server restart.
The job view shows signing progress and then the device-transfer phase. Use
**Ta bort vald IPA från servern** to permanently remove an uploaded IPA when it
is no longer needed; it is unavailable while that IPA has an active installation
or refresh job, and a removed IPA cannot be refreshed later.

The refresh timer runs hourly with up to a 10-minute delay. The dashboard lets
you choose automatic refresh on day 1–6 after the latest successful install;
day 6 is the default and is recommended for refreshing about one day before a
free signing normally expires. If the phone is unavailable, a later hourly run
retries automatically; use the History and diagnostics view to see each result.

The Overview shows remaining free-signing days for successful installations and
lists only apps that iPhoneLoadly installed on the selected trusted iPhone.

Use Caddy only on a trusted LAN with authentication; never expose it to the Internet.

On an iPhone or iPad, open `https://iphoneloadly.local` only after completing
the Bonjour name-resolution and Caddy certificate-trust steps in
[caddy-lan.md](operations/caddy-lan.md). A raw IP address is not a supported
dashboard URL because Caddy's HTTPS certificate is issued to
`iphoneloadly.local`.

## Troubleshooting

### Dashboard does not open

Check:

```bash
sudo systemctl status iphoneloadly-api --no-pager
curl --fail http://127.0.0.1:8080/healthz
```

If the API is healthy but an iPhone cannot open `https://iphoneloadly.local`,
verify the dashboard mDNS record and that the iPhone has trusted Caddy's root
certificate:

```bash
sudo systemctl status iphoneloadly-dashboard-mdns.service --no-pager
avahi-resolve --name iphoneloadly.local
```

The address must be the Debian LAN address. Do not use a Docker address or a raw
IP URL. See [caddy-lan.md](operations/caddy-lan.md) for the iPhone trust steps.

### iPhone is not detected or reachable

Unlock and reconnect it over USB, accept Trust, repeat the Wi-Fi enable step,
then disconnect USB. Confirm both devices use the same Wi-Fi/LAN and run:

```bash
sudo iphoneloadly-doctor
sudo bash /usr/share/iphoneloadly/scripts/preflight-wifi.sh
```

If Bonjour or direct Wi-Fi fails, check Wi-Fi client isolation, VLAN multicast
filtering and `iphoneloadly-netmuxd` status. Do not delete
pairing records unless you intentionally want to pair again.

### Apple sign-in fails

First confirm the local anisette endpoint:

```bash
curl --fail http://127.0.0.1:6970/
sudo systemctl status iphoneloadly-api --no-pager
```

Enter the password and 2FA response only in the local dashboard. A delayed or
failed 2FA interaction can time out; start a new sign-in. Any API restart ends
the memory-only signing session unless you explicitly selected **Save
credentials encrypted on this server**. That optional setting stores the Apple
email and password encrypted with a root-only local key; on restart the service
attempts to sign in again. Apple may still require a new 2FA response. Use
**Remove saved credentials** to delete the encrypted record. A server root user
can access the encryption key, so enable this only on a server you administer.

### Apple reports that the development-certificate limit is reached

For a free Apple developer account, iPhoneLoadly saves its signing key in its
root-only service data directory and reuses the matching Apple certificate
after a new login. You should therefore only select **Frigör gammalt
utvecklingscertifikat** if Apple explicitly reports that the certificate limit
has been reached. The next signing session then revokes one older development
certificate only if Apple rejects new-certificate creation for reaching the
limit. Revoking a certificate can invalidate apps signed with it; do not use
this action if an existing certificate supports an app you need to keep running.

### An app does not install

Check the job in the dashboard, then inspect redacted service logs:

```bash
sudo journalctl -u iphoneloadly-api -n 100 --no-pager
sudo iphoneloadly-doctor
```

Confirm the Apple signing session is active, the IPA is valid, and the phone is
awake and reachable over Wi-Fi. See [test IPA strategy](operations/test-ipa-strategy.md)
for the required real-device test conditions.

### Automatic refresh does not happen

Check the timer and trigger a safe API check after signing in:

```bash
systemctl list-timers iphoneloadly-refresh.timer
sudo systemctl status iphoneloadly-refresh.timer --no-pager
curl --fail -X POST http://127.0.0.1:8080/api/refresh
```

Refresh is not a guarantee: it needs Apple signing to be ready, a reachable
phone, and an app that has reached the configured automatic-refresh day. The
setting is stored on the server and defaults to day 6. A saved encrypted sign-in
can restore the Apple login after restart, though Apple may still require 2FA.

## Advanced paths

- [Illustrated dashboard user guide](USER_GUIDE.md)
- [Host and pairing details](operations/debian13-host-preparation.md)
- [Systemd, backup, and recovery operations](operations/api-systemd.md)
- [Secure Caddy LAN proxy](operations/caddy-lan.md)
- [Source build](operations/from-scratch.md)
