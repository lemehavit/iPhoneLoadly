# Run iPhoneLoadly API with systemd

This deployment keeps the API on `127.0.0.1:8080`. It requires the local anisette
container to remain bound to `127.0.0.1:6970`. Apple credentials are not stored
unless the user explicitly enables encrypted storage in the dashboard. After a
restart, iPhoneLoadly attempts to restore that saved sign-in; Apple may require 2FA.

Build the release binary, install it below `/opt`, then install the unit and its
root-only environment file:

```bash
cd ~/iphoneloadly
cargo build --release -p iphoneloadly-api
sudo install -d -o root -g root -m 0755 /opt/iphoneloadly/bin /var/lib/iphoneloadly /etc/iphoneloadly
sudo install -o root -g root -m 0755 target/release/iphoneloadly-api /opt/iphoneloadly/bin/iphoneloadly-api
sudo install -o root -g root -m 0644 deploy/systemd/iphoneloadly-api.service /etc/systemd/system/iphoneloadly-api.service
sudo install -o root -g root -m 0600 deploy/systemd/iphoneloadly-api.env.example /etc/iphoneloadly/api.env
sudoedit /etc/iphoneloadly/api.env
```

Keep `IPHONELOADLY_MUX_SOCKET` pointed at the dedicated `netmuxd` socket and
`IPHONELOADLY_PAIRING_DIR` at the host pairing-record directory. iPhoneLoadly
discovers trusted Wi-Fi devices dynamically; do not configure a fixed device IP
or UDID. Do not put an Apple-ID password or a two-factor code in this file.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now iphoneloadly-api
sudo systemctl status iphoneloadly-api --no-pager
curl --fail --silent http://127.0.0.1:8080/healthz
```

For logs:

```bash
sudo journalctl -u iphoneloadly-api -f
```

## Automatic refresh retry timer

The timer runs hourly with a random delay of up to ten minutes. It does not queue
anything until an IPA/device pair is at least six days past its last successful
installation. If the phone is asleep or unavailable, a later hourly run retries
when it is reachable; the dashboard history records the outcome. After a restart,
this requires Apple signing to be ready. A deliberately saved encrypted sign-in
can restore it automatically, although Apple may still request 2FA.

The timer runs hourly, but only queues an IPA/device pair once its latest
successful installation is at least six days old—about one day before the free
Apple signing period expires. It skips a target that already has a queued or
active job. Without encrypted credential storage, sign in again after restart;
with it enabled, restoration is attempted automatically and may still need 2FA.

```bash
sudo install -o root -g root -m 0644 deploy/systemd/iphoneloadly-refresh.service /etc/systemd/system/iphoneloadly-refresh.service
sudo install -o root -g root -m 0644 deploy/systemd/iphoneloadly-refresh.timer /etc/systemd/system/iphoneloadly-refresh.timer
sudo systemctl daemon-reload
sudo systemctl enable --now iphoneloadly-refresh.timer
systemctl list-timers iphoneloadly-refresh.timer
```

## Backup and restore

The installed commands create a checksum-verified backup and verify a backup
without changing the host:

```bash
sudo iphoneloadly-backup
sudo iphoneloadly-restore --verify /var/backups/iphoneloadly/REPLACE-WITH-BACKUP-DIRECTORY
```

Use `sudo iphoneloadly-restore --apply BACKUP_DIRECTORY` only when recovering a
host. It stops the API and asks you to type `RESTORE` before overwriting state.
