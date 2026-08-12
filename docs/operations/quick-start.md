# Legacy quick start

For the supported beginner path, start with [INSTALL.md](../INSTALL.md). This
page remains as a compact reference for an already prepared host.

Use a versioned release archive on Debian 13 amd64. It contains the compiled API,
systemd units, Caddy template, and backup tooling. Before installing, complete the
one-time iPhone USB pairing/Wi-Fi trust ceremony and start the local anisette
container as documented in `from-scratch.md`.

```bash
tar -xzf iphoneloadly-v0.1.0-linux-amd64.tar.gz
cd iphoneloadly-v0.1.0-linux-amd64
sudo sha256sum -c ../iphoneloadly-v0.1.0-linux-amd64.tar.gz.sha256

PAIRING_FILE="$(sudo find /var/lib/lockdown -maxdepth 1 -type f -name '00008110-*.plist' -print -quit)"
bash ./install-iphoneloadly.sh \
  --binary ./bin/iphoneloadly-api \
  --device-id 'REPLACE-WITH-LOCAL-DEVICE-ID' \
  --device-ip 'REPLACE-WITH-IPHONE-IP' \
  --pairing-file "$PAIRING_FILE"
```

Open the dashboard through an SSH tunnel or configure Caddy with
`docs/operations/caddy-lan.md`. Sign in with Apple and complete 2FA before
installing or refreshing apps.

## Backup and recovery test

```bash
sudo iphoneloadly-backup
sudo iphoneloadly-restore --verify /var/backups/iphoneloadly/REPLACE-WITH-BACKUP-DIRECTORY
```

`--verify` is non-destructive. `--apply` is deliberately guarded and overwrites
the installed state only after you type `RESTORE`.
