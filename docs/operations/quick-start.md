# Legacy quick start

For the supported beginner path, start with [INSTALL.md](../INSTALL.md). This
page remains as a compact reference for an already prepared host.

Use a versioned release archive on Debian 13 amd64. It contains the compiled API,
systemd units, Caddy template, and backup tooling. Before installing, complete the
one-time iPhone USB pairing/Wi-Fi trust ceremony and start the local anisette
container as documented in `from-scratch.md`.

```bash
sudo sha256sum -c iphoneloadly-v0.2.0-alpha.2-linux-amd64.tar.gz.sha256
tar -xzf iphoneloadly-v0.2.0-alpha.2-linux-amd64.tar.gz
cd iphoneloadly-v0.2.0-alpha.2-linux-amd64

bash ./install-iphoneloadly.sh \
  --binary ./bin/iphoneloadly-api
```

Open `https://iphoneloadly.local` after configuring authenticated Caddy with
`docs/operations/caddy-lan.md`, or use an SSH tunnel as an administrator fallback.
Sign in with Apple and complete 2FA before
installing or refreshing apps.

## Backup and recovery test

```bash
sudo iphoneloadly-backup
sudo iphoneloadly-restore --verify /var/backups/iphoneloadly/REPLACE-WITH-BACKUP-DIRECTORY
```

`--verify` is non-destructive. `--apply` is deliberately guarded and overwrites
the installed state only after you type `RESTORE`.
