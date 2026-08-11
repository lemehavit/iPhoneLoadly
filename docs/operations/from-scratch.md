# From-scratch installation

This guide installs iPhoneLoadly on Debian 13 amd64. The API stays on localhost;
use an SSH tunnel from a browser machine rather than exposing it directly.

## 1. Obtain the repository and host prerequisites

```bash
git clone https://github.com/lemehavit/lokal-ipa-signerare.git ~/iphoneloadly
cd ~/iphoneloadly
sudo bash deploy/host/install-debian13.sh
sudo apt-get install --yes docker.io
sudo systemctl enable --now docker
```

Install the Rust toolchain as the non-root deployment user if `cargo --version`
does not work. Use the official Rustup installer, then start a new shell before
continuing:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
```

Pair the iPhone by USB once, enable Wi-Fi pairing, then confirm that it is visible
over the trusted network. Follow `docs/operations/debian13-host-preparation.md`.

## 2. Start local anisette

Build the maintained source image and bind it to localhost only:

```bash
sudo docker build --pull --tag iphoneloadly-anisette:source https://github.com/Dadoum/anisette-v3-server.git
sudo docker run -d --name iphoneloadly-anisette-source --restart unless-stopped \
  --publish 127.0.0.1:6970:6969 \
  --volume iphoneloadly-anisette-source-libs:/home/Alcoholic/.config/anisette-v3/lib/ \
  iphoneloadly-anisette:source
curl --fail --silent http://127.0.0.1:6970/ >/dev/null
```

## 3. Build and configure the API

```bash
. "$HOME/.cargo/env"
cd ~/iphoneloadly
cargo build --release -p iphoneloadly-api
sudo install -d -o root -g root -m 0755 /opt/iphoneloadly/bin /var/lib/iphoneloadly /etc/iphoneloadly
sudo install -o root -g root -m 0755 target/release/iphoneloadly-api /opt/iphoneloadly/bin/iphoneloadly-api
sudo install -o root -g root -m 0644 deploy/systemd/iphoneloadly-api.service /etc/systemd/system/iphoneloadly-api.service
sudo install -o root -g root -m 0600 deploy/systemd/iphoneloadly-api.env.example /etc/iphoneloadly/api.env
sudoedit /etc/iphoneloadly/api.env
```

Set the device ID, iPhone IP, and pairing plist path in `/etc/iphoneloadly/api.env`.
Do not put an Apple-ID password or a two-factor code in that file.

Continue with `docs/operations/api-systemd.md` to enable the API and refresh timer.

## 4. Use the local dashboard

From the browser machine:

```powershell
ssh -N -L 8080:127.0.0.1:8080 debian-user@debian-host
```

Open `http://127.0.0.1:8080/`, sign in with Apple, complete 2FA, then upload and
install an IPA. Apple credentials are held only in memory and must be entered again
after an API or host restart.

## Backup and restore

Create a verified backup:

```bash
cd ~/iphoneloadly
sudo bash scripts/backup-state.sh
```

The archive includes uploaded IPA files, SQLite state, API configuration, the
pairing plist, and anisette libraries. Treat it as sensitive. For restore, stop
the API, verify `SHA256SUMS`, extract `iphoneloadly-system.tar.gz` at `/`, restore
`anisette-libs.tar.gz` to the named Docker volume, then start the API and sign in
with Apple again.
