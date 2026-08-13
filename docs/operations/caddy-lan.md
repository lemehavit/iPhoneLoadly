# Protected LAN access with Caddy

Caddy exposes the iPhoneLoadly dashboard at `https://iphoneloadly.local` while
the API remains bound to `127.0.0.1:8080`. Caddy basic authentication protects
every dashboard and API request. The refresh timer calls the API directly on
loopback, so it continues to work without a browser password.

This is required before sharing the dashboard with other people. Do not forward
ports 80 or 443 from the router, and do not publish this service to the public
Internet.

## Configure a dashboard account

Install Caddy using its official Debian repository, generate a password hash
without placing the password in a shell command, then create the Caddyfile:

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install caddy

read -rp 'Dashboard username: ' CADDY_USER
read -rsp 'Dashboard password: ' CADDY_PASSWORD
printf '\n'
CADDY_HASH="$(printf '%s' "$CADDY_PASSWORD" | caddy hash-password --algorithm bcrypt --cost 14)"
unset CADDY_PASSWORD

sudo install -m 0644 deploy/caddy/Caddyfile.example /etc/caddy/Caddyfile
sudo sed -i \
  -e "s/REPLACE-WITH-DASHBOARD-USERNAME/$CADDY_USER/" \
  -e "s|REPLACE-WITH-CADDY-PASSWORD-HASH|$CADDY_HASH|" \
  /etc/caddy/Caddyfile
unset CADDY_USER CADDY_HASH

sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo systemctl enable --now caddy
```

## Name resolution and certificate trust

Each client must resolve `iphoneloadly.local` to the Debian server's LAN IP.
For a small private network, add this line to the Windows hosts file
(`C:\Windows\System32\drivers\etc\hosts`) as Administrator:

```text
REPLACE-WITH-DEBIAN-LAN-IP iphoneloadly.local
```

Install Caddy's local root certificate in the Windows trusted-root store before
opening `https://iphoneloadly.local`. The root certificate normally resides at:

```text
/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt
```

Copy it to Windows with `scp`, then open it and choose **Install Certificate** →
**Local Machine** → **Trusted Root Certification Authorities**.

## Verify the protection

Open `https://iphoneloadly.local` and sign in with the dashboard account. In a
private/incognito browser window, the same address must prompt for credentials.
The API must never listen on the LAN address:

```bash
sudo ss -ltnp | grep ':8080'
```

The output should show `127.0.0.1:8080`, not `0.0.0.0:8080` or a LAN IP.
