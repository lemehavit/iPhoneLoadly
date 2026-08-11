# LAN access with Caddy

Caddy exposes the iPhoneLoadly dashboard over HTTPS on the Debian LAN address
while the API remains bound to `127.0.0.1:8080`. A separate Caddy basic-auth
password protects all dashboard and API requests.

Install Caddy using its official Debian repository, generate a password hash
without exposing the password in a command line, then create the Caddyfile:

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
CADDY_HASH="$(printf '%s' "$CADDY_PASSWORD" | sudo caddy hash-password --algorithm argon2id)"
unset CADDY_PASSWORD

SERVER_IP='REPLACE-WITH-DEBIAN-LAN-IP'
sudo install -m 0644 deploy/caddy/Caddyfile.example /etc/caddy/Caddyfile
sudo sed -i \
  -e "s/REPLACE-WITH-DEBIAN-LAN-IP/$SERVER_IP/" \
  -e "s/REPLACE-WITH-DASHBOARD-USERNAME/$CADDY_USER/" \
  -e "s|REPLACE-WITH-CADDY-PASSWORD-HASH|$CADDY_HASH|" \
  /etc/caddy/Caddyfile
unset CADDY_USER CADDY_HASH SERVER_IP

sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo systemctl enable --now caddy
```

Open `https://<Debian-LAN-IP>/` and accept the browser warning only after
verifying the certificate fingerprint, or install Caddy's local root certificate
in the Windows trusted-root store. The root certificate normally resides at:

```text
/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt
```

Copy it to Windows with `scp`, then open it and choose **Install Certificate** →
**Local Machine** → **Trusted Root Certification Authorities**. Do not expose
ports 80 or 443 to the Internet; this configuration is for the trusted LAN only.
