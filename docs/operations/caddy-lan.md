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

## iPhone, iPad, and computer access

iPhoneLoadly publishes `iphoneloadly.local` on the local network through
Bonjour/mDNS. The application installer enables
`iphoneloadly-dashboard-mdns.service` automatically. Verify the published name
on Debian:

```bash
sudo systemctl status iphoneloadly-dashboard-mdns.service --no-pager
avahi-resolve --name iphoneloadly.local
```

The response must show the Debian LAN address, for example `192.168.8.104`.
Clients must use the same ordinary LAN/Wi-Fi as the Debian host. Guest Wi-Fi,
client isolation, separate VLANs without an mDNS reflector, and multicast
filtering prevent `.local` names from working.

Caddy uses a private local certificate authority. Before an iPhone or iPad can
open the dashboard without a certificate warning, install Caddy's root
certificate. The root certificate normally resides at:

```text
/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt
```

Create an unsigned iOS configuration profile that contains only this public
certificate (never a private key):

```bash
sudo /usr/local/libexec/iphoneloadly/create-caddy-ios-profile.sh \
  /var/tmp/iphoneloadly-caddy-root.mobileconfig
```

Transfer that `.mobileconfig` file to the iPhone/iPad through a trusted local
method, such as AirDrop, Files, or a private USB transfer. On the device,
install the downloaded profile in **Settings**, then explicitly enable it in
**Settings → General → About → Certificate Trust Settings**. Apple requires
this second trust action for manually installed root-certificate profiles.

On Windows, copy `root.crt` by a trusted local method, open it, and choose
**Install Certificate → Local Machine → Trusted Root Certification
Authorities**.

After a DHCP address change, restart the publisher so it advertises the new LAN
address:

```bash
sudo systemctl restart iphoneloadly-dashboard-mdns.service
```

## Verify the protection

Open `https://iphoneloadly.local` and sign in with the dashboard account. In a
private/incognito browser window, the same address must prompt for credentials.
The API must never listen on the LAN address:

```bash
sudo ss -ltnp | grep ':8080'
```

The output should show `127.0.0.1:8080`, not `0.0.0.0:8080` or a LAN IP.
