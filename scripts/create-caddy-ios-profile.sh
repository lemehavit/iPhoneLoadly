#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

usage() {
  cat <<'EOF'
Usage: create-caddy-ios-profile.sh OUTPUT.mobileconfig [ROOT.crt]

Creates an unsigned iOS configuration profile containing only Caddy's public
local root certificate. It never reads or exports a private key.
EOF
}

[[ $# -ge 1 && $# -le 2 ]] || { usage >&2; exit 2; }
output="$1"
root_certificate="${2:-/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt}"

command -v openssl >/dev/null || { echo 'openssl is required.' >&2; exit 1; }
command -v base64 >/dev/null || { echo 'base64 is required.' >&2; exit 1; }
[[ -r "${root_certificate}" ]] || { echo "Caddy root certificate is not readable: ${root_certificate}" >&2; exit 1; }

certificate_data="$(openssl x509 -in "${root_certificate}" -outform DER | base64 --wrap=0)"
[[ -n "${certificate_data}" ]] || { echo 'Unable to encode Caddy root certificate.' >&2; exit 1; }

umask 077
cat >"${output}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadCertificateFileName</key>
      <string>iphoneloadly-caddy-root.crt</string>
      <key>PayloadContent</key>
      <data>${certificate_data}</data>
      <key>PayloadDescription</key>
      <string>Trusts the local HTTPS certificate authority used by iPhoneLoadly.</string>
      <key>PayloadDisplayName</key>
      <string>iPhoneLoadly Local HTTPS Root</string>
      <key>PayloadIdentifier</key>
      <string>local.iphoneloadly.caddy-root.certificate</string>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadUUID</key>
      <string>51F5B594-5085-4F74-9E72-8BFBCCF970B9</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDescription</key>
  <string>Allows this iPhone or iPad to securely reach iPhoneLoadly on the local network.</string>
  <key>PayloadDisplayName</key>
  <string>iPhoneLoadly Local HTTPS</string>
  <key>PayloadIdentifier</key>
  <string>local.iphoneloadly.caddy-root</string>
  <key>PayloadOrganization</key>
  <string>iPhoneLoadly</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>2D3E05A1-716E-4648-A5F3-89050C1D36EB</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
EOF

printf 'Created iOS profile containing only the public Caddy root certificate: %s\n' "${output}"
