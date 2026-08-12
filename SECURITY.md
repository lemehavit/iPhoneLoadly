# Security policy

## Security model

iPhoneLoadly is a self-hosted service for a trusted Debian host and iPhone. It
is experimental software; use a dedicated Apple ID and give host access only to
people you trust.

The API binds to `127.0.0.1:8080` by default. It is not exposed to the LAN or
Internet unless an administrator deliberately configures an SSH tunnel or a
separately authenticated Caddy reverse proxy. Do not publish the dashboard,
Apple-login endpoints, or port 8080 to the Internet.

Apple passwords and two-factor responses are submitted to the local dashboard
and kept only in the process memory used for the current signing session. They
are not written to iPhoneLoadly configuration or SQLite state. Restarting the
API ends that session and requires another sign-in.

The pairing record in `/var/lib/lockdown` is sensitive host-to-device
authentication material. The API needs it to reach the configured phone over
trusted Wi-Fi. Do not share it, place it in source control, or include its
contents in support requests. Uploaded IPA files and SQLite metadata live in
`/var/lib/iphoneloadly`; backups of that directory are sensitive too.

The supplied API service currently runs as `root` because it reads the
root-owned lockdown pairing record and uses host device-transport material.
Its systemd sandbox remains enabled. Moving it to an unprivileged account needs
a device-backed verification of pairing, file access, and Wi-Fi installation;
it has not been assumed safe merely from static inspection.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability or disclose
credentials, pairing records, UDIDs, tokens, or private keys. Contact the
repository owner privately through the contact method listed on the GitHub
profile, with a minimal reproduction and affected version. Allow time for a
fix before public disclosure.
