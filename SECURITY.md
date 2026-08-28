# Security policy

## Security model

iPhoneLoadly is a self-hosted service for a trusted Debian host and iPhone. It
is experimental software; use a dedicated Apple ID and give host access only to
people you trust.

The API binds to `127.0.0.1:8080` by default. It is not exposed to the LAN or
Internet unless an administrator deliberately configures an SSH tunnel or a
separately authenticated Caddy reverse proxy. Do not publish the dashboard,
Apple-login endpoints, or port 8080 to the Internet.

Apple passwords and two-factor responses are submitted only to the local
dashboard. Two-factor responses remain in process memory and are never persisted.
Passwords remain in memory by default. If the user explicitly selects encrypted
credential storage, iPhoneLoadly encrypts the Apple email and password with a
root-only local key and attempts to restore sign-in after restart; Apple may still
require 2FA. A root administrator can access both ciphertext and key, so this is
protection at rest rather than protection from a compromised root account.

The pairing record in `/var/lib/lockdown` is sensitive host-to-device
authentication material. The API needs it to reach the configured phone over
trusted Wi-Fi. Do not share it, place it in source control, or include its
contents in support requests. Uploaded IPA files, SQLite metadata, encrypted
credentials and the local encryption key live in `/var/lib/iphoneloadly`;
backups of that directory are sensitive too.

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

## GitHub IPA sources and automatic downloads

GitHub IPA sources are restricted to public canonical GitHub repositories and
bounded, structurally validated release assets. This does not establish trust
in the application code. A repository, maintainer account, release, or asset
can be compromised or replaced, and re-signing an IPA with your Apple account
does not make malicious code safe. Review release notes and provenance
manually when possible.

Automatic source downloads are disabled by default and require an explicit
acknowledgement in the dashboard. Automatic sync updates only the server copy;
it does not immediately install the IPA on an iPhone. If automatic refresh is
enabled, the newer server copy may later be installed during that normal
refresh cycle.

The official self-updater accepts only verified release artifacts from the
`lemehavit/iPhoneLoadly` repository. The browser cannot provide an update URL,
repository, command, or arbitrary version.
