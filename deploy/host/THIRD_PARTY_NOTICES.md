# Host-tool notices

The host installer downloads these tools from their upstream distribution channels. They are kept outside the future permissively licensed application binary.

| Component | Pinned version | License | Source |
|---|---:|---|---|
| netmuxd | 0.4.3 | LGPL-2.1-only | <https://github.com/jkcoxson/netmuxd/tree/v0.4.3> |
| pymobiledevice3 | 10.7.3 | GPL-3.0-or-later | <https://pypi.org/project/pymobiledevice3/10.7.3/> |
| Debian usbmuxd | Debian 13 package | GPL-3.0 | <https://packages.debian.org/trixie/usbmuxd> |
| Debian libimobiledevice | Debian 13 package | LGPL-2.1 | <https://packages.debian.org/trixie/libimobiledevice-utils> |
| Debian ideviceinstaller | Debian 13 package | GPL-2.0 | <https://packages.debian.org/trixie/ideviceinstaller> |

The pinned `netmuxd-x86_64-unknown-linux-gnu.tar.gz` release asset has SHA-256:

```text
85b6598284fc639f2a282584461d05e2090b79bdf3ec949d2a5e5d3dc655dde4
```

The extracted `netmuxd` ELF binary has SHA-256:

```text
d42e0d1ed1a29c38693083db919e4cb2e1ce9e08799fa19a2ee388882d9bcc23
```

Before redistributing a VM image or installer bundle, include the complete applicable license texts and source/corresponding-source information. Downloading these tools for private use is not the same as preparing a redistributable product image.
