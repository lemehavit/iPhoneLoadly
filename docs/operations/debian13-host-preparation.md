# Debian 13.6 host preparation

Target:

- Debian 13.6 "Trixie", amd64, netinst
- Proxmox VM
- iPhone 13 Pro Max, iOS 26.5
- USB for initial trust/pairing only
- Wi-Fi for every application install and refresh

This runbook prepares the host. It does not install the iPhoneLoadly application, authenticate an Apple account, sign an IPA, modify Proxmox, or pair a phone automatically.

## Prepared host layout

```text
USB onboarding
  iPhone -> Proxmox USB port -> Debian usbmuxd -> /run/usbmuxd
                                      |
                                      +-> /var/lib/lockdown/*.plist

Normal operation
  iPhone -> home Wi-Fi -> netmuxd mDNS/network transport
                              |
                              +-> shim to Debian usbmuxd when USB exists
                              +-> /run/iphoneloadly/mux.sock
                                      |
                                      +-> future Docker container
```

`netmuxd` v0.4.3 is run in shim mode. It listens on its own socket and uses Debian `usbmuxd` only as an upstream for USB and pairing operations. This avoids two daemons competing for `/run/usbmuxd`. The application socket contains both network and USB entries, but iPhoneLoadly must reject USB entries for install and refresh jobs.

## 1. Copy and inspect the kit

Copy this repository to the Debian VM. Before executing anything, review:

- `deploy/host/install-debian13.sh`
- `deploy/systemd/iphoneloadly-netmuxd.service`
- `deploy/host/THIRD_PARTY_NOTICES.md`

The installer requires root because it installs Debian packages, one pinned upstream binary, a Python diagnostic virtual environment, and a systemd unit.

## 2. Install host dependencies

From the repository root:

```sh
sudo bash deploy/host/install-debian13.sh
```

The script:

1. Refuses non-Debian-13 and non-amd64 hosts.
2. Installs Debian packages for usbmuxd, libimobiledevice, ideviceinstaller and Avahi.
3. Downloads exactly `netmuxd` v0.4.3 for x86-64 Linux.
4. Verifies release-archive SHA-256 `85b6598284fc639f2a282584461d05e2090b79bdf3ec949d2a5e5d3dc655dde4` before extraction.
5. Installs diagnostic-only `pymobiledevice3` 10.7.3 in `/opt/iphoneloadly-tools`; it is not linked into the future server.
6. Creates the `iphoneloadly-mux` system group.
7. Starts Avahi and the hardened `iphoneloadly-netmuxd` service.

It does not alter firewall rules, network interfaces, Docker, Proxmox, USB assignments, pairing records or Apple credentials.

Check the result:

```sh
sudo systemctl status avahi-daemon --no-pager
sudo systemctl status iphoneloadly-netmuxd --no-pager
sudo ls -ld /run/iphoneloadly
sudo ls -l /run/iphoneloadly/mux.sock
```

The socket itself is created mode `0666` by current netmuxd, but the enclosing systemd runtime directory is `0750` and owned by `root:iphoneloadly-mux`. Directory traversal is therefore the effective access control. The directory is preserved across service restarts so a future Docker bind mount does not retain a stale directory inode. Do not widen the directory mode.

The service uses `RUST_LOG=warn` because upstream informational logs can include device identifiers. Temporarily increase logging only for a controlled diagnostic session, then restore the unit and rotate/review the resulting journal before sharing it.

For a future Docker container, use the numeric group ID shown by:

```sh
getent group iphoneloadly-mux
```

Bind-mount the dedicated `/run/iphoneloadly` directory into the application container so a netmuxd restart can safely recreate `mux.sock`. Never mount all of `/run`, `/dev/bus/usb`, or `/var/lib/lockdown` into the application container.

## 3. Assign the intended physical USB port

This step waits until physical access is available.

On the Proxmox host, identify the port by comparing output before and after connecting the phone:

```sh
lsusb
lsusb -t
```

In the Proxmox UI, open the Debian VM, choose **Hardware -> Add -> USB Device**, and select **Use USB Port** rather than only Apple vendor/product ID. A physical-port mapping is less likely to break when the iPhone re-enumerates.

After starting the VM, verify inside Debian:

```sh
lsusb | grep -i apple
sudo journalctl -u usbmuxd --since "5 minutes ago" --no-pager
idevice_id --list
```

Do not delete old pairing records as a routine troubleshooting action.

## 4. Perform one-time pairing and enable Wi-Fi

Keep the iPhone unlocked. Accept **Trust This Computer** and enter the iPhone passcode when requested:

```sh
sudo idevicepair pair
sudo idevicepair validate
sudo ideviceinfo -k DeviceName
sudo ideviceinfo -k ProductVersion
sudo iphoneloadly-pymobiledevice3 lockdown wifi-connections --state on
```

Confirm that at least one device pairing record exists without printing its filename:

```sh
sudo find /var/lib/lockdown -maxdepth 1 -type f -name '*.plist' \
  ! -name 'SystemConfiguration.plist' -printf '.' | wc -c
```

Pairing files are credentials. Do not copy their contents into chat, tickets or diagnostics.

Restart netmuxd so its pairing cache begins from the newly created record:

```sh
sudo systemctl restart iphoneloadly-netmuxd
```

## 5. Disconnect USB and prove network discovery

Physically disconnect the USB cable. All remaining acceptance commands must run with the cable removed.

Check Bonjour:

```sh
timeout 15 avahi-browse -t -r _apple-mobdev2._tcp
```

Check the dedicated network-capable mux:

```sh
sudo env USBMUXD_SOCKET_ADDRESS=/run/iphoneloadly/mux.sock \
  idevice_id --network
```

Save the returned UDID locally, but redact it before sharing logs. Then test lockdownd:

```sh
sudo env USBMUXD_SOCKET_ADDRESS=/run/iphoneloadly/mux.sock \
  ideviceinfo --network -u '<UDID>' -k DeviceName

sudo env USBMUXD_SOCKET_ADDRESS=/run/iphoneloadly/mux.sock \
  ideviceinfo --network -u '<UDID>' -k ProductVersion
```

Expected product version is `26.5`. Debian's libimobiledevice and ideviceinstaller packages predate iOS 26.5; failure here is therefore a compatibility result to diagnose, not permission to fall back to USB installation.

If the Debian `idevice_*` client cannot enumerate the netmuxd socket despite a successful netmuxd discovery log, validate the existing USB-onboarding pairing record directly over TCP instead:

```sh
sudo /opt/iphoneloadly-tools/pymobiledevice3/bin/python \
  scripts/verify-wifi-direct.py --host '<IPHONE_IP>' --udid '<UDID>'
```

This diagnostic does not pair, install an IPA, or print pairing-record material.

## 6. Run the read-only preflight

```sh
sudo bash scripts/preflight-wifi.sh --udid '<UDID>'
```

The preflight does not pair, write pairing data or install an IPA. When exactly
one trusted Wi-Fi device is visible, it validates that device automatically;
with multiple devices, pass `--udid` only for a focused diagnostic. Failures
must be resolved before application code is connected to the device.

## 7. Collect diagnostics safely

```sh
sudo bash scripts/collect-host-diagnostics.sh /tmp
```

The script never reads pairing-file contents and performs best-effort redaction of UDID- and email-shaped values. It does collect local interface addresses and service journals because they are needed for mDNS troubleshooting. Review every generated file manually before sharing it.

## 8. Installation gate

No suitable signed IPA exists yet, so network discovery can be validated before the installation gate. Follow [the test-IPA strategy](test-ipa-strategy.md) before running:

```sh
sudo env USBMUXD_SOCKET_ADDRESS=/run/iphoneloadly/mux.sock \
  ideviceinstaller --network -u '<UDID>' install '/absolute/path/test-signed.ipa'
```

USB must remain disconnected. Version 0.1 may proceed to its native Rust device spike only after this succeeds and emits usable progress/status.

## Recovery rules

- If mDNS is empty, inspect AP client isolation, VLAN boundaries, multicast filtering, Proxmox bridge configuration and the phone's current Wi-Fi network.
- If mDNS works but netmuxd has no device, collect netmuxd logs and confirm the pairing record contains a HostID. Do not print the HostID.
- If the socket is unavailable, inspect `iphoneloadly-netmuxd.service`; do not mount all of `/run` as a workaround.
- If pairing is rejected, unlock the phone and repeat the explicit pairing ceremony. Do not automatically erase `/var/lib/lockdown`.
- If iOS 26.5 changed the protocol, keep the failure reproducible and test a newer pinned upstream version in isolation before changing the system service.

## Primary package and upstream references

- [Debian 13 usbmuxd](https://packages.debian.org/trixie/usbmuxd)
- [Debian 13 libimobiledevice utilities](https://packages.debian.org/trixie/libimobiledevice-utils)
- [Debian 13 ideviceinstaller](https://packages.debian.org/trixie/ideviceinstaller)
- [Debian 13 Avahi utilities](https://packages.debian.org/trixie/avahi-utils)
- [netmuxd v0.4.3 releases](https://github.com/jkcoxson/netmuxd/releases/tag/v0.4.3)
- [pymobiledevice3](https://pypi.org/project/pymobiledevice3/10.7.3/)
