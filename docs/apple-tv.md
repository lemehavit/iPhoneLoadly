# Apple TV (experimental)

iPhoneLoadly can pair with an Apple TV, sign apps for tvOS and install them
over Wi-Fi. It uses the same RSD path as the remotely paired iPhone, and the
same pairing and signing steps as atvloadly (PlumeImpactor).

## Enable

Set both variables in `/etc/iphoneloadly/api.env` and restart
`iphoneloadly-api`:

```
IPHONELOADLY_RSD_INSTALL=on
IPHONELOADLY_APPLE_TV=on
```

With `IPHONELOADLY_APPLE_TV` unset, nothing changes for the iPhone.

## Pair

1. On the Apple TV, open Settings → Remotes and Devices → Remote App and
   Devices. Leave it open.
2. In the dashboard, open Settings → Apple TV and choose Search for Apple TV.
3. Choose Pair next to the Apple TV. Type the six-digit PIN it shows.
4. When the card says the Apple TV is paired, close Remote App and Devices.
   The Apple TV then shows up in the device list.

The pairing is stored encrypted in `apple-tv/` under the wireless pairing
state directory, separate from the iPhone's pairing.

## Install

Choose the Apple TV as the device in Install. The first install registers the
Apple TV on the Apple developer team (atvloadly may already have done this
for the same Apple ID). Profiles are requested for tvOS. Refresh works the
same way as for the iPhone.

An IPA built for iPhone is refused for the Apple TV, and a tvOS IPA is refused
for the iPhone, before anything is sent to Apple.

## How it works

| Step | Apple TV | Where |
|---|---|---|
| Discovery | mDNS `_remotepairing-manual-pairing._tcp` | `wireless_pairing::discover_manual_pairing_targets` |
| Pairing | Client SRP pair-setup with the PIN (idevice `RemotePairingClient::connect`) | `WirelessPairingService::pair_with_pin` |
| Reconnect | `_remotepairing._tcp`, pair-verify, TLS-PSK tunnel, RSD | unchanged RSD path |
| Device class | `DeviceClass` from the RSD handshake | `RemoteRsdSession::verified_signing_identity` |
| Registration and profiles | iOS endpoints with `DTDK_Platform=tvos`, `subPlatform=tvOS` | isideload fork, branch `appletv-support` |
| Install | installation_proxy over RSD | unchanged RSD path |

## Known risks for the first live test

- Using the same Apple ID in atvloadly and iPhoneLoadly can make each tool
  revoke the other's development certificate. Plan to move fully to
  iPhoneLoadly once it works.
- The tvOS request fields are taken from PlumeImpactor, which atvloadly runs
  in production; they have not been tested against Apple from iPhoneLoadly.
- If the pairing is saved but the Apple TV does not answer afterwards, close
  Remote App and Devices on the TV and search for devices again.
