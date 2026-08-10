# Test IPA strategy

There is currently no IPA that can satisfy the real installation gate. A device-installable IPA must contain executable application content, a valid code signature, a non-expired provisioning profile, and—when the profile type requires it—the target iPhone's UDID. A synthetic ZIP fixture cannot prove installation.

## Two separate gates

The physical test is intentionally split:

1. **Network gate:** pair once over USB, disconnect it, discover the iPhone and query lockdownd over Wi-Fi. This does not require an IPA.
2. **Installation gate:** transfer and install a correctly signed IPA over the same Wi-Fi path. This requires a device-valid artifact.

The first gate can be completed before the test IPA is ready. Neither gate may be replaced by a USB installation.

## Selecting the test application

Use a small, harmless open-source iOS application with an upstream-published IPA or a reproducible build. Before downloading it, record:

- upstream repository and release URL;
- source-code and binary license;
- release version;
- original SHA-256;
- expected bundle identifier and extensions/entitlements.

Avoid random IPA mirrors, modified social-media clients, applications containing personal accounts, and complex entitlement-heavy applications for the first test.

## Producing the signed artifact

Do this only after the actual device UDID is available. Version 0.1 permits an external/manual signing step, but the signer must save the resulting IPA rather than only install it directly.

Required output properties:

- signature created with a certificate controlled by the user;
- provisioning profile is non-expired and includes the iPhone when required;
- bundle identifier is known and does not collide with an important installed app;
- signed IPA is saved to a new path; never overwrite the original download;
- SHA-256 is recorded after signing;
- no Apple password is stored in a script, shell history or file.

Potential signing routes to evaluate at that time are the MIT `isideload` pipeline used by iLoader, or `rcodesign` with an independently obtained certificate and provisioning profile. The route is not selected yet because obtaining the device-specific profile is part of the later Apple-account/signing work.

## Pre-install checks

Before the Wi-Fi installation test, record only non-secret metadata:

```text
application name
bundle identifier
version/build
signed IPA SHA-256
profile expiration
target device identifier hash
signing tool and exact version
```

Keep the real UDID, provisioning profile and certificate private. Store the signed test IPA with mode `0600` outside any web root.

## Acceptance result

With USB physically disconnected, this must succeed through `/run/iphoneloadly/mux.sock`:

```sh
ideviceinstaller --network -u '<UDID>' install '/absolute/path/test-signed.ipa'
```

Success means the application appears on the phone, launches, and the install command reports completion. Record duration and progress behavior. Then repeat after phone sleep/wake and after a Debian VM restart.

An unsigned or intentionally mismatched artifact is useful as a separate negative test, but it cannot substitute for the successful installation case.
