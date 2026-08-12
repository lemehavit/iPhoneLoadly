#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PACKAGE_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/../.." && pwd)"
HOST_PREP="${PACKAGE_ROOT}/deploy/host/install-debian13.sh"
APP_INSTALLER="${PACKAGE_ROOT}/install-iphoneloadly.sh"

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
step() { printf '\n[%s/6] %s...\n' "$1" "$2"; }
[[ $EUID -eq 0 ]] || fail 'Run with sudo: sudo bash ./install.sh'
[[ -x "${PACKAGE_ROOT}/bin/iphoneloadly-api" ]] || fail 'This installer must be run from an iPhoneLoadly release archive.'
[[ -f "$HOST_PREP" && -x "$APP_INSTALLER" ]] || fail 'Release archive is incomplete.'

step 1 'Checking host prerequisites'
source /etc/os-release
[[ "${ID:-}" == debian && "${VERSION_ID%%.*}" == 13 ]] || fail "Debian 13 is required."
[[ "$(dpkg --print-architecture)" == amd64 ]] || fail 'amd64 is required.'
printf 'OK: Debian %s on amd64\n' "$VERSION_ID"

step 2 'Preparing host dependencies'
"$HOST_PREP"

step 3 'Starting local anisette'
printf 'iPhoneLoadly requires a local anisette service at 127.0.0.1:6970.\n'
printf 'Follow docs/INSTALL.md if it is not running, then press Enter to continue. '
read -r
curl --fail --silent --max-time 5 http://127.0.0.1:6970/ >/dev/null || fail 'Local anisette is unavailable. See docs/INSTALL.md.'
printf 'OK\n'

step 4 'Pairing and Wi-Fi setup'
printf 'Connect and unlock the iPhone, accept Trust This Computer, then press Enter. '
read -r
idevicepair pair
idevicepair validate
iphoneloadly-pymobiledevice3 lockdown wifi-connections on
printf 'Disconnect USB. Enter the iPhone UDID and current Wi-Fi IP without printing pairing data.\n'
read -r -p 'UDID: ' device_id
read -r -p 'iPhone IP: ' device_ip
[[ "$device_id" =~ ^[0-9A-Fa-f-]+$ && -n "$device_ip" ]] || fail 'A UDID and iPhone IP are required.'
pairing_file="/var/lib/lockdown/${device_id}.plist"
[[ -r "$pairing_file" ]] || fail 'Pairing record was not found at the expected path.'

step 5 'Installing iPhoneLoadly'
bash "$APP_INSTALLER" --binary "${PACKAGE_ROOT}/bin/iphoneloadly-api" --device-id "$device_id" --device-ip "$device_ip" --pairing-file "$pairing_file"

step 6 'Checking installation'
iphoneloadly-doctor || true
printf '\niPhoneLoadly installation complete ✓\n\nNext:\n1. Open an SSH tunnel: ssh -N -L 8080:127.0.0.1:8080 USER@SERVER\n2. Open http://127.0.0.1:8080/ in your browser.\n3. Sign in with your Apple ID and upload an IPA.\n\nDocumentation: https://github.com/lemehavit/iPhoneLoadly/blob/main/docs/INSTALL.md\n'
