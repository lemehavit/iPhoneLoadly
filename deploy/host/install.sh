#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

find_package_root() {
  local candidate
  for candidate in "${SCRIPT_DIR}" "${SCRIPT_DIR}/../.."; do
    candidate="$(CDPATH= cd -- "${candidate}" 2>/dev/null && pwd)" || continue
    if [[ -f "${candidate}/bin/iphoneloadly-api" && -f "${candidate}/install-iphoneloadly.sh" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
    if [[ -f "${candidate}/Cargo.toml" && -f "${candidate}/deploy/host/install-iphoneloadly.sh" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  return 1
}

PACKAGE_ROOT="$(find_package_root)" || { printf 'ERROR: Unable to locate iPhoneLoadly package files.\n' >&2; exit 1; }
HOST_PREP="${PACKAGE_ROOT}/deploy/host/install-debian13.sh"
if [[ -f "${PACKAGE_ROOT}/install-iphoneloadly.sh" ]]; then
  APP_INSTALLER="${PACKAGE_ROOT}/install-iphoneloadly.sh"
else
  APP_INSTALLER="${PACKAGE_ROOT}/deploy/host/install-iphoneloadly.sh"
fi

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
step() { printf '\n[%s/6] %s...\n' "$1" "$2"; }
if [[ "${1:-}" == "--check-package-layout" ]]; then
  for required in \
    "${PACKAGE_ROOT}/bin/iphoneloadly-api" \
    "${HOST_PREP}" \
    "${APP_INSTALLER}" \
    "${PACKAGE_ROOT}/deploy/systemd/iphoneloadly-api.service" \
    "${PACKAGE_ROOT}/deploy/caddy/Caddyfile.example" \
    "${PACKAGE_ROOT}/scripts/iphoneloadly-doctor.sh" \
    "${PACKAGE_ROOT}/scripts/preflight-wifi.sh" \
    "${PACKAGE_ROOT}/scripts/backup-state.sh" \
    "${PACKAGE_ROOT}/docs/INSTALL.md"; do
    [[ -f "${required}" ]] || fail "Release package is missing ${required#"${PACKAGE_ROOT}/"}"
  done
  printf 'Release package layout is valid: %s\n' "${PACKAGE_ROOT}"
  exit 0
fi
[[ $EUID -eq 0 ]] || fail 'Run with sudo: sudo bash ./install.sh'
if [[ -f "${PACKAGE_ROOT}/bin/iphoneloadly-api" ]]; then
  API_ARGUMENTS=(--binary "${PACKAGE_ROOT}/bin/iphoneloadly-api")
else
  API_ARGUMENTS=()
fi
[[ -f "$HOST_PREP" && -f "$APP_INSTALLER" ]] || fail 'Release archive is incomplete.'

step 1 'Checking host prerequisites'
source /etc/os-release
[[ "${ID:-}" == debian && "${VERSION_ID%%.*}" == 13 ]] || fail "Debian 13 is required."
[[ "$(dpkg --print-architecture)" == amd64 ]] || fail 'amd64 is required.'
printf 'OK: Debian %s on amd64\n' "$VERSION_ID"

step 2 'Preparing host dependencies'
bash "$HOST_PREP"

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
printf 'Disconnect USB. iPhoneLoadly discovers trusted Wi-Fi devices automatically; no UDID or IP address is required.\n'
read -r -p 'Press Enter after disconnecting USB. '

step 5 'Installing iPhoneLoadly'
bash "$APP_INSTALLER" "${API_ARGUMENTS[@]}"

step 6 'Checking installation'
iphoneloadly-doctor || true
printf '\niPhoneLoadly installation complete ✓\n\nNext:\n1. Open an SSH tunnel: ssh -N -L 8080:127.0.0.1:8080 USER@SERVER\n2. Open http://127.0.0.1:8080/ in your browser.\n3. Sign in with your Apple ID and upload an IPA.\n\nDocumentation: https://github.com/lemehavit/iPhoneLoadly/blob/main/docs/INSTALL.md\n'
