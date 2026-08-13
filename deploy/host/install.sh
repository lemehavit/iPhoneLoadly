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

single_usb_udid() {
  local -a devices=()
  mapfile -t devices < <(idevice_id --list 2>/dev/null | sed '/^[[:space:]]*$/d')
  case "${#devices[@]}" in
    1) printf '%s\n' "${devices[0]}" ;;
    0) fail 'No iPhone was detected over USB. Check the cable, unlock the phone, and accept Trust This Computer.' ;;
    *) fail 'More than one iPhone is connected over USB. Disconnect every phone except the one to onboard.' ;;
  esac
}

wait_for_usb_pairing() {
  local device_udid="$1"
  local deadline
  deadline=$((SECONDS + 120))

  printf 'Waiting up to 120 seconds for Trust This Computer to be accepted on the iPhone.\n'
  while (( SECONDS < deadline )); do
    if idevicepair -u "${device_udid}" validate >/dev/null 2>&1; then
      printf 'SUCCESS: Validated pairing with device %s\n' "${device_udid}"
      return 0
    fi

    # Running pair again is intentional: before trust is accepted it keeps the
    # pairing request active; after acceptance it completes without new input.
    idevicepair -u "${device_udid}" pair >/dev/null 2>&1 || true
    sleep 2
  done

  fail 'Pairing was not validated within 120 seconds. Keep USB connected, unlock the iPhone, accept Trust This Computer, then run the installer again.'
}

wait_for_network_device() {
  local expected_udid="$1"
  local deadline network_ids network_ips network_ip remaining probe_timeout
  deadline=$((SECONDS + 90))
  while (( SECONDS < deadline )); do
    network_ids="$(USBMUXD_SOCKET_ADDRESS=/run/iphoneloadly/mux.sock idevice_id --network 2>/dev/null || true)"
    if printf '%s\n' "${network_ids}" | grep -Fxq "${expected_udid}" &&
      USBMUXD_SOCKET_ADDRESS=/run/iphoneloadly/mux.sock \
        ideviceinfo --network -u "${expected_udid}" -k DeviceName >/dev/null 2>&1; then
      return 0
    fi
    # Debian's libimobiledevice may fail to enumerate the current netmuxd
    # socket even though netmuxd has discovered the phone. Validate only
    # Bonjour-advertised IPv4 addresses with the existing pairing record.
    remaining=$((deadline - SECONDS))
    probe_timeout=$((remaining < 3 ? remaining : 3))
    (( probe_timeout > 0 )) || break
    network_ips="$(timeout "${probe_timeout}s" avahi-browse -p -t -r _apple-mobdev2._tcp 2>/dev/null \
      | awk -F ';' '$1 == "=" && $3 == "IPv4" { print $8 }' \
      | sort -u || true)"
    while IFS= read -r network_ip; do
      [[ -n "${network_ip}" ]] || continue
      remaining=$((deadline - SECONDS))
      probe_timeout=$((remaining < 5 ? remaining : 5))
      (( probe_timeout > 0 )) || break 2
      if timeout "${probe_timeout}s" /opt/iphoneloadly-tools/pymobiledevice3/bin/python \
        "${PACKAGE_ROOT}/scripts/verify-wifi-direct.py" \
        --host "${network_ip}" --udid "${expected_udid}" >/dev/null 2>&1; then
        return 0
      fi
    done <<< "${network_ips}"
    sleep 2
  done
  return 1
}
if [[ "${1:-}" == "--check-package-layout" ]]; then
  for required in \
    "${PACKAGE_ROOT}/bin/iphoneloadly-api" \
    "${HOST_PREP}" \
    "${APP_INSTALLER}" \
    "${PACKAGE_ROOT}/deploy/systemd/iphoneloadly-api.service" \
    "${PACKAGE_ROOT}/deploy/systemd/iphoneloadly-dashboard-mdns.service" \
    "${PACKAGE_ROOT}/deploy/caddy/Caddyfile.example" \
    "${PACKAGE_ROOT}/scripts/create-caddy-ios-profile.sh" \
    "${PACKAGE_ROOT}/scripts/publish-dashboard-mdns.sh" \
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
printf 'Connect and unlock exactly one iPhone, accept Trust This Computer, then press Enter. '
read -r
device_udid="$(single_usb_udid)"
wait_for_usb_pairing "${device_udid}"
ideviceinfo -u "${device_udid}" -k DeviceName >/dev/null
iphoneloadly-pymobiledevice3 lockdown wifi-connections --state on
systemctl restart iphoneloadly-netmuxd.service
printf 'Disconnect USB. iPhoneLoadly now verifies this phone over Wi-Fi; no UDID or IP address is required.\n'
read -r -p 'Press Enter after disconnecting USB. '
wait_for_network_device "${device_udid}" \
  || fail 'The trusted iPhone did not become reachable over Wi-Fi within 90 seconds. Keep USB disconnected and run iphoneloadly-doctor and preflight-wifi.sh.'
printf 'OK: trusted iPhone is reachable over Wi-Fi.\n'

step 5 'Installing iPhoneLoadly'
bash "$APP_INSTALLER" "${API_ARGUMENTS[@]}"

step 6 'Checking installation'
iphoneloadly-doctor || true
printf '\niPhoneLoadly installation complete ✓\n\nNext:\n1. Configure authenticated Caddy using docs/operations/caddy-lan.md.\n2. Open https://iphoneloadly.local (or use an SSH tunnel as an administrator fallback).\n3. Sign in with your Apple ID and upload an IPA.\n\nDocumentation: https://github.com/lemehavit/iPhoneLoadly/blob/main/docs/INSTALL.md\n'
