#!/usr/bin/env bash
set -u
IFS=$'\n\t'

EXPECTED_NETMUXD_BINARY_SHA="d42e0d1ed1a29c38693083db919e4cb2e1ce9e08799fa19a2ee388882d9bcc23"
MUX_SOCKET="/run/iphoneloadly/mux.sock"
PAIR_DIR="/var/lib/lockdown"
UDID=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --udid)
            [[ $# -ge 2 ]] || { printf 'Missing value after --udid\n' >&2; exit 2; }
            UDID="$2"
            shift 2
            ;;
        -h|--help)
            printf 'Usage: %s [--udid DEVICE_UDID]\n' "$0"
            printf 'Read-only checks; this script never pairs or installs an app.\n'
            exit 0
            ;;
        *)
            printf 'Unknown argument: %s\n' "$1" >&2
            exit 2
            ;;
    esac
done

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

pass() { PASS_COUNT=$((PASS_COUNT + 1)); printf '[PASS] %s\n' "$*"; }
warn() { WARN_COUNT=$((WARN_COUNT + 1)); printf '[WARN] %s\n' "$*"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); printf '[FAIL] %s\n' "$*"; }

check_command() {
    if command -v "$1" >/dev/null 2>&1; then
        pass "command available: $1"
    else
        fail "missing command: $1"
    fi
}

printf 'iPhoneLoadly Wi-Fi preflight (read-only)\n\n'

if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    if [[ "${ID:-}" == "debian" && "${VERSION_ID%%.*}" == "13" ]]; then
        pass "Debian ${VERSION_ID}"
    else
        fail "expected Debian 13; found ${PRETTY_NAME:-unknown}"
    fi
else
    fail "/etc/os-release is unreadable"
fi

if [[ "$(uname -m)" == "x86_64" ]]; then
    pass "architecture x86_64/amd64"
else
    fail "expected x86_64; found $(uname -m)"
fi

for tool in avahi-browse idevice_id ideviceinfo idevicepair ideviceinstaller sha256sum systemctl timeout; do
    check_command "${tool}"
done

if systemctl is-active --quiet avahi-daemon.service; then
    pass "avahi-daemon is active"
else
    fail "avahi-daemon is not active"
fi

if systemctl is-active --quiet iphoneloadly-netmuxd.service; then
    pass "iphoneloadly-netmuxd is active"
else
    fail "iphoneloadly-netmuxd is not active"
fi

if [[ -S "${MUX_SOCKET}" ]]; then
    pass "mux socket exists: ${MUX_SOCKET}"
else
    fail "mux socket is missing: ${MUX_SOCKET}"
fi

if [[ -r "${PAIR_DIR}" ]]; then
    PAIR_COUNT="$(find "${PAIR_DIR}" -maxdepth 1 -type f -name '*.plist' ! -name 'SystemConfiguration.plist' -printf '.' 2>/dev/null | wc -c)"
    if [[ "${PAIR_COUNT}" -gt 0 ]]; then
        pass "at least one pairing record exists (filenames not displayed)"
    else
        warn "no device pairing record exists yet"
    fi
else
    fail "pairing directory is not readable: ${PAIR_DIR}"
fi

if [[ -x /usr/local/libexec/iphoneloadly/netmuxd ]]; then
    ACTUAL_NETMUXD_SHA="$(sha256sum /usr/local/libexec/iphoneloadly/netmuxd | awk '{print $1}')"
    if [[ "${ACTUAL_NETMUXD_SHA}" == "${EXPECTED_NETMUXD_BINARY_SHA}" ]]; then
        pass "netmuxd binary matches the pinned v0.4.3 SHA-256"
    else
        fail "netmuxd binary SHA-256 differs from the pinned v0.4.3 build"
    fi
else
    fail "netmuxd binary is not installed"
fi

BONJOUR_OUTPUT="$(timeout 8 avahi-browse -p -t -r _apple-mobdev2._tcp 2>/dev/null || true)"
if printf '%s\n' "${BONJOUR_OUTPUT}" | grep -q '^='; then
    pass "Bonjour sees at least one _apple-mobdev2._tcp service"
else
    warn "no _apple-mobdev2._tcp service discovered (expected while the phone is away)"
fi

if [[ -S "${MUX_SOCKET}" ]] && command -v idevice_id >/dev/null 2>&1; then
    NETWORK_IDS="$(USBMUXD_SOCKET_ADDRESS="${MUX_SOCKET}" idevice_id --network 2>/dev/null || true)"
    if [[ -n "${NETWORK_IDS}" ]]; then
        NETWORK_COUNT="$(printf '%s\n' "${NETWORK_IDS}" | sed '/^[[:space:]]*$/d' | wc -l)"
        pass "network mux reports ${NETWORK_COUNT} network device(s); identifiers suppressed"
    else
        warn "network mux reports no network devices"
    fi
fi

if [[ -z "${UDID}" && -n "${NETWORK_IDS:-}" ]]; then
    mapfile -t DISCOVERED_IDS < <(printf '%s\n' "${NETWORK_IDS}" | sed '/^[[:space:]]*$/d')
    if [[ "${#DISCOVERED_IDS[@]}" -eq 1 ]]; then
        UDID="${DISCOVERED_IDS[0]}"
        pass "exactly one network device is available for a targeted lockdownd check"
    elif [[ "${#DISCOVERED_IDS[@]}" -gt 1 ]]; then
        warn "multiple network devices are available; use --udid only for an explicit diagnostic"
    fi
fi

if [[ -n "${UDID}" ]]; then
    if USBMUXD_SOCKET_ADDRESS="${MUX_SOCKET}" \
        timeout 15 ideviceinfo --network -u "${UDID}" -k DeviceName >/dev/null 2>&1; then
        pass "lockdownd query succeeded over the network for the selected device"
    else
        fail "lockdownd query failed over the network for the selected device"
    fi
else
    warn "no single network device was available; the targeted lockdownd query was skipped"
fi

printf '\nSummary: %d pass, %d warning, %d failure\n' \
    "${PASS_COUNT}" "${WARN_COUNT}" "${FAIL_COUNT}"

if [[ "${FAIL_COUNT}" -gt 0 ]]; then
    exit 1
fi
