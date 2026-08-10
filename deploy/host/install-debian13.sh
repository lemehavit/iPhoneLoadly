#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

NETMUXD_VERSION="0.4.3"
NETMUXD_ASSET="netmuxd-x86_64-unknown-linux-gnu.tar.gz"
NETMUXD_SHA256="85b6598284fc639f2a282584461d05e2090b79bdf3ec949d2a5e5d3dc655dde4"
NETMUXD_BINARY_SHA256="d42e0d1ed1a29c38693083db919e4cb2e1ce9e08799fa19a2ee388882d9bcc23"
NETMUXD_URL="https://github.com/jkcoxson/netmuxd/releases/download/v${NETMUXD_VERSION}/${NETMUXD_ASSET}"
PYMOBILEDEVICE3_VERSION="9.36.3"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/../.." && pwd)"
SYSTEMD_SOURCE="${REPO_ROOT}/deploy/systemd/iphoneloadly-netmuxd.service"

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

if [[ "${EUID}" -ne 0 ]]; then
    fail "Run this script as root, for example: sudo $0"
fi

[[ -r /etc/os-release ]] || fail "/etc/os-release is missing"
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == "debian" ]] || fail "This installer supports Debian only"
[[ "${VERSION_ID%%.*}" == "13" ]] || fail "Expected Debian 13, found ${VERSION_ID:-unknown}"
[[ "$(dpkg --print-architecture)" == "amd64" ]] || fail "Expected Debian amd64"
[[ -f "${SYSTEMD_SOURCE}" ]] || fail "Missing ${SYSTEMD_SOURCE}; copy the complete repository to Debian"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install --yes --no-install-recommends \
    avahi-daemon \
    avahi-utils \
    build-essential \
    ca-certificates \
    curl \
    ideviceinstaller \
    jq \
    libimobiledevice-utils \
    libplist-utils \
    openssl \
    python3-pip \
    python3-dev \
    python3-venv \
    tar \
    unzip \
    usbmuxd

if ! getent group iphoneloadly-mux >/dev/null; then
    groupadd --system iphoneloadly-mux
fi

install -d -o root -g root -m 0755 /usr/local/libexec/iphoneloadly
install -d -o root -g root -m 0755 /opt/iphoneloadly-tools
if [[ ! -d /var/lib/lockdown ]]; then
    install -d -o root -g root -m 0755 /var/lib/lockdown
fi

DOWNLOAD_DIR="$(mktemp -d /tmp/iphoneloadly-netmuxd.XXXXXX)"
cleanup() {
    rm -rf -- "${DOWNLOAD_DIR}"
}
trap cleanup EXIT

ARCHIVE="${DOWNLOAD_DIR}/${NETMUXD_ASSET}"
curl --fail --location --proto '=https' --tlsv1.2 \
    --output "${ARCHIVE}" \
    "${NETMUXD_URL}"

printf '%s  %s\n' "${NETMUXD_SHA256}" "${ARCHIVE}" | sha256sum --check --status \
    || fail "netmuxd SHA-256 verification failed"

ARCHIVE_MEMBERS="$(tar -tzf "${ARCHIVE}")"
[[ "${ARCHIVE_MEMBERS}" == "netmuxd" ]] \
    || fail "Unexpected files in the netmuxd archive"

tar -xzf "${ARCHIVE}" -C "${DOWNLOAD_DIR}" netmuxd
printf '%s  %s\n' "${NETMUXD_BINARY_SHA256}" "${DOWNLOAD_DIR}/netmuxd" \
    | sha256sum --check --status \
    || fail "extracted netmuxd binary SHA-256 verification failed"
install -o root -g root -m 0755 \
    "${DOWNLOAD_DIR}/netmuxd" \
    /usr/local/libexec/iphoneloadly/netmuxd

NETMUXD_ACTUAL_SHA="$(sha256sum /usr/local/libexec/iphoneloadly/netmuxd | awk '{print $1}')"
[[ -n "${NETMUXD_ACTUAL_SHA}" ]] || fail "Unable to hash the installed netmuxd binary"
[[ "${NETMUXD_ACTUAL_SHA}" == "${NETMUXD_BINARY_SHA256}" ]] \
    || fail "installed netmuxd binary SHA-256 verification failed"

PMD3_VENV="/opt/iphoneloadly-tools/pymobiledevice3"
if [[ ! -x "${PMD3_VENV}/bin/python" ]]; then
    python3 -m venv "${PMD3_VENV}"
fi
"${PMD3_VENV}/bin/python" -m pip install --disable-pip-version-check \
    "pymobiledevice3==${PYMOBILEDEVICE3_VERSION}"
ln -sfn "${PMD3_VENV}/bin/pymobiledevice3" /usr/local/bin/iphoneloadly-pymobiledevice3

install -o root -g root -m 0644 \
    "${SYSTEMD_SOURCE}" \
    /etc/systemd/system/iphoneloadly-netmuxd.service

systemctl daemon-reload
systemctl enable --now avahi-daemon.service
systemctl enable --now iphoneloadly-netmuxd.service

printf '\nHost preparation complete.\n'
printf 'netmuxd release: v%s\n' "${NETMUXD_VERSION}"
printf 'netmuxd binary SHA-256: %s\n' "${NETMUXD_ACTUAL_SHA}"
printf 'pymobiledevice3: %s\n' "${PYMOBILEDEVICE3_VERSION}"
printf 'mux group: %s\n' "$(getent group iphoneloadly-mux)"
printf 'mux socket: /run/iphoneloadly/mux.sock\n'
printf '\nNo firewall, Proxmox, USB-port, pairing, or Apple-account settings were changed.\n'
printf 'Continue with docs/operations/debian13-host-preparation.md.\n'
