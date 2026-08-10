#!/usr/bin/env bash
set -u
IFS=$'\n\t'

OUTPUT_PARENT="${1:-.}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUTPUT_DIR="${OUTPUT_PARENT%/}/iphoneloadly-diagnostics-${STAMP}"
MUX_SOCKET="/run/iphoneloadly/mux.sock"

umask 077
mkdir -p -- "${OUTPUT_DIR}"

redact() {
    sed -E \
        -e 's/[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}/<REDACTED-UDID>/g' \
        -e 's/([0-9A-Fa-f]{40})/<REDACTED-UDID>/g' \
        -e 's/([[:alnum:]_+.-]+)@([[:alnum:].-]+)/<REDACTED-EMAIL>/g'
}

capture() {
    local name="$1"
    shift
    {
        printf '$'
        printf ' %q' "$@"
        printf '\n\n'
        "$@" 2>&1 || true
    } | redact >"${OUTPUT_DIR}/${name}.txt"
}

{
    printf 'Created: %s\n' "${STAMP}"
    printf 'Purpose: iPhoneLoadly host diagnostics\n'
    printf 'Pairing-record contents are never collected.\n'
    printf 'UDID- and email-shaped strings are redacted on a best-effort basis.\n'
    printf 'Review every file before sharing it.\n'
} >"${OUTPUT_DIR}/README.txt"

capture os-release cat /etc/os-release
capture kernel uname -a
capture architecture dpkg --print-architecture
capture packages dpkg-query -W \
    avahi-daemon avahi-utils ideviceinstaller libimobiledevice-utils \
    libplist-utils python3-venv usbmuxd
capture service-avahi systemctl --no-pager --full status avahi-daemon.service
capture service-usbmuxd systemctl --no-pager --full status usbmuxd.service
capture service-netmuxd systemctl --no-pager --full status iphoneloadly-netmuxd.service
capture journal-usbmuxd journalctl --no-pager -u usbmuxd.service --since '-30 minutes'
capture journal-netmuxd journalctl --no-pager -u iphoneloadly-netmuxd.service --since '-30 minutes'
capture network-links ip -brief link
capture network-addresses ip -brief address
capture network-routes ip route
capture sockets ls -ld /run/iphoneloadly /run/iphoneloadly/mux.sock /run/usbmuxd /var/lib/lockdown
capture netmuxd-hash sha256sum /usr/local/libexec/iphoneloadly/netmuxd

if command -v timeout >/dev/null 2>&1 && command -v avahi-browse >/dev/null 2>&1; then
    capture bonjour timeout 10 avahi-browse -t -r _apple-mobdev2._tcp
fi

if [[ -S "${MUX_SOCKET}" ]] && command -v idevice_id >/dev/null 2>&1; then
    {
        printf '$ USBMUXD_SOCKET_ADDRESS=%q idevice_id --network\n\n' "${MUX_SOCKET}"
        USBMUXD_SOCKET_ADDRESS="${MUX_SOCKET}" idevice_id --network 2>&1 || true
    } | redact >"${OUTPUT_DIR}/network-devices.txt"
fi

printf '%s\n' "${OUTPUT_DIR}"
printf 'Diagnostics collected. Review all files before sharing.\n'
