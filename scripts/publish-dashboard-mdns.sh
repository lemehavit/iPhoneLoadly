#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# Publish the dashboard hostname on the LAN using the address of the active
# default route. This intentionally avoids Docker and loopback addresses.
dashboard_name="${IPHONELOADLY_DASHBOARD_NAME:-iphoneloadly.local}"

command -v ip >/dev/null || { echo 'iproute2 is required for dashboard mDNS.' >&2; exit 1; }
command -v avahi-publish >/dev/null || { echo 'avahi-utils is required for dashboard mDNS.' >&2; exit 1; }

interface="$(ip -4 route show default | awk '$1 == "default" { for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')"
[[ -n "${interface}" ]] || { echo 'No IPv4 default-route interface was found for dashboard mDNS.' >&2; exit 1; }

address="$(ip -o -4 addr show dev "${interface}" scope global up | awk 'NR == 1 { split($4, cidr, "/"); print cidr[1] }')"
[[ -n "${address}" ]] || { echo "No global IPv4 address was found on ${interface} for dashboard mDNS." >&2; exit 1; }

exec avahi-publish --address --no-fail "${dashboard_name}" "${address}"
