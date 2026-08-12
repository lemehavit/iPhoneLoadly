#!/usr/bin/env bash
set -u
IFS=$'\n\t'

PASS=0 WARN=0 FAIL=0
pass() { PASS=$((PASS + 1)); printf '✓ %s\n' "$*"; }
warn() { WARN=$((WARN + 1)); printf '! %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '✗ %s\n' "$*"; }
service() { if systemctl is-active --quiet "$1"; then pass "$1 is running"; else fail "$1 is not running"; fi; }
config_value() { sed -n "s/^$1=//p" /etc/iphoneloadly/api.env | head -n 1; }

printf 'iPhoneLoadly diagnostics\n\n'
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "${ID:-}" == debian && "${VERSION_ID%%.*}" == 13 ]] && pass "Debian ${VERSION_ID}" || fail "Debian 13 is required"
else fail '/etc/os-release is unavailable'; fi
[[ "$(dpkg --print-architecture 2>/dev/null)" == amd64 ]] && pass 'amd64 architecture' || fail 'amd64 architecture is required'

for command in curl systemctl idevice_id ideviceinfo; do
  command -v "$command" >/dev/null 2>&1 && pass "command available: $command" || fail "missing command: $command"
done
[[ -x /opt/iphoneloadly/bin/iphoneloadly-api ]] && pass 'iPhoneLoadly API installed' || fail 'iPhoneLoadly API binary is missing'
service iphoneloadly-api.service
service iphoneloadly-netmuxd.service
systemctl is-active --quiet iphoneloadly-refresh.timer && pass 'refresh timer is enabled and running' || warn 'refresh timer is not running'

if curl --fail --silent --max-time 5 http://127.0.0.1:8080/healthz >/dev/null; then pass 'dashboard/API health endpoint responds'; else fail 'dashboard/API health endpoint is unavailable'; fi
if curl --fail --silent --max-time 5 http://127.0.0.1:6970/ >/dev/null; then pass 'local anisette endpoint responds'; else warn 'local anisette endpoint does not respond'; fi

[[ -d /var/lib/iphoneloadly && -w /var/lib/iphoneloadly ]] && pass 'application state directory is writable' || fail 'application state directory is unavailable'
if [[ -f /etc/iphoneloadly/api.env ]]; then
  if [[ "$(stat -c '%a' /etc/iphoneloadly/api.env 2>/dev/null)" == 600 ]]; then pass 'API configuration permissions are 0600'; else warn 'API configuration should be mode 0600'; fi
  device_id="$(config_value IPHONELOADLY_DEVICE_ID)"
  device_ip="$(config_value IPHONELOADLY_DEVICE_IP)"
  pairing_file="$(config_value IPHONELOADLY_PAIRING_FILE)"
  if [[ -n "$device_id" && -n "$device_ip" ]]; then pass 'iPhone configuration is present'; else fail 'iPhone device ID or IP is missing'; fi
  if [[ -r "$pairing_file" ]]; then pass 'pairing file is present'; else fail 'configured pairing file is unavailable'; fi
  if [[ -n "$device_ip" ]]; then
    if ping -c 1 -W 2 "$device_ip" >/dev/null 2>&1; then pass 'configured iPhone IP responds to ping'; else warn 'configured iPhone IP does not respond (a sleeping phone may be normal)'; fi
  fi
else fail '/etc/iphoneloadly/api.env is missing'; fi

available_kb="$(df -Pk /var/lib/iphoneloadly 2>/dev/null | awk 'NR == 2 {print $4}')"
if [[ "${available_kb:-0}" -ge 5242880 ]]; then pass 'at least 5 GiB free for IPA storage'; else warn 'less than 5 GiB free for IPA storage'; fi
if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE '127\.0\.0\.1:8080$'; then pass 'API listens only on localhost:8080'; else warn 'localhost:8080 is not currently listening'; fi

if (( FAIL > 0 )); then
  printf '\nSuggested fix: review `systemctl status iphoneloadly-api` and `journalctl -u iphoneloadly-api -n 100`.\n'
fi
printf '\nSummary: %d passed, %d warnings, %d failures\n' "$PASS" "$WARN" "$FAIL"
(( FAIL == 0 ))
