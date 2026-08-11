#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

usage() {
  cat <<'EOF'
Usage: bash install-iphoneloadly.sh --device-id UUID --device-ip ADDRESS --pairing-file PATH [options]

Options:
  --binary PATH       Use a prebuilt API binary instead of building with Cargo.
  --anisette-url URL  Local anisette endpoint (default: http://127.0.0.1:6970).
  --rust-log LEVEL    Rust log level (default: info).
EOF
}

device_id=""
device_ip=""
pairing_file=""
api_binary=""
anisette_url="http://127.0.0.1:6970"
rust_log="info"

while (($#)); do
  case "$1" in
    --device-id) device_id="${2:?}"; shift 2 ;;
    --device-ip) device_ip="${2:?}"; shift 2 ;;
    --pairing-file) pairing_file="${2:?}"; shift 2 ;;
    --binary) api_binary="${2:?}"; shift 2 ;;
    --anisette-url) anisette_url="${2:?}"; shift 2 ;;
    --rust-log) rust_log="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n "${device_id}" && -n "${device_ip}" && -n "${pairing_file}" ]] || { usage >&2; exit 2; }
[[ -r "${pairing_file}" ]] || { echo "Pairing file is not readable: ${pairing_file}" >&2; exit 1; }
command -v sudo >/dev/null || { echo "sudo is required." >&2; exit 1; }

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "${script_dir}/../.." && pwd)"

if [[ -z "${api_binary}" ]]; then
  command -v cargo >/dev/null || { echo "Cargo is required when --binary is omitted." >&2; exit 1; }
  (cd "${repo_root}" && cargo build --release -p iphoneloadly-api)
  api_binary="${repo_root}/target/release/iphoneloadly-api"
fi
[[ -x "${api_binary}" ]] || { echo "API binary is not executable: ${api_binary}" >&2; exit 1; }

temporary_env="$(mktemp)"
cleanup() { rm -f -- "${temporary_env}"; }
trap cleanup EXIT
cat >"${temporary_env}" <<EOF
RUST_LOG=${rust_log}
IPHONELOADLY_ANISETTE_URL=${anisette_url}
IPHONELOADLY_DEVICE_ID=${device_id}
IPHONELOADLY_DEVICE_IP=${device_ip}
IPHONELOADLY_PAIRING_FILE=${pairing_file}
EOF

sudo install -d -o root -g root -m 0755 /opt/iphoneloadly/bin /var/lib/iphoneloadly /etc/iphoneloadly /usr/share/iphoneloadly
sudo install -o root -g root -m 0755 "${api_binary}" /opt/iphoneloadly/bin/iphoneloadly-api
sudo install -o root -g root -m 0644 "${repo_root}/deploy/systemd/iphoneloadly-api.service" /etc/systemd/system/iphoneloadly-api.service
sudo install -o root -g root -m 0644 "${repo_root}/deploy/systemd/iphoneloadly-refresh.service" /etc/systemd/system/iphoneloadly-refresh.service
sudo install -o root -g root -m 0644 "${repo_root}/deploy/systemd/iphoneloadly-refresh.timer" /etc/systemd/system/iphoneloadly-refresh.timer
sudo install -o root -g root -m 0644 "${repo_root}/deploy/caddy/Caddyfile.example" /usr/share/iphoneloadly/Caddyfile.example
sudo install -o root -g root -m 0755 "${repo_root}/scripts/backup-state.sh" /usr/local/sbin/iphoneloadly-backup
sudo install -o root -g root -m 0755 "${repo_root}/scripts/restore-state.sh" /usr/local/sbin/iphoneloadly-restore
sudo install -o root -g root -m 0600 "${temporary_env}" /etc/iphoneloadly/api.env

sudo systemctl daemon-reload
sudo systemctl enable --now iphoneloadly-api.service iphoneloadly-refresh.timer
sudo systemctl restart iphoneloadly-api.service
curl --fail --silent http://127.0.0.1:8080/healthz
printf '\nInstalled iPhoneLoadly. Sign in with Apple before creating installation jobs.\n'
