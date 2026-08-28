#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

usage() {
  cat <<'EOF'
Usage: bash install-iphoneloadly.sh [options]

Options:
  --binary PATH       Use a prebuilt API binary instead of building with Cargo.
  --anisette-url URL  Local anisette endpoint (default: http://127.0.0.1:6970).
  --upgrade           Replace runtime files without onboarding or rewriting api.env.
  --package-root PATH Use release package root for upgrade files.
EOF
}

api_binary=""
anisette_url="http://127.0.0.1:6970"
rust_log="info"
check_package_layout=false
upgrade=false
package_root=""
while (($#)); do
  case "$1" in
    --binary) api_binary="${2:?}"; shift 2 ;;
    --anisette-url) anisette_url="${2:?}"; shift 2 ;;
    --rust-log) rust_log="${2:?}"; shift 2 ;;
    --check-package-layout) check_package_layout=true; shift ;;
    --upgrade) upgrade=true; shift ;;
    --package-root) package_root="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
find_package_root() {
  local candidate
  for candidate in "${script_dir}" "${script_dir}/../.."; do
    candidate="$(CDPATH= cd -- "${candidate}" 2>/dev/null && pwd)" || continue
    if [[ -f "${candidate}/deploy/systemd/iphoneloadly-api.service" && ( -f "${candidate}/Cargo.toml" || -f "${candidate}/bin/iphoneloadly-api" ) ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  return 1
}
repo_root="$(find_package_root)" || { echo 'Unable to locate iPhoneLoadly package files.' >&2; exit 1; }

startup_timeout_seconds="${IPHONELOADLY_STARTUP_TIMEOUT_SECONDS:-30}"
startup_poll_interval_seconds="${IPHONELOADLY_STARTUP_POLL_INTERVAL_SECONDS:-1}"
replacement_temp=""
cleanup_replacement() {
  if [[ -n "${replacement_temp}" ]]; then
    sudo rm -f -- "${replacement_temp}" || true
  fi
}
stop_api_service() {
  sudo systemctl stop iphoneloadly-api.service
  local started_at="$SECONDS"
  while sudo systemctl is-active --quiet iphoneloadly-api.service; do
    (( SECONDS - started_at >= 20 )) && {
      echo 'Timed out waiting for iPhoneLoadly API to stop.' >&2
      return 1
    }
    sleep 1
  done
}
health_version() {
  local health="$1"
  if [[ "${health}" =~ \"version\"[[:space:]]*:[[:space:]]*\"([^\"]+)\" ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
  fi
}
wait_for_api_version() {
  local expected_version="$1"
  local started_at="$SECONDS"
  local deadline=$((started_at + startup_timeout_seconds))
  local remaining curl_timeout health actual_version
  while (( SECONDS < deadline )); do
    remaining=$((deadline - SECONDS))
    curl_timeout=$((remaining < 2 ? remaining : 2))
    if health="$(curl --fail --silent --show-error --max-time "${curl_timeout}" \
      http://127.0.0.1:8080/healthz 2>/dev/null)"; then
      actual_version="$(health_version "${health}")"
      if [[ -n "${actual_version}" && "${actual_version}" == "${expected_version}" ]]; then
        printf '%s\n' "${health}"
        return 0
      fi
    fi
    (( SECONDS < deadline )) && sleep "${startup_poll_interval_seconds}"
  done
  echo "Timed out waiting for API version ${expected_version}." >&2
  return 1
}
replace_api_binary() {
  local target=/opt/iphoneloadly/bin/iphoneloadly-api
  replacement_temp="$(sudo mktemp "$(dirname -- "${target}")/.iphoneloadly-api.XXXXXX")"
  sudo install -o root -g root -m 0755 "${api_binary}" "${replacement_temp}"
  sudo mv -f -- "${replacement_temp}" "${target}"
  replacement_temp=""
}

if [[ "${check_package_layout}" == true ]]; then
  for required in \
    "${repo_root}/deploy/systemd/iphoneloadly-api.service" \
    "${repo_root}/deploy/systemd/iphoneloadly-refresh.service" \
    "${repo_root}/deploy/systemd/iphoneloadly-refresh.timer" \
    "${repo_root}/deploy/systemd/iphoneloadly-dashboard-mdns.service" \
    "${repo_root}/deploy/systemd/iphoneloadly-update.service" \
    "${repo_root}/deploy/systemd/iphoneloadly-update.path" \
    "${repo_root}/deploy/systemd/iphoneloadly-source-sync.service" \
    "${repo_root}/deploy/systemd/iphoneloadly-source-sync.timer" \
    "${repo_root}/deploy/caddy/Caddyfile.example" \
    "${repo_root}/scripts/create-caddy-ios-profile.sh" \
    "${repo_root}/scripts/publish-dashboard-mdns.sh" \
    "${repo_root}/scripts/iphoneloadly-doctor.sh" \
    "${repo_root}/scripts/preflight-wifi.sh" \
    "${repo_root}/scripts/backup-state.sh"; do
    [[ -f "${required}" ]] || { echo "Release package is missing ${required#"${repo_root}/"}" >&2; exit 1; }
  done
  printf 'Application installer package root is valid: %s\n' "${repo_root}"
  exit 0
fi

if [[ "${upgrade}" == true ]]; then
  [[ -n "${package_root}" ]] || package_root="${repo_root}"
  [[ -f "${api_binary}" && -x "${api_binary}" ]] || {
    echo "Upgrade binary is missing or not executable." >&2
    exit 1
  }
  [[ -f "${package_root}/VERSION" ]] || {
    echo "Upgrade package is missing VERSION." >&2
    exit 1
  }
  expected_version="$(tr -d '[:space:]' < "${package_root}/VERSION")"
  [[ -n "${expected_version}" ]] || {
    echo "Upgrade package VERSION is empty." >&2
    exit 1
  }
  command -v sudo >/dev/null || { echo "sudo is required." >&2; exit 1; }
  for required in \
    "${package_root}/deploy/systemd/iphoneloadly-api.service" \
    "${package_root}/deploy/systemd/iphoneloadly-update.service" \
    "${package_root}/deploy/systemd/iphoneloadly-update.path" \
    "${package_root}/deploy/systemd/iphoneloadly-source-sync.service" \
    "${package_root}/deploy/systemd/iphoneloadly-source-sync.timer"; do
    [[ -f "${required}" ]] || { echo "Upgrade package is missing ${required#"${package_root}/"}" >&2; exit 1; }
  done
  trap cleanup_replacement EXIT
  sudo install -d -o root -g root -m 0755 /opt/iphoneloadly/bin /usr/share/iphoneloadly/scripts
  stop_api_service
  replace_api_binary
  sudo install -o root -g root -m 0644 "${package_root}/deploy/systemd/iphoneloadly-api.service" /etc/systemd/system/iphoneloadly-api.service
  sudo install -o root -g root -m 0644 "${package_root}/deploy/systemd/iphoneloadly-update.service" /etc/systemd/system/iphoneloadly-update.service
  sudo install -o root -g root -m 0644 "${package_root}/deploy/systemd/iphoneloadly-update.path" /etc/systemd/system/iphoneloadly-update.path
  sudo install -o root -g root -m 0644 "${package_root}/deploy/systemd/iphoneloadly-source-sync.service" /etc/systemd/system/iphoneloadly-source-sync.service
  sudo install -o root -g root -m 0644 "${package_root}/deploy/systemd/iphoneloadly-source-sync.timer" /etc/systemd/system/iphoneloadly-source-sync.timer
  sudo install -o root -g root -m 0755 "${package_root}/deploy/host/update-iphoneloadly.sh" /usr/local/libexec/iphoneloadly/update-iphoneloadly.sh
  sudo systemctl daemon-reload
  sudo systemctl enable --now iphoneloadly-update.path iphoneloadly-source-sync.timer
  sudo systemctl start iphoneloadly-api.service
  wait_for_api_version "${expected_version}"
  printf '\nUpgraded iPhoneLoadly to %s without changing configuration or state.\n' "${expected_version}"
  exit 0
fi
if [[ -z "${api_binary}" ]]; then
  cargo_binary="/opt/iphoneloadly-tools/cargo/bin/cargo"
  rustup_home="/opt/iphoneloadly-tools/rustup"
  cargo_home="/opt/iphoneloadly-tools/cargo"
  rust_toolchain="1.89.0"
  [[ -x "${cargo_binary}" ]] || { echo "The managed Rust toolchain is missing. Run: sudo bash deploy/host/install-debian13.sh" >&2; exit 1; }
  (cd "${repo_root}" && RUSTUP_HOME="${rustup_home}" CARGO_HOME="${cargo_home}" RUSTUP_TOOLCHAIN="${rust_toolchain}" \
    "${cargo_binary}" build --locked --release -p iphoneloadly-api)
  api_binary="${repo_root}/target/release/iphoneloadly-api"
fi
[[ -x "${api_binary}" ]] || { echo "API binary is not executable: ${api_binary}" >&2; exit 1; }

temporary_env="$(mktemp)"
cleanup() { rm -f -- "${temporary_env}"; }
trap cleanup EXIT
cat >"${temporary_env}" <<EOF
RUST_LOG=${rust_log}
IPHONELOADLY_ANISETTE_URL=${anisette_url}
IPHONELOADLY_MUX_SOCKET=/run/iphoneloadly/mux.sock
IPHONELOADLY_PAIRING_DIR=/var/lib/lockdown
EOF

sudo install -d -o root -g root -m 0755 /opt/iphoneloadly/bin /etc/iphoneloadly /usr/share/iphoneloadly /usr/share/iphoneloadly/scripts
sudo install -d -o root -g root -m 0700 /var/lib/iphoneloadly
sudo install -o root -g root -m 0755 "${api_binary}" /opt/iphoneloadly/bin/iphoneloadly-api
sudo install -o root -g root -m 0644 "${repo_root}/deploy/systemd/iphoneloadly-api.service" /etc/systemd/system/iphoneloadly-api.service
sudo install -o root -g root -m 0644 "${repo_root}/deploy/systemd/iphoneloadly-refresh.service" /etc/systemd/system/iphoneloadly-refresh.service
sudo install -o root -g root -m 0644 "${repo_root}/deploy/systemd/iphoneloadly-refresh.timer" /etc/systemd/system/iphoneloadly-refresh.timer
sudo install -o root -g root -m 0644 "${repo_root}/deploy/systemd/iphoneloadly-dashboard-mdns.service" /etc/systemd/system/iphoneloadly-dashboard-mdns.service
sudo install -o root -g root -m 0644 "${repo_root}/deploy/systemd/iphoneloadly-update.service" /etc/systemd/system/iphoneloadly-update.service
sudo install -o root -g root -m 0644 "${repo_root}/deploy/systemd/iphoneloadly-update.path" /etc/systemd/system/iphoneloadly-update.path
sudo install -o root -g root -m 0644 "${repo_root}/deploy/systemd/iphoneloadly-source-sync.service" /etc/systemd/system/iphoneloadly-source-sync.service
sudo install -o root -g root -m 0644 "${repo_root}/deploy/systemd/iphoneloadly-source-sync.timer" /etc/systemd/system/iphoneloadly-source-sync.timer
sudo install -o root -g root -m 0755 "${repo_root}/deploy/host/update-iphoneloadly.sh" /usr/local/libexec/iphoneloadly/update-iphoneloadly.sh
sudo install -o root -g root -m 0644 "${repo_root}/deploy/caddy/Caddyfile.example" /usr/share/iphoneloadly/Caddyfile.example
sudo install -o root -g root -m 0755 "${repo_root}/scripts/backup-state.sh" /usr/local/sbin/iphoneloadly-backup
sudo install -o root -g root -m 0755 "${repo_root}/scripts/restore-state.sh" /usr/local/sbin/iphoneloadly-restore
sudo install -o root -g root -m 0755 "${repo_root}/scripts/iphoneloadly-doctor.sh" /usr/local/sbin/iphoneloadly-doctor
sudo install -o root -g root -m 0755 "${repo_root}/scripts/preflight-wifi.sh" /usr/share/iphoneloadly/scripts/preflight-wifi.sh
sudo install -o root -g root -m 0755 "${repo_root}/scripts/create-caddy-ios-profile.sh" /usr/local/libexec/iphoneloadly/create-caddy-ios-profile.sh
sudo install -o root -g root -m 0755 "${repo_root}/scripts/publish-dashboard-mdns.sh" /usr/local/libexec/iphoneloadly/publish-dashboard-mdns.sh
sudo install -o root -g root -m 0600 "${temporary_env}" /etc/iphoneloadly/api.env

sudo systemctl daemon-reload
sudo systemctl enable --now iphoneloadly-api.service iphoneloadly-refresh.timer iphoneloadly-dashboard-mdns.service iphoneloadly-update.path iphoneloadly-source-sync.timer
sudo systemctl restart iphoneloadly-api.service
curl --fail --silent http://127.0.0.1:8080/healthz
printf '\nInstalled iPhoneLoadly. Sign in with Apple before creating installation jobs.\n'
