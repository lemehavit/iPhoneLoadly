#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

request=/run/iphoneloadly/update-request.json
status_file=/var/lib/iphoneloadly/data/update-status.json
work_root="$(mktemp -d /var/tmp/iphoneloadly-update.XXXXXX)"
cleanup() { rm -rf -- "${work_root}"; }
trap cleanup EXIT
upgrade_started=false
backup_root=""
runtime_targets=(
  /opt/iphoneloadly/bin/iphoneloadly-api
  /etc/systemd/system/iphoneloadly-api.service
  /etc/systemd/system/iphoneloadly-update.service
  /etc/systemd/system/iphoneloadly-update.path
  /etc/systemd/system/iphoneloadly-source-sync.service
  /etc/systemd/system/iphoneloadly-source-sync.timer
  /usr/local/libexec/iphoneloadly/update-iphoneloadly.sh
)
startup_timeout_seconds="${IPHONELOADLY_STARTUP_TIMEOUT_SECONDS:-30}"
update_path_was_enabled=false
source_sync_timer_was_enabled=false
capture_enablement() {
  if systemctl is-enabled --quiet iphoneloadly-update.path; then
    update_path_was_enabled=true
  fi
  if systemctl is-enabled --quiet iphoneloadly-source-sync.timer; then
    source_sync_timer_was_enabled=true
  fi
}
restore_enablement() {
  local restore_failed=false
  if [[ "${update_path_was_enabled}" == true ]]; then
    if ! systemctl enable --now iphoneloadly-update.path; then
      restore_failed=true
    fi
  elif ! systemctl disable --now iphoneloadly-update.path; then
    restore_failed=true
  fi
  if [[ "${source_sync_timer_was_enabled}" == true ]]; then
    if ! systemctl enable --now iphoneloadly-source-sync.timer; then
      restore_failed=true
    fi
  elif ! systemctl disable --now iphoneloadly-source-sync.timer; then
    restore_failed=true
  fi
  [[ "${restore_failed}" == false ]]
}
stop_api_service() {
  if ! systemctl stop iphoneloadly-api.service; then
    echo 'Failed to stop iPhoneLoadly API.' >&2
    return 1
  fi
  local started_at="$SECONDS"
  while systemctl is-active --quiet iphoneloadly-api.service; do
    if (( SECONDS - started_at >= 20 )); then
      echo 'Timed out waiting for iPhoneLoadly API to stop.' >&2
      return 1
    fi
    sleep 1
  done
  return 0
}
health_version() {
  local health="$1"
  if [[ "${health}" =~ \"version\"[[:space:]]*:[[:space:]]*\"([^\"]+)\" ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
  fi
}
wait_for_api_health() {
  local started_at="$SECONDS"
  local deadline=$((started_at + startup_timeout_seconds))
  local remaining curl_timeout health
  while (( SECONDS < deadline )); do
    remaining=$((deadline - SECONDS))
    curl_timeout=$((remaining < 2 ? remaining : 2))
    if health="$(curl --fail --silent --show-error --max-time "${curl_timeout}" \
      http://127.0.0.1:8080/healthz 2>/dev/null)"; then
      printf '%s\n' "${health}"
      return 0
    fi
    (( SECONDS < deadline )) && sleep 1
  done
  return 1
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
    (( SECONDS < deadline )) && sleep 1
  done
  return 1
}
backup_runtime() {
  local target key
  for target in "${runtime_targets[@]}"; do
    key="${target#/}"
    key="${key//\//__}"
    if [[ -e "${target}" ]]; then
      cp -a -- "${target}" "${backup_root}/${key}"
    else
      : >"${backup_root}/${key}.missing"
    fi
  done
}
restore_runtime() {
  local target key source temporary
  for target in "${runtime_targets[@]}"; do
    key="${target#/}"
    key="${key//\//__}"
    source="${backup_root}/${key}"
    if [[ -f "${backup_root}/${key}.missing" ]]; then
      if ! rm -f -- "${target}"; then
        return 1
      fi
    elif [[ -e "${source}" ]]; then
      if ! install -d -- "$(dirname -- "${target}")"; then
        return 1
      fi
      if ! temporary="$(mktemp "$(dirname -- "${target}")/.iphoneloadly-restore.XXXXXX")"; then
        return 1
      fi
      if ! rm -f -- "${temporary}"; then
        return 1
      fi
      if ! cp -a -- "${source}" "${temporary}"; then
        rm -f -- "${temporary}" || true
        return 1
      fi
      if ! mv -f -- "${temporary}" "${target}"; then
        rm -f -- "${temporary}" || true
        return 1
      fi
    fi
  done
  return 0
}
rollback_runtime() {
  local rollback_failed=false
  if ! stop_api_service; then
    echo 'Rollback could not stop the iPhoneLoadly API.' >&2
    return 1
  fi
  if ! restore_runtime; then
    echo 'Rollback could not restore the previous runtime.' >&2
    return 1
  fi
  if ! systemctl daemon-reload; then
    rollback_failed=true
  fi
  if ! restore_enablement; then
    rollback_failed=true
  fi
  if ! systemctl start iphoneloadly-api.service; then
    echo 'Rollback could not start the iPhoneLoadly API.' >&2
    return 1
  fi
  if [[ -n "${previous_version}" ]]; then
    if ! wait_for_api_version "${previous_version}"; then
      rollback_failed=true
    fi
  elif ! wait_for_api_health; then
    rollback_failed=true
  fi
  if [[ "${rollback_failed}" == true ]]; then
    return 1
  fi
  return 0
}
write_status() {
  local status="$1" message="$2"
  install -d -o root -g root -m 0700 "$(dirname -- "${status_file}")"
  printf '{"status":"%s","message":"%s"}\n' "${status}" "${message//\"/\\\"}" >"${status_file}"
}
fail() {
  local message="$1"
  if [[ "${upgrade_started}" == true ]]; then
    if ! rollback_runtime; then
      message="${message} Rollback verification failed."
    fi
  fi
  write_status failed "${message}"
  mv -- "${request}" "${request}.failed.$(date +%s)" 2>/dev/null || true
  exit 1
}
[[ -f "${request}" ]] || exit 0
[[ "$(stat -c '%U:%a' "${request}" 2>/dev/null || true)" == "root:600" ]] || fail 'Updater request permissions are invalid.'
command -v python3 >/dev/null || fail 'python3 is required for updater request validation.'
readarray -t request_values < <(python3 - "${request}" <<'PY'
import json, re, sys
with open(sys.argv[1], encoding='utf-8') as f:
    value = json.load(f)
if set(value) != {'targetVersion', 'expectedArchiveSha256', 'createdAt'}:
    raise SystemExit(2)
version = value['targetVersion']
digest = value['expectedArchiveSha256']
if not isinstance(version, str) or not re.fullmatch(r'(0|[1-9][0-9]*)\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?', version):
    raise SystemExit(3)
if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', digest):
    raise SystemExit(4)
print(version)
print(digest.lower())
PY
) || fail 'Updater request JSON is invalid.'
version="${request_values[0]}"
expected_digest="${request_values[1]}"
archive="iphoneloadly-v${version}-linux-amd64.tar.gz"
base_url="https://github.com/lemehavit/iPhoneLoadly/releases/download/v${version}"
archive_path="${work_root}/${archive}"
checksum_path="${archive_path}.sha256"

write_status running "Downloading and verifying iPhoneLoadly ${version}."
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --output "${archive_path}" "${base_url}/${archive}" || fail 'Official release archive download failed.'
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --output "${checksum_path}" "${base_url}/${archive}.sha256" || fail 'Official release checksum download failed.'
(
  cd "${work_root}"
  sha256sum -c "${checksum_path##*/}"
) || fail 'Official release checksum verification failed.'
actual_digest="$(sha256sum "${archive_path}" | cut -d' ' -f1)"
[[ "${actual_digest}" == "${expected_digest}" ]] || fail 'Official release digest does not match the verified API metadata.'

extract_root="${work_root}/extract"
mkdir -p -- "${extract_root}"
while IFS= read -r entry; do
  [[ "${entry}" != /* && "${entry}" != *'../'* && "${entry}" != *'/..'* ]] || fail 'Release archive contains an unsafe path.'
done < <(tar -tzf "${archive_path}")
tar -xzf "${archive_path}" -C "${extract_root}" || fail 'Release archive extraction failed.'
package_root="${extract_root}/iphoneloadly-v${version}-linux-amd64"
[[ -x "${package_root}/bin/iphoneloadly-api" ]] || fail 'Release package is missing the API binary.'
[[ -x "${package_root}/install-iphoneloadly.sh" ]] || fail 'Release package is missing the upgrade installer.'
[[ "$(tr -d '[:space:]' < "${package_root}/VERSION")" == "${version}" ]] || fail 'Release package contains the wrong version.'
for required in \
  "${package_root}/deploy/systemd/iphoneloadly-api.service" \
  "${package_root}/deploy/systemd/iphoneloadly-update.service" \
  "${package_root}/deploy/systemd/iphoneloadly-update.path" \
  "${package_root}/deploy/systemd/iphoneloadly-source-sync.service" \
  "${package_root}/deploy/systemd/iphoneloadly-source-sync.timer" \
  "${package_root}/deploy/systemd/iphoneloadly-dashboard-mdns.service" \
  "${package_root}/deploy/systemd/iphoneloadly-refresh.service" \
  "${package_root}/deploy/systemd/iphoneloadly-refresh.timer" \
  "${package_root}/deploy/host/update-iphoneloadly.sh" \
  "${package_root}/install.sh" \
  "${package_root}/deploy/host/install-debian13.sh" \
  "${package_root}/deploy/caddy/Caddyfile.example" \
  "${package_root}/scripts/backup-state.sh" \
  "${package_root}/scripts/restore-state.sh" \
  "${package_root}/docs/INSTALL.md" \
  "${package_root}/docs/USER_GUIDE.md"; do
  [[ -f "${required}" ]] || fail "Release package is missing ${required#"${package_root}/"}"
done

current_health="$(curl --fail --silent --show-error --max-time 2 \
  http://127.0.0.1:8080/healthz 2>/dev/null || true)"
previous_version="$(health_version "${current_health}")"
backup_root="${work_root}/backup"
mkdir -p -- "${backup_root}"
capture_enablement
backup_runtime || fail 'Unable to back up the current iPhoneLoadly runtime.'
upgrade_started=true
write_status installing "Installing verified iPhoneLoadly runtime files."
bash "${package_root}/install-iphoneloadly.sh" --upgrade --binary "${package_root}/bin/iphoneloadly-api" --package-root "${package_root}" || fail "Verified package installation failed while starting API version ${version}."
write_status succeeded "iPhoneLoadly ${version} installed successfully."
rm -f -- "${request}"
exit 0
