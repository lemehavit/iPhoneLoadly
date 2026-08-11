#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

usage() {
  cat <<'EOF'
Usage: sudo bash restore-state.sh --verify BACKUP_DIR
       sudo bash restore-state.sh --apply BACKUP_DIR

--verify validates checksums and archive contents without changing the system.
--apply stops the API, restores API/Caddy/pairing state and the anisette volume.
EOF
}

mode=""
backup_dir=""
while (($#)); do
  case "$1" in
    --verify|--apply) mode="${1#--}"; backup_dir="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ -n "${mode}" && -d "${backup_dir}" ]] || { usage >&2; exit 2; }
[[ "${EUID}" -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }

system_archive="${backup_dir}/iphoneloadly-system.tar.gz"
anisette_archive="${backup_dir}/anisette-libs.tar.gz"
[[ -f "${system_archive}" && -f "${anisette_archive}" && -f "${backup_dir}/SHA256SUMS" ]] \
  || { echo "Backup files are incomplete." >&2; exit 1; }

(
  cd "${backup_dir}"
  sha256sum -c SHA256SUMS
)
tar -tzf "${system_archive}" | grep -qx 'var/lib/iphoneloadly/' \
  || { echo "System archive does not contain iPhoneLoadly state." >&2; exit 1; }
tar -tzf "${anisette_archive}" >/dev/null
printf 'Backup verification succeeded: %s\n' "${backup_dir}"

[[ "${mode}" == "verify" ]] && exit 0

read -rp "Type RESTORE to overwrite local iPhoneLoadly state: " confirmation
[[ "${confirmation}" == "RESTORE" ]] || { echo "Restore cancelled."; exit 1; }

anisette_volume="${IPHONELOADLY_ANISETTE_VOLUME:-iphoneloadly-anisette-source-libs}"
systemctl stop iphoneloadly-api.service || true
tar -C / -xzf "${system_archive}"
docker volume create "${anisette_volume}" >/dev/null
docker run --rm \
  -v "${anisette_volume}:/target" \
  -v "${backup_dir}:/backup:ro" \
  alpine:3.22 \
  sh -c 'rm -rf /target/* && tar -C /target -xzf /backup/anisette-libs.tar.gz'
systemctl daemon-reload
systemctl start iphoneloadly-api.service
printf 'Restore completed. Sign in with Apple again before creating installation jobs.\n'
