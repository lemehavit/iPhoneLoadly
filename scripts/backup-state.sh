#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

[[ "${EUID}" -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }

backup_root="${1:-/var/backups/iphoneloadly}"
anisette_volume="${IPHONELOADLY_ANISETTE_VOLUME:-iphoneloadly-anisette-source-libs}"
backup_dir="${backup_root}/$(date +%F-%H%M%S)"

pairing_file="$(find /var/lib/lockdown -maxdepth 1 -type f -name '00008110-*.plist' -print -quit)"
[[ -n "${pairing_file}" ]] || { echo "No iPhone pairing file found." >&2; exit 1; }

install -d -o root -g root -m 0700 "${backup_dir}"
archive_paths=(etc/iphoneloadly var/lib/iphoneloadly "${pairing_file#/}")
[[ -d /etc/caddy ]] && archive_paths+=(etc/caddy)
tar -C / -czf "${backup_dir}/iphoneloadly-system.tar.gz" "${archive_paths[@]}"

docker run --rm \
  -v "${anisette_volume}:/source:ro" \
  -v "${backup_dir}:/backup" \
  alpine:3.22 \
  tar -C /source -czf /backup/anisette-libs.tar.gz .

(
  cd "${backup_dir}"
  sha256sum ./*.tar.gz > SHA256SUMS
  chmod 0600 ./*
  sha256sum -c SHA256SUMS
)

printf 'Backup verified: %s\n' "${backup_dir}"
