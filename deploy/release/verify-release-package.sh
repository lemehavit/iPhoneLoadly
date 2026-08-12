#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "${script_dir}/../.." && pwd)"
version="$(tr -d '[:space:]' < "${repo_root}/VERSION")"
archive="${1:-${repo_root}/dist/iphoneloadly-v${version}-linux-amd64.tar.gz}"

[[ -f "${archive}" ]] || { echo "Release archive is missing: ${archive}" >&2; exit 1; }
temporary_root="$(mktemp -d)"
cleanup() { rm -rf -- "${temporary_root}"; }
trap cleanup EXIT

tar -xzf "${archive}" -C "${temporary_root}"
package_dir="${temporary_root}/iphoneloadly-v${version}-linux-amd64"
[[ -d "${package_dir}" ]] || { echo 'Release archive has an unexpected top-level directory.' >&2; exit 1; }

for required in \
  bin/iphoneloadly-api \
  install.sh \
  install-iphoneloadly.sh \
  deploy/host/install-debian13.sh \
  deploy/systemd/iphoneloadly-api.service \
  deploy/systemd/iphoneloadly-refresh.service \
  deploy/systemd/iphoneloadly-refresh.timer \
  deploy/caddy/Caddyfile.example \
  scripts/iphoneloadly-doctor.sh \
  scripts/preflight-wifi.sh \
  scripts/backup-state.sh \
  scripts/restore-state.sh \
  docs/INSTALL.md; do
  [[ -f "${package_dir}/${required}" ]] || { echo "Release archive is missing: ${required}" >&2; exit 1; }
done

bash "${package_dir}/install.sh" --check-package-layout
bash "${package_dir}/install-iphoneloadly.sh" --check-package-layout
printf 'Release package validation passed: %s\n' "${archive}"
