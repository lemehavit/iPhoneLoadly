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
  VERSION \
  README.md \
  CHANGELOG.md \
  SECURITY.md \
  LICENSE \
  install.sh \
  install-iphoneloadly.sh \
  deploy/host/install-debian13.sh \
  deploy/systemd/iphoneloadly-api.service \
  deploy/systemd/iphoneloadly-dashboard-mdns.service \
  deploy/systemd/iphoneloadly-refresh.service \
  deploy/systemd/iphoneloadly-refresh.timer \
  deploy/caddy/Caddyfile.example \
  scripts/iphoneloadly-doctor.sh \
  scripts/create-caddy-ios-profile.sh \
  scripts/publish-dashboard-mdns.sh \
  scripts/preflight-wifi.sh \
  scripts/backup-state.sh \
  scripts/restore-state.sh \
  docs/INSTALL.md \
  docs/operations/caddy-lan.md \
  docs/operations/api-systemd.md; do
  [[ -f "${package_dir}/${required}" ]] || { echo "Release archive is missing: ${required}" >&2; exit 1; }
done

[[ "$(tr -d '[:space:]' < "${package_dir}/VERSION")" == "${version}" ]] \
  || { echo 'Release archive contains the wrong VERSION.' >&2; exit 1; }

if find "${package_dir}" -type f \( \
  -name '*.ipa' -o -name '*.mobileprovision' -o -name '*.p12' -o \
  -name '*.pfx' -o -name '*.pem' -o -name '*.key' -o -name '*.db' -o \
  -name '*.sqlite' -o -name '*.sqlite3' -o -name '*.plist' -o \
  -name '*.env' \) -print -quit | grep -q .; then
  echo 'Release archive contains a forbidden runtime or credential file.' >&2
  exit 1
fi

if grep -RIlE --binary-files=without-match \
  'gho_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY' \
  "${package_dir}" | grep -q .; then
  echo 'Release archive contains a high-confidence credential pattern.' >&2
  exit 1
fi

bash "${package_dir}/install.sh" --check-package-layout
bash "${package_dir}/install-iphoneloadly.sh" --check-package-layout
printf 'Release package validation passed: %s\n' "${archive}"
