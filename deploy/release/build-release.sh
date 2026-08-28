#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "${script_dir}/../.." && pwd)"
version="$(tr -d '[:space:]' < "${repo_root}/VERSION")"
[[ -n "${version}" ]] || { echo "VERSION is empty." >&2; exit 1; }
command -v cargo >/dev/null || { echo "Cargo is required." >&2; exit 1; }
[[ "$(uname -s)" == "Linux" ]] || {
  echo "Release packages must be built on Linux; use the CI artifact from the pull request." >&2
  exit 1
}
[[ "$(uname -m)" == "x86_64" ]] || {
  echo "Release packages currently support Linux x86_64/amd64 only." >&2
  exit 1
}
cargo_target_dir="${CARGO_TARGET_DIR:-${repo_root}/target}"

(cd "${repo_root}" && cargo build --locked --release -p iphoneloadly-api)

dist_root="${repo_root}/dist"
release_name="iphoneloadly-v${version}-linux-amd64"
release_dir="${dist_root}/${release_name}"
case "${release_dir}" in "${dist_root}"/*) ;; *) echo "Unsafe release directory." >&2; exit 1;; esac
rm -rf -- "${release_dir}"
mkdir -p "${release_dir}/bin" "${release_dir}/deploy/host" "${release_dir}/deploy/systemd" "${release_dir}/deploy/caddy" "${release_dir}/scripts" "${release_dir}/docs"

install -m 0755 "${cargo_target_dir}/release/iphoneloadly-api" "${release_dir}/bin/iphoneloadly-api"
install -m 0644 "${repo_root}/VERSION" "${release_dir}/VERSION"
install -m 0644 "${repo_root}/README.md" "${release_dir}/README.md"
install -m 0644 "${repo_root}/CHANGELOG.md" "${release_dir}/CHANGELOG.md"
install -m 0644 "${repo_root}/SECURITY.md" "${release_dir}/SECURITY.md"
install -m 0644 "${repo_root}/LICENSE" "${release_dir}/LICENSE"
install -m 0755 "${repo_root}/deploy/host/install-iphoneloadly.sh" "${release_dir}/install-iphoneloadly.sh"
install -m 0755 "${repo_root}/deploy/host/update-iphoneloadly.sh" "${release_dir}/deploy/host/update-iphoneloadly.sh"
install -m 0755 "${repo_root}/deploy/host/install.sh" "${release_dir}/install.sh"
install -m 0755 "${repo_root}/deploy/host/install-debian13.sh" "${release_dir}/deploy/host/install-debian13.sh"
install -m 0644 "${repo_root}/deploy/systemd/iphoneloadly-api.service" "${release_dir}/deploy/systemd/iphoneloadly-api.service"
install -m 0644 "${repo_root}/deploy/systemd/iphoneloadly-update.service" "${release_dir}/deploy/systemd/iphoneloadly-update.service"
install -m 0644 "${repo_root}/deploy/systemd/iphoneloadly-update.path" "${release_dir}/deploy/systemd/iphoneloadly-update.path"
install -m 0644 "${repo_root}/deploy/systemd/iphoneloadly-source-sync.service" "${release_dir}/deploy/systemd/iphoneloadly-source-sync.service"
install -m 0644 "${repo_root}/deploy/systemd/iphoneloadly-source-sync.timer" "${release_dir}/deploy/systemd/iphoneloadly-source-sync.timer"
install -m 0644 "${repo_root}/deploy/systemd/iphoneloadly-dashboard-mdns.service" "${release_dir}/deploy/systemd/iphoneloadly-dashboard-mdns.service"
install -m 0644 "${repo_root}/deploy/systemd/iphoneloadly-refresh.service" "${release_dir}/deploy/systemd/iphoneloadly-refresh.service"
install -m 0644 "${repo_root}/deploy/systemd/iphoneloadly-refresh.timer" "${release_dir}/deploy/systemd/iphoneloadly-refresh.timer"
install -m 0644 "${repo_root}/deploy/caddy/Caddyfile.example" "${release_dir}/deploy/caddy/Caddyfile.example"
install -m 0755 "${repo_root}/scripts/backup-state.sh" "${release_dir}/scripts/backup-state.sh"
install -m 0755 "${repo_root}/scripts/restore-state.sh" "${release_dir}/scripts/restore-state.sh"
install -m 0755 "${repo_root}/scripts/preflight-wifi.sh" "${release_dir}/scripts/preflight-wifi.sh"
install -m 0755 "${repo_root}/scripts/iphoneloadly-doctor.sh" "${release_dir}/scripts/iphoneloadly-doctor.sh"
install -m 0755 "${repo_root}/scripts/create-caddy-ios-profile.sh" "${release_dir}/scripts/create-caddy-ios-profile.sh"
install -m 0755 "${repo_root}/scripts/publish-dashboard-mdns.sh" "${release_dir}/scripts/publish-dashboard-mdns.sh"
cp -a "${repo_root}/docs/." "${release_dir}/docs/"
install -m 0644 "${repo_root}/deploy/host/THIRD_PARTY_NOTICES.md" "${release_dir}/THIRD_PARTY_NOTICES.md"

(cd "${dist_root}" && tar -czf "${release_name}.tar.gz" "${release_name}")
(cd "${dist_root}" && sha256sum "${release_name}.tar.gz" > "${release_name}.tar.gz.sha256")
printf 'Release created:\n%s\n%s\n' "${dist_root}/${release_name}.tar.gz" "${dist_root}/${release_name}.tar.gz.sha256"
