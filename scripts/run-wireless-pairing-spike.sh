#!/usr/bin/env bash
set -Eeuo pipefail

# This launcher never touches the installed systemd service or production data.
# Keep the directory across process restarts when testing persistence.
: "${IPHONELOADLY_SPIKE_DATA_DIR:=/tmp/iphoneloadly-wireless-spike}"
: "${IPHONELOADLY_SPIKE_API_ADDRESS:=127.0.0.1:18080}"
: "${IPHONELOADLY_PAIRING_PORT:=52345}"
: "${IPHONELOADLY_PAIRING_INTERFACE:=}"
: "${IPHONELOADLY_WIRELESS_PAIRING:=experimental}"

umask 077
mkdir -p "$IPHONELOADLY_SPIKE_DATA_DIR"
export IPHONELOADLY_SPIKE_DATA_DIR
export IPHONELOADLY_SPIKE_API_ADDRESS
export IPHONELOADLY_PAIRING_PORT
export IPHONELOADLY_PAIRING_INTERFACE
export IPHONELOADLY_WIRELESS_PAIRING
export IPHONELOADLY_WIRELESS_STATE_DIR="$IPHONELOADLY_SPIKE_DATA_DIR/wireless-pairing"

exec cargo run --release -p iphoneloadly-api -- --wireless-pairing-spike
