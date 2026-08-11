#!/usr/bin/env python3
"""Verify a trusted iPhone lockdownd connection directly over Wi-Fi.

This bypasses usbmuxd and netmuxd for the connection itself. It uses the
pairing record created during USB onboarding without displaying its contents.
"""

from __future__ import annotations

import argparse
import asyncio
import plistlib
import sys
from pathlib import Path

from pymobiledevice3.lockdown import create_using_tcp


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="iPhone IPv4 or IPv6 address")
    parser.add_argument("--udid", required=True, help="iPhone UDID")
    parser.add_argument(
        "--pair-record",
        type=Path,
        help="pairing-record path (default: /var/lib/lockdown/<UDID>.plist)",
    )
    return parser.parse_args()


async def verify(arguments: argparse.Namespace) -> None:
    record_path = arguments.pair_record or Path("/var/lib/lockdown") / f"{arguments.udid}.plist"
    if not record_path.is_file():
        raise FileNotFoundError("pairing record is unavailable")

    with record_path.open("rb") as record_file:
        pair_record = plistlib.load(record_file)

    lockdown = await create_using_tcp(
        hostname=arguments.host,
        identifier=arguments.udid,
        pair_record=pair_record,
        autopair=False,
    )
    device_name = await lockdown.get_value(key="DeviceName")
    product_version = await lockdown.get_value(key="ProductVersion")

    print(f"DeviceName: {device_name}")
    print(f"ProductVersion: {product_version}")


def main() -> int:
    try:
        asyncio.run(verify(parse_arguments()))
    except FileNotFoundError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    except Exception as error:
        print(f"ERROR: trusted Wi-Fi lockdown query failed: {type(error).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
