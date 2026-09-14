#!/usr/bin/env python3
'TSS/Cryptex personalization and installation details are redacted from this educational source release.'

from __future__ import annotations

if __name__ == "__main__":
    raise SystemExit('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


import argparse
import asyncio
import json
import plistlib
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from pymobiledevice3.remote.userspace_tunnel import establish_userspace_rsd
# [REDACTED] Related personalization helper imports omitted.
from pymobiledevice3.services.cryptexd import CryptexdService
from pymobiledevice3.tunneld.api import get_tunneld_device_by_udid

# [REDACTED] Related personalization helper imports omitted.


ALLOWED_INFO_KEYS = {
    "CFBundleIdentifier",
    "CFBundleVersion",
    "Name",
    "Publisher",
    "Version",
}
GENERIC_VERSION = None  # [REDACTED] Flow-specific parameters omitted.
MAX_IMAGE_SIZE = 128 * 1024 * 1024
CRYPTEXCTL = Path("/System/Library/SecurityResearch/usr/bin/cryptexctl.research")


def _read_payload(restore_dir: Path, identity: dict[str, Any], key: str) -> bytes:
    # [REDACTED] Related request, payload, or installation helper omitted.
    raise RuntimeError('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


def _validate_identity(identity: dict[str, Any]) -> None:
    # [REDACTED] Related request, payload, or installation helper omitted.
    raise RuntimeError('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


def _validate_trustcache(path: Path, expected_cdhash: str) -> str:
    if not CRYPTEXCTL.is_file():
        raise FileNotFoundError(f"missing {CRYPTEXCTL}")
    output = subprocess.run(
        [str(CRYPTEXCTL), "dump-trust-cache", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if "entry count = 1" not in output:
        raise ValueError("refusing trust cache whose entry count is not exactly one")
    entries = re.findall(r"^([0-9a-f]{40})\s+", output, flags=re.MULTILINE)
    if entries != [expected_cdhash.lower()]:
        raise ValueError(f"refusing unexpected trust-cache entries: {entries}")
    return output


async def _install(args: argparse.Namespace) -> dict[str, Any]:
    # [REDACTED] Related request, payload, or installation helper omitted.
    raise RuntimeError('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


def main() -> int:
    # [REDACTED] Related request, payload, or installation helper omitted.
    raise RuntimeError('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


if __name__ == "__main__":
    sys.exit(main())
