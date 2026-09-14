#!/usr/bin/env python3
'TSS/Cryptex personalization and installation details are redacted from this educational source release.'

from __future__ import annotations

if __name__ == "__main__":
    raise SystemExit('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


import argparse
import asyncio
import hashlib
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


WORKSPACE = Path(__file__).resolve().parents[2]
HELPER_DIR = WORKSPACE / "tools" / "cryptexd-static"
sys.path.insert(0, str(HELPER_DIR))

from install_generic_cryptex1_canary import (  # noqa: E402
    _read_payload,
    _validate_identity,
)
# [REDACTED] Related personalization helper imports omitted.


CRYPTEXCTL = Path("/System/Library/SecurityResearch/usr/bin/cryptexctl.research")
ALLOWED_INFO_KEYS = {
    "CFBundleIdentifier",
    "CFBundleVersion",
    "Name",
    "Publisher",
    "Version",
}
MAX_IMAGE_SIZE = 128 * 1024 * 1024


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _validate_trustcache(path: Path, expected: dict[str, Any]) -> dict[str, Any]:
    output = subprocess.run(
        [str(CRYPTEXCTL), "dump-trust-cache", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    count_match = re.search(r"^entry count = ([0-9]+)$", output, re.MULTILINE)
    if count_match is None:
        raise ValueError("could not parse trust-cache entry count")
    count = int(count_match.group(1))
    entries = re.findall(r"^([0-9a-f]{40})\s+", output, re.MULTILINE)
    expected_entries = expected.get("cdhashes")
    if count != expected.get("entryCount") or entries != expected_entries:
        raise ValueError(
            "trust cache does not exactly match the pinned build summary"
        )
    actual_sha256 = _sha256(path)
    if actual_sha256 != expected.get("sha256"):
        raise ValueError("trust-cache SHA-256 does not match build summary")
    return {
        "entryCount": count,
        "sha256": actual_sha256,
        "firstCdhash": entries[0],
        "lastCdhash": entries[-1],
    }


def _validate_bundle(
    bundle: Path, build_summary_path: Path
) -> tuple[Path, dict[str, Any], dict[str, bytes], dict[str, Any]]:
    # [REDACTED] Related request, payload, or installation helper omitted.
    raise RuntimeError('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


async def _install(args: argparse.Namespace) -> dict[str, Any]:
    # [REDACTED] Related request, payload, or installation helper omitted.
    raise RuntimeError('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


def main() -> int:
    # [REDACTED] Related request, payload, or installation helper omitted.
    raise RuntimeError('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


if __name__ == "__main__":
    sys.exit(main())
