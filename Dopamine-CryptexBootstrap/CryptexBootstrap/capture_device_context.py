#!/usr/bin/env python3
"""Capture read-only Cryptex1 personalization context from one paired device."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from pymobiledevice3.remote.userspace_tunnel import establish_userspace_rsd
from pymobiledevice3.services.cryptexd import CryptexdService


def _json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"$hex": value.hex()}
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return int(value) if hasattr(value, "__int__") else str(value)


async def _capture(udid: str, nonce_domain: int) -> dict[str, Any]:
    rsd = await establish_userspace_rsd(serial=udid)
    try:
        service = CryptexdService(rsd)
        chip = await service.read_personalization_identifiers()
        nonce = await service.cryptex_nonce(nonce_domain)
        installed = await service.copy_installed()
    finally:
        await rsd.close()

    return {
        "udid": udid,
        "nonceDomain": nonce_domain,
        "nonceHex": nonce.hex(),
        "nonceSha256": hashlib.sha256(nonce).hexdigest(),
        "chip": _json_value(chip),
        "installed": [
            {"identifier": item.identifier, "version": item.version}
            for item in installed
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--nonce-domain", type=int, default=3)
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()

    result = asyncio.run(
        _capture(args.udid, args.nonce_domain)
    )
    args.out_dir.mkdir(parents=True, exist_ok=False)
    (args.out_dir / "context.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    chip = result["chip"]
    if any(isinstance(value, dict) and "$hex" in value for value in chip.values()):
        raise ValueError("chip identifiers unexpectedly contain byte fields")
    (args.out_dir / "chip.json").write_text(
        json.dumps(chip, sort_keys=True) + "\n"
    )
    (args.out_dir / "nonce.hex").write_text(result["nonceHex"] + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
