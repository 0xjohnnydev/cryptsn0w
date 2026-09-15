#!/usr/bin/env python3
"""Probe whether TSS accepts an appregistrard LTRS payload with a supplied nonce.

This is deliberately host-only: it builds a one-entry version-1 trust cache,
wraps it as the same ``ltrs``/``cptx`` IM4P used by appregistrard, and submits
the same LoadableTrustCache TSS request.  It does not contact or mutate the
device and does not attempt to load the resulting IMG4.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import plistlib
import re
import struct
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

from pyimg4 import IM4M, IM4P, IMG4
from pymobiledevice3.restore.tss import TSSRequest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--nonce-file", type=Path, required=True)
    parser.add_argument("--chip-file", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    return parser.parse_args()


def read_cdhash(binary: Path) -> bytes:
    result = subprocess.run(
        ["codesign", "-d", "--verbose=4", str(binary)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"codesign failed for {binary}:\n{result.stdout}")
    match = re.search(r"^CDHash=([0-9a-fA-F]{40})$", result.stdout, re.MULTILINE)
    if match is None:
        raise RuntimeError(f"codesign did not report a 20-byte CDHash:\n{result.stdout}")
    return bytes.fromhex(match.group(1))


def read_nonce(path: Path) -> bytes:
    compact = "".join(path.read_text().split())
    nonce = bytes.fromhex(compact)
    if len(nonce) != 48:
        raise ValueError(f"expected a 48-byte nonce, got {len(nonce)} bytes")
    return nonce


def build_trust_cache(cdhash: bytes, cache_uuid: uuid.UUID) -> bytes:
    if len(cdhash) != 20:
        raise ValueError("version-1 trust-cache CDHash must be 20 bytes")
    return (
        struct.pack("<I", 1)
        + cache_uuid.bytes
        + struct.pack("<I", 1)
        + cdhash
        + bytes((2, 0xC0))
    )


def make_request(chip: dict[str, Any], nonce: bytes, im4p: bytes) -> dict[str, Any]:
    return {
        "@ApImg4Ticket": True,
        "@BBTicket": True,
        "@HostPlatformInfo": "mac",
        "@UUID": str(uuid.uuid4()).upper(),
        "@VersionInfo": "libauthinstall-1104.80.2",
        "ApBoardID": int(chip["img4_chip_bord"]),
        "ApChipID": int(chip["img4_chip_chip"]),
        "ApECID": int(chip["img4_chip_ecid"]),
        "ApNonce": nonce,
        "SepNonce": bytes(20),
        "UID_MODE": False,
        "ApProductionMode": bool(chip["img4_chip_epro"]),
        "ApSecurityMode": bool(chip["img4_chip_esec"]),
        "ApSecurityDomain": int(chip["img4_chip_sdom"]),
        "Ap,SikaFuse": int(chip["img4_chip_cepo"]),
        "LoadableTrustCache": {
            "Digest": hashlib.sha384(im4p).digest(),
            "EPRO": bool(chip["img4_chip_epro"]),
            "ESEC": bool(chip["img4_chip_esec"]),
            "Trusted": True,
        },
    }


async def main() -> int:
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    binary = args.binary.resolve(strict=True)
    nonce = read_nonce(args.nonce_file)
    chip = json.loads(args.chip_file.read_text())
    cdhash = read_cdhash(binary)
    cache_uuid = uuid.uuid4()

    trust_cache = build_trust_cache(cdhash, cache_uuid)
    im4p = IM4P(fourcc="ltrs", description="cptx", payload=trust_cache).output()
    request_dictionary = make_request(chip, nonce, im4p)

    (args.out_dir / "trustcache.raw").write_bytes(trust_cache)
    (args.out_dir / "trustcache.im4p").write_bytes(im4p)
    (args.out_dir / "request.plist").write_bytes(
        plistlib.dumps(request_dictionary, fmt=plistlib.FMT_XML, sort_keys=True)
    )

    summary: dict[str, Any] = {
        "binary": str(binary),
        "cdhash": cdhash.hex(),
        "trust_cache_uuid": str(cache_uuid).upper(),
        "nonce": nonce.hex(),
        "nonce_length": len(nonce),
        "im4p_sha384": hashlib.sha384(im4p).hexdigest(),
        "request_path": str(args.out_dir / "request.plist"),
    }

    request = TSSRequest()
    request.update(request_dictionary)
    try:
        response = await request.send_receive()
    except Exception as error:
        summary["tss_status"] = "rejected-or-transport-error"
        summary["error_type"] = type(error).__name__
        summary["error"] = str(error)
        (args.out_dir / "result.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary, indent=2))
        return 2

    response_dictionary = dict(response)
    (args.out_dir / "response.plist").write_bytes(
        plistlib.dumps(response_dictionary, fmt=plistlib.FMT_XML, sort_keys=True)
    )
    ticket = response.ap_img4_ticket
    (args.out_dir / "apticket.im4m").write_bytes(ticket)
    img4 = IMG4(im4p=IM4P(im4p), im4m=IM4M(ticket)).output()
    (args.out_dir / "trustcache.img4").write_bytes(img4)

    summary["tss_status"] = "success"
    summary["response_keys"] = sorted(response_dictionary)
    summary["ticket_length"] = len(ticket)
    summary["img4_path"] = str(args.out_dir / "trustcache.img4")
    (args.out_dir / "result.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
