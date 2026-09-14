#!/usr/bin/env python3
"""Guarded, nonpersistent install of a generic Cryptex1 canary.

The installer refuses bundles outside the generic ``999.*`` / NDOM 3 identity,
unexpected CryptexInfoPlist directives, images over 128 MiB, a trust cache with
anything other than one explicitly named cdhash, stale tickets, or an already
installed identifier.  It uses the in-process userspace tunnel by default;
``--tunneld`` selects an already-running local kernel tunnel.
"""

from __future__ import annotations

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
from pymobiledevice3.remote.xpc_message import XpcUInt64Type
from pymobiledevice3.services.cryptexd import CryptexdService
from pymobiledevice3.tunneld.api import get_tunneld_device_by_udid

from personalize_generic_cryptex1 import (
    SIGNED_COMPONENTS,
    _component_digests,
    _identity,
    _restore_dir,
    _ticket_checks,
)


ALLOWED_INFO_KEYS = {
    "CFBundleIdentifier",
    "CFBundleVersion",
    "Name",
    "Publisher",
    "Version",
}
GENERIC_VERSION = "999.999.999.999.999,999"
MAX_IMAGE_SIZE = 128 * 1024 * 1024
CRYPTEXCTL = Path("/System/Library/SecurityResearch/usr/bin/cryptexctl.research")


def _read_payload(restore_dir: Path, identity: dict[str, Any], key: str) -> bytes:
    path = restore_dir / identity["Manifest"][key]["Info"]["Path"]
    return path.read_bytes()


def _validate_identity(identity: dict[str, Any]) -> None:
    expected = {
        "Cryptex1,ChipID": "0xff10",
        "Cryptex1,Type": 3,
        "Cryptex1,SubType": 0,
        "Cryptex1,ProductClass": "0xf2",
        "Cryptex1,UseProductClass": True,
        "Cryptex1,NonceDomain": 3,
        "Cryptex1,Version": GENERIC_VERSION,
        "Cryptex1,PreauthorizationVersion": GENERIC_VERSION,
    }
    normalized = dict(identity)
    normalized["Cryptex1,ChipID"] = str(identity["Cryptex1,ChipID"]).lower()
    normalized["Cryptex1,ProductClass"] = str(identity["Cryptex1,ProductClass"]).lower()
    mismatches = {
        key: {"expected": value, "actual": normalized.get(key)}
        for key, value in expected.items()
        if normalized.get(key) != value
    }
    if mismatches:
        raise ValueError(f"refusing non-canary Cryptex1 identity: {mismatches}")


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
    restore_dir, _ = _restore_dir(args.bundle)
    manifest = plistlib.loads((restore_dir / "BuildManifest.plist").read_bytes())
    identity = _identity(manifest)
    _validate_identity(identity)
    digests = _component_digests(restore_dir, identity)

    info = _read_payload(restore_dir, identity, "Cryptex1,CryptexInfoPlist")
    info_plist = plistlib.loads(info)
    unexpected_info = sorted(set(info_plist) - ALLOWED_INFO_KEYS)
    if unexpected_info:
        raise ValueError(f"refusing CryptexInfoPlist directives: {unexpected_info}")
    if info_plist.get("CFBundleIdentifier") != args.expect_identifier:
        raise ValueError(f"unexpected identifier: {info_plist.get('CFBundleIdentifier')!r}")
    if info_plist.get("CFBundleVersion") != args.expect_version:
        raise ValueError(f"unexpected version: {info_plist.get('CFBundleVersion')!r}")
    if args.expect_identifier.startswith("com.apple."):
        raise ValueError("refusing an Apple-owned identifier")

    image = _read_payload(restore_dir, identity, "Cryptex1,GenericDmg")
    if len(image) > MAX_IMAGE_SIZE:
        raise ValueError(f"refusing {len(image)}-byte image (limit {MAX_IMAGE_SIZE})")
    trustcache = _read_payload(restore_dir, identity, "Cryptex1,GenericTrustCache")
    volumehash = _read_payload(restore_dir, identity, "Cryptex1,GenericVolume")
    trustcache_path = restore_dir / identity["Manifest"]["Cryptex1,GenericTrustCache"]["Info"]["Path"]
    trustcache_dump = _validate_trustcache(trustcache_path, args.expect_cdhash)

    variant_dir = (
        restore_dir / identity["Manifest"]["Cryptex1,CryptexInfoPlist"]["Info"]["Path"]
    ).parent
    ticket_path = variant_dir / "im4m"
    ticket = ticket_path.read_bytes()

    if args.tunneld:
        rsd = await get_tunneld_device_by_udid(args.udid)
        if rsd is None:
            raise RuntimeError(f"local tunneld has no active tunnel for {args.udid}")
    else:
        rsd = await establish_userspace_rsd(serial=args.udid)
    try:
        service = CryptexdService(rsd)
        before = await service.copy_installed()
        if any(item.identifier == args.expect_identifier for item in before):
            raise ValueError(f"{args.expect_identifier} is already installed")

        chip = await service.read_personalization_identifiers()
        nonce = await service.cryptex_nonce(identity["Cryptex1,NonceDomain"])
        ticket_checks = _ticket_checks(ticket, identity, chip, nonce, digests)
        if not all(ticket_checks.values()):
            failed = [name for name, passed in ticket_checks.items() if not passed]
            raise ValueError(f"refusing stale or mismatched ticket: {', '.join(failed)}")

        preflight = {
            "validated": True,
            "imageBytes": len(image),
            "identity": {
                "nonceDomain": identity["Cryptex1,NonceDomain"],
                "subType": identity["Cryptex1,SubType"],
                "version": identity["Cryptex1,Version"],
            },
            "installArguments": {
                "imageTypeIndex": 10,
                "persistence": 0,
                "noncePersistence": 0,
                "auth": 0,
            },
            "ticketChecks": ticket_checks,
            "trustCache": {
                "entryCount": 1,
                "cdhash": args.expect_cdhash.lower(),
                "dump": trustcache_dump.strip().splitlines(),
            },
        }
        if args.validate_only:
            return preflight | {"installed": False}

        properties: dict[str, Any] = {
            "Cryptex1,UseProductClass": identity["Cryptex1,UseProductClass"],
            "MountedCryptex": False,
            "Cryptex1,SubType": XpcUInt64Type(identity["Cryptex1,SubType"]),
            "Cryptex1,NonceDomain": XpcUInt64Type(identity["Cryptex1,NonceDomain"]),
            "Cryptex1,Version": identity["Cryptex1,Version"],
            "Cryptex1,PreauthVersion": identity["Cryptex1,PreauthorizationVersion"],
        }
        await service.install(
            image=image,
            trustcache=trustcache,
            im4m=ticket,
            info=info,
            volumehash=volumehash,
            cryptex1_properties=properties,
            image_type_index=10,
            persistence=0,
            nonce_persistence=0,
            auth=0,
        )
        after = await service.copy_installed()
    finally:
        await rsd.close()

    installed = [
        {"identifier": item.identifier, "version": item.version}
        for item in after
        if item.identifier == args.expect_identifier
    ]
    if installed != [{"identifier": args.expect_identifier, "version": args.expect_version}]:
        raise RuntimeError(f"install returned but exact canary was not listed: {installed}")
    return preflight | {"installed": installed[0]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--expect-identifier", required=True)
    parser.add_argument("--expect-version", required=True)
    parser.add_argument("--expect-cdhash", required=True)
    parser.add_argument("--result-json", type=Path)
    parser.add_argument("--validate-only", action="store_true", help="perform all checks but do not install")
    parser.add_argument("--tunneld", action="store_true", help="use the local kernel tunnel on port 49151")
    args = parser.parse_args()

    result = asyncio.run(_install(args))
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.result_json is not None:
        args.result_json.write_text(rendered)
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
