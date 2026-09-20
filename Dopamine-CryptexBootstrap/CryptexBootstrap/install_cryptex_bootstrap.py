#!/usr/bin/env python3
"""Validate and install the pinned Dopamine bootstrap generic Cryptex1.

This installer accepts only the generic 999.* identity, a non-Apple bundle
identifier matching the build summary, an exact build-pinned multi-entry trust
cache, a current device-bound IM4M, and the same persistent cryptexd install
flags Xcode uses for its DeveloperDiskImage.
The root job inside the image separately refuses to replace an existing
``/var/jb``.
"""

from __future__ import annotations

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

from pymobiledevice3.exceptions import ConnectionTerminatedError, StreamClosedError
from pymobiledevice3.remote.userspace_tunnel import UserspaceRsdTunnel
from pymobiledevice3.remote.xpc_message import XpcUInt64Type
from pymobiledevice3.services.cryptexd import (
    DDI_NONCE_PERSISTENCE,
    DDI_PERSISTENCE,
    CryptexdService,
)


from personalize_generic_cryptex1 import (
    _component_digests,
    _identity,
    _restore_dir,
    _ticket_checks,
)


CRYPTEXCTL = Path("/System/Library/SecurityResearch/usr/bin/cryptexctl.research")
ALLOWED_INFO_KEYS = {
    "CFBundleIdentifier",
    "CFBundleVersion",
    "Name",
    "Publisher",
    "Version",
}
MAX_IMAGE_SIZE = 128 * 1024 * 1024
GENERIC_VERSION = "999.999.999.999.999,999"
INSTALL_TIMEOUT_SECONDS = 90
INSTALL_ATTEMPTS = 3


def _read_payload(
    restore_dir: Path, identity: dict[str, Any], key: str
) -> bytes:
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
    normalized["Cryptex1,ProductClass"] = str(
        identity["Cryptex1,ProductClass"]
    ).lower()
    mismatches = {
        key: {"expected": value, "actual": normalized.get(key)}
        for key, value in expected.items()
        if normalized.get(key) != value
    }
    if mismatches:
        raise ValueError(f"refusing unexpected Cryptex1 identity: {mismatches}")


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
    summary = json.loads(build_summary_path.read_text())
    restore_dir, _ = _restore_dir(bundle)
    manifest = plistlib.loads((restore_dir / "BuildManifest.plist").read_bytes())
    identity = _identity(manifest)
    _validate_identity(identity)
    digests = _component_digests(restore_dir, identity)

    identifier = summary.get("identifier")
    version = summary.get("version")
    if not isinstance(identifier, str) or identifier.startswith("com.apple."):
        raise ValueError("refusing missing or Apple-owned Cryptex identifier")
    if not isinstance(version, str):
        raise ValueError("build summary has no Cryptex version")

    info = plistlib.loads(
        _read_payload(restore_dir, identity, "Cryptex1,CryptexInfoPlist")
    )
    unexpected_info = sorted(set(info) - ALLOWED_INFO_KEYS)
    if unexpected_info:
        raise ValueError(f"refusing CryptexInfoPlist directives: {unexpected_info}")
    if info.get("CFBundleIdentifier") != identifier:
        raise ValueError(f"unexpected Cryptex identifier: {info!r}")
    if info.get("CFBundleVersion") != version:
        raise ValueError(f"unexpected Cryptex version: {info!r}")

    image = _read_payload(restore_dir, identity, "Cryptex1,GenericDmg")
    if len(image) > MAX_IMAGE_SIZE:
        raise ValueError(
            f"refusing {len(image)}-byte image (limit {MAX_IMAGE_SIZE})"
        )
    trustcache_path = (
        restore_dir
        / identity["Manifest"]["Cryptex1,GenericTrustCache"]["Info"]["Path"]
    )
    trustcache_summary = _validate_trustcache(
        trustcache_path, summary["trustCache"]
    )
    return restore_dir, identity, digests, {
        "summary": summary,
        "info": info,
        "imageBytes": len(image),
        "trustCache": trustcache_summary,
    }


async def _open_rsd(args: argparse.Namespace) -> tuple[Any, Any | None]:
    tunnel = UserspaceRsdTunnel(serial=args.udid, autopair=True)
    try:
        return await tunnel.aopen(), tunnel
    except Exception:
        await tunnel.aclose()
        raise


async def _close_rsd(rsd: Any, owner: Any | None) -> None:
    if owner is not None:
        await owner.aclose()
    else:
        await rsd.close()


async def _install(args: argparse.Namespace) -> dict[str, Any]:
    restore_dir, identity, digests, local = _validate_bundle(
        args.bundle, args.build_summary
    )
    summary = local["summary"]
    identifier = summary["identifier"]
    version = summary["version"]
    image = _read_payload(restore_dir, identity, "Cryptex1,GenericDmg")
    trustcache = _read_payload(
        restore_dir, identity, "Cryptex1,GenericTrustCache"
    )
    info = _read_payload(restore_dir, identity, "Cryptex1,CryptexInfoPlist")
    volumehash = _read_payload(
        restore_dir, identity, "Cryptex1,GenericVolume"
    )
    variant_dir = (
        restore_dir
        / identity["Manifest"]["Cryptex1,CryptexInfoPlist"]["Info"]["Path"]
    ).parent
    ticket = (variant_dir / "im4m").read_bytes()

    rsd, rsd_owner = await _open_rsd(args)
    try:
        service = CryptexdService(rsd)
        before = await service.copy_installed()
        existing = [item for item in before if item.identifier == identifier]
        if existing and not args.replace_installed:
            raise ValueError(f"{identifier} is already installed")
        if len(existing) > 1:
            raise ValueError(
                f"refusing multiple installed versions of {identifier}: "
                f"{[item.version for item in existing]}"
            )
        exact_version_installed = bool(
            existing and existing[0].version == version
        )
        chip = await service.read_personalization_identifiers()
        nonce = await service.cryptex_nonce(identity["Cryptex1,NonceDomain"])
        ticket_checks = _ticket_checks(ticket, identity, chip, nonce, digests)
        if not all(ticket_checks.values()):
            failed = [name for name, passed in ticket_checks.items() if not passed]
            raise ValueError(
                f"refusing stale or mismatched ticket: {', '.join(failed)}"
            )

        preflight = {
            "validated": True,
            "identifier": identifier,
            "version": version,
            "imageBytes": local["imageBytes"],
            "trustCache": local["trustCache"],
            "ticketChecks": ticket_checks,
            "installArguments": {
                "imageTypeIndex": 10,
                "persistence": DDI_PERSISTENCE,
                "noncePersistence": DDI_NONCE_PERSISTENCE,
                "auth": 0,
            },
            "installedBefore": [
                {"identifier": item.identifier, "version": item.version}
                for item in before
            ],
        }
        if exact_version_installed:
            return preflight | {
                "installed": {"identifier": identifier, "version": version},
                "replaced": None,
                "installAttempts": 0,
                "recoveredExistingInstall": True,
                "sameVersionAlreadyInstalled": True,
            }

        replaced = None
        if existing:
            replaced = {
                "identifier": existing[0].identifier,
                "version": existing[0].version,
            }
            await service.uninstall(
                existing[0].identifier, existing[0].version
            )
    finally:
        await _close_rsd(rsd, rsd_owner)

    expected = [{"identifier": identifier, "version": version}]
    properties: dict[str, Any] = {
        "Cryptex1,UseProductClass": identity["Cryptex1,UseProductClass"],
        "MountedCryptex": False,
        "Cryptex1,SubType": XpcUInt64Type(identity["Cryptex1,SubType"]),
        "Cryptex1,NonceDomain": XpcUInt64Type(
            identity["Cryptex1,NonceDomain"]
        ),
        "Cryptex1,Version": identity["Cryptex1,Version"],
        "Cryptex1,PreauthVersion": identity[
            "Cryptex1,PreauthorizationVersion"
        ],
    }

    # Unmounting an older Cryptex tears down its jobs and file mappings. Give
    # cryptexd a clean RemoteXPC session for the replacement image transfer.
    if replaced is not None:
        await asyncio.sleep(1)

    retryable = (
        asyncio.TimeoutError,
        ConnectionError,
        ConnectionTerminatedError,
        EOFError,
        OSError,
        StreamClosedError,
    )
    for attempt in range(1, INSTALL_ATTEMPTS + 1):
        install_rsd = None
        install_rsd_owner = None
        try:
            install_rsd, install_rsd_owner = await _open_rsd(args)
            service = CryptexdService(install_rsd)
            current = await service.copy_installed()
            installed = [
                {"identifier": item.identifier, "version": item.version}
                for item in current
                if item.identifier == identifier
            ]
            if installed == expected:
                return preflight | {
                    "installed": installed[0],
                    "replaced": replaced,
                    "installAttempts": attempt,
                    "recoveredExistingInstall": True,
                }
            if installed:
                raise RuntimeError(
                    "unexpected Cryptex appeared before replacement transfer: "
                    f"{installed}"
                )

            chip = await service.read_personalization_identifiers()
            nonce = await service.cryptex_nonce(
                identity["Cryptex1,NonceDomain"]
            )
            current_checks = _ticket_checks(
                ticket, identity, chip, nonce, digests
            )
            if not all(current_checks.values()):
                failed = [
                    name for name, passed in current_checks.items() if not passed
                ]
                raise ValueError(
                    "ticket changed before replacement transfer: "
                    + ", ".join(failed)
                )

            await asyncio.wait_for(
                service.install(
                    image=image,
                    trustcache=trustcache,
                    im4m=ticket,
                    info=info,
                    volumehash=volumehash,
                    cryptex1_properties=properties,
                    image_type_index=10,
                    persistence=DDI_PERSISTENCE,
                    nonce_persistence=DDI_NONCE_PERSISTENCE,
                    auth=0,
                ),
                timeout=INSTALL_TIMEOUT_SECONDS,
            )
            after = await service.copy_installed()
            installed = [
                {"identifier": item.identifier, "version": item.version}
                for item in after
                if item.identifier == identifier
            ]
            if installed != expected:
                raise RuntimeError(
                    "install returned but exact Cryptex was not listed: "
                    f"{installed}"
                )
            return preflight | {
                "installed": installed[0],
                "replaced": replaced,
                "installAttempts": attempt,
                "recoveredExistingInstall": False,
            }
        except retryable as error:
            if attempt == INSTALL_ATTEMPTS:
                raise RuntimeError(
                    f"Cryptex transfer failed after {attempt} attempts: {error}"
                ) from error
            print(
                f"Cryptex transfer attempt {attempt} failed: {error}; retrying",
                file=sys.stderr,
                flush=True,
            )
        finally:
            if install_rsd is not None:
                try:
                    await _close_rsd(install_rsd, install_rsd_owner)
                except retryable:
                    pass
        await asyncio.sleep(attempt)

    raise AssertionError("unreachable Cryptex install retry state")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--build-summary", required=True, type=Path)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--result-json", type=Path)
    parser.add_argument(
        "--replace-installed",
        action="store_true",
        help="replace one older Cryptex with this exact identifier",
    )
    args = parser.parse_args()

    result = asyncio.run(_install(args))
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.result_json is not None:
        args.result_json.parent.mkdir(parents=True, exist_ok=True)
        args.result_json.write_text(rendered)
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
