#!/usr/bin/env python3
"""Install an already-personalized generic Cryptex1 bundle without TSS.

The bundle must contain its saved ``im4m`` beside the four generic Cryptex1
payloads.  Before any mutation, this tool verifies the generic 999.* identity,
all manifest SHA-384 digests, the expected identifier/version, and every IM4M
binding against the device's current Cryptex nonce and personalization IDs.

Only a direct userspace RSD connection to the explicitly named USB device is
opened.  Remote-pairing fallback is disabled, and this module has no TSS or
HTTP request path.  Installation is always nonpersistent (persistence=0 and
nonce-persistence=0).  An existing matching identifier is left untouched
unless ``--replace-existing`` is explicitly supplied.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import plistlib
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from pymobiledevice3.remote.userspace_tunnel import UserspaceRsdTunnel
from pymobiledevice3.remote.xpc_message import XpcUInt64Type
from pymobiledevice3.services.cryptexd import CryptexdService, unwrap_nonce


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
STATIC_HELPERS = REPOSITORY_ROOT / "tools" / "cryptexd-static"
if not STATIC_HELPERS.is_dir():
    raise RuntimeError(f"missing Cryptex static helpers: {STATIC_HELPERS}")
sys.path.insert(0, str(STATIC_HELPERS))

# Reuse the audited bundle/digest/IM4M validators used by the static Cryptex
# utilities.  Importing them does not send a request; this script never calls
# the personalization/TSS entry point from that module.
from install_generic_cryptex1_canary import _validate_identity  # noqa: E402
from personalize_generic_cryptex1 import (  # noqa: E402
    SIGNED_COMPONENTS,
    UNSIGNED_COMPONENT,
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
EXPECTED_COMPONENTS = {*SIGNED_COMPONENTS, UNSIGNED_COMPONENT}
MAX_TICKET_BYTES = 16 * 1024 * 1024
INSTALL_ARGUMENTS = {
    "imageTypeIndex": 10,
    "persistence": 0,
    "noncePersistence": 0,
    "auth": 0,
}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bundle",
        required=True,
        type=Path,
        help="already-personalized .cxbd directory (or its Restore directory)",
    )
    parser.add_argument(
        "--udid",
        required=True,
        help="exact UDID of the USB-connected device",
    )
    parser.add_argument("--expect-identifier", required=True)
    parser.add_argument("--expect-version", required=True)
    parser.add_argument(
        "--replace-existing",
        action="store_true",
        help=(
            "after all checks pass, uninstall exactly one existing record with "
            "the expected identifier before installing the saved bundle"
        ),
    )
    return parser.parse_args()


def _validate_expected_strings(identifier: str, version: str, udid: str) -> None:
    if not identifier or len(identifier) > 255:
        raise ValueError("expected identifier must contain 1 to 255 characters")
    if identifier.startswith("com.apple."):
        raise ValueError("refusing an Apple-owned identifier")
    if any(character.isspace() for character in identifier) or any(
        character in identifier for character in ("/", "\\", "\0")
    ):
        raise ValueError(f"invalid expected identifier: {identifier!r}")
    if not version or len(version) > 255 or "\0" in version:
        raise ValueError("expected version must contain 1 to 255 characters")
    if not udid or any(character.isspace() for character in udid):
        raise ValueError("UDID must be a nonempty string without whitespace")


def _payload_path(
    restore_dir: Path, identity: dict[str, Any], component: str
) -> Path:
    try:
        relative_value = identity["Manifest"][component]["Info"]["Path"]
    except (KeyError, TypeError) as error:
        raise ValueError(f"missing payload path for {component}") from error
    if not isinstance(relative_value, str):
        raise ValueError(f"non-string payload path for {component}")

    relative = PurePosixPath(relative_value)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError(f"unsafe payload path for {component}: {relative_value!r}")

    restore_real = restore_dir.resolve(strict=True)
    candidate = restore_real.joinpath(*relative.parts)
    cursor = restore_real
    for part in relative.parts:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError(f"refusing symlink in payload path: {cursor}")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(restore_real):
        raise ValueError(f"payload escapes Restore directory: {relative_value!r}")
    if not resolved.is_file():
        raise ValueError(f"payload is not a regular file: {resolved}")
    return resolved


def _load_and_validate_bundle(
    bundle: Path, expected_identifier: str, expected_version: str
) -> dict[str, Any]:
    restore_dir, bundle_dir = _restore_dir(bundle)
    restore_dir = restore_dir.resolve(strict=True)
    bundle_dir = bundle_dir.resolve(strict=True)
    manifest_path = restore_dir / "BuildManifest.plist"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError(f"invalid BuildManifest.plist: {manifest_path}")
    manifest = plistlib.loads(manifest_path.read_bytes())
    identity = _identity(manifest)
    if set(identity.get("Manifest", {})) != EXPECTED_COMPONENTS:
        raise ValueError(
            "unexpected generic Cryptex1 component set: "
            f"{sorted(identity.get('Manifest', {}))}"
        )
    _validate_identity(identity)

    payload_paths = {
        component: _payload_path(restore_dir, identity, component)
        for component in EXPECTED_COMPONENTS
    }
    # This helper both hashes each payload and compares it to the manifest's
    # exact SHA-384 Digest field.
    digests = _component_digests(restore_dir, identity)

    info_path = payload_paths["Cryptex1,CryptexInfoPlist"]
    info = info_path.read_bytes()
    info_plist = plistlib.loads(info)
    if not isinstance(info_plist, dict):
        raise ValueError("CryptexInfoPlist is not a dictionary")
    unexpected_info = sorted(set(info_plist) - ALLOWED_INFO_KEYS)
    if unexpected_info:
        raise ValueError(
            f"refusing CryptexInfoPlist directives: {unexpected_info}"
        )
    if info_plist.get("CFBundleIdentifier") != expected_identifier:
        raise ValueError(
            "unexpected Cryptex identifier: "
            f"{info_plist.get('CFBundleIdentifier')!r}"
        )
    if info_plist.get("CFBundleVersion") != expected_version:
        raise ValueError(
            f"unexpected Cryptex version: {info_plist.get('CFBundleVersion')!r}"
        )
    if "Version" in info_plist and info_plist["Version"] != expected_version:
        raise ValueError(
            f"CryptexInfoPlist Version disagrees: {info_plist['Version']!r}"
        )

    cryptex_dir = (restore_dir / "Cryptex").resolve(strict=True)
    variant_dir = info_path.parent
    if variant_dir.parent != cryptex_dir:
        raise ValueError(
            f"CryptexInfoPlist is not in one direct Cryptex variant: {info_path}"
        )
    variant_entries = sorted(cryptex_dir.iterdir())
    if (
        len(variant_entries) != 1
        or variant_entries[0].is_symlink()
        or not variant_entries[0].is_dir()
        or variant_entries[0].resolve(strict=True) != variant_dir
    ):
        raise ValueError(
            "expected exactly one regular Cryptex variant directory, found "
            f"{variant_entries}"
        )

    ticket_path = variant_dir / "im4m"
    if ticket_path.is_symlink() or not ticket_path.is_file():
        raise ValueError(f"signed bundle has no regular embedded im4m: {ticket_path}")
    ticket = ticket_path.read_bytes()
    if not ticket or len(ticket) > MAX_TICKET_BYTES:
        raise ValueError(
            f"invalid embedded im4m length {len(ticket)} (max {MAX_TICKET_BYTES})"
        )

    return {
        "bundleDir": bundle_dir,
        "restoreDir": restore_dir,
        "identity": identity,
        "payloadPaths": payload_paths,
        "payloadDigests": digests,
        "info": info,
        "ticket": ticket,
        "ticketPath": ticket_path,
    }


def _installed_records(items: list[Any], identifier: str) -> list[dict[str, str]]:
    return sorted(
        (
            {"identifier": item.identifier, "version": item.version}
            for item in items
            if item.identifier == identifier
        ),
        key=lambda item: (item["identifier"], item["version"]),
    )


def _fixed_properties(identity: dict[str, Any]) -> dict[str, Any]:
    return {
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


async def _current_nonce(service: CryptexdService, nonce_domain: int) -> bytes:
    nonce_blob = await service.cryptex_nonce(nonce_domain)
    nonce = unwrap_nonce(nonce_blob) if len(nonce_blob) != 48 else nonce_blob
    if len(nonce) != 48:
        raise ValueError(
            f"expected a 48-byte Cryptex nonce, received {len(nonce)} bytes"
        )
    return nonce


async def _install(args: argparse.Namespace) -> dict[str, Any]:
    _validate_expected_strings(
        args.expect_identifier, args.expect_version, args.udid
    )
    local = _load_and_validate_bundle(
        args.bundle, args.expect_identifier, args.expect_version
    )
    identity = local["identity"]
    payload_paths = local["payloadPaths"]
    digests = local["payloadDigests"]
    ticket = local["ticket"]

    async with UserspaceRsdTunnel(
        serial=args.udid,
        autopair=True,
        remotepairing_fallback=False,
    ) as rsd:
        service = CryptexdService(rsd)
        before = await service.copy_installed()
        existing = _installed_records(before, args.expect_identifier)
        if len(existing) > 1:
            raise ValueError(
                "multiple existing records have the expected identifier; refusing "
                f"ambiguous replacement: {existing}"
            )
        if existing and not args.replace_existing:
            raise ValueError(
                f"{args.expect_identifier} is already installed as {existing[0]}; "
                "use --replace-existing to replace that one exact record"
            )

        chip = await service.read_personalization_identifiers()
        nonce = await _current_nonce(
            service, int(identity["Cryptex1,NonceDomain"])
        )
        ticket_checks = _ticket_checks(ticket, identity, chip, nonce, digests)
        if not all(ticket_checks.values()):
            failed = sorted(
                name for name, passed in ticket_checks.items() if not passed
            )
            raise ValueError(
                "refusing stale or mismatched embedded im4m: " + ", ".join(failed)
            )

        # Re-read the matching records and nonce immediately before mutation so
        # an install/uninstall or nonce roll racing the preflight fails closed.
        current = _installed_records(
            await service.copy_installed(), args.expect_identifier
        )
        if current != existing:
            raise RuntimeError(
                f"installed-record state changed during preflight: {existing} -> {current}"
            )
        if await _current_nonce(
            service, int(identity["Cryptex1,NonceDomain"])
        ) != nonce:
            raise RuntimeError("Cryptex nonce changed during preflight")

        replaced: dict[str, str] | None = None
        if existing:
            replaced = existing[0]
            await service.uninstall(
                replaced["identifier"], replaced["version"]
            )
            remaining = _installed_records(
                await service.copy_installed(), args.expect_identifier
            )
            if remaining:
                raise RuntimeError(
                    f"replacement uninstall left matching records: {remaining}"
                )
            if await _current_nonce(
                service, int(identity["Cryptex1,NonceDomain"])
            ) != nonce:
                raise RuntimeError(
                    "Cryptex nonce changed after replacement uninstall; "
                    "saved ticket was not installed"
                )

        await service.install(
            image=payload_paths["Cryptex1,GenericDmg"].read_bytes(),
            trustcache=payload_paths[
                "Cryptex1,GenericTrustCache"
            ].read_bytes(),
            im4m=ticket,
            info=local["info"],
            volumehash=payload_paths["Cryptex1,GenericVolume"].read_bytes(),
            cryptex1_properties=_fixed_properties(identity),
            image_type_index=INSTALL_ARGUMENTS["imageTypeIndex"],
            persistence=INSTALL_ARGUMENTS["persistence"],
            nonce_persistence=INSTALL_ARGUMENTS["noncePersistence"],
            auth=INSTALL_ARGUMENTS["auth"],
        )
        installed = _installed_records(
            await service.copy_installed(), args.expect_identifier
        )

    expected_entry = {
        "identifier": args.expect_identifier,
        "version": args.expect_version,
    }
    if installed != [expected_entry]:
        raise RuntimeError(
            "install returned without the one exact expected entry: "
            f"expected={[expected_entry]} actual={installed}"
        )

    return {
        "ok": True,
        "operation": "install-saved-ticket-generic-cryptex",
        "device": args.udid,
        "transport": "usb-userspace-rsd",
        "networkFallback": False,
        "tssRequests": 0,
        "bundle": str(local["bundleDir"]),
        "expected": expected_entry,
        "identity": {
            "chipId": identity["Cryptex1,ChipID"],
            "type": identity["Cryptex1,Type"],
            "subType": identity["Cryptex1,SubType"],
            "productClass": identity["Cryptex1,ProductClass"],
            "nonceDomain": identity["Cryptex1,NonceDomain"],
            "version": identity["Cryptex1,Version"],
            "preauthorizationVersion": identity[
                "Cryptex1,PreauthorizationVersion"
            ],
        },
        "nonceSha256": hashlib.sha256(nonce).hexdigest(),
        "payloadSha384": {
            component: digest.hex()
            for component, digest in sorted(digests.items())
        },
        "ticket": {
            "path": str(local["ticketPath"]),
            "bytes": len(ticket),
            "sha256": hashlib.sha256(ticket).hexdigest(),
            "checks": ticket_checks,
        },
        "installArguments": INSTALL_ARGUMENTS,
        "replaced": replaced,
        "installed": installed[0],
    }


def main() -> int:
    args = _parse_args()
    try:
        result = asyncio.run(_install(args))
    except Exception as error:
        print(
            json.dumps(
                {
                    "ok": False,
                    "operation": "install-saved-ticket-generic-cryptex",
                    "error": {
                        "type": type(error).__name__,
                        "message": str(error),
                    },
                },
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
