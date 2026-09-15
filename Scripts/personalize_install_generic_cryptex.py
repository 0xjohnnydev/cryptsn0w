#!/usr/bin/env python3
"""Personalize and install one locally built Generic Cryptex1 bundle.

The script keeps the entire device transaction sequential: one userspace RSD
tunnel, identity query, nonce query, TSS request, install, and verification.
It also saves the exact request, response, ticket, and a signed bundle copy so
the transaction can be audited without repeating USB operations.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import plistlib
import shutil
import sys
from pathlib import Path
from typing import Any

from pymobiledevice3.remote.userspace_tunnel import UserspaceRsdTunnel
from pymobiledevice3.remote.xpc_message import XpcUInt64Type
from pymobiledevice3.restore.tss import TSSRequest, cryptex1_udid
from pymobiledevice3.services.cryptexd import (
    DDI_NONCE_PERSISTENCE,
    DDI_PERSISTENCE,
    CryptexdService,
)


PERSONALIZED_COMPONENTS = (
    "Cryptex1,CryptexInfoPlist",
    "Cryptex1,GenericTrustCache",
    "Cryptex1,GenericVolume",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--identifier", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    return parser.parse_args()


def load_bundle(bundle: Path) -> tuple[Path, dict[str, Any], dict[str, bytes]]:
    restore = bundle.resolve(strict=True) / "Restore"
    manifest_path = restore / "BuildManifest.plist"
    manifest = plistlib.loads(manifest_path.read_bytes())
    identities = manifest.get("BuildIdentities", [])
    if len(identities) != 1:
        raise ValueError(f"expected one build identity, found {len(identities)}")
    identity = identities[0]

    payloads: dict[str, bytes] = {}
    for component, entry in identity["Manifest"].items():
        payloads[component] = (restore / entry["Info"]["Path"]).read_bytes()
    return restore, identity, payloads


def request_dictionary(
    identity: dict[str, Any], chip: dict[str, Any], nonce: bytes
) -> dict[str, Any]:
    request: dict[str, Any] = {
        "@Cryptex1,Ticket": True,
        "Cryptex1,ChipID": int(str(identity["Cryptex1,ChipID"]), 0),
        "Cryptex1,Type": identity["Cryptex1,Type"],
        "Cryptex1,SubType": identity["Cryptex1,SubType"],
        "Cryptex1,ProductClass": int(str(identity["Cryptex1,ProductClass"]), 0),
        "Cryptex1,UseProductClass": identity["Cryptex1,UseProductClass"],
        "Cryptex1,NonceDomain": identity["Cryptex1,NonceDomain"],
        "Cryptex1,Version": identity["Cryptex1,Version"],
        "Cryptex1,PreauthorizationVersion": identity[
            "Cryptex1,PreauthorizationVersion"
        ],
        "Cryptex1,Nonce": nonce,
        "Cryptex1,ProductionMode": bool(chip["img4_chip_cpro"]),
        "Cryptex1,UDID": cryptex1_udid(chip),
        "Cryptex1,UniqueTagList": b"",
    }
    for component in PERSONALIZED_COMPONENTS:
        request[component] = {"Digest": identity["Manifest"][component]["Digest"]}
    return request


def properties(identity: dict[str, Any]) -> dict[str, Any]:
    return {
        "Cryptex1,UseProductClass": identity["Cryptex1,UseProductClass"],
        "MountedCryptex": False,
        "Cryptex1,SubType": XpcUInt64Type(identity["Cryptex1,SubType"]),
        "Cryptex1,NonceDomain": XpcUInt64Type(identity["Cryptex1,NonceDomain"]),
        "Cryptex1,Version": identity["Cryptex1,Version"],
        "Cryptex1,PreauthVersion": identity["Cryptex1,PreauthorizationVersion"],
    }


async def run(args: argparse.Namespace) -> int:
    args.out_dir.mkdir(parents=True, exist_ok=True)
    restore, identity, payloads = load_bundle(args.bundle)
    expected = {
        "Cryptex1,GenericDmg",
        "Cryptex1,GenericTrustCache",
        "Cryptex1,CryptexInfoPlist",
        "Cryptex1,GenericVolume",
    }
    if set(payloads) != expected:
        raise ValueError(f"unexpected payload set: {sorted(payloads)}")

    summary: dict[str, Any] = {
        "bundle": str(args.bundle.resolve()),
        "identifier": args.identifier,
        "version": args.version,
        "nonce_domain": int(identity["Cryptex1,NonceDomain"]),
        "payload_sha384": {
            key: hashlib.sha384(value).hexdigest() for key, value in payloads.items()
        },
    }

    async with UserspaceRsdTunnel(
        serial=args.udid, autopair=True, remotepairing_fallback=False
    ) as rsd:
        cryptexd = CryptexdService(rsd)
        installed_before = await cryptexd.copy_installed()
        if any(item.identifier == args.identifier for item in installed_before):
            raise RuntimeError(f"{args.identifier} is already installed")

        chip = await cryptexd.read_personalization_identifiers()
        nonce = await cryptexd.cryptex_nonce(int(identity["Cryptex1,NonceDomain"]))
        request_body = request_dictionary(identity, chip, nonce)
        request = TSSRequest()
        request.update(request_body)

        (args.out_dir / "chip.json").write_text(json.dumps(chip, indent=2) + "\n")
        (args.out_dir / "nonce.hex").write_text(nonce.hex() + "\n")
        (args.out_dir / "request.plist").write_bytes(
            plistlib.dumps(request._request, fmt=plistlib.FMT_XML, sort_keys=True)
        )

        response = await request.send_receive()
        response_body = dict(response)
        (args.out_dir / "response.plist").write_bytes(
            plistlib.dumps(response_body, fmt=plistlib.FMT_XML, sort_keys=True)
        )
        ticket = response.get("Cryptex1,Ticket") or response.get("ApImg4Ticket")
        if not isinstance(ticket, bytes):
            raise RuntimeError("TSS response did not include a Cryptex1 ticket")
        (args.out_dir / "ticket.im4m").write_bytes(ticket)

        signed_bundle = args.out_dir / f"{args.identifier}.signed.cxbd"
        if signed_bundle.exists():
            raise FileExistsError(signed_bundle)
        shutil.copytree(args.bundle, signed_bundle, symlinks=True)
        variant_dirs = [path for path in (signed_bundle / "Restore" / "Cryptex").iterdir() if path.is_dir()]
        if len(variant_dirs) != 1:
            raise ValueError("signed bundle did not contain exactly one variant")
        (variant_dirs[0] / "im4m").write_bytes(ticket)

        await cryptexd.install(
            image=payloads["Cryptex1,GenericDmg"],
            trustcache=payloads["Cryptex1,GenericTrustCache"],
            im4m=ticket,
            info=payloads["Cryptex1,CryptexInfoPlist"],
            volumehash=payloads["Cryptex1,GenericVolume"],
            cryptex1_properties=properties(identity),
            image_type_index=10,
            persistence=DDI_PERSISTENCE,
            nonce_persistence=DDI_NONCE_PERSISTENCE,
            auth=0,
        )

        installed_after = await cryptexd.copy_installed()
        match = next(
            (
                item
                for item in installed_after
                if item.identifier == args.identifier and item.version == args.version
            ),
            None,
        )
        if match is None:
            raise RuntimeError("install returned without the expected installed record")

    summary.update(
        {
            "nonce": nonce.hex(),
            "ticket_length": len(ticket),
            "ticket_sha256": hashlib.sha256(ticket).hexdigest(),
            "signed_bundle": str(signed_bundle),
            "installed": True,
        }
    )
    (args.out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0


def main() -> int:
    args = parse_args()
    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())
