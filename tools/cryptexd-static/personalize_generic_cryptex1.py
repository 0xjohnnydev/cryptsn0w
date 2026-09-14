#!/usr/bin/env python3
"""Personalize a locally-created generic Cryptex1 bundle without installing it.

The Apple ``cryptexctl create --use-cryptex1-format`` manifest omits the
``Info.Personalize`` booleans used by pymobiledevice3's DDI-oriented loader.
This utility deliberately signs only the three generic Cryptex1 objects which
the device imports through Image4 (ginf, gtcd and gtgv); gdmg remains unsigned.

Every referenced payload is hashed before the request is sent.  The returned
IM4M is parsed and checked against the exact payload digests, nonce, device
identity and generic Cryptex1 identity before a signed bundle copy is emitted.
This utility does not open a cryptexd connection and cannot install anything.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import plistlib
import shutil
import sys
from pathlib import Path
from typing import Any

from pyimg4 import IM4M

from pymobiledevice3.restore.tss import TSSRequest, cryptex1_udid
from pymobiledevice3.services.cryptexd import unwrap_nonce

from probe_cryptex1_tss import _json_value, _send


SIGNED_COMPONENTS = {
    "Cryptex1,CryptexInfoPlist": "ginf",
    "Cryptex1,GenericTrustCache": "gtcd",
    "Cryptex1,GenericVolume": "gtgv",
}
UNSIGNED_COMPONENT = "Cryptex1,GenericDmg"


def _restore_dir(path: Path) -> tuple[Path, Path]:
    path = path.resolve()
    if (path / "BuildManifest.plist").is_file():
        return path, path.parent
    if (path / "Restore" / "BuildManifest.plist").is_file():
        return path / "Restore", path
    raise FileNotFoundError(f"no Restore/BuildManifest.plist below {path}")


def _identity(manifest: dict[str, Any]) -> dict[str, Any]:
    matches = [
        item
        for item in manifest.get("BuildIdentities", [])
        if all(key in item.get("Manifest", {}) for key in (*SIGNED_COMPONENTS, UNSIGNED_COMPONENT))
    ]
    if len(matches) != 1:
        raise ValueError(f"expected one generic Cryptex1 identity, found {len(matches)}")
    return matches[0]


def _component_digests(restore_dir: Path, identity: dict[str, Any]) -> dict[str, bytes]:
    digests: dict[str, bytes] = {}
    for key in (*SIGNED_COMPONENTS, UNSIGNED_COMPONENT):
        entry = identity["Manifest"][key]
        path = restore_dir / entry["Info"]["Path"]
        data = path.read_bytes()
        actual = hashlib.sha384(data).digest()
        expected = entry["Digest"]
        if actual != expected:
            raise ValueError(
                f"SHA-384 mismatch for {key}: manifest={expected.hex()} actual={actual.hex()} ({path})"
            )
        digests[key] = actual
    return digests


def _property_dict(properties: Any) -> dict[str, Any]:
    return {prop.fourcc: prop.value for prop in properties}


def _ticket_checks(
    ticket: bytes,
    identity: dict[str, Any],
    chip: dict[str, Any],
    nonce: bytes,
    digests: dict[str, bytes],
) -> dict[str, bool]:
    im4m = IM4M(ticket)
    properties = _property_dict(im4m.properties)
    images = {image.fourcc: _property_dict(image.properties) for image in im4m.images}

    version = identity["Cryptex1,Version"].encode()
    preauth = identity["Cryptex1,PreauthorizationVersion"].encode()
    checks = {
        "productionMode": properties.get("CPRO") is bool(chip["img4_chip_cpro"]),
        "udid": properties.get("UDID") == cryptex1_udid(chip),
        "nonce": properties.get("cnch") == nonce,
        "chipFamily": properties.get("fchp") == int(str(identity["Cryptex1,ChipID"]), 0),
        "type": properties.get("type") == identity["Cryptex1,Type"],
        "subType": properties.get("styp") == identity["Cryptex1,SubType"],
        "productClass": properties.get("clas") == int(str(identity["Cryptex1,ProductClass"]), 0),
        "nonceDomain": properties.get("ndom") == identity["Cryptex1,NonceDomain"],
        "useProductClass": properties.get("upcl") is bool(identity["Cryptex1,UseProductClass"]),
        "version": properties.get("vnum") == version,
        "preauthorizationVersion": properties.get("pave") == preauth,
    }
    for key, fourcc in SIGNED_COMPONENTS.items():
        checks[f"digest:{fourcc}"] = images.get(fourcc, {}).get("DGST") == digests[key]
    checks["noUnsignedGdmgDigest"] = "gdmg" not in images
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path, help="cxbd or its Restore directory")
    parser.add_argument("--chip-json", required=True, help="cryptexd personalization-identifiers JSON")
    parser.add_argument("--nonce-hex", required=True, help="wrapped or bare nonce for the manifest's NDOM")
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()

    restore_dir, bundle_dir = _restore_dir(args.bundle)
    manifest_path = restore_dir / "BuildManifest.plist"
    manifest = plistlib.loads(manifest_path.read_bytes())
    identity = _identity(manifest)
    digests = _component_digests(restore_dir, identity)

    chip = json.loads(args.chip_json)
    nonce_blob = bytes.fromhex(args.nonce_hex)
    nonce = unwrap_nonce(nonce_blob) if len(nonce_blob) != 48 else nonce_blob
    if len(nonce) != 48:
        raise ValueError(f"expected a 48-byte Cryptex1 nonce, got {len(nonce)} bytes")

    request_identity = copy.deepcopy(identity)
    for key, entry in request_identity["Manifest"].items():
        entry.setdefault("Info", {})["Personalize"] = key in SIGNED_COMPONENTS

    builder = TSSRequest()
    builder.add_cryptex1_tags(request_identity, chip, nonce)
    request = copy.deepcopy(builder._request)
    requested_components = {key for key in request if key in SIGNED_COMPONENTS or key == UNSIGNED_COMPONENT}
    if requested_components != set(SIGNED_COMPONENTS):
        raise ValueError(f"unexpected personalized component set: {sorted(requested_components)}")

    args.out_dir.mkdir(parents=True, exist_ok=False)
    (args.out_dir / "request.plist").write_bytes(plistlib.dumps(request))
    (args.out_dir / "request.json").write_text(
        json.dumps(_json_value(request), indent=2, sort_keys=True) + "\n"
    )

    response, status, message, response_plist = _send(request)
    (args.out_dir / "response.raw").write_bytes(response.content)
    if response_plist is not None:
        (args.out_dir / "response.plist").write_bytes(plistlib.dumps(response_plist))
    if status != 0 or message != "SUCCESS" or response_plist is None:
        raise RuntimeError(f"TSS rejected request: STATUS={status} MESSAGE={message!r}")

    ticket = response_plist.get("Cryptex1,Ticket") or response_plist.get("ApImg4Ticket")
    if not isinstance(ticket, bytes):
        raise RuntimeError("successful TSS response did not contain a Cryptex1 ticket")
    (args.out_dir / "ticket.im4m").write_bytes(ticket)

    checks = _ticket_checks(ticket, identity, chip, nonce, digests)
    if not all(checks.values()):
        failed = [name for name, passed in checks.items() if not passed]
        raise RuntimeError(f"returned ticket did not match request: {', '.join(failed)}")

    signed_bundle = args.out_dir / f"{bundle_dir.stem}.signed.cxbd"
    shutil.copytree(bundle_dir, signed_bundle)
    variant_paths = [path for path in (signed_bundle / "Restore" / "Cryptex").iterdir() if path.is_dir()]
    if len(variant_paths) != 1:
        raise ValueError(f"expected one Cryptex variant directory, found {len(variant_paths)}")
    (variant_paths[0] / "im4m").write_bytes(ticket)

    summary = {
        "bundle": str(bundle_dir),
        "signedBundle": str(signed_bundle),
        "variant": variant_paths[0].name,
        "nonceDomain": identity["Cryptex1,NonceDomain"],
        "nonceSha256": hashlib.sha256(nonce).hexdigest(),
        "ticketSha256": hashlib.sha256(ticket).hexdigest(),
        "ticketLength": len(ticket),
        "payloadDigests": {key: value.hex() for key, value in digests.items()},
        "checks": checks,
        "verified": all(checks.values()),
    }
    (args.out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
