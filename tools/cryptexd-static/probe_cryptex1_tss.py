#!/usr/bin/env python3
"""Send non-installing Cryptex1 TSS canary requests and preserve raw replies.

This tool never talks to cryptexd and never installs a ticket.  It starts from a
real DDI BuildManifest request, then changes only selected personalized digests
to deterministic SHA-384 canaries.  Requests, raw HTTP replies, and any returned
tickets are retained for inspection.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import json
import plistlib
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import unquote_to_bytes

import requests

from pymobiledevice3.restore.tss import (
    TSS_CLIENT_VERSION_STRING,
    TSS_CONTROLLER_ACTION_URL,
    TSSRequest,
)
from pymobiledevice3.services.cryptexd import load_cryptex1_assets, unwrap_nonce


PERSONALIZED_COMPONENTS = {
    "ginf": "Cryptex1,CryptexInfoPlist",
    "gtcd": "Cryptex1,GenericTrustCache",
    "gtgv": "Cryptex1,GenericVolume",
}


def _json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"$hex": value.hex()}
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    return value


def _parse_tss_envelope(content: bytes) -> tuple[int | None, str | None, bytes | None]:
    status_match = re.search(rb"(?:^|&)STATUS=([^&]*)", content)
    message_match = re.search(rb"(?:^|&)MESSAGE=([^&]*)", content)
    status: int | None = None
    if status_match:
        try:
            status = int(status_match.group(1))
        except ValueError:
            pass
    message = None
    if message_match:
        message = unquote_to_bytes(message_match.group(1)).decode("utf-8", "replace")
    request_string = None
    marker = b"REQUEST_STRING="
    if marker in content:
        request_string = unquote_to_bytes(content.split(marker, 1)[1])
    return status, message, request_string


def _send(request: dict[str, Any]) -> tuple[requests.Response, int | None, str | None, dict[str, Any] | None]:
    headers = {
        "Cache-Control": "no-cache",
        "Content-type": 'text/xml; charset="utf-8"',
        "User-Agent": "InetURL/1.0",
        "Expect": "100-continue",
    }
    response = requests.post(
        TSS_CONTROLLER_ACTION_URL,
        headers=headers,
        data=plistlib.dumps(request),
        timeout=45,
        verify=False,
    )
    status, message, response_plist_raw = _parse_tss_envelope(response.content)
    response_plist = None
    if response_plist_raw:
        try:
            response_plist = plistlib.loads(response_plist_raw)
        except Exception:
            response_plist = None
    return response, status, message, response_plist


def _canary_digest(run_id: str, variant: str, component: str) -> bytes:
    material = f"codex-cryptex1-tss-canary:{run_id}:{variant}:{component}".encode()
    return hashlib.sha384(material).digest()


def _variant_request(
    base: dict[str, Any],
    run_id: str,
    variant: str,
    components: tuple[str, ...],
    metadata: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    request = copy.deepcopy(base)
    # A UUID is metadata rather than a signed component, but keep each request unique.
    request["@UUID"] = TSSRequest()._request["@UUID"]
    if metadata:
        request.update(metadata)
    canaries: dict[str, str] = {}
    for short_name in components:
        key = PERSONALIZED_COMPONENTS[short_name]
        digest = _canary_digest(run_id, variant, short_name)
        request[key] = {"Digest": digest}
        canaries[key] = digest.hex()
    return request, canaries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--restore-dir", required=True, type=Path)
    parser.add_argument("--chip-json", required=True, help="JSON object from personalization-identifiers")
    parser.add_argument("--nonce-hex", required=True, help="wrapped or bare Cryptex nonce")
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument(
        "--generic-preauth-probes",
        action="store_true",
        help="probe the 999.* generic namespace emitted by cryptexctl.research create",
    )
    args = parser.parse_args()

    chip = json.loads(args.chip_json)
    nonce_blob = bytes.fromhex(args.nonce_hex)
    nonce = unwrap_nonce(nonce_blob) if len(nonce_blob) != 48 else nonce_blob
    assets = load_cryptex1_assets(args.restore_dir)

    builder = TSSRequest()
    builder.add_cryptex1_tags(assets.build_identity, chip, nonce)
    base = copy.deepcopy(builder._request)

    args.out_dir.mkdir(parents=True, exist_ok=False)
    run_id = hashlib.sha256(plistlib.dumps(base)).hexdigest()[:16]
    variants: list[tuple[str, tuple[str, ...], dict[str, Any]]] = [
        ("baseline", (), {}),
        ("gtcd_only", ("gtcd",), {}),
        ("gtgv_only", ("gtgv",), {}),
        ("ginf_only", ("ginf",), {}),
        ("gtcd_gtgv", ("gtcd", "gtgv"), {}),
        ("all_personalized", ("ginf", "gtcd", "gtgv"), {}),
    ]
    if args.generic_preauth_probes:
        generic_version = "999.999.999.999.999,999"
        common = {
            "Cryptex1,Version": generic_version,
            "Cryptex1,PreauthorizationVersion": generic_version,
        }
        variants = [
            ("generic999_stock_digests", (), common),
            (
                "generic999_domain3_styp0_all",
                ("ginf", "gtcd", "gtgv"),
                common | {"Cryptex1,NonceDomain": 3, "Cryptex1,SubType": 0},
            ),
            (
                "generic999_domain3_styp2_all",
                ("ginf", "gtcd", "gtgv"),
                common | {"Cryptex1,NonceDomain": 3, "Cryptex1,SubType": 2},
            ),
            (
                "generic999_domain4_styp0_all",
                ("ginf", "gtcd", "gtgv"),
                common | {"Cryptex1,NonceDomain": 4, "Cryptex1,SubType": 0},
            ),
        ]

    summary: dict[str, Any] = {
        "endpoint": TSS_CONTROLLER_ACTION_URL,
        "clientVersion": TSS_CLIENT_VERSION_STRING,
        "restoreDir": str(args.restore_dir),
        "nonceSha256": hashlib.sha256(nonce).hexdigest(),
        "device": {
            "chip": chip.get("img4_chip_chip"),
            "class": chip.get("img4_chip_clas"),
            "fchp": chip.get("img4_chip_fchp"),
            "cpro": chip.get("img4_chip_cpro"),
            "rsch": chip.get("img4_chip_rsch"),
        },
        "variants": [],
    }

    for index, (variant, components, metadata) in enumerate(variants, start=1):
        request, canaries = _variant_request(base, run_id, variant, components, metadata)
        prefix = args.out_dir / f"{index:02d}-{variant}"
        prefix.with_suffix(".request.plist").write_bytes(plistlib.dumps(request))
        prefix.with_suffix(".request.json").write_text(
            json.dumps(_json_value(request), indent=2, sort_keys=True) + "\n"
        )

        response, status, message, response_plist = _send(request)
        prefix.with_suffix(".response.raw").write_bytes(response.content)
        if response_plist is not None:
            prefix.with_suffix(".response.plist").write_bytes(plistlib.dumps(response_plist))

        ticket_key = None
        ticket_len = 0
        if response_plist:
            for candidate in ("Cryptex1,Ticket", "ApImg4Ticket"):
                ticket = response_plist.get(candidate)
                if isinstance(ticket, bytes):
                    ticket_key = candidate
                    ticket_len = len(ticket)
                    prefix.with_suffix(".ticket.im4m").write_bytes(ticket)
                    break

        result = {
            "variant": variant,
            "mutatedComponents": list(components),
            "canaryDigests": canaries,
            "metadataOverrides": _json_value(metadata),
            "httpStatus": response.status_code,
            "tssStatus": status,
            "message": message,
            "ticketKey": ticket_key,
            "ticketLength": ticket_len,
        }
        summary["variants"].append(result)
        print(json.dumps(result, sort_keys=True), flush=True)

    (args.out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(f"artifacts={args.out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
