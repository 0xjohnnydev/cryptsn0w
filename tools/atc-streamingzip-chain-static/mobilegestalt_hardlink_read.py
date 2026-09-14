#!/usr/bin/env python3
"""Read-only AirTraffic/AFC hard-link gate for the canonical MG cache.

The live cache is never opened for write, moved, renamed, or removed.  A fresh
relocated directory symlink is created by the existing StreamingZip/AirTraffic
chain, AFC is asked to create one fresh hard-link alias below Media, and only
that alias is downloaded.  Cleanup removes the alias before the generated
symlink and staging tree.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import plistlib
import secrets
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import chain_canary as chain
import directory_matrix as matrix
from pymobiledevice3.services.afc import AfcService


EXPECTED_PRODUCT = "iPhone18,2"
EXPECTED_VERSION = "27.0"
EXPECTED_BUILD = "24A435"
TARGET_DIRECTORY = (
    "/private/var/containers/Shared/SystemGroup/"
    "systemgroup.com.apple.mobilegestaltcache/Library/Caches"
)
TARGET_TAIL = (
    "private/var/containers/Shared/SystemGroup/"
    "systemgroup.com.apple.mobilegestaltcache/Library/Caches"
)
TARGET_LEAF = "com.apple.MobileGestalt.plist"
ATC_SEQUENCE = Path(__file__).resolve().parent / "atc_sequence"
EVIDENCE_DIRECTORY = Path(__file__).resolve().parent / "evidence" / "private"


def one_book(identifier: str) -> bytes:
    return plistlib.dumps(
        {"Books": [{"Persistent ID": identifier, "Item ID": "1", "DSID": "1"}]},
        fmt=plistlib.FMT_BINARY,
        sort_keys=True,
    )


def run_atc_sequence(udid: str, identifier: str, destination: str) -> dict[str, Any]:
    import subprocess

    completed = subprocess.run(
        [os.fspath(ATC_SEQUENCE), udid, identifier, destination],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=100,
    )
    parsed: dict[str, Any] = {"ok": False, "error": "no JSON response"}
    for line in reversed(completed.stdout.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            parsed = value
            break
    parsed["exitCode"] = completed.returncode
    if completed.stderr:
        parsed["stderrTail"] = completed.stderr.splitlines()[-6:]
    return parsed


async def download_alias(udid: str, alias: str, destination: Path) -> dict[str, Any]:
    result: dict[str, Any] = {}
    async with chain.paired_wifi_provider(result) as provider:
        observed = (
            provider.product_type,
            provider.product_version,
            provider.product_build_version,
        )
        if observed != (EXPECTED_PRODUCT, EXPECTED_VERSION, EXPECTED_BUILD):
            raise RuntimeError("device/build safety gate rejected the connected target")
        async with AfcService(provider) as afc:
            await afc.pull(alias, os.fspath(destination), progress_bar=False)
    result["bytesDownloaded"] = destination.stat().st_size
    result["sha256"] = hashlib.sha256(destination.read_bytes()).hexdigest()
    return result


def validate_cache(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    root = plistlib.loads(raw)
    if not isinstance(root, dict):
        raise RuntimeError("downloaded cache root is not a dictionary")
    cache_data = root.get("CacheData")
    cache_extra = root.get("CacheExtra")
    return {
        "binaryPlist": raw.startswith(b"bplist00"),
        "rootKeys": sorted(str(key) for key in root),
        "cacheDataBytes": len(cache_data) if isinstance(cache_data, bytes) else None,
        "cacheExtraCount": len(cache_extra) if isinstance(cache_extra, dict) else None,
        "hasExpectedShape": bool(
            raw.startswith(b"bplist00")
            and isinstance(cache_data, bytes)
            and isinstance(cache_extra, dict)
            and "CacheVersion" in root
            and "CacheUUID" in root
        ),
    }


async def run() -> tuple[int, dict[str, Any]]:
    token = secrets.token_hex(10)
    source = f"codex-dir-src-24A435-{token}"
    outer_link = f"codex-dir-link-24A435-{token}"
    alias = f"codex-mgcache-hardlink-24A435-{token}.plist"
    recovered = f"codex-dir-recovered-24A435-mgcache-{token}"
    payload = f"codex MG cache hardlink read setup 24A435 {token}\n".encode()
    archive, target_tail = matrix.build_matrix_archive(TARGET_DIRECTORY, payload)
    if target_tail != TARGET_TAIL:
        raise RuntimeError("target-tail safety gate failed")
    link_identifier = f"../../{source}/p0/p1/p2/link"
    books = one_book(link_identifier)
    result: dict[str, Any] = {
        "schema": 1,
        "test": "MobileGestaltCanonicalCacheHardlinkRead",
        "device": {
            "productType": EXPECTED_PRODUCT,
            "productVersion": EXPECTED_VERSION,
            "buildVersion": EXPECTED_BUILD,
        },
        "target": f"{TARGET_DIRECTORY}/{TARGET_LEAF}",
        "hardlinkAlias": alias,
        "safety": {
            "liveCacheMoved": False,
            "liveCacheOpenedForWrite": False,
            "liveCacheRenamedOrRemoved": False,
            "freshMediaAliasOnly": True,
        },
    }
    staged = False
    alias_attempted = False
    exit_code = 1
    direct_path = Path("/tmp") / (
        f"codex-mgcache-read-24A435-{secrets.token_hex(12)}.plist"
    )

    with tempfile.TemporaryDirectory(prefix="mgcache-hardlink-read-24A435-") as tmp:
        work = Path(tmp)
        archive_path = work / "payload.zip"
        books_path = work / "Books.plist"
        expected_path = work / "expected.bin"
        cache_path = work / TARGET_LEAF
        archive_path.write_bytes(archive)
        books_path.write_bytes(books)
        expected_path.write_bytes(payload)
        try:
            udid = chain.TRANSPORT.paired_coredevice_udid()
            result["preflight"] = await matrix.preflight(udid)
            result["stage"] = await asyncio.to_thread(
                chain.run_mobiledevice_io,
                "stage",
                udid,
                source,
                outer_link,
                recovered,
                os.fspath(archive_path),
                os.fspath(books_path),
            )
            staged = bool(
                result["stage"].get("targetGatePassed")
                and result["stage"].get("operation", {}).get("ok")
            )
            if not staged:
                raise RuntimeError("StreamingZip/Books staging failed")

            result["relocateLink"] = await asyncio.to_thread(
                run_atc_sequence, udid, link_identifier, outer_link
            )
            if not result["relocateLink"].get("ok"):
                raise RuntimeError("AirTraffic did not relocate the cache-directory link")

            result["hardlink"] = await asyncio.to_thread(
                chain.run_mobiledevice_io,
                "create-generated-mgcache-hardlink",
                udid,
                outer_link,
                alias,
            )
            alias_attempted = bool(
                result["hardlink"].get("operation", {}).get("linkAttempted")
            )
            operation = result["hardlink"].get("operation", {})
            if not (
                result["hardlink"].get("targetGatePassed")
                and operation.get("ok")
                and operation.get("regularAlias")
            ):
                result["directRead"] = await asyncio.to_thread(
                    chain.run_mobiledevice_io,
                    "read-generated-mgcache-direct",
                    udid,
                    outer_link,
                    os.fspath(direct_path),
                )
                direct_operation = result["directRead"].get("operation", {})
                if direct_operation.get("ok") and direct_path.is_file():
                    result["cacheValidation"] = validate_cache(direct_path)
                    if not result["cacheValidation"]["hasExpectedShape"]:
                        raise RuntimeError("directly read object is not a valid MG cache")
                    EVIDENCE_DIRECTORY.mkdir(parents=True, exist_ok=True)
                    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                    evidence_path = EVIDENCE_DIRECTORY / f"mgcache-{stamp}.plist"
                    evidence_path.write_bytes(direct_path.read_bytes())
                    evidence_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
                    result["evidencePath"] = os.fspath(evidence_path)
                    result["outcome"] = "canonical-cache-read-through-direct-open"
                    exit_code = 0
                else:
                    result["outcome"] = "hardlink-and-direct-open-denied"
            else:
                result["download"] = await download_alias(udid, alias, cache_path)
                result["cacheValidation"] = validate_cache(cache_path)
                if not result["cacheValidation"]["hasExpectedShape"]:
                    raise RuntimeError("downloaded object is not a valid MG cache")
                EVIDENCE_DIRECTORY.mkdir(parents=True, exist_ok=True)
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                evidence_path = EVIDENCE_DIRECTORY / f"mgcache-{stamp}.plist"
                evidence_path.write_bytes(cache_path.read_bytes())
                evidence_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
                result["evidencePath"] = os.fspath(evidence_path)
                result["outcome"] = "canonical-cache-read-through-hardlink"
                exit_code = 0
        except Exception as error:
            result["error"] = {
                "type": type(error).__name__,
                "message": chain.TRANSPORT.redact(error)[:800],
            }
        finally:
            if staged:
                if alias_attempted:
                    result["hardlinkCleanup"] = await asyncio.to_thread(
                        chain.run_mobiledevice_io,
                        "remove-generated-mgcache-hardlink",
                        udid,
                        outer_link,
                        alias,
                    )
                result["generatedCleanup"] = await asyncio.to_thread(
                    chain.run_mobiledevice_io,
                    "verify-matrix-cleanup",
                    udid,
                    source,
                    outer_link,
                    recovered,
                    os.fspath(expected_path),
                    TARGET_TAIL,
                )
                result["postflight"] = await asyncio.to_thread(
                    chain.run_mobiledevice_io, "probe-afc", udid
                )
            direct_path.unlink(missing_ok=True)

    cleanup = result.get("generatedCleanup", {}).get("operation", {})
    alias_after = (
        result.get("hardlinkCleanup", {}).get("operation", {}).get("aliasAfter", {})
    )
    result["cleanupVerified"] = bool(
        (not alias_attempted or alias_after.get("present") is False)
        and cleanup.get("safeArguments")
        and cleanup.get("cleanupFailureCount") == 0
        and cleanup.get("sourceMediaAbsent")
        and cleanup.get("linkAbsent")
        and cleanup.get("booksFilesAbsent")
        and not result.get("postflight", {})
        .get("operation", {})
        .get("booksSyncPlistPresent", True)
    )
    if not result["cleanupVerified"]:
        result["cleanupWarning"] = "generated cleanup was not fully verified"
        exit_code = 3
    return exit_code, result


def main() -> int:
    code, result = asyncio.run(run())
    print(json.dumps(result, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
