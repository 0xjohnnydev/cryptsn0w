#!/usr/bin/env python3
"""Non-destructive known-path read probe for the live Messages database.

The live database is never moved, opened for write, or renamed.  The probe
relocates a fresh symlink to the SMS directory, asks AFC to create one fresh
hard-link alias below Media, downloads that alias read-only, and removes the
alias before removing all other generated state.  WAL and SHM files are never
selected.  SQLite is opened with mode=ro&immutable=1 so the local copy cannot
create or modify a journal.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import plistlib
import secrets
import sqlite3
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import chain_canary as chain
import directory_matrix as matrix
from pymobiledevice3.services.afc import AfcService


EXPECTED_PRODUCT = "iPhone18,2"
EXPECTED_VERSION = "27.0"
EXPECTED_BUILD = "24A435"
TARGET_DIRECTORY = "/var/mobile/Library/SMS"
TARGET_TAIL = "var/mobile/Library/SMS"
ATC_SEQUENCE = Path(__file__).resolve().parent / "atc_sequence"


def one_book(identifier: str) -> bytes:
    return plistlib.dumps(
        {"Books": [{"Persistent ID": identifier, "Item ID": "1", "DSID": "1"}]},
        fmt=plistlib.FMT_BINARY,
        sort_keys=True,
    )


def run_atc_sequence(udid: str, identifier: str, destination: str) -> dict[str, Any]:
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


def info_value(info: dict[str, Any], key: str) -> str | None:
    values = info.get("values")
    return values.get(key) if isinstance(values, dict) else None


def query_one_message(database: Path) -> dict[str, Any]:
    uri = f"file:{database.as_posix()}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    try:
        connection.execute("PRAGMA query_only=ON")
        row = connection.execute(
            "SELECT ROWID, text, date, is_from_me "
            "FROM message WHERE text IS NOT NULL AND length(text) > 0 "
            "ORDER BY date DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return {"rowFound": False}
        body = str(row[1])
        return {
            "rowFound": True,
            "rowID": int(row[0]),
            "text": body,
            "textLength": len(body),
            "textSHA256": hashlib.sha256(body.encode()).hexdigest(),
            "appleDateRaw": int(row[2]) if row[2] is not None else None,
            "isFromMe": bool(row[3]),
        }
    finally:
        connection.close()


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


async def run() -> tuple[int, dict[str, Any]]:
    token = secrets.token_hex(10)
    source = f"codex-dir-src-24A435-{token}"
    outer_link = f"codex-dir-link-24A435-{token}"
    hardlink_alias = f"codex-sms-hardlink-24A435-{token}.db"
    cleanup_recovered = f"codex-dir-recovered-24A435-sms-{token}"
    payload = f"codex SMS hardlink read setup 24A435 {token}\n".encode()
    archive, target_tail = matrix.build_matrix_archive(TARGET_DIRECTORY, payload)
    if target_tail != TARGET_TAIL:
        raise RuntimeError("target-tail safety gate failed")
    link_identifier = f"../../{source}/p0/p1/p2/link"
    books = one_book(link_identifier)
    result: dict[str, Any] = {
        "test": "MessagesDatabaseKnownPathHardlinkRead",
        "device": {
            "productType": EXPECTED_PRODUCT,
            "productVersion": EXPECTED_VERSION,
            "buildVersion": EXPECTED_BUILD,
        },
        "target": "/var/mobile/Library/SMS/sms.db",
        "hardlinkAlias": hardlink_alias,
        "safety": {
            "liveDatabaseMoved": False,
            "liveDatabaseOpenedForWrite": False,
            "walOrShmSelected": False,
            "freshMediaAliasOnly": True,
        },
    }
    staged = False
    alias_attempted = False
    exit_code = 1

    with tempfile.TemporaryDirectory(prefix="messages-hardlink-read-24A435-") as tmp:
        work = Path(tmp)
        archive_path = work / "payload.zip"
        books_path = work / "Books.plist"
        expected_path = work / "expected.bin"
        database_path = work / "sms-hardlink-copy.db"
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
                cleanup_recovered,
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
                raise RuntimeError("ATAirlock did not relocate the SMS directory link")

            result["hardlink"] = await asyncio.to_thread(
                chain.run_mobiledevice_io,
                "create-generated-sms-hardlink",
                udid,
                outer_link,
                hardlink_alias,
            )
            alias_attempted = bool(
                result["hardlink"].get("operation", {}).get("linkAttempted")
            )
            hardlink_operation = result["hardlink"].get("operation", {})
            if not (
                result["hardlink"].get("targetGatePassed")
                and hardlink_operation.get("ok")
                and hardlink_operation.get("regularAlias")
            ):
                result["outcome"] = "hardlink-denied"
            else:
                result["download"] = await download_alias(
                    udid, hardlink_alias, database_path
                )
                result["message"] = query_one_message(database_path)
                result["outcome"] = (
                    "one-message-read" if result["message"].get("rowFound")
                    else "database-read-no-text-row"
                )
                exit_code = 0 if result["message"].get("rowFound") else 2
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
                        "remove-generated-sms-hardlink",
                        udid,
                        outer_link,
                        hardlink_alias,
                    )
                result["generatedCleanup"] = await asyncio.to_thread(
                    chain.run_mobiledevice_io,
                    "verify-matrix-cleanup",
                    udid,
                    source,
                    outer_link,
                    cleanup_recovered,
                    os.fspath(expected_path),
                    TARGET_TAIL,
                )
                result["postflight"] = await asyncio.to_thread(
                    chain.run_mobiledevice_io, "probe-afc", udid
                )

    cleanup = result.get("generatedCleanup", {}).get("operation", {})
    alias_after = (
        result.get("hardlinkCleanup", {})
        .get("operation", {})
        .get("aliasAfter", {})
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
