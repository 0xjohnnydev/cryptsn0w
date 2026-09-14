#!/usr/bin/env python3
"""Export and restore the live SpringBoard IconState plist via AirTraffic."""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import secrets
import subprocess
import time
from pathlib import Path
from typing import Any

import chain_canary as chain
import directory_matrix
from springboard_preferences_probe import paired_udid


ROOT = Path(__file__).resolve().parent
RUN_ROOT = ROOT / "run" / "springboard-iconstate-roundtrip"
STATE_PATH = ROOT / "springboard-iconstate-roundtrip-state.json"
TARGET_DIRECTORY = "/var/mobile/Library/SpringBoard"
TARGET_TAIL = "var/mobile/Library/SpringBoard"
LEAF = "IconState.plist"


def operation_ok(result: dict[str, Any]) -> bool:
    return bool(
        result.get("targetGatePassed")
        and result.get("operation", {}).get("ok")
    )


def books(identifiers: list[str]) -> bytes:
    return plistlib.dumps(
        {
            "Books": [
                {"Persistent ID": value, "Item ID": str(index + 1), "DSID": "1"}
                for index, value in enumerate(identifiers)
            ]
        },
        fmt=plistlib.FMT_BINARY,
        sort_keys=True,
    )


def run_sequence(udid: str, pairs: list[tuple[str, str]]) -> dict[str, Any]:
    command = [os.fspath(ROOT / "atc_sequence"), udid]
    for identifier, destination in pairs:
        command.extend([identifier, destination])
    completed = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
    )
    result: dict[str, Any] = {"ok": False, "error": "no JSON response"}
    for line in reversed(completed.stdout.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            result = value
            break
    result["exitCode"] = completed.returncode
    if completed.stderr:
        result["stderrTail"] = completed.stderr.splitlines()[-6:]
    return result


def save(report: dict[str, Any], report_path: Path) -> None:
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    STATE_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


def main() -> int:
    if STATE_PATH.exists():
        raise RuntimeError(f"unfinished round-trip state exists: {STATE_PATH}")

    udid = paired_udid()
    preflight = chain.run_mobiledevice_io("probe-afc", udid)
    if not operation_ok(preflight) or preflight["operation"].get(
        "booksSyncPlistPresent"
    ):
        raise RuntimeError("native device/Books preflight failed")

    token = secrets.token_hex(10)
    source = f"codex-sb-roundtrip-src-24A435-{token}"
    link_destination = f"codex-sb-roundtrip-link-24A435-{token}"
    recovered = f"codex-sb-roundtrip-backup-24A435-{token}.plist"
    link_identifier = f"../../{source}/p0/p1/p2/link"
    target_identifier = f"../../../Library/SpringBoard/{LEAF}"
    backup_identifier = f"../../{recovered}"
    run_dir = RUN_ROOT / token
    run_dir.mkdir(parents=True, exist_ok=False)
    report_path = run_dir / "springboard-iconstate-roundtrip.json"
    local_copy = run_dir / LEAF
    temporary_copy = Path("/tmp") / (
        f"codex-springboard-read-24A435-{token}.plist"
    )
    temporary_copy.unlink(missing_ok=True)

    archive, target_tail = directory_matrix.build_matrix_archive(
        TARGET_DIRECTORY, b"SpringBoard IconState exact round-trip\n"
    )
    if target_tail != TARGET_TAIL:
        raise RuntimeError("fixed SpringBoard target-tail gate failed")
    archive_path = run_dir / "pivot.zip"
    export_books_path = run_dir / "Books-export.plist"
    restore_books_path = run_dir / "Books-restore.plist"
    archive_path.write_bytes(archive)
    export_books_path.write_bytes(books([link_identifier, target_identifier]))
    restore_books_path.write_bytes(books([backup_identifier]))

    report: dict[str, Any] = {
        "test": "AirTrafficSpringBoardIconStateExactRoundTrip",
        "target": f"{TARGET_DIRECTORY}/{LEAF}",
        "token": token,
        "source": source,
        "linkDestination": link_destination,
        "recovered": recovered,
        "linkIdentifier": link_identifier,
        "targetIdentifier": target_identifier,
        "backupIdentifier": backup_identifier,
        "preflight": preflight,
        "targetContentModified": False,
        "targetFileMovedForReadback": False,
        "exactSameObjectRestoreRequested": True,
        "status": "artifacts-ready",
    }
    save(report, report_path)

    staged = False
    backup_present = False
    restored = False
    failure: Exception | None = None
    try:
        report["stage"] = chain.run_mobiledevice_io(
            "stage-springboard-roundtrip",
            udid,
            source,
            link_destination,
            recovered,
            LEAF,
            os.fspath(archive_path),
            os.fspath(export_books_path),
        )
        staged = operation_ok(report["stage"])
        if not staged:
            raise RuntimeError("native round-trip staging failed")
        report["status"] = "staged"
        save(report, report_path)

        report["export"] = run_sequence(
            udid,
            [
                (link_identifier, link_destination),
                (target_identifier, recovered),
            ],
        )
        report["afterExportProbe"] = chain.run_mobiledevice_io(
            "probe-springboard-roundtrip",
            udid,
            link_destination,
            recovered,
            LEAF,
        )
        backup_present = bool(
            report["afterExportProbe"].get("operation", {}).get("backupPresent")
        )
        report["targetFileMovedForReadback"] = backup_present
        if not report["export"].get("ok") or not backup_present:
            raise RuntimeError("AirTraffic did not export IconState.plist")
        report["status"] = "live-file-exported"
        save(report, report_path)

        report["copy"] = chain.run_mobiledevice_io(
            "copy-springboard-roundtrip-backup",
            udid,
            recovered,
            os.fspath(temporary_copy),
        )
        if not operation_ok(report["copy"]) or not temporary_copy.is_file():
            raise RuntimeError("exported IconState backup was not readable")
        os.replace(temporary_copy, local_copy)
        data = local_copy.read_bytes()
        value = plistlib.loads(data)
        if not isinstance(value, (dict, list)):
            raise RuntimeError("IconState export was not a dictionary or array plist")
        report["localCopy"] = {
            "path": os.fspath(local_copy),
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "rootType": "dictionary" if isinstance(value, dict) else "array",
            "rootCount": len(value),
            "topLevelKeys": sorted(str(key) for key in value)
            if isinstance(value, dict)
            else [],
        }
        report["status"] = "exact-local-copy-saved"
        save(report, report_path)
    except Exception as error:
        failure = error
        report["failure"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
    finally:
        temporary_copy.unlink(missing_ok=True)
        if staged:
            latest_probe = chain.run_mobiledevice_io(
                "probe-springboard-roundtrip",
                udid,
                link_destination,
                recovered,
                LEAF,
            )
            report["preRestoreProbe"] = latest_probe
            backup_present = bool(
                latest_probe.get("operation", {}).get("backupPresent")
            )
            if backup_present:
                report["restoreAttempts"] = []
                for attempt in range(1, 4):
                    staged_restore = chain.run_mobiledevice_io(
                        "stage-springboard-restore-books",
                        udid,
                        source,
                        link_destination,
                        recovered,
                        LEAF,
                        os.fspath(restore_books_path),
                    )
                    row: dict[str, Any] = {
                        "attempt": attempt,
                        "stage": staged_restore,
                    }
                    if operation_ok(staged_restore):
                        row["airTraffic"] = run_sequence(
                            udid,
                            [(backup_identifier, f"{link_destination}/{LEAF}")],
                        )
                    row["probe"] = chain.run_mobiledevice_io(
                        "probe-springboard-roundtrip",
                        udid,
                        link_destination,
                        recovered,
                        LEAF,
                    )
                    report["restoreAttempts"].append(row)
                    operation = row["probe"].get("operation", {})
                    restored = bool(
                        not operation.get("backupPresent", True)
                        and operation.get("targetObserved") is True
                        and row.get("airTraffic", {}).get("ok") is True
                    )
                    if restored:
                        break
                    time.sleep(0.25)
            else:
                operation = latest_probe.get("operation", {})
                restored = bool(operation.get("targetObserved") is True)

            report["restored"] = restored
            if restored:
                report["cleanup"] = chain.run_mobiledevice_io(
                    "cleanup-springboard-roundtrip",
                    udid,
                    source,
                    link_destination,
                    recovered,
                    LEAF,
                )
            else:
                report["cleanup"] = {
                    "operation": {
                        "ok": False,
                        "preserved": "generated link and exact Media backup retained",
                    }
                }

        cleanup_ok = operation_ok(report.get("cleanup", {})) if staged else True
        report["cleanupVerified"] = cleanup_ok
        report["status"] = (
            "complete"
            if failure is None and restored and cleanup_ok
            else "restore-required"
            if backup_present and not restored
            else "failed-clean"
        )
        save(report, report_path)

    success = bool(failure is None and restored and report["cleanupVerified"])
    if success:
        STATE_PATH.unlink(missing_ok=True)
    print(
        json.dumps(
            {
                "ok": success,
                "status": report["status"],
                "report": os.fspath(report_path),
                "localCopy": report.get("localCopy"),
                "restored": restored,
                "cleanupVerified": report["cleanupVerified"],
                "failure": report.get("failure"),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if success else 2


if __name__ == "__main__":
    raise SystemExit(main())
