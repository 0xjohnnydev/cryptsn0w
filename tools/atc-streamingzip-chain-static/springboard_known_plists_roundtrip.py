#!/usr/bin/env python3
"""Safely export and restore known SpringBoard plists through AirTraffic."""

from __future__ import annotations

import hashlib
import io
import json
import os
import plistlib
import re
import secrets
import stat
import struct
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
MOBILEDEVICE_IO = ROOT / "mobiledevice_io"
ATC_SEQUENCE = ROOT / "atc_sequence"
RUN_ROOT = ROOT / "run" / "springboard-known-plists-roundtrip"
STATE_PATH = ROOT / "springboard-known-plists-roundtrip-state.json"
TARGET_DIRECTORY = "/var/mobile/Library/SpringBoard"
TARGET_TAIL = "var/mobile/Library/SpringBoard"
LEAF_PATTERN = re.compile(r"^[A-Za-z0-9._-]+\.plist$")

# Names recovered from exact 24A435 SpringBoard/HomeScreen strings.  The
# display-prefixed variants are intentionally omitted until their prefix is
# known; guessing a destination name is unnecessary for this read-only pass.
CANDIDATES = (
    "DesiredIconState.plist",
    "TodayViewArchive.plist",
    "LockScreenColorConfigurations.plist",
    "LockoutStateJournal.plist",
    "applicationstate.plist",
    "transientSettings.plist",
    "ControlsIconState.plist",
    "ControlsDesiredIconState.plist",
    "WidgetLayoutState.plist",
    "HomeScreenLayout.plist",
)


def operation_ok(result: dict[str, Any]) -> bool:
    return bool(
        result.get("targetGatePassed")
        and result.get("operation", {}).get("ok")
    )


def paired_udid() -> str:
    completed = subprocess.run(
        [
            "xcrun", "devicectl", "list", "devices", "--timeout", "8",
            "--quiet", "--json-output", "-",
            "--omit-deprecated-fields-in-json",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=12,
    )
    devices = json.loads(completed.stdout)["result"]["devices"]
    matches = []
    for device in devices:
        properties = device.get("properties", {})
        if (
            properties.get("hardware", {}).get("productType") == "iPhone18,2"
            and properties.get("connection", {}).get("pairingState") == "paired"
        ):
            matches.append(device)
    if len(matches) != 1:
        raise RuntimeError(f"expected one paired iPhone18,2, found {len(matches)}")
    udid = matches[0].get("properties", {}).get("hardware", {}).get("udid")
    if not isinstance(udid, str) or not udid:
        raise RuntimeError("paired device inventory omitted its UDID")
    return udid


def run_mobiledevice_io(command: str, *arguments: str) -> dict[str, Any]:
    completed = subprocess.run(
        [os.fspath(MOBILEDEVICE_IO), command, *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=55,
        text=True,
    )
    result: dict[str, Any] = {
        "operation": {"ok": False},
        "error": "no JSON response",
    }
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


def run_sequence(udid: str, pairs: list[tuple[str, str]]) -> dict[str, Any]:
    command = [os.fspath(ATC_SEQUENCE), udid]
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


def zip_info(name: str, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(2026, 9, 13, 15, 0, 0))
    info.create_system = 3
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = (mode & 0xFFFF) << 16
    info.extra = struct.pack("<HHH", 0x5A53, 2, mode & 0xFFFF)
    return info


def build_matrix_archive(target_directory: str, payload: bytes) -> tuple[bytes, str]:
    if not target_directory.startswith("/") or target_directory == "/":
        raise ValueError("target must be a non-root absolute directory")
    target_tail = target_directory[1:].rstrip("/")
    components = target_tail.split("/")
    if any(component in ("", ".", "..") for component in components):
        raise ValueError("target contains an unsafe component")

    metadata = plistlib.dumps(
        {"Version": 2}, fmt=plistlib.FMT_BINARY, sort_keys=True
    )
    output = io.BytesIO()
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
            f"../../../{target_tail}".encode(),
        )
        cursor = ""
        for component in components:
            cursor = f"{cursor}{component}/"
            archive.writestr(zip_info(cursor, stat.S_IFDIR | 0o755), b"")
        archive.writestr(zip_info("payload", stat.S_IFREG | 0o600), payload)
    return output.getvalue(), target_tail


def save(report: dict[str, Any], report_path: Path) -> None:
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    STATE_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


def summarize_plist(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    value = plistlib.loads(data)
    if isinstance(value, dict):
        root_type = "dictionary"
        keys = sorted(str(key) for key in value)
    elif isinstance(value, list):
        root_type = "array"
        keys = []
    else:
        root_type = type(value).__name__
        keys = []
    return {
        "path": os.fspath(path),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "rootType": root_type,
        "rootCount": len(value) if hasattr(value, "__len__") else None,
        "topLevelKeys": keys,
    }


def probe_leaf(udid: str, leaf: str, batch_dir: Path) -> dict[str, Any]:
    if not LEAF_PATTERN.fullmatch(leaf):
        raise ValueError(f"unsafe SpringBoard leaf: {leaf!r}")

    token = secrets.token_hex(10)
    source = f"codex-sb-roundtrip-src-24A435-{token}"
    link_destination = f"codex-sb-roundtrip-link-24A435-{token}"
    recovered = f"codex-sb-roundtrip-backup-24A435-{token}.plist"
    link_identifier = f"../../{source}/p0/p1/p2/link"
    target_identifier = f"../../../Library/SpringBoard/{leaf}"
    backup_identifier = f"../../{recovered}"
    run_dir = batch_dir / leaf.removesuffix(".plist")
    run_dir.mkdir(parents=True, exist_ok=False)
    report_path = run_dir / "roundtrip.json"
    local_copy = run_dir / leaf
    temporary_copy = Path("/tmp") / (
        f"codex-springboard-read-24A435-{token}.plist"
    )
    temporary_copy.unlink(missing_ok=True)

    archive, target_tail = build_matrix_archive(
        TARGET_DIRECTORY, f"SpringBoard {leaf} exact round-trip\n".encode()
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
        "test": "AirTrafficSpringBoardKnownPlistExactRoundTrip",
        "target": f"{TARGET_DIRECTORY}/{leaf}",
        "leaf": leaf,
        "token": token,
        "source": source,
        "linkDestination": link_destination,
        "recovered": recovered,
        "linkIdentifier": link_identifier,
        "targetIdentifier": target_identifier,
        "backupIdentifier": backup_identifier,
        "targetContentModified": False,
        "exactSameObjectRestoreRequested": True,
        "status": "artifacts-ready",
    }
    save(report, report_path)

    staged = False
    backup_present = False
    restored = False
    clean_absence = False
    failure: Exception | None = None
    try:
        report["stage"] = run_mobiledevice_io(
            "stage-springboard-roundtrip",
            udid,
            source,
            link_destination,
            recovered,
            leaf,
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
            [(link_identifier, link_destination),
             (target_identifier, recovered)],
        )
        report["afterExportProbe"] = run_mobiledevice_io(
            "probe-springboard-roundtrip",
            udid,
            link_destination,
            recovered,
            leaf,
        )
        operation = report["afterExportProbe"].get("operation", {})
        backup_present = bool(operation.get("backupPresent"))
        target_observed = bool(operation.get("targetObserved"))
        report["exists"] = backup_present
        if not backup_present:
            if target_observed:
                raise RuntimeError(
                    "target remained observed but no readable Media backup exists"
                )
            clean_absence = True
            report["status"] = "not-found"
            save(report, report_path)
            return report

        report["status"] = "live-file-exported"
        save(report, report_path)
        report["copy"] = run_mobiledevice_io(
            "copy-springboard-roundtrip-backup",
            udid,
            recovered,
            os.fspath(temporary_copy),
        )
        if not operation_ok(report["copy"]) or not temporary_copy.is_file():
            raise RuntimeError("exported SpringBoard plist was not readable")
        os.replace(temporary_copy, local_copy)
        report["localCopy"] = summarize_plist(local_copy)
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
            latest_probe = run_mobiledevice_io(
                "probe-springboard-roundtrip",
                udid,
                link_destination,
                recovered,
                leaf,
            )
            report["preRestoreProbe"] = latest_probe
            backup_present = bool(
                latest_probe.get("operation", {}).get("backupPresent")
            )
            if backup_present:
                report["restoreAttempts"] = []
                for attempt in range(1, 4):
                    staged_restore = run_mobiledevice_io(
                        "stage-springboard-restore-books",
                        udid,
                        source,
                        link_destination,
                        recovered,
                        leaf,
                        os.fspath(restore_books_path),
                    )
                    row: dict[str, Any] = {
                        "attempt": attempt,
                        "stage": staged_restore,
                    }
                    if operation_ok(staged_restore):
                        row["airTraffic"] = run_sequence(
                            udid,
                            [(backup_identifier,
                              f"{link_destination}/{leaf}")],
                        )
                    row["probe"] = run_mobiledevice_io(
                        "probe-springboard-roundtrip",
                        udid,
                        link_destination,
                        recovered,
                        leaf,
                    )
                    report["restoreAttempts"].append(row)
                    current = row["probe"].get("operation", {})
                    restored = bool(
                        not current.get("backupPresent", True)
                        and current.get("targetObserved") is True
                        and row.get("airTraffic", {}).get("ok") is True
                    )
                    if restored:
                        break
                    time.sleep(0.25)
            elif clean_absence:
                restored = True

            if restored:
                report["cleanup"] = run_mobiledevice_io(
                    "cleanup-springboard-roundtrip",
                    udid,
                    source,
                    link_destination,
                    recovered,
                    leaf,
                )
            else:
                report["cleanup"] = {
                    "operation": {
                        "ok": False,
                        "preserved": (
                            "generated link and exact Media backup retained"
                        ),
                    }
                }

        cleanup_ok = operation_ok(report.get("cleanup", {})) if staged else False
        report["restoredOrAbsent"] = restored
        report["cleanupVerified"] = cleanup_ok
        report["status"] = (
            "complete" if failure is None and restored and cleanup_ok
            else "restore-required" if backup_present and not restored
            else "failed"
        )
        save(report, report_path)

    if failure is not None or not restored or not report["cleanupVerified"]:
        raise RuntimeError(
            f"{leaf}: {report['status']}; see {report_path}"
        )
    return report


def main() -> int:
    if STATE_PATH.exists():
        raise RuntimeError(f"unfinished round-trip state exists: {STATE_PATH}")

    udid = paired_udid()
    preflight = run_mobiledevice_io("probe-afc", udid)
    if not operation_ok(preflight) or preflight["operation"].get(
        "booksSyncPlistPresent"
    ):
        raise RuntimeError("native device/Books preflight failed")

    token = secrets.token_hex(10)
    batch_dir = RUN_ROOT / token
    batch_dir.mkdir(parents=True, exist_ok=False)
    batch_report: dict[str, Any] = {
        "test": "AirTrafficSpringBoardKnownPlistsBatch",
        "token": token,
        "preflight": preflight,
        "candidates": list(CANDIDATES),
        "results": [],
    }
    batch_report_path = batch_dir / "batch.json"
    try:
        for index, leaf in enumerate(CANDIDATES, start=1):
            print(f"[{index}/{len(CANDIDATES)}] probing {leaf}", flush=True)
            result = probe_leaf(udid, leaf, batch_dir)
            batch_report["results"].append({
                "leaf": leaf,
                "exists": result.get("exists", False),
                "localCopy": result.get("localCopy"),
                "report": os.fspath(
                    batch_dir / leaf.removesuffix(".plist") / "roundtrip.json"
                ),
            })
            batch_report_path.write_text(
                json.dumps(batch_report, indent=2, sort_keys=True) + "\n"
            )
    except Exception as error:
        batch_report["failure"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
        batch_report_path.write_text(
            json.dumps(batch_report, indent=2, sort_keys=True) + "\n"
        )
        raise

    STATE_PATH.unlink(missing_ok=True)
    batch_report["ok"] = True
    batch_report_path.write_text(
        json.dumps(batch_report, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps({
        "ok": True,
        "report": os.fspath(batch_report_path),
        "exports": [
            row for row in batch_report["results"] if row["exists"]
        ],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
