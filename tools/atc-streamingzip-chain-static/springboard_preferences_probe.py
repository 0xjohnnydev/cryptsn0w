#!/usr/bin/env python3
"""Read-only AirTraffic export of SpringBoard state plists on 24A435."""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import secrets
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import chain_canary as chain
import directory_matrix


ROOT = Path(__file__).resolve().parent
RUN_ROOT = ROOT / "run" / "springboard-preferences"
TARGET = "/var/mobile/Library/SpringBoard"
CANDIDATE_PLISTS = (
    "IconState.plist",
    "DesiredIconState.plist",
    "LockScreenColorConfigurations.plist",
    "LockoutStateJournal.plist",
    "TodayViewArchive.plist",
    "applicationstate.plist",
    "transientSettings.plist",
)


def operation_ok(result: dict[str, Any]) -> bool:
    return bool(
        result.get("targetGatePassed")
        and result.get("operation", {}).get("ok")
    )


def paired_udid() -> str:
    completed = subprocess.run(
        [
            "xcrun",
            "devicectl",
            "list",
            "devices",
            "--timeout",
            "8",
            "--quiet",
            "--json-output",
            "-",
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
        connection = properties.get("connection", {})
        if (
            properties.get("hardware", {}).get("productType") == "iPhone18,2"
            and connection.get("pairingState") == "paired"
        ):
            matches.append(device)
    if len(matches) != 1:
        raise RuntimeError(f"expected one paired iPhone18,2, found {len(matches)}")
    udid = matches[0].get("properties", {}).get("hardware", {}).get("udid")
    if not isinstance(udid, str) or not udid:
        raise RuntimeError("paired device inventory omitted its UDID")
    return udid


def run_sequence(udid: str, identifier: str, destination: str) -> dict[str, Any]:
    completed = subprocess.run(
        [os.fspath(ROOT / "atc_sequence"), udid, identifier, destination],
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


def summarize_plist(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    value = plistlib.loads(data)
    if isinstance(value, dict):
        keys = sorted(str(key) for key in value)
        root_type = "dictionary"
    elif isinstance(value, list):
        keys = []
        root_type = "array"
    else:
        keys = []
        root_type = type(value).__name__
    return {
        "path": os.fspath(path),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "rootType": root_type,
        "rootCount": len(value) if hasattr(value, "__len__") else None,
        "topLevelKeys": keys,
    }


def main() -> int:
    udid = paired_udid()
    preflight = chain.run_mobiledevice_io("probe-afc", udid)
    if not operation_ok(preflight) or preflight["operation"].get(
        "booksSyncPlistPresent"
    ):
        raise RuntimeError("native device/Books preflight failed")

    token = secrets.token_hex(10)
    source = f"codex-sb-browser-src-24A435-{token}"
    link_destination = f"codex-sb-browser-link-24A435-{token}"
    link_identifier = f"../../{source}/p0/p1/p2/link"
    run_dir = RUN_ROOT / token
    files_dir = run_dir / "files"
    files_dir.mkdir(parents=True, exist_ok=False)
    archive, target_tail = directory_matrix.build_matrix_archive(
        TARGET, b"read-only SpringBoard browser\n"
    )
    if target_tail != "var/mobile/Library/SpringBoard":
        raise RuntimeError("fixed target-tail gate failed")
    books = plistlib.dumps(
        {
            "Books": [
                {"Persistent ID": link_identifier, "Item ID": "1", "DSID": "1"}
            ]
        },
        fmt=plistlib.FMT_BINARY,
        sort_keys=True,
    )

    report: dict[str, Any] = {
        "test": "ReadOnlyAirTrafficSpringBoardPreferencesExport",
        "target": TARGET,
        "token": token,
        "source": source,
        "linkDestination": link_destination,
        "linkIdentifier": link_identifier,
        "preflight": preflight,
        "deviceWriteTargets": [
            "/var/mobile/Media/<generated staging>",
            "/var/mobile/Media/Books/Sync/Books.plist",
        ],
        "targetDirectoryOpenedReadOnly": True,
        "targetContentModified": False,
    }
    staged = False
    try:
        with tempfile.TemporaryDirectory(prefix="sb-browser-") as work_dir:
            work = Path(work_dir)
            archive_path = work / "browser.zip"
            books_path = work / "Books.plist"
            archive_path.write_bytes(archive)
            books_path.write_bytes(books)
            report["stage"] = chain.run_mobiledevice_io(
                "stage-springboard-browser",
                udid,
                source,
                link_destination,
                os.fspath(archive_path),
                os.fspath(books_path),
            )
            staged = operation_ok(report["stage"])
            if not staged:
                raise RuntimeError("native SpringBoard browser staging failed")

            report["airTraffic"] = run_sequence(
                udid, link_identifier, link_destination
            )
            if not report["airTraffic"].get("ok"):
                raise RuntimeError("AirTraffic link relocation failed")

            report["listing"] = chain.run_mobiledevice_io(
                "list-springboard-browser", udid, link_destination
            )
            report["exports"] = []
            if operation_ok(report["listing"]):
                entries = report["listing"]["operation"].get("entries", [])
                plist_names = sorted(
                    row["name"]
                    for row in entries
                    if isinstance(row, dict)
                    and isinstance(row.get("name"), str)
                    and row["name"].endswith(".plist")
                )
                report["discoveryMethod"] = "directory-enumeration"
            else:
                plist_names = list(CANDIDATE_PLISTS)
                report["discoveryMethod"] = "artifact-derived-known-filenames"
            for index, name in enumerate(plist_names):
                temporary = Path("/tmp") / (
                    f"codex-springboard-read-24A435-{token}-{index}.plist"
                )
                temporary.unlink(missing_ok=True)
                direct = chain.run_mobiledevice_io(
                    "copy-springboard-browser-plist",
                    udid,
                    link_destination,
                    name,
                    os.fspath(temporary),
                )
                export: dict[str, Any] = {"name": name, "directCopy": direct}
                copied = direct
                if not operation_ok(direct):
                    alias = f"codex-sb-hardlink-24A435-{token}-{index}.plist"
                    copied = chain.run_mobiledevice_io(
                        "copy-springboard-known-plist",
                        udid,
                        link_destination,
                        name,
                        alias,
                        os.fspath(temporary),
                    )
                    export["hardlinkCopy"] = copied
                    alias_after = copied.get("operation", {}).get(
                        "aliasAfter", {}
                    )
                    if alias_after.get("present") is True:
                        export["hardlinkCleanup"] = chain.run_mobiledevice_io(
                            "remove-springboard-hardlink", udid, alias
                        )
                if operation_ok(copied) and temporary.is_file():
                    destination = files_dir / name
                    os.replace(temporary, destination)
                    export["summary"] = summarize_plist(destination)
                else:
                    temporary.unlink(missing_ok=True)
                report["exports"].append(export)
    except Exception as error:
        report["errorType"] = type(error).__name__
        report["error"] = str(error)
    finally:
        if staged or "stage" in report:
            report["cleanup"] = chain.run_mobiledevice_io(
                "cleanup-springboard-browser", udid, source, link_destination
            )

    report_path = run_dir / "springboard-preferences-export.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    success = bool(
        "error" not in report
        and operation_ok(report.get("cleanup", {}))
        and report.get("exports")
        and any("summary" in row for row in report["exports"])
    )
    print(
        json.dumps(
            {
                "ok": success,
                "report": os.fspath(report_path),
                "directoryEntryCount": report.get("listing", {})
                .get("operation", {})
                .get("entryCount"),
                "plistExports": [
                    row.get("summary", {})
                    for row in report.get("exports", [])
                    if "summary" in row
                ],
                "cleanupVerified": operation_ok(report.get("cleanup", {})),
                "error": report.get("error"),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if success else 2


if __name__ == "__main__":
    raise SystemExit(main())
