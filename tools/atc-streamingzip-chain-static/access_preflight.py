#!/usr/bin/env python3
"""Measure browse, direct read, export readback, and fresh-file write.

The read probe consumes at most 4096 bytes and never returns file contents.
The write probe targets a fresh randomized leaf, recovers its exact bytes, and
requires all generated state to be accounted for before continuing.  That
recovery is recorded as an export-read capability, not merely write cleanup.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import posixpath
import secrets
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
CONTROLLER_ROOT = ROOT.parent / "mobilegestalt-macos-controller"
sys.path.insert(0, os.fspath(CONTROLLER_ROOT))
sys.path.insert(0, os.fspath(ROOT))

import backend  # noqa: E402
import directory_matrix  # noqa: E402


backend.progress = lambda *args, **kwargs: None
directory_matrix.chain.TRANSPORT.paired_coredevice_udid = (
    backend.controller_paired_coredevice_udid
)

TOP_LEVEL_OBSERVED = (
    "/etc",
    "/exclaves",
    "/preboot",
    "/system_data",
    "/var",
    "/xarts",
)

EXTRA_TARGETS = (
    ("root", "/"),
    *((f"top-level-{path[1:].replace('/', '-')}", path) for path in TOP_LEVEL_OBSERVED),
    ("mobile-media", "/var/mobile/Media"),
    ("mobile-media-downloads", "/var/mobile/Media/Downloads"),
)

# Exact names are used only when directory enumeration is unavailable.  No
# content is returned; the helper reads at most one 4096-byte prefix.
KNOWN_READ_LEAVES = {
    "/var/mobile/Media/Downloads": "downloads.28.sqlitedb",
    "/var/mobile/Library/SpringBoard": "IconState.plist",
    "/var/mobile/Library/SMS": "sms.db",
    "/var/mobile/Library/AddressBook": "AddressBook.sqlitedb",
    "/var/mobile/Library/CallHistoryDB": "CallHistory.storedata",
    "/var/mobile/Library/Calendar": "Calendar.sqlitedb",
    "/var/mobile/Library/Safari": "Bookmarks.db",
}


def targets() -> list[tuple[str, str]]:
    combined: list[tuple[str, str]] = [
        *EXTRA_TARGETS,
        *directory_matrix.MATRIX_TARGETS,
        *directory_matrix.LIBRARY_EXPANSION_TARGETS,
    ]
    for parent, rows in backend.ESCAPED_PATH_CATALOG.items():
        combined.append((f"catalog-{parent.strip('/').replace('/', '-') or 'root'}", parent))
        for name, kind in rows:
            if kind == "directory":
                child = posixpath.join(parent, name)
                combined.append((f"catalog-{child.strip('/').replace('/', '-')}", child))

    deduplicated: list[tuple[str, str]] = []
    seen: set[str] = set()
    for label, path in combined:
        normalized = posixpath.normpath(path)
        if normalized not in seen:
            seen.add(normalized)
            deduplicated.append((label, normalized))
    return deduplicated


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def public_error(error: BaseException) -> str:
    return directory_matrix.chain.TRANSPORT.redact(
        f"{type(error).__name__}: {error}"
    )


def file_kind(row: dict[str, Any]) -> str | None:
    info = row.get("info", {})
    values = info.get("values", {}) if isinstance(info, dict) else {}
    return values.get("st_ifmt") if isinstance(values, dict) else None


def file_size(row: dict[str, Any]) -> int:
    info = row.get("info", {})
    values = info.get("values", {}) if isinstance(info, dict) else {}
    try:
        return int(values.get("st_size", 2**63 - 1))
    except (TypeError, ValueError, OverflowError):
        return 2**63 - 1


def select_leaf(path: str, listing: dict[str, Any]) -> tuple[str | None, str]:
    known = KNOWN_READ_LEAVES.get(path)
    if known:
        return known, "known-exact-name"
    operation = listing.get("operation", {})
    entries = operation.get("entries", []) if isinstance(operation, dict) else []
    regular = [
        row
        for row in entries
        if isinstance(row, dict)
        and isinstance(row.get("name"), str)
        and file_kind(row) == "S_IFREG"
    ]
    if not regular:
        return None, "no-regular-file-enumerated"
    row = min(regular, key=lambda candidate: (file_size(candidate), candidate["name"]))
    return row["name"], "smallest-enumerated-regular-file"


def summarize_read(result: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {"status": "not-attempted"}
    operation = result.get("operation", {})
    if not isinstance(operation, dict):
        operation = {}
    direct = operation.get("direct", {})
    aliased = operation.get("aliased", {})
    if not isinstance(direct, dict):
        direct = {}
    if not isinstance(aliased, dict):
        aliased = {}
    if "bytesRead" in operation:
        direct = operation
        used = operation
    else:
        used = direct if direct.get("ok") else aliased
    if not isinstance(used, dict):
        used = {}
    direct_info = direct.get("info", {})
    if not isinstance(direct_info, dict):
        direct_info = {}
    return {
        "status": "confirmed" if backend.native_operation_ok(result) else "not-confirmed",
        "method": operation.get("pathUsed"),
        "bytesRead": used.get("bytesRead"),
        "expectedLength": used.get("expectedLength"),
        "directInfoStatus": direct_info.get("status"),
        "directOpenStatus": direct.get("openStatus"),
        "hardlinkStatus": operation.get("linkStatus"),
        "temporaryAliasRemoved": operation.get("aliasRemoved"),
        "contentReturned": False,
    }


async def probe_media(path: str) -> dict[str, Any]:
    udid = backend.controller_paired_coredevice_udid()
    relative = posixpath.relpath(path, backend.MEDIA_ROOT)
    listing = await backend.native_mobile("list-media-directory", udid, relative)
    leaf, selection = select_leaf(path, listing)
    read_result = None
    if leaf:
        remote = leaf if relative == "." else posixpath.join(relative, leaf)
        read_result = await backend.native_mobile("probe-media-read", udid, remote)
    return {
        "transport": "ordinary AFC Media control",
        "pivotCompleted": False,
        "browse": {
            "status": "confirmed" if backend.native_operation_ok(listing) else "not-confirmed",
            "entryCount": listing.get("operation", {}).get("entryCount"),
            "openStatus": listing.get("operation", {}).get("openStatus"),
            "readStatus": listing.get("operation", {}).get("readStatus"),
        },
        "readCandidate": leaf,
        "readCandidateSelection": selection,
        "existingFileRead": summarize_read(read_result),
        "cleanupVerified": True,
    }


async def probe_escaped(path: str) -> dict[str, Any]:
    async def inspect(udid: str, link_destination: str, source: str) -> dict[str, Any]:
        del source
        listing = await backend.native_mobile(
            "list-file-browser", udid, link_destination
        )
        leaf, selection = select_leaf(path, listing)
        read_result = None
        if leaf:
            read_result = await backend.native_mobile(
                "probe-file-browser-read", udid, link_destination, leaf
            )
        return {
            "listing": listing,
            "leaf": leaf,
            "selection": selection,
            "read": read_result,
        }

    result, details = await backend.with_directory_browser(path, inspect)
    listing = result["listing"]
    return {
        "transport": "AirTraffic relocated directory pivot",
        "pivotCompleted": True,
        "browse": {
            "status": "confirmed" if backend.native_operation_ok(listing) else "not-confirmed",
            "entryCount": listing.get("operation", {}).get("entryCount"),
            "openStatus": listing.get("operation", {}).get("openStatus"),
            "readStatus": listing.get("operation", {}).get("readStatus"),
        },
        "readCandidate": result["leaf"],
        "readCandidateSelection": result["selection"],
        "existingFileRead": summarize_read(result["read"]),
        "cleanupVerified": details.get("cleanupVerified") is True,
    }


async def probe_read(path: str) -> dict[str, Any]:
    try:
        if path == backend.MEDIA_ROOT or path.startswith(backend.MEDIA_ROOT + "/"):
            return await probe_media(path)
        return await probe_escaped(path)
    except Exception as error:
        return {
            "transport": "AirTraffic relocated directory pivot",
            "pivotCompleted": False,
            "browse": {"status": "error"},
            "existingFileRead": {"status": "error"},
            "cleanupVerified": False,
            "error": public_error(error),
        }


async def probe_write(udid: str, label: str, path: str) -> tuple[dict[str, Any], bool]:
    if path == "/":
        return {
            "status": "not-tested",
            "reason": "root-target writes are excluded by the safety gate",
            "exportRead": {
                "status": "not-tested",
                "method": "AirTraffic relocation to Media followed by host readback",
            },
            "existingFileOverwriteTested": False,
        }, True
    row, safe = await directory_matrix.run_target(udid, label, path)
    primary = row.get("primary", {})
    recovery = row.get("dedicatedRecovery", {})
    exact_recovery = bool(
        primary.get("recoveredExactBytes")
        or recovery.get("recoveredExactBytes")
    )
    return {
        "status": (
            "confirmed" if row.get("outcome", "").startswith("write-")
            else "not-confirmed"
        ),
        "outcome": row.get("outcome"),
        "exactBytesRecovered": exact_recovery,
        "exportRead": {
            "status": "confirmed" if exact_recovery else "not-confirmed",
            "method": "known-path AirTraffic relocation to Media followed by host readback",
            "testedObject": "fresh randomized canary",
            "existingFileTested": False,
            "contentMatchedExactly": exact_recovery,
        },
        "generatedStateAccountedFor": row.get("residueAccountedFor"),
        "existingFileOverwriteTested": False,
    }, safe


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("all", "read", "write"), default="all")
    parser.add_argument("--report")
    arguments = parser.parse_args()

    selected = targets()
    if arguments.report:
        report_path = Path(arguments.report).resolve()
        report = json.loads(report_path.read_text())
    else:
        run_id = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4)
        report_path = ROOT / "run" / "access-preflight" / run_id / "report.json"
        report = {
            "schema": 1,
            "test": "AirTrafficDirectoryAccessPreflight",
            "expectedDevice": {
                "productType": backend.EXPECTED_PRODUCT,
                "productVersion": backend.EXPECTED_VERSION,
                "build": backend.EXPECTED_BUILD,
            },
            "scope": "configured, catalogued, and observed top-level directories",
            "readLimitBytes": 4096,
            "existingFileContentsReturned": False,
            "existingFileOverwriteTested": False,
            "rows": {},
            "complete": False,
        }

    udid = backend.controller_paired_coredevice_udid()
    initial = directory_matrix.chain.run_mobiledevice_io("probe-afc", udid)
    initial_operation = initial.get("operation", {})
    if not (
        initial.get("targetGatePassed")
        and initial_operation.get("ok")
        and initial_operation.get("booksSyncPlistPresent") is False
    ):
        raise RuntimeError("target/build/Books preflight failed")
    report["initialPreflight"] = {
        "targetGatePassed": initial.get("targetGatePassed"),
        "operationOK": initial_operation.get("ok"),
        "booksSyncPlistPresent": initial_operation.get("booksSyncPlistPresent"),
    }
    atomic_json(report_path, report)
    print(json.dumps({"report": os.fspath(report_path), "targetCount": len(selected)}), flush=True)

    for index, (label, path) in enumerate(selected, 1):
        row = report["rows"].setdefault(path, {"label": label, "path": path})
        if arguments.phase in ("all", "read") and "readBrowse" not in row:
            row["readBrowse"] = await probe_read(path)
            atomic_json(report_path, report)
            print(json.dumps({
                "phase": "read",
                "progress": f"{index}/{len(selected)}",
                "path": path,
                "browse": row["readBrowse"]["browse"]["status"],
                "read": row["readBrowse"]["existingFileRead"]["status"],
            }, sort_keys=True), flush=True)

        if arguments.phase in ("all", "write") and "freshFileWrite" not in row:
            write, safe = await probe_write(udid, f"access-preflight-{label}", path)
            row["freshFileWrite"] = write
            atomic_json(report_path, report)
            print(json.dumps({
                "phase": "write",
                "progress": f"{index}/{len(selected)}",
                "path": path,
                "write": write["status"],
                "cleanup": write.get("generatedStateAccountedFor"),
            }, sort_keys=True), flush=True)
            if not safe:
                report["abortedAfter"] = path
                report["abortReason"] = "generated state was not fully accounted for"
                atomic_json(report_path, report)
                return 2

    final = directory_matrix.chain.run_mobiledevice_io("probe-afc", udid)
    final_operation = final.get("operation", {})
    report["finalPreflight"] = {
        "targetGatePassed": final.get("targetGatePassed"),
        "operationOK": final_operation.get("ok"),
        "booksSyncPlistPresent": final_operation.get("booksSyncPlistPresent"),
    }
    report["complete"] = (
        "abortedAfter" not in report
        and final.get("targetGatePassed")
        and final_operation.get("ok")
        and final_operation.get("booksSyncPlistPresent") is False
    )
    atomic_json(report_path, report)
    print(json.dumps({"final": {"report": os.fspath(report_path), "complete": report["complete"]}}, sort_keys=True), flush=True)
    return 0 if report["complete"] else 2


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
