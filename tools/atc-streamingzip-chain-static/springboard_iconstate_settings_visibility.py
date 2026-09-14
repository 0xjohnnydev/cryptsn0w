#!/usr/bin/env python3
"""Hide or restore the Settings Home Screen icon through AirTraffic."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import plistlib
import secrets
from pathlib import Path
from typing import Any

from springboard_known_plists_roundtrip import (
    TARGET_TAIL,
    books,
    build_matrix_archive,
    operation_ok,
    paired_udid,
    run_mobiledevice_io,
    run_sequence,
)


ROOT = Path(__file__).resolve().parent
RUN_ROOT = ROOT / "run" / "springboard-iconstate-settings-visibility"
STATE_PATH = ROOT / "springboard-iconstate-settings-visibility-state.json"
TARGET = "/var/mobile/Library/SpringBoard/IconState.plist"
LEAF = "IconState.plist"
SETTINGS = "com.apple.Preferences"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def save(report: dict[str, Any]) -> None:
    report_path = Path(report["reportPath"])
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    STATE_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


def require_ok(result: dict[str, Any], message: str) -> None:
    if not operation_ok(result):
        raise RuntimeError(message)


def require_sequence(result: dict[str, Any], message: str) -> None:
    if not result.get("ok"):
        raise RuntimeError(message)


def count_identifier(value: Any, identifier: str) -> int:
    if isinstance(value, str):
        return int(value == identifier)
    if isinstance(value, list):
        return sum(count_identifier(child, identifier) for child in value)
    if isinstance(value, dict):
        return sum(count_identifier(child, identifier) for child in value.values())
    return 0


def remove_identifier_from_lists(value: Any, identifier: str) -> int:
    removed = 0
    if isinstance(value, list):
        kept = []
        for child in value:
            if isinstance(child, str) and child == identifier:
                removed += 1
                continue
            removed += remove_identifier_from_lists(child, identifier)
            kept.append(child)
        value[:] = kept
    elif isinstance(value, dict):
        for child in value.values():
            removed += remove_identifier_from_lists(child, identifier)
    return removed


def build_hidden_settings(original: bytes) -> tuple[bytes, dict[str, Any]]:
    value = plistlib.loads(original)
    if not isinstance(value, dict):
        raise RuntimeError("live IconState root is not a dictionary")
    if not isinstance(value.get("iconLists"), list):
        raise RuntimeError("live IconState omitted iconLists")
    if not isinstance(value.get("ignored"), list):
        raise RuntimeError("live IconState omitted ignored")
    if not isinstance(value.get("buttonBar"), list):
        raise RuntimeError("live IconState omitted buttonBar")

    before = {
        "iconLists": count_identifier(value["iconLists"], SETTINGS),
        "ignored": count_identifier(value["ignored"], SETTINGS),
        "buttonBar": count_identifier(value["buttonBar"], SETTINGS),
    }
    if before != {"iconLists": 1, "ignored": 0, "buttonBar": 0}:
        raise RuntimeError(f"unexpected live Settings placement: {before}")

    modified = copy.deepcopy(value)
    removed = remove_identifier_from_lists(modified["iconLists"], SETTINGS)
    modified["ignored"].append(SETTINGS)
    after = {
        "iconLists": count_identifier(modified["iconLists"], SETTINGS),
        "ignored": count_identifier(modified["ignored"], SETTINGS),
        "buttonBar": count_identifier(modified["buttonBar"], SETTINGS),
    }
    if removed != 1 or after != {
        "iconLists": 0,
        "ignored": 1,
        "buttonBar": 0,
    }:
        raise RuntimeError(f"invalid hidden-Settings transformation: {after}")

    for key in value:
        if key not in ("iconLists", "ignored") and modified[key] != value[key]:
            raise RuntimeError(f"unexpected mutation outside layout arrays: {key}")
    replacement = plistlib.dumps(
        modified, fmt=plistlib.FMT_BINARY, sort_keys=False
    )
    if replacement == original:
        raise RuntimeError("hidden-Settings transformation produced no change")
    return replacement, {
        "identifier": SETTINGS,
        "before": before,
        "after": after,
        "removedFromIconLists": removed,
        "addedToIgnored": 1,
    }


def generated_names(token: str) -> dict[str, str]:
    return {
        "source": f"codex-dir-src-24A435-{token}",
        "linkDestination": f"codex-dir-link-24A435-{token}",
        "originalBackup": (
            f"codex-dir-recovered-24A435-{token}-original.plist"
        ),
        "verificationBackup": (
            f"codex-dir-recovered-24A435-{token}-verification.plist"
        ),
    }


def identifiers(report: dict[str, Any]) -> dict[str, str]:
    return {
        "link": f"../../{report['source']}/p0/p1/p2/link",
        "target": "../../../Library/SpringBoard/IconState.plist",
        "payload": f"../../{report['source']}/payload",
        "original": f"../../{report['originalBackup']}",
        "verification": f"../../{report['verificationBackup']}",
    }


def write_books(run_dir: Path, name: str, values: list[str]) -> Path:
    path = run_dir / name
    path.write_bytes(books(values))
    return path


def stage_books(
    udid: str,
    report: dict[str, Any],
    manifest: Path,
) -> dict[str, Any]:
    return run_mobiledevice_io(
        "stage-springboard-replace-books",
        udid,
        report["source"],
        report["linkDestination"],
        report["originalBackup"],
        report["verificationBackup"],
        os.fspath(manifest),
    )


def probe(udid: str, report: dict[str, Any]) -> dict[str, Any]:
    return run_mobiledevice_io(
        "probe-springboard-replace",
        udid,
        report["source"],
        report["linkDestination"],
        report["originalBackup"],
        report["verificationBackup"],
    )


def copy_generated(
    udid: str,
    generated: str,
    destination: Path,
    token: str,
    suffix: str,
) -> dict[str, Any]:
    temporary = Path("/tmp") / (
        f"codex-mgcache-read-24A435-{token}-{suffix}.plist"
    )
    temporary.unlink(missing_ok=True)
    result = run_mobiledevice_io(
        "copy-generated-mg-export", udid, generated, os.fspath(temporary)
    )
    if operation_ok(result) and temporary.is_file():
        os.replace(temporary, destination)
    else:
        temporary.unlink(missing_ok=True)
    return result


def verify_generated(
    udid: str, generated: str, expected: Path
) -> dict[str, Any]:
    return run_mobiledevice_io(
        "verify-generated-mg-export",
        udid,
        generated,
        os.fspath(expected),
    )


def apply_hide_settings() -> int:
    if STATE_PATH.exists():
        raise RuntimeError(
            f"an active Settings-visibility transaction exists: {STATE_PATH}"
        )

    udid = paired_udid()
    preflight = run_mobiledevice_io("probe-afc", udid)
    require_ok(preflight, "native device preflight failed")
    if preflight["operation"].get("booksSyncPlistPresent"):
        raise RuntimeError("Books staging is not clean")

    token = secrets.token_hex(10)
    run_dir = RUN_ROOT / token
    run_dir.mkdir(parents=True, exist_ok=False)
    names = generated_names(token)
    report: dict[str, Any] = {
        "test": "AirTrafficSpringBoardHideSettingsIcon",
        "action": "hide-settings",
        "status": "starting",
        "target": TARGET,
        "targetTail": TARGET_TAIL,
        "token": token,
        "udid": udid,
        "runDirectory": os.fspath(run_dir),
        "reportPath": os.fspath(run_dir / "transaction.json"),
        "preflight": preflight,
        "targetContentModified": True,
        "rollbackRequired": False,
        **names,
    }
    save(report)
    ids = identifiers(report)

    archive, target_tail = build_matrix_archive(
        "/var/mobile/Library/SpringBoard",
        b"IconState payload placeholder; replaced only after live export\n",
    )
    if target_tail != TARGET_TAIL:
        raise RuntimeError("fixed target-tail gate failed")
    archive_path = run_dir / "pivot.zip"
    export_books = write_books(
        run_dir, "Books-01-export-original.plist", [ids["link"], ids["target"]]
    )
    archive_path.write_bytes(archive)

    original_path = run_dir / "IconState.original.plist"
    modified_path = run_dir / "IconState.hidden-settings.plist"
    report["originalPath"] = os.fspath(original_path)
    report["modifiedPath"] = os.fspath(modified_path)
    save(report)

    report["stage"] = run_mobiledevice_io(
        "stage",
        udid,
        report["source"],
        report["linkDestination"],
        report["originalBackup"],
        os.fspath(archive_path),
        os.fspath(export_books),
    )
    require_ok(report["stage"], "initial StreamingZip/Books stage failed")
    report["status"] = "staged"
    save(report)

    report["exportOriginal"] = run_sequence(
        udid,
        [
            (ids["link"], report["linkDestination"]),
            (ids["target"], report["originalBackup"]),
        ],
    )
    require_sequence(report["exportOriginal"], "live IconState export failed")
    report["afterOriginalExport"] = probe(udid, report)
    require_ok(report["afterOriginalExport"], "post-export probe failed")
    export_state = report["afterOriginalExport"]["operation"]
    if not export_state.get("originalPresent") or export_state.get("targetObserved"):
        raise RuntimeError("live IconState did not enter the exact backup state")
    report["rollbackRequired"] = True
    report["status"] = "live-original-preserved"
    save(report)

    report["copyOriginal"] = copy_generated(
        udid,
        report["originalBackup"],
        original_path,
        token,
        "original",
    )
    require_ok(report["copyOriginal"], "live original could not be copied locally")
    original = original_path.read_bytes()
    modified, transformation = build_hidden_settings(original)
    modified_path.write_bytes(modified)
    report["transformation"] = transformation
    report["original"] = {"bytes": len(original), "sha256": sha256(original)}
    report["modified"] = {"bytes": len(modified), "sha256": sha256(modified)}
    report["status"] = "replacement-built-from-live-original"
    save(report)

    report["writePayload"] = run_mobiledevice_io(
        "write-springboard-replace-payload",
        udid,
        report["source"],
        report["linkDestination"],
        report["originalBackup"],
        os.fspath(modified_path),
    )
    require_ok(report["writePayload"], "generated payload exact-write failed")

    install_books = write_books(
        run_dir, "Books-02-install-modified.plist", [ids["payload"]]
    )
    report["stageInstall"] = stage_books(udid, report, install_books)
    require_ok(report["stageInstall"], "modified-install manifest stage failed")
    report["install"] = run_sequence(
        udid,
        [(ids["payload"], f"{report['linkDestination']}/{LEAF}")],
    )
    require_sequence(report["install"], "modified IconState install failed")
    report["afterInstall"] = probe(udid, report)
    require_ok(report["afterInstall"], "post-install probe failed")
    installed = report["afterInstall"]["operation"]
    if (
        not installed.get("targetObserved")
        or not installed.get("originalPresent")
        or installed.get("payloadPresent")
    ):
        raise RuntimeError("modified install did not reach the expected state")
    report["status"] = "modified-installed-pending-readback"
    save(report)

    readback_books = write_books(
        run_dir, "Books-03-readback-modified.plist", [ids["target"]]
    )
    report["stageReadback"] = stage_books(udid, report, readback_books)
    require_ok(report["stageReadback"], "modified-readback manifest stage failed")
    report["exportModifiedForReadback"] = run_sequence(
        udid, [(ids["target"], report["verificationBackup"])]
    )
    require_sequence(
        report["exportModifiedForReadback"], "modified readback export failed"
    )
    report["verifyModified"] = verify_generated(
        udid, report["verificationBackup"], modified_path
    )
    require_ok(report["verifyModified"], "modified readback was not byte-exact")

    reinsert_books = write_books(
        run_dir, "Books-04-reinsert-modified.plist", [ids["verification"]]
    )
    report["stageReinsert"] = stage_books(udid, report, reinsert_books)
    require_ok(report["stageReinsert"], "modified-reinsert manifest stage failed")
    report["reinsertModified"] = run_sequence(
        udid,
        [(ids["verification"], f"{report['linkDestination']}/{LEAF}")],
    )
    require_sequence(report["reinsertModified"], "modified reinsert failed")
    report["afterVerifiedReinsert"] = probe(udid, report)
    require_ok(report["afterVerifiedReinsert"], "final modified-state probe failed")
    final_state = report["afterVerifiedReinsert"]["operation"]
    if (
        not final_state.get("targetObserved")
        or not final_state.get("originalPresent")
        or final_state.get("verificationPresent")
    ):
        raise RuntimeError("final modified state failed its invariant checks")

    report["clearBooks"] = run_mobiledevice_io(
        "clear-springboard-replace-books",
        udid,
        report["source"],
        report["linkDestination"],
        report["originalBackup"],
        report["verificationBackup"],
    )
    require_ok(report["clearBooks"], "Books cleanup failed")
    report["status"] = "awaiting-user-verification"
    report["rollbackRequired"] = True
    report["exactReadbackVerified"] = True
    save(report)

    print(json.dumps({
        "ok": True,
        "status": report["status"],
        "report": report["reportPath"],
        "original": report["original"],
        "modified": report["modified"],
        "transformation": report["transformation"],
        "exactReadbackVerified": True,
        "next": "respring and check whether Settings disappeared from the Home Screen",
    }, indent=2, sort_keys=True))
    return 0


def restore_settings() -> int:
    if not STATE_PATH.is_file():
        raise RuntimeError("no active hidden-Settings transaction exists")
    report = json.loads(STATE_PATH.read_text())
    if report.get("status") != "awaiting-user-verification":
        raise RuntimeError(f"transaction is not restorable: {report.get('status')}")

    udid = paired_udid()
    if udid != report.get("udid"):
        raise RuntimeError("paired device changed since the transaction began")
    preflight = run_mobiledevice_io("probe-afc", udid)
    require_ok(preflight, "restore preflight failed")
    if preflight["operation"].get("booksSyncPlistPresent"):
        raise RuntimeError("Books staging is not clean before restore")

    run_dir = Path(report["runDirectory"])
    original_path = Path(report["originalPath"])
    modified_path = Path(report["modifiedPath"])
    ids = identifiers(report)
    report["restorePreflight"] = preflight
    report["beforeRestore"] = probe(udid, report)
    require_ok(report["beforeRestore"], "restore state probe failed")
    before = report["beforeRestore"]["operation"]
    if (
        not before.get("targetObserved")
        or not before.get("originalPresent")
        or before.get("verificationPresent")
    ):
        raise RuntimeError("retained rollback state failed its invariants")
    report["status"] = "restoring"
    save(report)

    restore_books = write_books(
        run_dir,
        "Books-05-restore-original.plist",
        [ids["target"], ids["original"]],
    )
    report["stageRestore"] = stage_books(udid, report, restore_books)
    require_ok(report["stageRestore"], "restore manifest stage failed")
    report["restore"] = run_sequence(
        udid,
        [
            (ids["target"], report["verificationBackup"]),
            (ids["original"], f"{report['linkDestination']}/{LEAF}"),
        ],
    )
    require_sequence(report["restore"], "original restore sequence failed")

    # Export the restored target once and compare it with the live original
    # captured before modification, then put that exact same object back.
    verify_original_books = write_books(
        run_dir, "Books-06-readback-original.plist", [ids["target"]]
    )
    report["stageOriginalReadback"] = stage_books(
        udid, report, verify_original_books
    )
    require_ok(
        report["stageOriginalReadback"], "original-readback manifest stage failed"
    )
    report["exportRestoredOriginal"] = run_sequence(
        udid, [(ids["target"], report["originalBackup"])]
    )
    require_sequence(
        report["exportRestoredOriginal"], "restored-original readback failed"
    )
    report["verifyRestoredOriginal"] = verify_generated(
        udid, report["originalBackup"], original_path
    )
    require_ok(
        report["verifyRestoredOriginal"], "restored original was not byte-exact"
    )

    reinsert_original_books = write_books(
        run_dir, "Books-07-reinsert-original.plist", [ids["original"]]
    )
    report["stageOriginalReinsert"] = stage_books(
        udid, report, reinsert_original_books
    )
    require_ok(
        report["stageOriginalReinsert"], "original-reinsert manifest stage failed"
    )
    report["reinsertOriginal"] = run_sequence(
        udid,
        [(ids["original"], f"{report['linkDestination']}/{LEAF}")],
    )
    require_sequence(report["reinsertOriginal"], "original reinsert failed")

    current_path = run_dir / "IconState.device-before-restore.plist"
    report["copyDeviceBeforeRestore"] = copy_generated(
        udid,
        report["verificationBackup"],
        current_path,
        report["token"],
        "device-before-restore",
    )
    require_ok(
        report["copyDeviceBeforeRestore"],
        "pre-restore IconState could not be copied for cleanup verification",
    )
    current_data = current_path.read_bytes()
    plistlib.loads(current_data)
    report["deviceBeforeRestore"] = {
        "path": os.fspath(current_path),
        "bytes": len(current_data),
        "sha256": sha256(current_data),
        "matchesInitiallyInstalledModified": current_data == modified_path.read_bytes(),
    }

    report["cleanup"] = run_mobiledevice_io(
        "verify-matrix-cleanup",
        udid,
        report["source"],
        report["linkDestination"],
        report["verificationBackup"],
        os.fspath(current_path),
        report["targetTail"],
    )
    require_ok(report["cleanup"], "post-restore generated-state cleanup failed")
    report["afterRestorePreflight"] = run_mobiledevice_io("probe-afc", udid)
    require_ok(report["afterRestorePreflight"], "post-restore preflight failed")
    if report["afterRestorePreflight"]["operation"].get("booksSyncPlistPresent"):
        raise RuntimeError("Books staging remained after restore")

    report["status"] = "restored"
    report["rollbackRequired"] = False
    report["restoredOriginalExact"] = True
    save(report)
    STATE_PATH.unlink(missing_ok=True)
    print(json.dumps({
        "ok": True,
        "status": "restored",
        "report": report["reportPath"],
        "restoredOriginalExact": True,
        "next": "respring to reload the restored Home Screen layout",
    }, indent=2, sort_keys=True))
    return 0


def emergency_restore(error: Exception) -> dict[str, Any]:
    """Best-effort fail-closed restore after an interrupted apply."""
    outcome: dict[str, Any] = {
        "attempted": False,
        "error": {"type": type(error).__name__, "message": str(error)},
    }
    if not STATE_PATH.is_file():
        return outcome
    report = json.loads(STATE_PATH.read_text())
    outcome["attempted"] = True
    report["applyFailure"] = outcome["error"]
    report["status"] = "emergency-restore"
    save(report)
    try:
        udid = report["udid"]
        ids = identifiers(report)
        run_dir = Path(report["runDirectory"])
        state = probe(udid, report)
        outcome["initialProbe"] = state
        require_ok(state, "emergency state probe failed")
        operation = state["operation"]

        if operation.get("originalPresent"):
            if operation.get("targetObserved"):
                if operation.get("verificationPresent"):
                    raise RuntimeError(
                        "both a live target and verification backup exist"
                    )
                evacuate = write_books(
                    run_dir,
                    "Books-emergency-evacuate-target.plist",
                    [ids["target"]],
                )
                outcome["stageEvacuate"] = stage_books(udid, report, evacuate)
                require_ok(
                    outcome["stageEvacuate"],
                    "emergency target-evacuation stage failed",
                )
                outcome["evacuate"] = run_sequence(
                    udid, [(ids["target"], report["verificationBackup"])]
                )
                require_sequence(
                    outcome["evacuate"], "emergency target evacuation failed"
                )

            restore_manifest = write_books(
                run_dir,
                "Books-emergency-restore-original.plist",
                [ids["original"]],
            )
            outcome["stageRestore"] = stage_books(
                udid, report, restore_manifest
            )
            require_ok(
                outcome["stageRestore"], "emergency original stage failed"
            )
            outcome["restore"] = run_sequence(
                udid,
                [(ids["original"], f"{report['linkDestination']}/{LEAF}")],
            )
            require_sequence(
                outcome["restore"], "emergency original restore failed"
            )

        after = probe(udid, report)
        outcome["afterRestoreProbe"] = after
        require_ok(after, "emergency post-restore probe failed")
        after_operation = after["operation"]
        if after_operation.get("linkPresent") and not after_operation.get(
            "targetObserved"
        ):
            raise RuntimeError("emergency restore could not observe IconState")
        if after_operation.get("originalPresent"):
            raise RuntimeError("emergency original backup was not consumed")

        verification_path = run_dir / "IconState.emergency-evacuated.plist"
        expected_for_cleanup = verification_path
        if after_operation.get("verificationPresent"):
            outcome["copyEvacuated"] = copy_generated(
                udid,
                report["verificationBackup"],
                verification_path,
                report["token"],
                "emergency-evacuated",
            )
            require_ok(
                outcome["copyEvacuated"],
                "emergency evacuated target could not be copied",
            )
        else:
            expected_for_cleanup = Path(
                report.get("modifiedPath", report.get("originalPath", ""))
            )

        outcome["cleanup"] = run_mobiledevice_io(
            "verify-matrix-cleanup",
            udid,
            report["source"],
            report["linkDestination"],
            report["verificationBackup"],
            os.fspath(expected_for_cleanup),
            report["targetTail"],
        )
        cleanup_operation = outcome["cleanup"].get("operation", {})
        cleanup_complete = bool(
            cleanup_operation.get("sourceMediaAbsent")
            and cleanup_operation.get("linkAbsent")
            and cleanup_operation.get("recoveredAbsent")
            and cleanup_operation.get("booksFilesAbsent")
        )
        if not cleanup_complete:
            raise RuntimeError("emergency generated-state cleanup was incomplete")

        report["emergencyRestore"] = outcome
        report["status"] = "failed-restored-clean"
        report["rollbackRequired"] = False
        save(report)
        STATE_PATH.unlink(missing_ok=True)
        outcome["restored"] = True
        outcome["cleanupComplete"] = True
    except Exception as recovery_error:
        outcome["recoveryFailure"] = {
            "type": type(recovery_error).__name__,
            "message": str(recovery_error),
        }
        report["emergencyRestore"] = outcome
        report["status"] = "manual-restore-required"
        report["rollbackRequired"] = True
        save(report)
    return outcome


def show_status() -> int:
    if not STATE_PATH.is_file():
        print(json.dumps({"active": False}, indent=2))
        return 0
    report = json.loads(STATE_PATH.read_text())
    print(json.dumps({
        "active": True,
        "status": report.get("status"),
        "target": report.get("target"),
        "report": report.get("reportPath"),
        "rollbackRequired": report.get("rollbackRequired"),
    }, indent=2, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("hide-settings", "restore", "status"))
    arguments = parser.parse_args()
    if arguments.action == "hide-settings":
        try:
            return apply_hide_settings()
        except Exception as error:
            recovery = emergency_restore(error)
            print(json.dumps({
                "ok": False,
                "error": {"type": type(error).__name__, "message": str(error)},
                "emergencyRestore": recovery,
            }, indent=2, sort_keys=True))
            return 2
    if arguments.action == "restore":
        return restore_settings()
    return show_status()


if __name__ == "__main__":
    raise SystemExit(main())
