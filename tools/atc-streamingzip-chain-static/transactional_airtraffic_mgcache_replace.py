#!/usr/bin/env python3
"""Single-session, fail-closed AirTraffic MobileGestalt cache replacement."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import subprocess
import time
from pathlib import Path
from typing import Any

import chain_canary as chain
import direct_airtraffic_mgcache_replace as base


ROOT = Path(__file__).resolve().parent
HELPER = ROOT / "atc_transaction_sequence"
RUN_ROOT = ROOT / "run" / "transactional-mgcache-replace"
STATE_PATH = ROOT / "transactional-mgcache-replace-state.json"
base.STATE_PATH = STATE_PATH


def save(state: dict[str, Any]) -> None:
    STATE_PATH.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")


def write_control(path: Path, value: str) -> None:
    temporary = Path(f"{path}.new")
    temporary.write_text(f"{value}\n")
    os.replace(temporary, path)


def last_json(stdout: str, stderr: str, exit_code: int | None) -> dict[str, Any]:
    result: dict[str, Any] = {"ok": False, "error": "no JSON helper result"}
    for line in reversed(stdout.splitlines()):
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict):
            result = candidate
            break
    result["exitCode"] = exit_code
    result["stdoutTail"] = stdout.splitlines()[-10:]
    if stderr:
        result["stderrTail"] = stderr.splitlines()[-8:]
    return result


def collect_helper(
    process: subprocess.Popen[str],
    timeout: float,
    *,
    may_terminate: bool,
) -> dict[str, Any]:
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        if not may_terminate:
            return {
                "ok": False,
                "error": "transaction helper still active after canonical commit",
                "exitCode": None,
            }
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=2.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=2.0)
    return last_json(stdout, stderr, process.returncode)


def wait_marker(path: Path, process: subprocess.Popen[str], seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.is_file():
            return True
        if process.poll() is not None:
            return False
        time.sleep(0.01)
    return False


def lock_state(udid: str) -> dict[str, Any]:
    completed = subprocess.run(
        [
            "xcrun",
            "devicectl",
            "-q",
            "device",
            "info",
            "lockState",
            "--device",
            udid,
            "--timeout",
            "10",
            "--json-output",
            "-",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=15,
    )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError:
        value = {"info": {"outcome": "invalid-json"}, "result": {}}
    value["exitCode"] = completed.returncode
    if completed.stderr:
        value["stderrTail"] = completed.stderr.splitlines()[-8:]
    return value


async def placeholder(
    state: dict[str, Any], *, create: bool = False, remove: bool = False
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    marker = f"codex-mgcache-rollback-placeholder-24A435-{state['token']}\n".encode()
    async with chain.paired_wifi_provider(result) as provider:
        observed = (
            provider.product_type,
            provider.product_version,
            provider.product_build_version,
        )
        if observed != ("iPhone18,2", "27.0", "24A435"):
            raise RuntimeError(f"device/build gate rejected {observed!r}")
        from pymobiledevice3.services.afc import AfcService

        async with AfcService(provider) as afc:
            present_before = await afc.exists(state["backup"])
            result["presentBefore"] = present_before
            if create:
                if present_before:
                    raise RuntimeError("rollback placeholder path is not fresh")
                await afc.set_file_contents(state["backup"], marker)
            if remove:
                current = (
                    await afc.get_file_contents(state["backup"])
                    if await afc.exists(state["backup"])
                    else None
                )
                result["placeholderExact"] = current == marker
                if current != marker:
                    raise RuntimeError("rollback placeholder changed before commit")
                await afc.rm(state["backup"], force=True)
            result["presentAfter"] = await afc.exists(state["backup"])
    result["ok"] = bool(
        (create and result["presentAfter"])
        or (remove and not result["presentAfter"] and result["placeholderExact"])
    )
    return result


def direct_read(
    state: dict[str, Any], label: str
) -> tuple[dict[str, Any], bytes | None]:
    output = Path("/tmp") / (
        f"codex-mgcache-read-24A435-{state['token']}-{label}.plist"
    )
    output.unlink(missing_ok=True)
    try:
        report: dict[str, Any] = {
            "method": "fresh-media-hardlink",
            "removeBefore": base.remove_alias(state),
        }
        created = base.mobile(
            state["udid"],
            "create-generated-mgcache-hardlink",
            state["outer"],
            state["alias"],
        )
        report["create"] = created
        if base.operation_ok(created):
            try:
                copied = base.mobile(
                    state["udid"],
                    "copy-generated-mg-export",
                    state["alias"],
                    os.fspath(output),
                )
                report["copy"] = copied
                data = (
                    output.read_bytes()
                    if base.operation_ok(copied) and output.is_file()
                    else None
                )
            finally:
                report["removeAfter"] = base.remove_alias(state)
            report["ok"] = bool(
                data is not None and base.operation_ok(report["removeAfter"])
            )
        else:
            report["method"] = "direct-open-fallback"
            fallback = base.mobile(
                state["udid"],
                "read-generated-mgcache-direct",
                state["outer"],
                os.fspath(output),
            )
            report["direct"] = fallback
            data = (
                output.read_bytes()
                if base.operation_ok(fallback) and output.is_file()
                else None
            )
            report["ok"] = data is not None
        report["savedSHA256"] = base.digest(data) if data is not None else None
        report["savedLength"] = len(data) if data is not None else 0
        return report, data
    finally:
        output.unlink(missing_ok=True)


def read_until(
    state: dict[str, Any], label: str, candidates: tuple[bytes, ...], seconds: float
) -> tuple[dict[str, Any], bytes | None]:
    deadline = time.monotonic() + seconds
    last: dict[str, Any] = {}
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        last, data = direct_read(state, f"{label}-{attempt}")
        if data in candidates:
            last["attempt"] = attempt
            return last, data
        time.sleep(0.05)
    last["attempt"] = attempt
    return last, None


def generated_cleanup(state: dict[str, Any]) -> dict[str, Any]:
    return base.cleanup(state)


def recover_transaction() -> dict[str, Any]:
    if not STATE_PATH.is_file():
        raise RuntimeError("no preserved transactional state")
    state = json.loads(STATE_PATH.read_text())
    if state.get("status") not in ("rollback-incomplete", "rollback-verified"):
        raise RuntimeError(f"state is not recoverable: {state.get('status')}")
    observed = state.get("observedPreimage", {})
    original_path = Path(observed.get("path", ""))
    original, original_plist = base.plist_bytes(original_path)
    if (
        base.digest(original) != observed.get("sha256")
        or original_plist.get("CacheExtra", {}).get("0+nc/Udy4WNG8S+Q7a/s1A")
        != "iPhone18,2"
        or state.get("transaction", {}).get("rollbackCoalesced") is not True
    ):
        raise RuntimeError("preserved rollback evidence safety gate rejected")

    # A system-group reimport is not consumed on this build: AirTraffic can
    # export the canonical cache but cannot create the return destination.
    # Do not repeat that destructive-looking no-op during recovery.  Accept
    # the already-recorded rollback only when both post-rollback exports were
    # byte-for-byte equal to the captured live preimage and the canonical path
    # was observed as a regular file of the exact expected size between them.
    round_trip = state.get("restoreRoundTrip", {})
    target_after = round_trip.get("targetAfterReassert", {})
    target_operation = target_after.get("operation", {})
    target_size = (
        target_operation.get("fileInfo", {}).get("values", {}).get("st_size")
    )
    state["rollbackEvidence"] = {
        "firstExactExport": base.operation_ok(round_trip.get("exactExport", {})),
        "secondExactExport": base.operation_ok(
            round_trip.get("exportAfterReassert", {})
        ),
        "canonicalRegular": bool(
            base.operation_ok(target_after)
            and target_operation.get("regularFile") is True
        ),
        "canonicalLengthMatches": str(target_size) == str(len(original)),
        "reimportKnownBlocked": True,
    }
    state["rollbackVerified"] = all(state["rollbackEvidence"].values())
    state["status"] = (
        "rollback-verified" if state["rollbackVerified"] else "rollback-incomplete"
    )
    save(state)
    if not state["rollbackVerified"]:
        raise RuntimeError("exact transactional rollback verification failed")

    cleanup_result = generated_cleanup(state)
    report_path = Path(state["runDirectory"]) / "transaction-recovery-audit.json"
    report_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    if not base.operation_ok(cleanup_result):
        raise RuntimeError(f"rollback verified but cleanup incomplete: {report_path}")
    STATE_PATH.unlink(missing_ok=True)
    return {
        "ok": True,
        "rollbackVerified": True,
        "originalSHA256": base.digest(original),
        "cleanupVerified": True,
        "report": os.fspath(report_path),
    }


def run(
    original_path: Path, replacement_path: Path, *, capture_only: bool = False
) -> dict[str, Any]:
    if STATE_PATH.exists():
        prior = json.loads(STATE_PATH.read_text())
        if prior.get("status") == "clean" and base.operation_ok(prior.get("cleanup", {})):
            archive = Path(prior["runDirectory"]) / "aborted-clean-state.json"
            archive.write_text(json.dumps(prior, indent=2, sort_keys=True) + "\n")
            STATE_PATH.unlink()
        else:
            raise RuntimeError(f"unfinished state exists: {STATE_PATH}")

    original, _ = base.plist_bytes(original_path)
    replacement, replacement_plist = base.plist_bytes(replacement_path)
    risky = base.validate_risky(replacement_plist)
    if not risky["enabled"] or original == replacement:
        raise RuntimeError("replacement Risky gate rejected")

    udid = chain.TRANSPORT.paired_coredevice_udid()
    preflight = base.mobile(udid, "probe-afc")
    if not base.operation_ok(preflight) or preflight["operation"].get(
        "booksSyncPlistPresent"
    ):
        raise RuntimeError("device/build/Books preflight failed")
    observed_lock = lock_state(udid)
    lock_result = observed_lock.get("result", {})
    if observed_lock.get("info", {}).get("outcome") != "success" or lock_result.get(
        "passcodeRequired", True
    ):
        raise RuntimeError("device must be unlocked before AirTraffic transaction")

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
    target_identifier = os.path.relpath(
        f"{base.TARGET_DIRECTORY}/{base.TARGET_LEAF}", base.AIRLOCK_BOOK_ROOT
    )
    # Keep this AssetID lexically distinct from target_identifier while resolving
    # to the same leaf.  AirTraffic keys transaction rows by the unnormalised
    # identifier, so os.path.relpath() must not collapse Caches/../Caches here.
    rollback_target_identifier = (
        f"{target_identifier.rsplit('/', 1)[0]}/../Caches/{base.TARGET_LEAF}"
    )
    if (
        rollback_target_identifier == target_identifier
        or os.path.normpath(rollback_target_identifier)
        != os.path.normpath(target_identifier)
    ):
        raise RuntimeError("rollback AssetID alias safety gate rejected")
    rollback_backup_identifier = os.path.relpath(
        f"/var/mobile/Media/{backup}", base.AIRLOCK_BOOK_ROOT
    )
    archive_data = base.build_archive(replacement)
    manifest_data = base.books(
        [
            link_identifier,
            target_identifier,
            payload_identifier,
            rollback_target_identifier,
            rollback_backup_identifier,
        ]
    )
    archive_path = run_dir / "payload.zip"
    books_path = run_dir / "Books-transaction.plist"
    archive_path.write_bytes(archive_data)
    books_path.write_bytes(manifest_data)
    control = run_dir / "transaction-control"

    state: dict[str, Any] = {
        "schema": 2,
        "test": "TransactionalAirTrafficMobileGestaltFullCacheReplace",
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
        "rollbackTargetIdentifier": rollback_target_identifier,
        "rollbackBackupIdentifier": rollback_backup_identifier,
        "target": f"{base.TARGET_DIRECTORY}/{base.TARGET_LEAF}",
        "originalPath": os.fspath(original_path),
        "replacementPath": os.fspath(replacement_path),
        "originalLength": len(original),
        "replacementLength": len(replacement),
        "originalSHA256": base.digest(original),
        "replacementSHA256": base.digest(replacement),
        "riskyValidation": risky,
        "preflight": preflight,
        "lockState": observed_lock,
        "archiveSHA256": base.digest(archive_data),
        "manifestSHA256": base.digest(manifest_data),
        "manifestIdentifiers": [
            link_identifier,
            target_identifier,
            payload_identifier,
            rollback_target_identifier,
            rollback_backup_identifier,
        ],
        "canonicalMutationAttempted": False,
        "commitVerified": False,
        "rollbackVerified": False,
    }
    save(state)

    staged = base.mobile(
        udid,
        "stage",
        source,
        outer,
        backup,
        os.fspath(archive_path),
        os.fspath(books_path),
    )
    state["stage"] = staged
    state["status"] = "staged" if base.operation_ok(staged) else "staging-failed"
    save(state)
    if not base.operation_ok(staged):
        generated_cleanup(state)
        raise RuntimeError("StreamingZip staging failed before target access")

    state["rollbackPlaceholder"] = {"skipped": True}
    process = subprocess.Popen(
        [
            os.fspath(HELPER),
            udid,
            link_identifier,
            outer,
            target_identifier,
            backup,
            payload_identifier,
            f"{outer}/{base.TARGET_LEAF}",
            rollback_target_identifier,
            rollback_backup_identifier,
            discard,
            os.fspath(control),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    state["status"] = "transaction-connecting"
    save(state)

    canonical_attempted = False
    decision_sent = False
    failure: Exception | None = None
    try:
        if not wait_marker(Path(f"{control}.ready"), process, 85.0):
            state["transaction"] = collect_helper(
                process, 2.0, may_terminate=True
            )
            raise RuntimeError("AirTraffic transaction did not reach prelude gate")

        placement: dict[str, Any] = {}
        metadata: dict[str, Any] = {}
        for _ in range(20):
            placement = base.link_present(state)
            metadata = base.probe_target(state)
            if placement.get("operation", {}).get("linkPresent") and base.operation_ok(
                metadata
            ):
                break
            time.sleep(0.05)
        state["placementProbe"] = placement
        state["beforeMetadata"] = metadata
        before_values = (
            metadata.get("operation", {})
            .get("fileInfo", {})
            .get("values", {})
        )
        before_size = before_values.get("st_size")
        if (
            not placement.get("operation", {}).get("linkPresent")
            or not base.operation_ok(metadata)
            or not metadata.get("operation", {}).get("regularFile")
        ):
            write_control(control, "abort")
            decision_sent = True
            state["transaction"] = collect_helper(process, 10.0, may_terminate=True)
            raise RuntimeError("relocated link or canonical metadata preflight failed")

        if capture_only:
            state["canonicalMutationAttempted"] = True
            state["status"] = "capture-export-authorized"
            save(state)
            canonical_attempted = True
            write_control(control, "commit")
            if not wait_marker(Path(f"{control}.committed"), process, 12.0):
                state["transaction"] = collect_helper(
                    process, 55.0, may_terminate=False
                )
                raise RuntimeError("capture export commit marker was not observed")

            observed_path = run_dir / "live-observed-preimage.plist"
            state["backupCopy"] = base.copy_export(state, backup, observed_path)
            if not base.operation_ok(state["backupCopy"]) or not observed_path.is_file():
                raise RuntimeError("capture export could not be copied from Media")
            observed_data, observed_plist = base.plist_bytes(observed_path)
            observed_extra = observed_plist.get("CacheExtra", {})
            if observed_extra.get("0+nc/Udy4WNG8S+Q7a/s1A") != "iPhone18,2":
                raise RuntimeError("captured cache model identity mismatch")
            observed_risky = base.validate_risky(observed_plist)
            state["observedPreimage"] = {
                "path": os.fspath(observed_path),
                "length": len(observed_data),
                "sha256": base.digest(observed_data),
                "metadataLength": before_size,
                "metadataMatchesRead": str(before_size) == str(len(observed_data)),
                "cacheVersion": observed_plist.get("CacheVersion"),
                "cacheUUID": observed_plist.get("CacheUUID"),
                "riskyValidation": observed_risky,
            }
            if not state["observedPreimage"]["metadataMatchesRead"]:
                raise RuntimeError("captured cache metadata/read length mismatch")
            save(state)

            write_control(Path(f"{control}.decision"), "rollback")
            decision_sent = True
            if not wait_marker(Path(f"{control}.rolledback"), process, 12.0):
                state["transaction"] = collect_helper(
                    process, 15.0, may_terminate=False
                )
                raise RuntimeError("capture rollback marker was not observed")
            state["transaction"] = collect_helper(
                process, 15.0, may_terminate=False
            )
            state["restoreRoundTrip"] = base.verify_and_reassert(
                state,
                observed_path,
                "capture-restore",
                verification,
            )
            state["rollbackVerified"] = bool(
                state["transaction"].get("rollbackCoalesced") is True
                and state["restoreRoundTrip"].get("ok") is True
            )
            if not state["rollbackVerified"]:
                raise RuntimeError("capture rollback did not restore exact live bytes")
            state["status"] = "capture-complete"
            save(state)
            cleanup_result = generated_cleanup(state)
            report_path = run_dir / "transactional-airtraffic-mgcache-replace.json"
            report_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
            if base.operation_ok(cleanup_result):
                STATE_PATH.unlink(missing_ok=True)
            else:
                raise RuntimeError(f"live capture cleanup incomplete: {report_path}")
            return {
                "ok": True,
                "captureOnly": True,
                "canonicalMutationAttempted": True,
                "rollbackVerified": True,
                "livePreimage": state["observedPreimage"],
                "cleanupVerified": True,
                "report": os.fspath(report_path),
            }

        before_read, before_bytes = direct_read(state, "before")
        state["exactPreimageRead"] = before_read
        if before_bytes is None:
            write_control(control, "abort")
            decision_sent = True
            state["transaction"] = collect_helper(process, 10.0, may_terminate=True)
            raise RuntimeError("canonical exact-read preflight failed")

        observed_path = run_dir / "live-observed-preimage.plist"
        observed_path.write_bytes(before_bytes)
        try:
            observed_data, observed_plist = base.plist_bytes(observed_path)
            observed_extra = observed_plist.get("CacheExtra", {})
            if observed_extra.get("0+nc/Udy4WNG8S+Q7a/s1A") != "iPhone18,2":
                raise RuntimeError("live cache model identity mismatch")
            observed_risky = base.validate_risky(observed_plist)
        except Exception:
            write_control(control, "abort")
            decision_sent = True
            state["transaction"] = collect_helper(process, 10.0, may_terminate=True)
            raise
        state["observedPreimage"] = {
            "path": os.fspath(observed_path),
            "length": len(observed_data),
            "sha256": base.digest(observed_data),
            "metadataLength": before_size,
            "metadataMatchesRead": str(before_size) == str(len(observed_data)),
            "cacheVersion": observed_plist.get("CacheVersion"),
            "cacheUUID": observed_plist.get("CacheUUID"),
            "riskyValidation": observed_risky,
        }
        save(state)
        if before_bytes != original:
            write_control(control, "abort")
            decision_sent = True
            state["transaction"] = collect_helper(process, 10.0, may_terminate=True)
            raise RuntimeError(
                "canonical preimage changed; exact live bytes were saved at "
                f"{observed_path}"
            )
        if str(before_size) != str(len(before_bytes)):
            write_control(control, "abort")
            decision_sent = True
            state["transaction"] = collect_helper(process, 10.0, may_terminate=True)
            raise RuntimeError("canonical metadata/read length mismatch")

        state["canonicalMutationAttempted"] = True
        state["status"] = "transaction-commit-authorized"
        save(state)
        canonical_attempted = True
        write_control(control, "commit")
        if not wait_marker(Path(f"{control}.committed"), process, 12.0):
            state["transaction"] = collect_helper(
                process, 55.0, may_terminate=False
            )
            raise RuntimeError("transaction commit marker was not observed")

        final_read, final_bytes = read_until(
            state, "after", (replacement, original), 4.0
        )
        state["exactReplacementRead"] = final_read
        live_original_path = run_dir / "live-original.plist"
        state["backupCopy"] = base.copy_export(state, backup, live_original_path)
        backup_exact = bool(
            base.operation_ok(state["backupCopy"])
            and live_original_path.is_file()
            and live_original_path.read_bytes() == original
        )
        state["backupExact"] = backup_exact
        if final_bytes == replacement and backup_exact:
            write_control(Path(f"{control}.decision"), "accept")
            decision_sent = True
            state["transaction"] = collect_helper(
                process, 15.0, may_terminate=False
            )
            state["commitVerified"] = state["transaction"].get("accepted") is True
            if not state["commitVerified"]:
                raise RuntimeError("helper did not accept the verified commit")
            state["status"] = "commit-verified"
            save(state)
        else:
            write_control(Path(f"{control}.decision"), "rollback")
            decision_sent = True
            wait_marker(Path(f"{control}.rolledback"), process, 12.0)
            state["transaction"] = collect_helper(
                process, 15.0, may_terminate=False
            )
            rollback_read, rollback_bytes = read_until(
                state, "rollback", (original,), 4.0
            )
            state["exactRollbackRead"] = rollback_read
            state["rollbackVerified"] = rollback_bytes == original
            state["status"] = (
                "rollback-verified"
                if state["rollbackVerified"]
                else "rollback-incomplete"
            )
            save(state)
            raise RuntimeError("installed cache did not match replacement bytes")
    except Exception as error:
        failure = error
        state["commitError"] = f"{type(error).__name__}: {error}"
        if canonical_attempted and not decision_sent and process.poll() is None:
            write_control(Path(f"{control}.decision"), "rollback")
            wait_marker(Path(f"{control}.rolledback"), process, 50.0)
            state["transaction"] = collect_helper(
                process, 10.0, may_terminate=False
            )
            rollback_read, rollback_bytes = read_until(
                state, "exception-rollback", (original,), 4.0
            )
            state["exactRollbackRead"] = rollback_read
            state["rollbackVerified"] = rollback_bytes == original
        elif not canonical_attempted and process.poll() is None:
            write_control(control, "abort")
            state["transaction"] = collect_helper(
                process, 10.0, may_terminate=True
            )
        state["status"] = (
            "rollback-verified"
            if state.get("rollbackVerified")
            else "precommit-failed"
            if not canonical_attempted
            else "rollback-incomplete"
        )
        save(state)

    safe_to_clean = failure is None or not canonical_attempted or state.get(
        "rollbackVerified"
    )
    if safe_to_clean:
        cleanup_result = generated_cleanup(state)
    else:
        cleanup_result = {"ok": False, "preserved": "rollback not exact"}
        state["cleanup"] = cleanup_result
        save(state)

    report_path = run_dir / "transactional-airtraffic-mgcache-replace.json"
    report_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    if base.operation_ok(cleanup_result):
        STATE_PATH.unlink(missing_ok=True)

    if failure is not None:
        raise RuntimeError(
            f"{failure}; rollbackVerified={state.get('rollbackVerified')}; "
            f"report={report_path}"
        )
    if not base.operation_ok(cleanup_result):
        raise RuntimeError(f"commit verified but cleanup incomplete: {report_path}")
    return {
        "ok": True,
        "commitVerified": True,
        "exactCanonicalReadback": True,
        "target": state["target"],
        "originalSHA256": state["originalSHA256"],
        "replacementSHA256": state["replacementSHA256"],
        "replacementLength": state["replacementLength"],
        "riskyValidation": state["riskyValidation"],
        "cleanupVerified": True,
        "report": os.fspath(report_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--recover", action="store_true")
    parser.add_argument("--capture-only", action="store_true")
    parser.add_argument("--original", type=Path, default=base.EXPECTED_ORIGINAL)
    parser.add_argument("--replacement", type=Path, default=base.EXPECTED_REPLACEMENT)
    args = parser.parse_args()
    try:
        result = (
            recover_transaction()
            if args.recover
            else run(
                args.original,
                args.replacement,
                capture_only=args.capture_only,
            )
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
