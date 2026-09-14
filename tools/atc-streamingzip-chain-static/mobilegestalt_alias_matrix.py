#!/usr/bin/env python3
"""Probe alternate spellings of the MobileGestalt system-group path.

Every attempt uses a fresh random canary leaf and the cleanup/recovery gates
from directory_matrix.  The live MobileGestalt cache leaf is never named.
"""

from __future__ import annotations

import asyncio
import json

import chain_canary as chain
import directory_matrix as matrix


TARGETS = (
    (
        "mobile-containers-systemgroup-parent",
        "/var/mobile/Containers/Shared/SystemGroup",
    ),
    (
        "mobile-containers-mobilegestalt-caches",
        "/var/mobile/Containers/Shared/SystemGroup/"
        "systemgroup.com.apple.mobilegestaltcache/Library/Caches",
    ),
    (
        "private-mobile-containers-systemgroup-parent",
        "/private/var/mobile/Containers/Shared/SystemGroup",
    ),
    (
        "private-mobile-containers-mobilegestalt-caches",
        "/private/var/mobile/Containers/Shared/SystemGroup/"
        "systemgroup.com.apple.mobilegestaltcache/Library/Caches",
    ),
    (
        "user-alias-systemgroup-parent",
        "/User/Containers/Shared/SystemGroup",
    ),
    (
        "user-alias-mobilegestalt-caches",
        "/User/Containers/Shared/SystemGroup/"
        "systemgroup.com.apple.mobilegestaltcache/Library/Caches",
    ),
)


async def main() -> int:
    udid = chain.TRANSPORT.paired_coredevice_udid()
    summary = {
        "schema": 1,
        "test": "ATCStreamingZipMobileGestaltAliasMatrix",
        "expectedProduct": chain.EXPECTED_PRODUCT,
        "expectedVersion": chain.EXPECTED_VERSION,
        "expectedBuild": chain.EXPECTED_BUILD,
        "canonicalMobileGestaltCacheTouched": False,
        "existingFilesTargeted": False,
        "targets": [],
    }
    try:
        summary["initialPreflight"] = await matrix.preflight(udid)
        for index, (label, target_directory) in enumerate(TARGETS, 1):
            row, safe_to_continue = await matrix.run_target(
                udid, label, target_directory
            )
            summary["targets"].append(row)
            print(
                json.dumps(
                    {
                        "progress": f"{index}/{len(TARGETS)}",
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
                summary["abortReason"] = (
                    "generated artifacts were not fully accounted for"
                )
                break
        summary["finalPreflight"] = await matrix.preflight(udid)
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
    print(json.dumps({"final": summary}, sort_keys=True), flush=True)
    return 0 if summary["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
