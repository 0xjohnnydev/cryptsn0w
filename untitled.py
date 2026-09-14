#!/usr/bin/env python3
"""Build, personalize, install, prove root, and open key-only SSH."""

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import json
import os
import plistlib
import re
import shutil
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import unquote_to_bytes


ROOT = Path(__file__).resolve().parent
VENV_PYTHON = ROOT / ".venv" / "bin" / "python"
BUILD_SUMMARY = ROOT / "build" / "build-summary.json"
CLIENT_KEY = ROOT / "build" / "ssh" / "id_ed25519"
CRYPTEXCTL = Path(
    "/System/Library/SecurityResearch/usr/bin/cryptexctl.research"
)

PRODUCT = "iPhone18,2"
VERSION = "27.0"
BUILD = "24A435"
IDENTIFIER = "com.0xjohnnydev.untitled"
DEVICE_SSH_PORT = 2222
MAX_IMAGE_SIZE = 128 * 1024 * 1024
GENERIC_VERSION = "999.999.999.999.999,999"

SIGNED_COMPONENTS = {
    "Cryptex1,CryptexInfoPlist": "ginf",
    "Cryptex1,GenericTrustCache": "gtcd",
    "Cryptex1,GenericVolume": "gtgv",
}
UNSIGNED_COMPONENT = "Cryptex1,GenericDmg"
ALLOWED_INFO_KEYS = {
    "CFBundleIdentifier",
    "CFBundleVersion",
    "Name",
    "Publisher",
    "Version",
}


class UntitledError(RuntimeError):
    pass


def note(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def ensure_python() -> None:
    try:
        import pyimg4  # noqa: F401
        import pymobiledevice3  # noqa: F401
        import requests  # noqa: F401
        return
    except ModuleNotFoundError:
        pass

    if Path(sys.prefix).resolve() == (ROOT / ".venv").resolve():
        raise UntitledError("the project virtual environment is incomplete")
    note("Preparing the pinned Python environment...")
    subprocess.run(["make", "-C", str(ROOT), "python"], check=True)
    os.execv(
        str(VENV_PYTHON),
        [str(VENV_PYTHON), str(Path(__file__).resolve()), *sys.argv[1:]],
    )


ensure_python()

import requests  # noqa: E402
from pyimg4 import IM4M  # noqa: E402
from pymobiledevice3.exceptions import TunneldConnectionError  # noqa: E402
from pymobiledevice3.remote.userspace_tunnel import (  # noqa: E402
    establish_userspace_rsd,
)
from pymobiledevice3.remote.xpc_message import XpcUInt64Type  # noqa: E402
from pymobiledevice3.restore.tss import (  # noqa: E402
    TSS_CONTROLLER_ACTION_URL,
    TSSRequest,
    cryptex1_udid,
)
from pymobiledevice3.services.cryptexd import (  # noqa: E402
    CryptexdService,
    unwrap_nonce,
)
from pymobiledevice3.tunneld.api import (  # noqa: E402
    get_tunneld_device_by_udid,
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def device_version(properties: dict[str, Any]) -> str:
    value = (
        properties.get("software", {})
        .get("osVersionNumber", {})
        .get("stringValue")
    )
    return value if isinstance(value, str) else "unknown"


def device_build(properties: dict[str, Any]) -> str:
    value = (
        properties.get("software", {})
        .get("osBuildVersions", {})
        .get("buildVersion", {})
        .get("name")
    )
    return value if isinstance(value, str) else "unknown"


def compatible_devices(devices: list[dict[str, Any]]) -> list[dict[str, str]]:
    matches: list[dict[str, str]] = []
    for device in devices:
        properties = device.get("properties", {})
        connection = properties.get("connection", {})
        hardware = properties.get("hardware", {})
        state = properties.get("state", {})
        udid = hardware.get("udid")
        if not (
            hardware.get("reality") == "physical"
            and hardware.get("productType") == PRODUCT
            and connection.get("pairingState") == "paired"
            and connection.get("state") == "connected"
            and device_version(properties) == VERSION
            and device_build(properties) == BUILD
            and isinstance(udid, str)
            and udid
        ):
            continue
        transport = {
            "localNetwork": "Wi-Fi",
            "wired": "USB",
        }.get(connection.get("transportType"), "connected")
        matches.append(
            {
                "name": state.get("name") or PRODUCT,
                "model": hardware.get("marketingName") or PRODUCT,
                "transport": transport,
                "udid": udid,
            }
        )
    return sorted(matches, key=lambda item: (item["name"], item["udid"]))


def compatible_usbmux_devices(devices: Any) -> list[dict[str, str]]:
    if not isinstance(devices, list):
        return []
    matches: list[dict[str, str]] = []
    for device in devices:
        if not isinstance(device, dict):
            continue
        udid = device.get("UniqueDeviceID") or device.get("Identifier")
        connection_type = device.get("ConnectionType")
        if not (
            device.get("ProductType") == PRODUCT
            and device.get("ProductVersion") == VERSION
            and device.get("BuildVersion") == BUILD
            and isinstance(connection_type, str)
            and connection_type.casefold() == "usb"
            and isinstance(udid, str)
            and udid
        ):
            continue
        matches.append(
            {
                "name": device.get("DeviceName") or PRODUCT,
                "model": PRODUCT,
                "transport": "USB",
                "udid": udid,
            }
        )
    return sorted(matches, key=lambda item: (item["name"], item["udid"]))


def resolve_device(requested: str | None) -> str:
    command = [
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
    ]
    completed = subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=12,
    )
    devices = compatible_devices(json.loads(completed.stdout)["result"]["devices"])
    try:
        usbmux_completed = subprocess.run(
            [sys.executable, "-m", "pymobiledevice3", "usbmux", "list"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=12,
        )
        usbmux_devices = compatible_usbmux_devices(
            json.loads(usbmux_completed.stdout)
        )
    except (
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
    ):
        usbmux_devices = []
    devices_by_udid = {device["udid"].casefold(): device for device in devices}
    for device in usbmux_devices:
        devices_by_udid.setdefault(device["udid"].casefold(), device)
    devices = sorted(
        devices_by_udid.values(), key=lambda item: (item["name"], item["udid"])
    )
    if requested is not None:
        for device in devices:
            if device["udid"].casefold() == requested.casefold():
                return device["udid"]
        raise UntitledError(
            f"{requested} is not a connected paired {PRODUCT} on "
            f"iOS {VERSION} ({BUILD})"
        )
    if len(devices) == 1:
        return devices[0]["udid"]
    if not devices:
        raise UntitledError(
            f"no connected paired {PRODUCT} on iOS {VERSION} ({BUILD}) found"
        )
    if not sys.stdin.isatty():
        raise UntitledError("multiple compatible devices found; pass --device")

    note("Available compatible iPhones:")
    for index, device in enumerate(devices, 1):
        note(
            f"  [{index}] {device['name']} · {device['model']} · "
            f"{device['transport']}\n      {device['udid']}"
        )
    while True:
        try:
            selection = int(input("Select device: ").strip())
        except (EOFError, KeyboardInterrupt) as error:
            raise UntitledError("device selection cancelled") from error
        except ValueError:
            selection = 0
        if 1 <= selection <= len(devices):
            return devices[selection - 1]["udid"]
        note(f"Enter a number from 1 to {len(devices)}.")


def ensure_payload() -> dict[str, Any]:
    note("Building and validating the pinned payload...")
    subprocess.run(["make", "-C", str(ROOT), "payload"], check=True)
    if not BUILD_SUMMARY.is_file():
        raise UntitledError("the build did not produce build-summary.json")
    return json.loads(BUILD_SUMMARY.read_text())


def restore_dir(bundle: Path) -> tuple[Path, Path]:
    bundle = bundle.resolve()
    if (bundle / "BuildManifest.plist").is_file():
        return bundle, bundle.parent
    if (bundle / "Restore" / "BuildManifest.plist").is_file():
        return bundle / "Restore", bundle
    raise UntitledError(f"no Restore/BuildManifest.plist below {bundle}")


def generic_identity(manifest: dict[str, Any]) -> dict[str, Any]:
    required = (*SIGNED_COMPONENTS, UNSIGNED_COMPONENT)
    matches = [
        candidate
        for candidate in manifest.get("BuildIdentities", [])
        if all(key in candidate.get("Manifest", {}) for key in required)
    ]
    if len(matches) != 1:
        raise UntitledError(
            f"expected one generic Cryptex1 identity, found {len(matches)}"
        )
    return matches[0]


def read_payload(
    directory: Path, identity: dict[str, Any], component: str
) -> bytes:
    relative = identity["Manifest"][component]["Info"]["Path"]
    return (directory / relative).read_bytes()


def component_digests(
    directory: Path, identity: dict[str, Any]
) -> dict[str, bytes]:
    digests: dict[str, bytes] = {}
    for component in (*SIGNED_COMPONENTS, UNSIGNED_COMPONENT):
        actual = hashlib.sha384(
            read_payload(directory, identity, component)
        ).digest()
        expected = identity["Manifest"][component]["Digest"]
        if actual != expected:
            raise UntitledError(f"SHA-384 mismatch for {component}")
        digests[component] = actual
    return digests


def validate_identity(identity: dict[str, Any]) -> None:
    expected = {
        "Cryptex1,ChipID": "0xff10",
        "Cryptex1,Type": 3,
        "Cryptex1,SubType": 0,
        "Cryptex1,ProductClass": "0xf2",
        "Cryptex1,UseProductClass": True,
        "Cryptex1,NonceDomain": 3,
        "Cryptex1,Version": GENERIC_VERSION,
        "Cryptex1,PreauthorizationVersion": GENERIC_VERSION,
    }
    normalized = dict(identity)
    normalized["Cryptex1,ChipID"] = str(
        identity.get("Cryptex1,ChipID")
    ).lower()
    normalized["Cryptex1,ProductClass"] = str(
        identity.get("Cryptex1,ProductClass")
    ).lower()
    mismatches = {
        key: {"expected": value, "actual": normalized.get(key)}
        for key, value in expected.items()
        if normalized.get(key) != value
    }
    if mismatches:
        raise UntitledError(f"unexpected Cryptex1 identity: {mismatches}")


def validate_trust_cache(
    path: Path, expected: dict[str, Any]
) -> dict[str, Any]:
    completed = subprocess.run(
        [str(CRYPTEXCTL), "dump-trust-cache", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    count_match = re.search(
        r"^entry count = ([0-9]+)$", completed.stdout, re.MULTILINE
    )
    if count_match is None:
        raise UntitledError("could not parse trust-cache entry count")
    count = int(count_match.group(1))
    entries = re.findall(
        r"^([0-9a-f]{40})\s+", completed.stdout, re.MULTILINE
    )
    if count != expected.get("entryCount") or entries != expected.get("cdhashes"):
        raise UntitledError("trust cache differs from the build summary")
    actual_hash = sha256(path)
    if actual_hash != expected.get("sha256"):
        raise UntitledError("trust-cache SHA-256 differs from the build summary")
    return {
        "entryCount": count,
        "sha256": actual_hash,
        "firstCdhash": entries[0],
        "lastCdhash": entries[-1],
    }


def validate_bundle(
    summary: dict[str, Any]
) -> tuple[Path, Path, dict[str, Any], dict[str, bytes], dict[str, Any]]:
    bundle_value = summary.get("bundle")
    if not isinstance(bundle_value, str):
        raise UntitledError("build summary has no bundle path")
    directory, bundle = restore_dir(Path(bundle_value))
    manifest = plistlib.loads((directory / "BuildManifest.plist").read_bytes())
    identity = generic_identity(manifest)
    validate_identity(identity)
    digests = component_digests(directory, identity)

    identifier = summary.get("identifier")
    version = summary.get("version")
    if identifier != IDENTIFIER or not isinstance(version, str):
        raise UntitledError("unexpected identifier or version in build summary")
    info = plistlib.loads(
        read_payload(directory, identity, "Cryptex1,CryptexInfoPlist")
    )
    unexpected = sorted(set(info) - ALLOWED_INFO_KEYS)
    if unexpected:
        raise UntitledError(f"unexpected Cryptex info directives: {unexpected}")
    if (
        info.get("CFBundleIdentifier") != identifier
        or info.get("CFBundleVersion") != version
    ):
        raise UntitledError("Cryptex info does not match the build summary")

    image = read_payload(directory, identity, "Cryptex1,GenericDmg")
    if len(image) > MAX_IMAGE_SIZE:
        raise UntitledError(
            f"Cryptex image is {len(image)} bytes; limit is {MAX_IMAGE_SIZE}"
        )
    trust_cache_path = directory / identity["Manifest"][
        "Cryptex1,GenericTrustCache"
    ]["Info"]["Path"]
    trust_cache = validate_trust_cache(
        trust_cache_path, summary.get("trustCache", {})
    )
    return directory, bundle, identity, digests, {
        "identifier": identifier,
        "version": version,
        "imageBytes": len(image),
        "trustCache": trust_cache,
    }


def json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"$hex": value.hex()}
    if isinstance(value, dict):
        return {key: json_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_value(item) for item in value]
    return value


def parse_tss_envelope(
    content: bytes,
) -> tuple[int | None, str | None, bytes | None]:
    status_match = re.search(rb"(?:^|&)STATUS=([^&]*)", content)
    message_match = re.search(rb"(?:^|&)MESSAGE=([^&]*)", content)
    status = None
    if status_match is not None:
        try:
            status = int(status_match.group(1))
        except ValueError:
            pass
    message = None
    if message_match is not None:
        message = unquote_to_bytes(message_match.group(1)).decode(
            "utf-8", "replace"
        )
    marker = b"REQUEST_STRING="
    response_plist = (
        unquote_to_bytes(content.split(marker, 1)[1])
        if marker in content
        else None
    )
    return status, message, response_plist


def property_dict(properties: Any) -> dict[str, Any]:
    return {property_.fourcc: property_.value for property_ in properties}


def ticket_checks(
    ticket: bytes,
    identity: dict[str, Any],
    chip: dict[str, Any],
    nonce: bytes,
    digests: dict[str, bytes],
) -> dict[str, bool]:
    im4m = IM4M(ticket)
    properties = property_dict(im4m.properties)
    images = {
        image.fourcc: property_dict(image.properties) for image in im4m.images
    }
    checks = {
        "productionMode": properties.get("CPRO")
        is bool(chip["img4_chip_cpro"]),
        "udid": properties.get("UDID") == cryptex1_udid(chip),
        "nonce": properties.get("cnch") == nonce,
        "chipFamily": properties.get("fchp")
        == int(str(identity["Cryptex1,ChipID"]), 0),
        "type": properties.get("type") == identity["Cryptex1,Type"],
        "subType": properties.get("styp") == identity["Cryptex1,SubType"],
        "productClass": properties.get("clas")
        == int(str(identity["Cryptex1,ProductClass"]), 0),
        "nonceDomain": properties.get("ndom")
        == identity["Cryptex1,NonceDomain"],
        "useProductClass": properties.get("upcl")
        is bool(identity["Cryptex1,UseProductClass"]),
        "version": properties.get("vnum")
        == identity["Cryptex1,Version"].encode(),
        "preauthorizationVersion": properties.get("pave")
        == identity["Cryptex1,PreauthorizationVersion"].encode(),
    }
    for component, fourcc in SIGNED_COMPONENTS.items():
        checks[f"digest:{fourcc}"] = (
            images.get(fourcc, {}).get("DGST") == digests[component]
        )
    checks["noUnsignedGdmgDigest"] = "gdmg" not in images
    return checks


def personalize(
    bundle: Path,
    directory: Path,
    identity: dict[str, Any],
    chip: dict[str, Any],
    nonce: bytes,
    digests: dict[str, bytes],
    udid: str,
) -> tuple[bytes, dict[str, Any]]:
    request_identity = copy.deepcopy(identity)
    for component, entry in request_identity["Manifest"].items():
        entry.setdefault("Info", {})["Personalize"] = (
            component in SIGNED_COMPONENTS
        )
    builder = TSSRequest()
    builder.add_cryptex1_tags(request_identity, chip, nonce)
    request = copy.deepcopy(builder._request)
    requested = {
        key
        for key in request
        if key in SIGNED_COMPONENTS or key == UNSIGNED_COMPONENT
    }
    if requested != set(SIGNED_COMPONENTS):
        raise UntitledError(
            f"unexpected personalized component set: {sorted(requested)}"
        )

    stamp = time.strftime("%Y%m%d-%H%M%S")
    output = (
        ROOT
        / "build"
        / "personalized"
        / f"{udid}-{stamp}-{uuid.uuid4().hex[:8]}"
    )
    output.mkdir(parents=True, exist_ok=False)
    (output / "request.plist").write_bytes(plistlib.dumps(request))
    (output / "request.json").write_text(
        json.dumps(json_value(request), indent=2, sort_keys=True) + "\n"
    )

    note("Requesting a device-bound generic Cryptex ticket...")
    response = requests.post(
        TSS_CONTROLLER_ACTION_URL,
        headers={
            "Cache-Control": "no-cache",
            "Content-type": 'text/xml; charset="utf-8"',
            "User-Agent": "InetURL/1.0",
            "Expect": "100-continue",
        },
        data=plistlib.dumps(request),
        timeout=45,
        verify=False,
    )
    (output / "response.raw").write_bytes(response.content)
    status, message, raw_plist = parse_tss_envelope(response.content)
    response_plist = None
    if raw_plist is not None:
        try:
            response_plist = plistlib.loads(raw_plist)
        except Exception:
            response_plist = None
    if response_plist is not None:
        (output / "response.plist").write_bytes(
            plistlib.dumps(response_plist)
        )
    if (
        response.status_code != 200
        or status != 0
        or message != "SUCCESS"
        or response_plist is None
    ):
        raise UntitledError(
            "TSS rejected the Cryptex request: "
            f"HTTP={response.status_code} STATUS={status} MESSAGE={message!r}"
        )
    ticket = response_plist.get("Cryptex1,Ticket") or response_plist.get(
        "ApImg4Ticket"
    )
    if not isinstance(ticket, bytes):
        raise UntitledError("TSS returned no Cryptex1 ticket")
    (output / "ticket.im4m").write_bytes(ticket)

    checks = ticket_checks(ticket, identity, chip, nonce, digests)
    if not all(checks.values()):
        failed = [name for name, passed in checks.items() if not passed]
        raise UntitledError(
            f"the returned ticket mismatched the request: {', '.join(failed)}"
        )

    signed_bundle = output / f"{bundle.stem}.signed.cxbd"
    shutil.copytree(bundle, signed_bundle)
    variants = [
        path
        for path in (signed_bundle / "Restore" / "Cryptex").iterdir()
        if path.is_dir()
    ]
    if len(variants) != 1:
        raise UntitledError("expected exactly one signed Cryptex variant")
    (variants[0] / "im4m").write_bytes(ticket)
    result = {
        "artifacts": str(output),
        "signedBundle": str(signed_bundle),
        "ticketBytes": len(ticket),
        "ticketSha256": hashlib.sha256(ticket).hexdigest(),
        "nonceSha256": hashlib.sha256(nonce).hexdigest(),
        "checks": checks,
        "verified": True,
    }
    (output / "summary.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    return ticket, result


async def open_rsd(udid: str) -> tuple[Any, str]:
    try:
        rsd = await get_tunneld_device_by_udid(udid)
    except (ConnectionError, OSError, TunneldConnectionError):
        rsd = None
    if rsd is not None:
        return rsd, "tunneld"
    note("No existing tunnel found; opening a userspace tunnel...")
    return await establish_userspace_rsd(serial=udid), "userspace"


async def install(
    udid: str,
    summary: dict[str, Any],
    replace: bool,
) -> dict[str, Any]:
    directory, bundle, identity, digests, local = validate_bundle(summary)
    rsd, transport = await open_rsd(udid)
    try:
        service = CryptexdService(rsd)
        before = await service.copy_installed()
        existing = [item for item in before if item.identifier == IDENTIFIER]
        if len(existing) > 1:
            raise UntitledError(
                f"multiple installed {IDENTIFIER} versions found; refusing"
            )
        if existing and not replace:
            raise UntitledError(
                f"{IDENTIFIER} is installed; omit --no-replace to refresh it"
            )

        chip = await service.read_personalization_identifiers()
        nonce_blob = await service.cryptex_nonce(
            identity["Cryptex1,NonceDomain"]
        )
        nonce = unwrap_nonce(nonce_blob) if len(nonce_blob) != 48 else nonce_blob
        if len(nonce) != 48:
            raise UntitledError(
                f"expected a 48-byte Cryptex nonce, got {len(nonce)}"
            )
        ticket, personalization = personalize(
            bundle, directory, identity, chip, nonce, digests, udid
        )
        checks = ticket_checks(ticket, identity, chip, nonce, digests)
        if not all(checks.values()):
            failed = [name for name, passed in checks.items() if not passed]
            raise UntitledError(f"ticket revalidation failed: {failed}")

        replaced = None
        if existing:
            replaced = {
                "identifier": existing[0].identifier,
                "version": existing[0].version,
            }
            note(f"Refreshing the existing {IDENTIFIER} mount...")
            await service.uninstall(
                existing[0].identifier, existing[0].version
            )

        properties: dict[str, Any] = {
            "Cryptex1,UseProductClass": identity[
                "Cryptex1,UseProductClass"
            ],
            "MountedCryptex": False,
            "Cryptex1,SubType": XpcUInt64Type(
                identity["Cryptex1,SubType"]
            ),
            "Cryptex1,NonceDomain": XpcUInt64Type(
                identity["Cryptex1,NonceDomain"]
            ),
            "Cryptex1,Version": identity["Cryptex1,Version"],
            "Cryptex1,PreauthVersion": identity[
                "Cryptex1,PreauthorizationVersion"
            ],
        }
        note("Installing the nonpersistent generic Cryptex...")
        await service.install(
            image=read_payload(directory, identity, "Cryptex1,GenericDmg"),
            trustcache=read_payload(
                directory, identity, "Cryptex1,GenericTrustCache"
            ),
            im4m=ticket,
            info=read_payload(
                directory, identity, "Cryptex1,CryptexInfoPlist"
            ),
            volumehash=read_payload(
                directory, identity, "Cryptex1,GenericVolume"
            ),
            cryptex1_properties=properties,
            image_type_index=10,
            persistence=0,
            nonce_persistence=0,
            auth=0,
        )
        after = await service.copy_installed()
    finally:
        await rsd.close()

    installed = [
        {"identifier": item.identifier, "version": item.version}
        for item in after
        if item.identifier == IDENTIFIER
    ]
    expected = [{"identifier": IDENTIFIER, "version": local["version"]}]
    if installed != expected:
        raise UntitledError(
            f"install returned without the exact expected mount: {installed}"
        )
    return {
        "device": udid,
        "transport": transport,
        "validated": True,
        "identifier": IDENTIFIER,
        "version": local["version"],
        "imageBytes": local["imageBytes"],
        "trustCache": local["trustCache"],
        "personalization": personalization,
        "installArguments": {
            "imageTypeIndex": 10,
            "persistence": 0,
            "noncePersistence": 0,
            "auth": 0,
        },
        "replaced": replaced,
        "installed": installed[0],
    }


def check_local_port(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(("127.0.0.1", port))
        except OSError as error:
            raise UntitledError(
                f"local TCP port {port} is unavailable: {error}"
            ) from error


def ssh_command(local_port: int, remote_command: str | None) -> list[str]:
    command = [
        shutil.which("ssh") or "/usr/bin/ssh",
        "-i",
        str(CLIENT_KEY),
        "-p",
        str(local_port),
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=2",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "LogLevel=ERROR",
        "root@127.0.0.1",
    ]
    if remote_command is not None:
        command.append(remote_command)
    return command


def ssh_session(
    udid: str,
    local_port: int,
    command: str | None,
    interactive: bool,
) -> dict[str, Any]:
    iproxy = shutil.which("iproxy")
    if iproxy is None:
        raise UntitledError("iproxy is required (brew install libimobiledevice)")
    if not CLIENT_KEY.is_file():
        raise UntitledError("the generated SSH client key is missing")
    check_local_port(local_port)
    log_path = ROOT / "build" / "iproxy.log"
    log = log_path.open("ab")
    forward = subprocess.Popen(
        [iproxy, "-u", udid, f"{local_port}:{DEVICE_SSH_PORT}"],
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    try:
        # The iOS 27 root filesystem does not ship /usr/bin/id.  zsh exposes
        # the credentials of the actual remote command process as readonly
        # special parameters, so the proof has no payload-path dependency.
        proof_command = (
            "printf '%s\\n' \"$EUID\" "
            "\"uid=$UID euid=$EUID gid=$GID egid=$EGID\""
        )
        deadline = time.monotonic() + 35
        proof = None
        while time.monotonic() < deadline:
            if forward.poll() is not None:
                raise UntitledError(
                    f"iproxy exited with {forward.returncode}; see {log_path}"
                )
            candidate = subprocess.run(
                ssh_command(local_port, proof_command),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=8,
            )
            lines = candidate.stdout.strip().splitlines()
            if (
                candidate.returncode == 0
                and len(lines) >= 2
                and lines[0] == "0"
                and re.search(r"(?:^|\s)uid=0(?:\(|\s|$)", lines[1])
            ):
                proof = {
                    "uid": 0,
                    "id": lines[1],
                    "stdout": candidate.stdout.strip(),
                }
                break
            time.sleep(0.5)
        if proof is None:
            raise UntitledError(
                f"root SSH did not become ready; see {log_path}"
            )

        result: dict[str, Any] = {
            "forward": {
                "listenAddress": "127.0.0.1",
                "localPort": local_port,
                "devicePort": DEVICE_SSH_PORT,
            },
            "rootProof": proof,
        }
        if command is not None:
            completed = subprocess.run(
                ssh_command(local_port, command),
                check=False,
                text=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            result["command"] = {
                "value": command,
                "exitCode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
            }
            if completed.returncode != 0:
                raise UntitledError(
                    f"remote command exited with {completed.returncode}"
                )
        elif interactive:
            note(
                f"Root verified. Opening root@127.0.0.1:{local_port}; "
                "exit returns to the Mac."
            )
            result["interactiveExitCode"] = subprocess.run(
                ssh_command(local_port, None), check=False
            ).returncode
        return result
    finally:
        forward.terminate()
        try:
            forward.wait(timeout=3)
        except subprocess.TimeoutExpired:
            forward.kill()
            forward.wait(timeout=3)
        log.close()


def render_result(result: dict[str, Any], path: Path | None) -> None:
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered)
    print(rendered, end="")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", help="paired device UDID")
    parser.add_argument("--local-port", type=int, default=DEVICE_SSH_PORT)
    parser.add_argument("--command", help="run one command after proving root")
    parser.add_argument(
        "--no-shell",
        action="store_true",
        help="prove root over SSH without opening an interactive shell",
    )
    parser.add_argument(
        "--no-replace",
        action="store_true",
        help="refuse to refresh this PoC's already-installed identifier",
    )
    parser.add_argument("--result-json", type=Path)
    args = parser.parse_args()
    if not 1 <= args.local_port <= 65535:
        parser.error("--local-port must be between 1 and 65535")

    summary = ensure_payload()
    udid = resolve_device(args.device)
    note(f"Using {udid}")
    result = asyncio.run(install(udid, summary, not args.no_replace))
    interactive = not args.no_shell and args.command is None and sys.stdin.isatty()
    result["ssh"] = ssh_session(
        udid, args.local_port, args.command, interactive
    )
    render_result(result, args.result_json)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (UntitledError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
