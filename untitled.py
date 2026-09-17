#!/usr/bin/env python3
'TSS/Cryptex personalization and installation details are redacted from this educational source release.'

from __future__ import annotations

if __name__ == "__main__":
    raise SystemExit('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


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

PRODUCTS = ("iPhone18,2", "iPhone14,5")
VERSION = "27.0"
BUILD = "24A435"
IDENTIFIER = "com.0xjohnnydev.untitled"
DEVICE_SSH_PORT = 2222
MAX_IMAGE_SIZE = 128 * 1024 * 1024
GENERIC_VERSION = None  # [REDACTED] Flow-specific parameters omitted.

SIGNED_COMPONENTS = None  # [REDACTED] Flow-specific parameters omitted.
UNSIGNED_COMPONENT = None  # [REDACTED] Flow-specific parameters omitted.
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
# [REDACTED] Related personalization helper imports omitted.
from pymobiledevice3.exceptions import TunneldConnectionError  # noqa: E402
from pymobiledevice3.remote.userspace_tunnel import (  # noqa: E402
    establish_userspace_rsd,
)
# [REDACTED] Related personalization helper imports omitted.
# [REDACTED] TSS request dependency import omitted.
# [REDACTED] Related personalization helper imports omitted.
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
            and hardware.get("productType") in PRODUCTS
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
                "name": state.get("name") or hardware["productType"],
                "model": hardware.get("marketingName") or hardware["productType"],
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
            device.get("ProductType") in PRODUCTS
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
                "name": device.get("DeviceName") or device["ProductType"],
                "model": device["ProductType"],
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
    devices: list[dict[str, str]] = []
    try:
        completed = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=12,
        )
        devices = compatible_devices(
            json.loads(completed.stdout)["result"]["devices"]
        )
    except (
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        ValueError,
        KeyError,
    ):
        pass
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
            f"{requested} is not a connected paired {PRODUCTS} on "
            f"iOS {VERSION} ({BUILD})"
        )
    if len(devices) == 1:
        return devices[0]["udid"]
    if not devices:
        raise UntitledError(
            f"no connected paired {PRODUCTS} on iOS {VERSION} ({BUILD}) found"
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
    # [REDACTED] Related request, payload, or installation helper omitted.
    raise RuntimeError('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


def read_payload(
    directory: Path, identity: dict[str, Any], component: str
) -> bytes:
    relative = identity["Manifest"][component]["Info"]["Path"]
    return (directory / relative).read_bytes()


def component_digests(
    directory: Path, identity: dict[str, Any]
) -> dict[str, bytes]:
    # [REDACTED] Related request, payload, or installation helper omitted.
    raise RuntimeError('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


def validate_identity(identity: dict[str, Any]) -> None:
    # [REDACTED] TSS/Cryptex personalization and installation details are redacted from this educational source release.
    raise RuntimeError('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


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
    # [REDACTED] Related request, payload, or installation helper omitted.
    raise RuntimeError('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


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
    # [REDACTED] Related request, payload, or installation helper omitted.
    raise RuntimeError('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


def property_dict(properties: Any) -> dict[str, Any]:
    return {property_.fourcc: property_.value for property_ in properties}


def ticket_checks(
    ticket: bytes,
    identity: dict[str, Any],
    chip: dict[str, Any],
    nonce: bytes,
    digests: dict[str, bytes],
) -> dict[str, bool]:
    # [REDACTED] Related request, payload, or installation helper omitted.
    raise RuntimeError('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


def personalize(
    bundle: Path,
    directory: Path,
    identity: dict[str, Any],
    chip: dict[str, Any],
    nonce: bytes,
    digests: dict[str, bytes],
    udid: str,
) -> tuple[bytes, dict[str, Any]]:
    # [REDACTED] Related request, payload, or installation helper omitted.
    raise RuntimeError('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


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
    # [REDACTED] Related request, payload, or installation helper omitted.
    raise RuntimeError('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


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
