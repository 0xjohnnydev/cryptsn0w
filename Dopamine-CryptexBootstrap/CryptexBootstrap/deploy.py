#!/usr/bin/env python3
"""Build or install the matched Sileo and generic-Cryptex bootstrap pair."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import plistlib
import re
import shlex
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
UPSTREAM_ROOT = SCRIPT_DIR.parent
WORKSPACE = UPSTREAM_ROOT.parent
HELPER_DIR = WORKSPACE / "tools" / "cryptexd-static"

BUILD_SCRIPT = SCRIPT_DIR / "build_cryptex.sh"
CAPTURE_SCRIPT = SCRIPT_DIR / "capture_device_context.py"
INSTALL_SCRIPT = SCRIPT_DIR / "install_cryptex_bootstrap.py"
PERSONALIZE_SCRIPT = HELPER_DIR / "personalize_generic_cryptex1.py"
BUILD_SUMMARY = SCRIPT_DIR / "out" / "build-summary.json"

SUPPORTED_TARGETS = (
    {
        "udid": "00008110-000C542E0EA8201E",
        "product": "iPhone14,5",
        "version": "27.0",
        "build": "24A435",
    },
    {
        "udid": "00008150-0018252C1130C01C",
        "product": "iPhone18,2",
        "version": "27.0",
        "build": "24A435",
    },
    {
        "udid": "00008101-001C39641A9B001E",
        "product": "iPhone13,1",
        "version": "27.0",
        "build": "24A437",
    },
)
SILEO_TRUSTED_EXECUTABLES = (
    "Sileo",
    "giveMeRoot",
    "F/libiosexec.1.dylib",
    "F/liblzma.5.dylib",
    "F/libcodex-sileo-broker.dylib",
    "F/libzstd.1.dylib",
    "F/libzstd.real.dylib",
)
SYSTEM_SILEO_IDENTIFIER = "org.coolstar.SileoStore"
SYSTEM_SILEO_URL = (
    "file:///private/var/containers/Bundle/Application/"
    "D7A9C65A-1FD8-4D9C-AC8D-4E8E5143A191/Sileo.app/"
)
LEGACY_SILEO_IDENTIFIERS = ("com.lilycohl.sileo27b8",)
GENERIC_IOS_APP_ICON_SHA256 = (
    "666ac286068bbddb0c83b828ec86f8fd0978cec4f7a4b0cfcc8800182197eb09"
)


class DeployError(RuntimeError):
    pass


def note(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise DeployError(f"missing expected JSON output: {path}")
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise DeployError(f"expected a JSON object in {path}")
    return value


def run(command: list[str], *, env: dict[str, str] | None = None) -> None:
    note(f"+ {shlex.join(command)}")
    subprocess.run(command, check=True, env=env)


def capture_json(command: list[str], *, timeout: float) -> dict[str, Any]:
    note(f"+ {shlex.join(command)}")
    completed = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise DeployError(
            f"command exited {completed.returncode}: {shlex.join(command)}"
            + (f"\n{detail}" if detail else "")
        )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise DeployError(
            f"command returned invalid JSON: {shlex.join(command)}"
        ) from error
    if not isinstance(value, dict):
        raise DeployError(f"command did not return a JSON object: {shlex.join(command)}")
    return value


def process_snapshot(device: dict[str, str]) -> dict[int, str]:
    payload = capture_json(
        [
            sys.executable,
            "-m",
            "pymobiledevice3",
            "processes",
            "ps",
            "--udid",
            device["udid"],
        ],
        timeout=20,
    )
    result: dict[int, str] = {}
    for raw_pid, information in payload.items():
        if not isinstance(information, dict):
            continue
        name = information.get("ProcessName")
        try:
            pid = int(raw_pid)
        except (TypeError, ValueError):
            continue
        if pid > 1 and isinstance(name, str):
            result[pid] = name
    return result


def application_record(device: dict[str, str], identifier: str) -> dict[str, Any] | None:
    payload = capture_json(
        [
            "xcrun",
            "devicectl",
            "device",
            "info",
            "apps",
            "--device",
            device["udid"],
            "--include-all-apps",
            "--bundle-id",
            identifier,
            "--timeout",
            "20",
            "--json-output",
            "-",
            "--omit-deprecated-fields-in-json",
        ],
        timeout=25,
    )
    apps = payload.get("result", {}).get("apps", [])
    matches = [
        app
        for app in apps
        if isinstance(app, dict) and app.get("bundleIdentifier") == identifier
    ]
    if len(matches) > 1:
        raise DeployError(f"LaunchServices returned duplicate records for {identifier}")
    return matches[0] if matches else None


def system_sileo_record_is_valid(
    record: dict[str, Any] | None, expected_version: str
) -> bool:
    if record is None:
        return False
    url = record.get("url")
    return (
        record.get("bundleIdentifier") == SYSTEM_SILEO_IDENTIFIER
        and record.get("bundleVersion") == expected_version
        and record.get("builtByDeveloper") is False
        and record.get("removable") is False
        and isinstance(url, str)
        and url == SYSTEM_SILEO_URL
    )


def signal_stale_bootstrap(
    device: dict[str, str], preinstall_pids: set[int]
) -> list[int]:
    if not preinstall_pids:
        return []
    current = process_snapshot(device)
    signaled: list[int] = []
    for pid in sorted(preinstall_pids):
        if current.get(pid) != "codex-dopamine-bootstrap":
            continue
        command = [
            "xcrun",
            "devicectl",
            "device",
            "process",
            "signal",
            "--device",
            device["udid"],
            "--pid",
            str(pid),
            "--signal",
            "15",
            "--timeout",
            "20",
            "--json-output",
            "-",
            "--omit-deprecated-fields-in-json",
        ]
        capture_json(command, timeout=25)
        signaled.append(pid)
    return signaled


def verify_and_launch_system_sileo(
    device: dict[str, str],
    expected_version: str,
    preinstall_bootstrap_pids: set[int],
    icon_output: Path,
) -> dict[str, Any]:
    initial = application_record(device, SYSTEM_SILEO_IDENTIFIER)
    signaled: list[int] = []
    if not system_sileo_record_is_valid(initial, expected_version):
        signaled = signal_stale_bootstrap(device, preinstall_bootstrap_pids)

    record: dict[str, Any] | None = None
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        candidate = application_record(device, SYSTEM_SILEO_IDENTIFIER)
        if system_sileo_record_is_valid(candidate, expected_version):
            record = candidate
            break
        time.sleep(1.0)
    if record is None:
        raise DeployError(
            "the new Cryptex did not register original-ID Sileo as a system app"
        )

    expected_executable_url = record["url"].rstrip("/") + "/Sileo"
    launched_pid: int | None = None
    launch_deadline = time.monotonic() + 120.0
    while time.monotonic() < launch_deadline:
        launch = capture_json(
            [
                "xcrun",
                "devicectl",
                "device",
                "process",
                "launch",
                "--device",
                device["udid"],
                "--timeout",
                "20",
                "--terminate-existing",
                "--json-output",
                "-",
                "--omit-deprecated-fields-in-json",
                SYSTEM_SILEO_IDENTIFIER,
            ],
            timeout=25,
        )
        process = launch.get("result", {}).get("process", {})
        candidate_pid = process.get("processIdentifier")
        launched_url = process.get("executable")
        time.sleep(2.0)
        if (
            isinstance(candidate_pid, int)
            and candidate_pid > 1
            and launched_url == expected_executable_url
            and process_snapshot(device).get(candidate_pid) == "Sileo"
        ):
            launched_pid = candidate_pid
            break
        time.sleep(2.0)
    if launched_pid is None:
        raise DeployError(
            "system Sileo did not survive launch from its registered fixed path"
        )

    icon_payload = capture_json(
        [
            "xcrun",
            "devicectl",
            "device",
            "info",
            "appIcon",
            "--device",
            device["udid"],
            "--app-bundle-id",
            SYSTEM_SILEO_IDENTIFIER,
            "--allow-placeholder",
            "false",
            "--width",
            "60",
            "--height",
            "60",
            "--scale",
            "3",
            "--destination",
            str(icon_output),
            "--timeout",
            "20",
            "--json-output",
            "-",
            "--omit-deprecated-fields-in-json",
        ],
        timeout=25,
    )
    icon = icon_payload.get("result", {}).get("icon", {})
    pixel_size = icon.get("pixelSize", {})
    icon_sha256 = sha256_file(icon_output) if icon_output.is_file() else None
    if (
        icon.get("placeholder") is not False
        or pixel_size.get("width") != 180
        or pixel_size.get("height") != 180
        or not icon_output.is_file()
        or icon_output.stat().st_size < 512
        or icon_sha256 == GENERIC_IOS_APP_ICON_SHA256
    ):
        raise DeployError(
            "IconServices returned a placeholder or generic grid instead of "
            "Sileo's 60pt @3x icon"
        )

    removed_legacy: list[str] = []
    for identifier in LEGACY_SILEO_IDENTIFIERS:
        if application_record(device, identifier) is None:
            continue
        capture_json(
            [
                "xcrun",
                "devicectl",
                "device",
                "uninstall",
                "app",
                "--device",
                device["udid"],
                "--timeout",
                "30",
                "--json-output",
                "-",
                "--omit-deprecated-fields-in-json",
                identifier,
            ],
            timeout=35,
        )
        removed_legacy.append(identifier)

    return {
        "bundleIdentifier": SYSTEM_SILEO_IDENTIFIER,
        "url": record["url"],
        "builtByDeveloper": record["builtByDeveloper"],
        "removable": record["removable"],
        "launchedPid": launched_pid,
        "icon": {
            "path": str(icon_output.resolve()),
            "sha256": icon_sha256,
            "pixelWidth": pixel_size["width"],
            "pixelHeight": pixel_size["height"],
            "placeholder": icon["placeholder"],
        },
        "staleBootstrapPidsSignaled": signaled,
        "legacyAppsRemoved": removed_legacy,
    }


def require_layout() -> None:
    required = (
        BUILD_SCRIPT,
        CAPTURE_SCRIPT,
        INSTALL_SCRIPT,
        PERSONALIZE_SCRIPT,
        UPSTREAM_ROOT / "Application" / "Dopamine" / "Resources" / "sileo.deb",
    )
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        rendered = "\n  ".join(missing)
        raise DeployError(
            "the prepared opa334/Dopamine working tree is incomplete; run "
            "Dopamine-CryptexBootstrap/setup.sh first. Missing:\n  " + rendered
        )


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


def connected_devices() -> list[dict[str, str]]:
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
        stderr=subprocess.PIPE,
        timeout=12,
    )
    payload = json.loads(completed.stdout)
    raw_devices = payload.get("result", {}).get("devices", [])
    devices: dict[str, dict[str, str]] = {}
    for raw in raw_devices:
        properties = raw.get("properties", {})
        connection = properties.get("connection", {})
        hardware = properties.get("hardware", {})
        state = properties.get("state", {})
        udid = hardware.get("udid")
        if not (
            hardware.get("reality") == "physical"
            and connection.get("pairingState") == "paired"
            and connection.get("state") == "connected"
            and isinstance(udid, str)
            and udid
        ):
            continue
        devices[udid.casefold()] = {
            "udid": udid,
            "name": state.get("name") or hardware.get("productType") or "iPhone",
            "model": hardware.get("marketingName") or hardware.get("productType") or "unknown",
            "product": hardware.get("productType") or "unknown",
            "version": device_version(properties),
            "build": device_build(properties),
            "transport": {
                "localNetwork": "Wi-Fi",
                "wired": "USB",
            }.get(connection.get("transportType"), "connected"),
        }

    # CoreDevice and usbmux maintain separate pairing state. On SRD-style
    # configurations CoreDevice may report a USB-attached, lockdown-accessible
    # phone as disconnected/unpaired even while MobileDevice can use it. The
    # install path uses pymobiledevice3, so merge its authoritative USB view.
    usbmux_command = [
        sys.executable,
        "-m",
        "pymobiledevice3",
        "usbmux",
        "list",
    ]
    try:
        usbmux_completed = subprocess.run(
            usbmux_command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=12,
        )
        usbmux_payload = json.loads(usbmux_completed.stdout)
    except (
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
    ):
        usbmux_payload = []
    if isinstance(usbmux_payload, list):
        for raw in usbmux_payload:
            if not isinstance(raw, dict):
                continue
            udid = raw.get("UniqueDeviceID") or raw.get("Identifier")
            connection_type = raw.get("ConnectionType")
            product = raw.get("ProductType")
            if not (
                isinstance(udid, str)
                and udid
                and isinstance(product, str)
                and product
                and isinstance(connection_type, str)
                and connection_type.casefold() == "usb"
            ):
                continue
            devices.setdefault(
                udid.casefold(),
                {
                    "udid": udid,
                    "name": raw.get("DeviceName") or product,
                    "model": product,
                    "product": product,
                    "version": raw.get("ProductVersion") or "unknown",
                    "build": raw.get("BuildVersion") or "unknown",
                    "transport": "USB",
                },
            )
    return sorted(devices.values(), key=lambda item: (item["name"], item["udid"]))


def is_verified_device(device: dict[str, str]) -> bool:
    return any(
        device["udid"].casefold() == target["udid"].casefold()
        and device["product"] == target["product"]
        and device["version"] == target["version"]
        and device["build"] == target["build"]
        for target in SUPPORTED_TARGETS
    )


def configure_target_build_environment(device: dict[str, str]) -> None:
    os.environ.setdefault("CODEX_TARGET_UDID", device["udid"])


def supported_target_description() -> str:
    return ", ".join(
        f"{target['product']} / iOS {target['version']} "
        f"({target['build']}) / {target['udid']}"
        for target in SUPPORTED_TARGETS
    )


def render_device(device: dict[str, str]) -> str:
    return (
        f"{device['name']} · {device['model']} · {device['transport']} · "
        f"{device['product']} / iOS {device['version']} ({device['build']}) · "
        f"{device['udid']}"
    )


def choose_device(
    requested: str | None, allow_unverified: bool
) -> dict[str, str]:
    devices = connected_devices()
    if requested is not None:
        devices = [
            device
            for device in devices
            if device["udid"].casefold() == requested.casefold()
        ]
        if not devices:
            raise DeployError(
                f"{requested} is not a connected, paired physical Apple device"
            )
    if not allow_unverified:
        devices = [device for device in devices if is_verified_device(device)]
    if not devices:
        qualifier = (
            "connected, paired physical device"
            if allow_unverified
            else f"connected, paired supported device: {supported_target_description()}"
        )
        raise DeployError(f"no {qualifier} found")
    if len(devices) == 1:
        return devices[0]
    if not sys.stdin.isatty():
        raise DeployError("multiple eligible devices found; pass --device UDID")

    note("Eligible devices:")
    for index, device in enumerate(devices, 1):
        note(f"  [{index}] {render_device(device)}")
    while True:
        try:
            selection = int(input("Select device: ").strip())
        except (EOFError, KeyboardInterrupt) as error:
            raise DeployError("device selection cancelled") from error
        except ValueError:
            selection = 0
        if 1 <= selection <= len(devices):
            return devices[selection - 1]
        note(f"Enter a number from 1 to {len(devices)}.")


def new_version() -> str:
    # Numeric dot components remain compatible with CryptexInfo parsing while
    # microseconds make accidental same-version replacement vanishingly rare.
    # Keep seconds and microseconds separate so every component fits in uint64.
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M%S.%f")
    return f"1.0.{stamp}"


def build_pair(version: str | None) -> dict[str, Any]:
    require_layout()
    version = version or os.environ.get("CODEX_CRYPTEX_VERSION") or new_version()
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", version):
        raise DeployError(
            "Cryptex version must contain only numeric dot-separated components"
        )
    env = os.environ.copy()
    env["CODEX_CRYPTEX_VERSION"] = version

    note(f"Building fixed-trust Cryptex system Sileo version {version}")
    run([str(BUILD_SCRIPT)], env=env)

    build_summary = read_json(BUILD_SUMMARY)
    if build_summary.get("version") != version:
        raise DeployError("Cryptex build summary version does not match this run")
    system_app = SCRIPT_DIR / "work" / "image-root" / "Applications" / "Sileo.app"
    info_path = system_app / "Info.plist"
    if not info_path.is_file():
        raise DeployError("Cryptex system Sileo Info.plist is missing")
    info = plistlib.loads(info_path.read_bytes())
    if info.get("CFBundleIdentifier") != "org.coolstar.SileoStore":
        raise DeployError("Cryptex system Sileo does not use its original bundle ID")
    if info.get("CFBundleVersion") != version:
        raise DeployError("Cryptex system Sileo bundle version is not build-unique")
    primary_icon_files = (
        info.get("CFBundleIcons", {})
        .get("CFBundlePrimaryIcon", {})
        .get("CFBundleIconFiles")
    )
    if (
        primary_icon_files != ["AppIcon60x60"]
        or info.get("CFBundleIconFiles") != ["AppIcon60x60"]
        or not (system_app / "Assets.car").is_file()
        or not (system_app / "AppIcon60x60@2x.png").is_file()
        or not (system_app / "AppIcon60x60@3x.png").is_file()
        or not (system_app / "CodexSystemEntitlements.plist").is_file()
    ):
        raise DeployError("Cryptex system Sileo icon metadata is incomplete")
    if (system_app / "embedded.mobileprovision").exists():
        raise DeployError("Cryptex system Sileo unexpectedly has a provisioning profile")

    fixed_trust = build_summary.get("inputs", {}).get("sileoFixedTrust", {})
    if (
        fixed_trust.get("installMode") != "cryptex-system-app"
        or fixed_trust.get("bundleIdentifier") != "org.coolstar.SileoStore"
        or fixed_trust.get("provisioningProfile") is not False
    ):
        raise DeployError("build summary does not describe fixed-trust system Sileo")
    executable_hashes: dict[str, str] = {}
    for relative_path in SILEO_TRUSTED_EXECUTABLES:
        path = system_app / relative_path
        if not path.is_file():
            raise DeployError(f"missing Cryptex Sileo executable {relative_path}")
        executable_hashes[relative_path] = sha256_file(path)
    summarized = {
        Path(item["path"]).relative_to(system_app).as_posix(): item["sha256"]
        for item in fixed_trust.get("machOs", [])
        if isinstance(item, dict)
        and isinstance(item.get("path"), str)
        and isinstance(item.get("sha256"), str)
        and Path(item["path"]).is_relative_to(system_app)
    }
    if summarized != executable_hashes:
        raise DeployError("Cryptex Sileo executable hashes do not match the summary")

    result = {
        "identifier": build_summary["identifier"],
        "version": version,
        "unsignedBundle": build_summary["bundle"],
        "buildSummary": str(BUILD_SUMMARY.resolve()),
        "sileoSystemApp": str(system_app.resolve()),
        "sileoBundleIdentifier": "org.coolstar.SileoStore",
        "sileoProvisioningProfile": False,
        "sileoFixedTrustExecutables": executable_hashes,
    }
    note("Fixed-trust system Sileo build verification passed")
    print(json.dumps(result, indent=2, sort_keys=True))
    return result


def install_pair(args: argparse.Namespace, device: dict[str, str]) -> dict[str, Any]:
    # [REDACTED] Related request, payload, or installation helper omitted.
    raise RuntimeError('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "install"))
    parser.add_argument("--device", help="target UDID; auto-selects when exactly one matches")
    parser.add_argument(
        "--allow-unverified-device",
        action="store_true",
        help=(
            "allow a connected paired physical device other than the validated "
            f"targets: {supported_target_description()}"
        ),
    )
    parser.add_argument(
        "--no-replace",
        action="store_true",
        help="refuse rather than replace one older build of this non-Apple Cryptex",
    )
    parser.add_argument(
        "--cryptex-version",
        help="fresh numeric dot-separated version (generated automatically by default)",
    )
    args = parser.parse_args()

    if args.action == "build":
        build_pair(args.cryptex_version)
        return 0

    device = choose_device(args.device, args.allow_unverified_device)
    configure_target_build_environment(device)
    if not is_verified_device(device):
        note("WARNING: continuing on a device outside the validated target matrix")
    install_pair(args, device)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        DeployError,
        KeyError,
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        ValueError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
