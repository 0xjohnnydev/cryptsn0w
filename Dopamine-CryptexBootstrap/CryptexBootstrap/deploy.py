#!/usr/bin/env python3
"""Build or install the matched Sileo and generic-Cryptex bootstrap pair."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import uuid
import zipfile
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
UPSTREAM_ROOT = SCRIPT_DIR.parent
WORKSPACE = UPSTREAM_ROOT.parent
HELPER_DIR = WORKSPACE / "tools" / "cryptexd-static"

BUILD_SCRIPT = SCRIPT_DIR / "build_cryptex.sh"
APP_SCRIPT = SCRIPT_DIR / "build_sileo_launcher.sh"
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
        "sileoBundleIdentifier": "com.lilycohl.sileo27b8",
    },
    {
        "udid": "00008150-0018252C1130C01C",
        "product": "iPhone18,2",
        "version": "27.0",
        "build": "24A435",
        "sileoBundleIdentifier": "org.coolstar.SileoStore",
    },
    {
        "udid": "00008101-001C39641A9B001E",
        "product": "iPhone13,1",
        "version": "27.0",
        "build": "24A437",
        "sileoBundleIdentifier": "com.johnnyfranks.codex.profilebootstrap12mini",
    },
)
SILEO_TRUSTED_EXECUTABLES = (
    "Sileo",
    "giveMeRoot",
    "F/libiosexec.1.dylib",
    "F/liblzma.5.dylib",
    "F/libzstd.1.dylib",
    "F/libzstd.real.dylib",
)


class DeployError(RuntimeError):
    pass


def note(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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


def require_layout() -> None:
    required = (
        BUILD_SCRIPT,
        APP_SCRIPT,
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
    for target in SUPPORTED_TARGETS:
        if device["udid"].casefold() == target["udid"].casefold():
            os.environ.setdefault(
                "CODEX_SILEO_BUNDLE_IDENTIFIER",
                target["sileoBundleIdentifier"],
            )
            return


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


def app_member_from_ipa(ipa: Path, relative_path: str) -> bytes:
    member = f"Payload/Sileo.app/{relative_path}"
    with zipfile.ZipFile(ipa) as archive:
        matches = [info for info in archive.infolist() if info.filename == member]
        if len(matches) != 1:
            raise DeployError(
                f"expected one {member} in {ipa}, found {len(matches)}"
            )
        return archive.read(matches[0])


def build_pair(version: str | None) -> dict[str, Any]:
    require_layout()
    version = version or os.environ.get("CODEX_CRYPTEX_VERSION") or new_version()
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", version):
        raise DeployError(
            "Cryptex version must contain only numeric dot-separated components"
        )
    safe_version = re.sub(r"[^A-Za-z0-9._-]", "_", version)
    ipa = SCRIPT_DIR / "out" / f"Sileo.brokered-{safe_version}.ipa"
    app_summary_path = SCRIPT_DIR / "out" / f"sileo-brokered-{safe_version}.json"

    env = os.environ.copy()
    env["CODEX_CRYPTEX_VERSION"] = version
    env["CODEX_SILEO_LAUNCHER_IPA"] = str(ipa)
    env["CODEX_SILEO_LAUNCHER_SUMMARY"] = str(app_summary_path)

    note(f"Building matched Cryptex/Sileo pair version {version}")
    run([str(BUILD_SCRIPT)], env=env)
    run([str(APP_SCRIPT)], env=env)

    build_summary = read_json(BUILD_SUMMARY)
    app_summary = read_json(app_summary_path)
    if build_summary.get("version") != version:
        raise DeployError("Cryptex build summary version does not match this run")
    if Path(str(app_summary.get("ipa", ""))).resolve() != ipa.resolve():
        raise DeployError("Sileo build summary points at an unexpected IPA")
    if app_summary.get("cryptexVersion") != version:
        raise DeployError("Sileo build summary is not paired to this Cryptex version")
    if app_summary.get("cryptexBuildSummarySha256") != sha256_file(BUILD_SUMMARY):
        raise DeployError("Sileo build summary is not paired to this build summary")

    source_app = (
        SCRIPT_DIR
        / "work"
        / "sileo-package"
        / "var"
        / "jb"
        / "Applications"
        / "Sileo.app"
    )
    trusted_app = (
        SCRIPT_DIR
        / "work"
        / "image-root"
        / "usr"
        / "local"
        / "share"
        / "codex-bootstrap"
        / "trusted"
        / "Sileo.app"
    )
    executable_copies: dict[str, dict[str, str]] = {}
    for relative_path in SILEO_TRUSTED_EXECUTABLES:
        hashes = {
            "workingCopy": sha256_file(source_app / relative_path),
            "cryptexCopy": sha256_file(trusted_app / relative_path),
            "ipaCopy": sha256_bytes(app_member_from_ipa(ipa, relative_path)),
        }
        if len(set(hashes.values())) != 1:
            raise DeployError(
                "the Cryptex and provisioned app differ for Sileo executable "
                + relative_path
            )
        executable_copies[relative_path] = hashes

    expected = app_summary.get("rootHelperSha256")
    helper_hashes = executable_copies["giveMeRoot"]
    if not isinstance(expected, str) or set(helper_hashes.values()) != {expected}:
        raise DeployError("Sileo's root helper does not match its build summary")

    result = {
        "identifier": build_summary["identifier"],
        "version": version,
        "unsignedBundle": build_summary["bundle"],
        "buildSummary": str(BUILD_SUMMARY.resolve()),
        "ipa": str(ipa.resolve()),
        "ipaSha256": sha256_file(ipa),
        "appSummary": str(app_summary_path.resolve()),
        "rootHelperSha256": expected,
        "rootHelperCopies": helper_hashes,
        "sileoFixedTrustCopies": executable_copies,
    }
    note("Matched build verification passed")
    print(json.dumps(result, indent=2, sort_keys=True))
    return result


def install_pair(args: argparse.Namespace, device: dict[str, str]) -> dict[str, Any]:
    build = build_pair(args.cryptex_version)
    run_id = (
        dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid.uuid4().hex[:8]
    )
    run_dir = SCRIPT_DIR / "out" / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=False)

    ipa = Path(build["ipa"])
    note(f"Installing provisioned Sileo on {render_device(device)}")
    run(
        [
            sys.executable,
            "-m",
            "pymobiledevice3",
            "apps",
            "install",
            "--developer",
            "--userspace",
            "--udid",
            device["udid"],
            str(ipa),
        ]
    )

    context_dir = run_dir / "device-context"
    run(
        [
            sys.executable,
            str(CAPTURE_SCRIPT),
            "--udid",
            device["udid"],
            "--nonce-domain",
            "3",
            "--out-dir",
            str(context_dir),
        ]
    )
    chip = json.dumps(
        json.loads((context_dir / "chip.json").read_text()),
        separators=(",", ":"),
        sort_keys=True,
    )
    nonce = (context_dir / "nonce.hex").read_text().strip()

    personalized_dir = run_dir / "personalized"
    run(
        [
            sys.executable,
            str(PERSONALIZE_SCRIPT),
            "--bundle",
            build["unsignedBundle"],
            "--chip-json",
            chip,
            "--nonce-hex",
            nonce,
            "--out-dir",
            str(personalized_dir),
        ]
    )
    signed = [
        path
        for path in personalized_dir.glob("*.signed.cxbd")
        if path.is_dir()
    ]
    if len(signed) != 1:
        raise DeployError(
            f"expected one personalized Cryptex bundle, found {len(signed)}"
        )

    common = [
        sys.executable,
        str(INSTALL_SCRIPT),
        "--bundle",
        str(signed[0]),
        "--build-summary",
        str(BUILD_SUMMARY),
        "--udid",
        device["udid"],
    ]
    if not args.no_replace:
        common.append("--replace-installed")

    validate_json = run_dir / "validate.json"
    run(common + ["--validate-only", "--result-json", str(validate_json)])
    validation = read_json(validate_json)
    if validation.get("validated") is not True or validation.get("installed") is not False:
        raise DeployError("Cryptex validation did not return the expected acceptance result")

    install_json = run_dir / "install.json"
    run(common + ["--result-json", str(install_json)])
    installation = read_json(install_json)
    expected_installed = {
        "identifier": build["identifier"],
        "version": build["version"],
    }
    if installation.get("installed") != expected_installed:
        raise DeployError("cryptexd did not report the exact new Cryptex as installed")

    result = {
        "result": "success",
        "device": device,
        "build": build,
        "context": str((context_dir / "context.json").resolve()),
        "personalization": str((personalized_dir / "summary.json").resolve()),
        "validation": str(validate_json.resolve()),
        "installation": str(install_json.resolve()),
    }
    summary_path = run_dir / "flow-summary.json"
    summary_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    note(f"Install flow succeeded; summary: {summary_path}")
    print(json.dumps(result, indent=2, sort_keys=True))
    return result


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
        zipfile.BadZipFile,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
