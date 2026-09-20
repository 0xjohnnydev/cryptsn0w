#!/usr/bin/env python3
"""Build or install the matched Sileo and generic-Cryptex bootstrap pair."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import selectors
import shlex
import shutil
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
UPSTREAM_ROOT = SCRIPT_DIR.parent

BUILD_SCRIPT = SCRIPT_DIR / "build_cryptex.sh"
CAPTURE_SCRIPT = SCRIPT_DIR / "capture_device_context.py"
INSTALL_SCRIPT = SCRIPT_DIR / "install_cryptex_bootstrap.py"
PERSONALIZE_SCRIPT = SCRIPT_DIR / "personalize_generic_cryptex1.py"
BUILD_SUMMARY = SCRIPT_DIR / "out" / "build-summary.json"
TARGET_BUNDLE_ROOT = SCRIPT_DIR.parents[1] / "build" / "target"
SYSTEM_SILEO_IDENTIFIER = "org.coolstar.SileoStore"
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
        and url.endswith("/Sileo.app/")
    )


def verify_and_launch_system_sileo(
    device: dict[str, str],
    expected_version: str,
    icon_output: Path,
) -> dict[str, Any]:
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


def transport_priority(transport: str) -> int:
    return 0 if transport.casefold() == "usb" else 1


def connected_devices() -> list[dict[str, str]]:
    completed = subprocess.run(
        [sys.executable, "-m", "pymobiledevice3", "usbmux", "list"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=12,
    )
    payload = json.loads(completed.stdout)
    if not isinstance(payload, list):
        raise DeployError("usbmux returned an invalid device list")
    devices: dict[str, dict[str, str]] = {}
    for raw in payload:
        if not isinstance(raw, dict):
            continue
        udid = raw.get("UniqueDeviceID") or raw.get("Identifier")
        product = raw.get("ProductType")
        if not isinstance(udid, str) or not isinstance(product, str):
            continue
        record = {
            "udid": udid,
            "name": str(raw.get("DeviceName") or product),
            "model": product,
            "product": product,
            "version": str(raw.get("ProductVersion") or "unknown"),
            "build": str(raw.get("BuildVersion") or "unknown"),
            "transport": str(raw.get("ConnectionType") or "usbmux"),
        }
        existing = devices.get(udid)
        if existing is not None and (
            transport_priority(existing["transport"])
            <= transport_priority(record["transport"])
        ):
            continue
        devices[udid] = record
    return list(devices.values())


def configure_target_build_environment(device: dict[str, str]) -> None:
    os.environ.setdefault("CODEX_TARGET_UDID", device["udid"])
    os.environ["CODEX_TARGET_BUNDLE_ROOT"] = str(TARGET_BUNDLE_ROOT)


def choose_device(requested: str | None) -> dict[str, str]:
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
    if not devices:
        raise DeployError("no connected, paired physical Apple device found")
    if len(devices) != 1:
        connected = "\n  ".join(f'{d["udid"]}  {d["name"]}' for d in devices)
        raise DeployError(
            "multiple eligible devices found; pass --device UDID:\n  " + connected
        )
    return devices[0]


def free_local_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def pull_target_bundles(device: dict[str, str], private_key: Path) -> None:
    local_port = free_local_port()
    staging = TARGET_BUNDLE_ROOT.with_name(f".target-{uuid.uuid4().hex}")
    staging.mkdir(parents=True)
    forward = subprocess.Popen(
        [
            sys.executable, "-m", "pymobiledevice3", "usbmux", "forward",
            str(local_port), "22222", "--serial", device["udid"],
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    options = [
        "-i", str(private_key), "-p", str(local_port),
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=2",
        "-o", "ConnectionAttempts=1",
    ]
    try:
        deadline = time.monotonic() + 45.0
        while True:
            ready = subprocess.run(
                ["ssh", *options, "root@127.0.0.1", "true"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode == 0
            if ready or time.monotonic() >= deadline:
                break
            time.sleep(1)
        if not ready:
            raise DeployError("temporary Cryptex SSH service did not start")
        scp_options = [
            "-i", str(private_key), "-P", str(local_port), "-p", "-r",
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
        ]
        for remote in (
            "/System/Library/CoreServices/SpringBoard.app",
            "/Applications/Preferences.app",
        ):
            run(["scp", *scp_options, f"root@127.0.0.1:{remote}", str(staging)])
        if not (staging / "SpringBoard.app" / "SpringBoard").is_file() or not (
            staging / "Preferences.app" / "Preferences"
        ).is_file():
            raise DeployError("device app transfer is incomplete")
        if TARGET_BUNDLE_ROOT.exists():
            shutil.rmtree(TARGET_BUNDLE_ROOT)
        os.replace(staging, TARGET_BUNDLE_ROOT)
    finally:
        forward.terminate()
        try:
            forward.wait(timeout=5)
        except subprocess.TimeoutExpired:
            forward.kill()
        if staging.exists():
            shutil.rmtree(staging)


def start_stage_handoff(
    device: dict[str, str], private_key: Path
) -> tuple[subprocess.Popen[bytes], subprocess.Popen[bytes]]:
    local_port = free_local_port()
    forward = subprocess.Popen(
        [
            sys.executable, "-m", "pymobiledevice3", "usbmux", "forward",
            str(local_port), "22222", "--serial", device["udid"],
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    options = [
        "-i", str(private_key), "-p", str(local_port),
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5",
    ]
    time.sleep(1)
    handoff = subprocess.Popen(
        [
            "ssh", *options, "root@127.0.0.1",
            "/private/var/tmp/codex-stage-ssh/cleanup --cleanup",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert handoff.stdout is not None
    selector = selectors.DefaultSelector()
    try:
        selector.register(handoff.stdout, selectors.EVENT_READ)
        events = selector.select(timeout=10)
        ready = handoff.stdout.readline() if events else b""
    finally:
        selector.close()
    if ready != b"handoff-ready\n" or handoff.poll() is not None:
        handoff.terminate()
        forward.terminate()
        try:
            _, error = handoff.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            handoff.kill()
            _, error = handoff.communicate()
        detail = error.decode("utf-8", "replace").strip()
        raise DeployError(f"could not arm SSH-stage handoff: {detail}")
    return forward, handoff


def finish_stage_handoff(
    forward: subprocess.Popen[bytes], handoff: subprocess.Popen[bytes]
) -> None:
    try:
        output, error = handoff.communicate(b"\n", timeout=30)
        acknowledged = b"handoff-armed\n" in output.splitlines(keepends=True)
        expected_close = (
            handoff.returncode == 255
            and b"closed by remote host" in error
        )
        # cryptexd normally tears down the replaced stage as soon as the final
        # mount becomes active, closing this already-authenticated connection
        # before the delayed helper needs to fire.  Either an explicit helper
        # acknowledgement or that exact post-install SSH close is a valid
        # handoff; all other exits remain failures.
        if not expected_close and (
            not acknowledged or handoff.returncode != 0
        ):
            raise DeployError(
                "SSH-stage handoff failed: "
                + error.decode("utf-8", "replace").strip()
            )
    finally:
        forward.terminate()
        try:
            forward.wait(timeout=5)
        except subprocess.TimeoutExpired:
            forward.kill()


def cancel_stage_handoff(
    forward: subprocess.Popen[bytes], handoff: subprocess.Popen[bytes]
) -> None:
    handoff.terminate()
    forward.terminate()
    for process in (handoff, forward):
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


def new_version() -> str:
    # Numeric dot components remain compatible with CryptexInfo parsing while
    # microseconds make accidental same-version replacement vanishingly rare.
    # Keep seconds and microseconds separate so every component fits in uint64.
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M%S.%f")
    return f"1.0.{stamp}"


def build_pair(
    version: str | None,
    host_ssh_public_key: Path | None = None,
) -> dict[str, Any]:
    require_layout()
    version = version or os.environ.get("CODEX_CRYPTEX_VERSION") or new_version()
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", version):
        raise DeployError(
            "Cryptex version must contain only numeric dot-separated components"
        )
    env = os.environ.copy()
    env["CODEX_CRYPTEX_VERSION"] = version
    if host_ssh_public_key is not None:
        if not host_ssh_public_key.is_file():
            raise DeployError("host SSH public key is missing")
        env["CODEX_HOST_SSH_AUTHORIZED_KEY"] = str(
            host_ssh_public_key.resolve()
        )

    note(f"Building fixed-trust Cryptex system Sileo version {version}")
    run([str(BUILD_SCRIPT)], env=env)

    build_summary = read_json(BUILD_SUMMARY)
    if build_summary.get("version") != version:
        raise DeployError("Cryptex build summary version does not match this run")
    result = {
        "identifier": build_summary["identifier"],
        "version": version,
        "unsignedBundle": build_summary["bundle"],
        "buildSummary": str(BUILD_SUMMARY.resolve()),
    }
    note("Final Cryptex build completed")
    print(json.dumps(result, indent=2, sort_keys=True))
    return result


def capture_context(device: dict[str, str], output: Path) -> None:
    # [REDACTED] Related request, payload, or installation helper omitted.
    raise RuntimeError('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


def personalize(build: dict[str, Any], context: Path, output: Path) -> Path:
    # [REDACTED] Related request, payload, or installation helper omitted.
    raise RuntimeError('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


def install_cryptex(
    build: dict[str, Any], bundle: Path, device: dict[str, str], result: Path
) -> dict[str, Any]:
    # [REDACTED] Related request, payload, or installation helper omitted.
    raise RuntimeError('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


def build_ssh_stage(version: str, public_key: Path) -> dict[str, Any]:
    summary_path = SCRIPT_DIR / "out" / "ssh-stage" / "build-summary.json"
    env = os.environ.copy()
    env.update({
        "CODEX_CRYPTEX_STAGE": "ssh",
        "CODEX_CRYPTEX_VERSION": version,
        "CODEX_STAGE_AUTHORIZED_KEY": str(public_key),
    })
    run([str(BUILD_SCRIPT)], env=env)
    summary = read_json(summary_path)
    return {
        "identifier": summary["identifier"],
        "version": version,
        "unsignedBundle": summary["bundle"],
        "buildSummary": str(summary_path.resolve()),
    }




def finish_install(
    run_dir: Path,
    device: dict[str, str],
    private_key: Path,
    base_version: str,
    stage_install: Path,
    enable_host_ssh: bool,
) -> dict[str, Any]:
    # Resume is intentionally idempotent: a prior final build/install failure
    # may leave generated context and personalization outputs in this run.
    # Device-pulled target bundles and the installed stage/key remain valid.
    # [REDACTED] Related request, payload, or installation helper omitted.
    raise RuntimeError('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


def install_pair(args: argparse.Namespace, device: dict[str, str]) -> dict[str, Any]:
    # [REDACTED] Related request, payload, or installation helper omitted.
    raise RuntimeError('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


def resume_pair(run_dir: Path, device: dict[str, str]) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    runs_root = (SCRIPT_DIR / "out" / "runs").resolve()
    if run_dir.parent != runs_root:
        raise DeployError("resume run must be a direct child of out/runs")
    private_key = run_dir / "stage-key"
    host_ssh_marker = run_dir / "host-ssh-enabled"
    enable_host_ssh = (
        host_ssh_marker.is_file()
        and host_ssh_marker.read_text().strip() == "yes"
    )
    stage_install = run_dir / "stage-install.json"
    stage_version = read_json(stage_install).get("installed", {}).get("version")
    if not private_key.is_file() or not isinstance(stage_version, str) or not (
        stage_version.endswith(".1")
    ):
        raise DeployError("resume run has no installed SSH stage or private key")
    return finish_install(
        run_dir, device, private_key, stage_version.removesuffix(".1"),
        stage_install, enable_host_ssh,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "install", "resume"))
    parser.add_argument("--device", help="target UDID; optional with one device")
    parser.add_argument(
        "--cryptex-version",
        help="fresh numeric dot-separated version (generated automatically by default)",
    )
    parser.add_argument("--run", type=Path, help="interrupted out/runs directory")
    parser.add_argument(
        "--enable-host-ssh", action="store_true",
        help="retain the run key and authorize it for root SSH on the device",
    )
    args = parser.parse_args()
    if getattr(args, "action", None) in ("install", "resume"):
        raise DeployError('TSS/Cryptex personalization and installation details are redacted from this educational source release.')

    if args.action == "build":
        build_pair(args.cryptex_version)
        return 0

    device = choose_device(args.device)
    configure_target_build_environment(device)
    if args.action == "resume":
        if args.run is None:
            parser.error("resume requires --run")
        resume_pair(args.run, device)
    else:
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
