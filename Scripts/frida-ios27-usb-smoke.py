#!/usr/bin/env python3
"""Prove Frida 17.17 Interceptor over the native iOS USB/RSD path.

The test is intentionally narrow.  It launches one project-owned disposable
get-task-allow target, resolves that exact PID and process name through Frida,
hooks getpid(), and cleans up only after revalidating the target path.  It does
not start a device-side frida-server, restart policyd, or touch PID 1.

Run this through run-frida-ios27-usb-smoke.zsh.  macOS 27 currently exposes the
RSD TCP table to Apple's /usr/bin/python3 but not to the Homebrew interpreter.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time
import typing
from typing import Any

import typing_extensions


# Frida's Python 3.9 annotations import these names from typing.  The abi3
# extension itself is compatible with Apple's interpreter.
if not hasattr(typing, "NotRequired"):
    typing.NotRequired = typing_extensions.NotRequired  # type: ignore[attr-defined]
if not hasattr(typing, "ParamSpec"):
    typing.ParamSpec = typing_extensions.ParamSpec  # type: ignore[attr-defined]

import frida  # noqa: E402  (typing compatibility must be installed first)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_KEY = ROOT / "build" / "ssh" / "id_ed25519"
STAGED_GADGET = (
    ROOT
    / "build"
    / "frida-ios27-host"
    / "gadget-ios.17.17.0.code-page-plan.dylib"
)
CACHED_GADGET = Path.home() / ".cache" / "frida" / "gadget-ios.dylib"
EXPECTED_GADGET_SHA256 = (
    "10a34a745f3e2342004847ee921119ff50fc41ea6ffc949b0c6a4ccd37182c71"
)
EXPECTED_FRIDA_VERSION = "17.17.0"
IDENTIFIER = "com.0xjohnnydev.untitled"
MOUNT_PREFIX = "/private/var/run/com.apple.security.cryptexd/mnt"
BUILD_VERSION_RELATIVE = "usr/local/share/untitled/build-version"
TARGET_NAME = "untitled-frida-debug-target"
TARGET_RELATIVE = f"usr/local/bin/{TARGET_NAME}"
DEVICE_SSH_PORT = 2222
DEVICE_FRIDA_PORT = 27042
CS_GET_TASK_ALLOW = 0x4


class SmokeError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def available_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def ssh_command(port: int, key: Path, remote: str) -> list[str]:
    return [
        shutil.which("ssh") or "/usr/bin/ssh",
        "-i",
        str(key),
        "-p",
        str(port),
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
        "ConnectTimeout=3",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "LogLevel=ERROR",
        "root@127.0.0.1",
        remote,
    ]


def ssh(port: int, key: Path, remote: str, *, check: bool = True) -> str:
    completed = subprocess.run(
        ssh_command(port, key, remote),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=15,
    )
    if check and completed.returncode != 0:
        raise SmokeError(
            f"remote command failed ({completed.returncode}): "
            f"{completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def wait_for_ssh(
    proxy: subprocess.Popen[bytes] | None, port: int, key: Path
) -> None:
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        if proxy is not None and proxy.poll() is not None:
            raise SmokeError(f"SSH iproxy exited with {proxy.returncode}")
        try:
            if ssh(port, key, "printf '%s' \"$EUID\"") == "0":
                return
        except (SmokeError, subprocess.TimeoutExpired):
            pass
        time.sleep(0.25)
    raise SmokeError("root SSH did not become ready")


def expected_bundle_version() -> str:
    summary_path = ROOT / "build" / "build-summary.json"
    try:
        summary = json.loads(summary_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise SmokeError(f"cannot read the local build summary: {error}") from error
    if summary.get("identifier") != IDENTIFIER:
        raise SmokeError("local build summary has the wrong Cryptex identifier")
    version = summary.get("version")
    if not isinstance(version, str) or re.fullmatch(r"[0-9.]+", version) is None:
        raise SmokeError(f"invalid local Cryptex version: {version!r}")
    return version


def resolve_cryptex_root(port: int, key: Path, version: str) -> str:
    marker_suffix = f"/{BUILD_VERSION_RELATIVE}"
    marker_glob = f"{MOUNT_PREFIX}/{IDENTIFIER}.*{marker_suffix}"
    output = ssh(
        port,
        key,
        "emulate -L zsh; setopt null_glob; selected=''; count=0; "
        f"for marker in {marker_glob}; do "
        "IFS= read -r found_version < \"$marker\" || continue; "
        f"[[ \"$found_version\" == {shlex.quote(version)} ]] || continue; "
        f"root=\"${{marker%{marker_suffix}}}\"; "
        f"test -x \"$root/{TARGET_RELATIVE}\" || continue; "
        "(( count += 1 )); selected=\"$root\"; done; "
        "(( count == 1 )) || { printf 'count=%d\\n' \"$count\" >&2; exit 72; }; "
        "printf '%s' \"$selected\"",
    )
    expected = re.compile(re.escape(f"{MOUNT_PREFIX}/{IDENTIFIER}.") + r"[^/]+")
    if expected.fullmatch(output) is None:
        raise SmokeError(f"unsafe Cryptex mount selection: {output!r}")
    return output


def process_path(port: int, key: Path, pid: int) -> str:
    if pid <= 1:
        raise SmokeError(f"refusing unsafe process-path query for pid {pid}")
    return ssh(
        port,
        key,
        f"ps -ww -p {pid} -o comm= 2>/dev/null | "
        "while IFS= read -r line; do printf '%s' \"$line\"; done",
        check=False,
    )


def assert_pid1_healthy(port: int, key: Path) -> str:
    output = ssh(
        port,
        key,
        "ps -ww -p 1 -o pid=,comm= 2>/dev/null | "
        "while IFS= read -r line; do printf '%s' \"$line\"; done",
    )
    normalized = " ".join(output.split())
    if normalized != "1 /sbin/launchd":
        raise SmokeError(f"PID 1 health check failed: {output!r}")
    return normalized


def assert_no_frida_server_listener(port: int, key: Path) -> None:
    output = ssh(
        port,
        key,
        f"/usr/sbin/netstat -an -p tcp 2>/dev/null | "
        "while IFS= read -r line; do case \"$line\" in "
        f"*'.{DEVICE_FRIDA_PORT} '*) printf '%s\\n' \"$line\";; esac; done",
        check=False,
    )
    if output:
        raise SmokeError(
            "a device-side listener is using TCP 27042; stop the legacy "
            f"frida-server before native USB/RSD testing: {output!r}"
        )


def assert_no_stale_target(port: int, key: Path, target_path: str) -> None:
    output = ssh(
        port,
        key,
        "ps -axo pid=,comm= 2>/dev/null | while read -r pid command; do "
        f"if [[ \"$command\" == {shlex.quote(target_path)} ]]; then "
        "printf '%s %s\\n' \"$pid\" \"$command\"; fi; done",
        check=False,
    )
    if output:
        raise SmokeError(f"a stale disposable target is already running: {output!r}")


def start_target(
    port: int,
    key: Path,
    target_path: str,
    token: str,
    started_pids: list[int],
) -> tuple[int, int, str]:
    log_path = f"/var/tmp/{TARGET_NAME}-{token}.log"
    output = ssh(
        port,
        key,
        f"test -x {shlex.quote(target_path)} || exit 72; "
        f": > {shlex.quote(log_path)}; "
        f"{shlex.quote(target_path)} </dev/null >{shlex.quote(log_path)} 2>&1 & "
        "printf '%s' $!",
    )
    try:
        pid = int(output)
    except ValueError as error:
        raise SmokeError(f"target returned an invalid pid: {output!r}") from error
    if pid <= 1:
        raise SmokeError(f"refusing unsafe target pid {pid}")
    started_pids.append(pid)

    deadline = time.monotonic() + 8
    startup = ""
    while time.monotonic() < deadline:
        if process_path(port, key, pid) != target_path:
            time.sleep(0.1)
            continue
        startup = ssh(
            port,
            key,
            f"if IFS= read -r line < {shlex.quote(log_path)}; then "
            "printf '%s' \"$line\"; fi",
            check=False,
        )
        if f"pid={pid}" in startup:
            break
        time.sleep(0.1)
    else:
        raise SmokeError(f"target did not become ready (pid {pid})")

    if "expectedGetTaskAllow=1" not in startup or "csopsStatus=0" not in startup:
        raise SmokeError(f"unexpected target startup record: {startup!r}")
    match = re.search(r"(?:^| )csflags=0x([0-9a-fA-F]{8})(?: |$)", startup)
    if match is None:
        raise SmokeError(f"target emitted no parseable csflags: {startup!r}")
    flags = int(match.group(1), 16)
    if (flags & CS_GET_TASK_ALLOW) == 0:
        raise SmokeError(
            f"target lacks kernel-accepted CS_GET_TASK_ALLOW: 0x{flags:08x}"
        )
    return pid, flags, startup


def cleanup_target(port: int, key: Path, pid: int, target_path: str) -> str:
    if pid <= 1:
        raise SmokeError(f"refusing unsafe cleanup pid {pid}")
    actual = process_path(port, key, pid)
    if not actual:
        return "already-exited"
    if actual != target_path:
        raise SmokeError(
            f"refusing cleanup after target identity changed: pid={pid} "
            f"expected={target_path!r} actual={actual!r}"
        )

    output = ssh(
        port,
        key,
        "emulate -L zsh; "
        f"pid={pid}; expected={shlex.quote(target_path)}; "
        "(( pid > 1 )) || exit 70; kill -TERM $pid; i=0; "
        "while kill -0 $pid 2>/dev/null && (( i < 50 )); do "
        "sleep 0.1; (( i += 1 )); done; "
        "if kill -0 $pid 2>/dev/null; then "
        "actual=$(ps -ww -p $pid -o comm= 2>/dev/null | "
        "while IFS= read -r line; do printf '%s' \"$line\"; done); "
        "[[ \"$actual\" == \"$expected\" ]] || exit 73; kill -KILL $pid; fi; "
        "kill -0 $pid 2>/dev/null && exit 74; printf 'terminated'",
    )
    return output


def run_interceptor_probe(device: Any, pid: int) -> dict[str, Any]:
    if pid <= 1:
        raise SmokeError(f"refusing unsafe Frida attach pid {pid}")
    matches = [
        process for process in device.enumerate_processes() if process.pid == pid
    ]
    if len(matches) != 1 or matches[0].name != TARGET_NAME:
        identity = [(process.pid, process.name) for process in matches]
        raise SmokeError(f"exact Frida target mismatch for pid {pid}: {identity!r}")

    session = device.attach(pid)
    script = None
    messages: list[dict[str, Any]] = []
    completed = threading.Event()
    try:
        source = r"""
const getpid = Module.getGlobalExportByName('getpid');
const range = Process.findRangeByAddress(getpid);
send({
  kind: 'resolved',
  address: getpid.toString(),
  rangeBase: range === null ? null : range.base.toString(),
  protection: range === null ? null : range.protection
});
Interceptor.attach(getpid, {
  onEnter(args) {
    send({ kind: 'hook-enter', threadId: this.threadId });
  }
});
const result = new NativeFunction(getpid, 'int', [])();
send({ kind: 'result', value: result });
"""
        script = session.create_script(source, runtime="qjs")

        def on_message(message: dict[str, Any], data: bytes | None) -> None:
            del data
            messages.append(message)
            payloads = [
                item.get("payload", {})
                for item in messages
                if item.get("type") == "send"
            ]
            kinds = {payload.get("kind") for payload in payloads}
            if message.get("type") == "error" or {
                "resolved",
                "hook-enter",
                "result",
            }.issubset(kinds):
                completed.set()

        script.on("message", on_message)
        script.load()
        if not completed.wait(10):
            raise SmokeError(f"timed out waiting for hook evidence: {messages!r}")

        errors = [
            message for message in messages if message.get("type") == "error"
        ]
        if errors:
            raise SmokeError(f"Frida script errors: {errors!r}")
        payloads = [
            message.get("payload", {})
            for message in messages
            if message.get("type") == "send"
        ]
        by_kind = {payload.get("kind"): payload for payload in payloads}
        if not {"resolved", "hook-enter", "result"}.issubset(by_kind):
            raise SmokeError(f"missing expected hook messages: {messages!r}")
        if by_kind["result"].get("value") != pid:
            raise SmokeError(f"getpid returned the wrong value: {by_kind['result']!r}")
        if "x" not in str(by_kind["resolved"].get("protection", "")):
            raise SmokeError(
                f"getpid did not resolve to executable memory: {by_kind['resolved']!r}"
            )
        return {
            "processName": matches[0].name,
            "resolved": by_kind["resolved"],
            "hookEnter": by_kind["hook-enter"],
            "nativeFunctionResult": by_kind["result"]["value"],
            "interceptor": True,
        }
    finally:
        if script is not None:
            try:
                script.unload()
            except frida.InvalidOperationError:
                pass
        try:
            session.detach()
        except frida.InvalidOperationError:
            pass


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True, help="exact connected iPhone UDID")
    parser.add_argument("--ssh-key", type=Path, default=DEFAULT_KEY)
    parser.add_argument(
        "--ssh-port",
        type=int,
        help="reuse an exact-device SSH tunnel instead of starting iproxy",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--expected-gadget-sha256",
        default=EXPECTED_GADGET_SHA256,
        help="expected staged and cached Gadget SHA-256",
    )
    args = parser.parse_args()

    output = args.output or (
        ROOT
        / "build"
        / f"frida-ios27-usb-smoke-{time.strftime('%Y%m%d-%H%M%S')}.json"
    )
    report: dict[str, Any] = {
        "schemaVersion": 1,
        "status": "running",
        "requestedUdid": args.udid,
        "pid1Touched": False,
        "startedAtUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    proxy: subprocess.Popen[bytes] | None = None
    proxy_log = None
    ssh_port = args.ssh_port
    target_pid: int | None = None
    target_path: str | None = None
    started_pids: list[int] = []
    primary_error: Exception | None = None
    cleanup_error: Exception | None = None

    try:
        apple_python = (
            sys.executable == "/usr/bin/python3"
            or sys.executable.endswith("/Contents/Developer/usr/bin/python3")
            or sys.executable.endswith("/CommandLineTools/usr/bin/python3")
        )
        if not apple_python:
            raise SmokeError(
                "native RSD discovery on macOS 27 must run under /usr/bin/python3; "
                "use Scripts/run-frida-ios27-usb-smoke.zsh"
            )
        if not args.ssh_key.is_file():
            raise SmokeError(f"missing SSH key: {args.ssh_key}")
        if frida.__version__ != EXPECTED_FRIDA_VERSION:
            raise SmokeError(
                f"expected Frida {EXPECTED_FRIDA_VERSION}, found {frida.__version__}"
            )
        report["host"] = {
            "python": sys.executable,
            "pythonVersion": sys.version.split()[0],
            "fridaVersion": frida.__version__,
            "binding": frida._frida.__file__,
            "bindingSha256": sha256(Path(frida._frida.__file__)),
        }

        for role, path in (("staged", STAGED_GADGET), ("cached", CACHED_GADGET)):
            if not path.is_file():
                raise SmokeError(f"missing {role} Frida Gadget: {path}")
            digest = sha256(path)
            report.setdefault("gadget", {})[role] = {
                "path": str(path),
                "sha256": digest,
            }
            if digest != args.expected_gadget_sha256:
                raise SmokeError(
                    f"unexpected {role} Gadget hash {digest}; expected "
                    f"{args.expected_gadget_sha256}"
                )

        if ssh_port is None:
            iproxy = shutil.which("iproxy")
            if iproxy is None:
                raise SmokeError("iproxy is required (brew install libimobiledevice)")
            ssh_port = available_port()
            proxy_log_path = output.with_suffix(".iproxy.log")
            proxy_log_path.parent.mkdir(parents=True, exist_ok=True)
            proxy_log = proxy_log_path.open("wb")
            proxy = subprocess.Popen(
                [iproxy, "-u", args.udid, f"{ssh_port}:{DEVICE_SSH_PORT}"],
                stdin=subprocess.DEVNULL,
                stdout=proxy_log,
                stderr=subprocess.STDOUT,
            )
            report["sshTransport"] = {
                "mode": "owned-iproxy",
                "port": ssh_port,
                "pid": proxy.pid,
                "log": str(proxy_log_path),
            }
        else:
            if not (1 <= ssh_port <= 65535):
                raise SmokeError(f"invalid SSH port: {ssh_port}")
            report["sshTransport"] = {"mode": "existing-tunnel", "port": ssh_port}

        wait_for_ssh(proxy, ssh_port, args.ssh_key)
        report["pid1Before"] = assert_pid1_healthy(ssh_port, args.ssh_key)
        assert_no_frida_server_listener(ssh_port, args.ssh_key)

        version = expected_bundle_version()
        cryptex_root = resolve_cryptex_root(ssh_port, args.ssh_key, version)
        target_path = f"{cryptex_root}/{TARGET_RELATIVE}"
        assert_no_stale_target(ssh_port, args.ssh_key, target_path)
        report["cryptex"] = {
            "identifier": IDENTIFIER,
            "version": version,
            "root": cryptex_root,
        }

        target_pid, flags, startup = start_target(
            ssh_port,
            args.ssh_key,
            target_path,
            f"{int(time.time())}-{os.getpid()}",
            started_pids,
        )
        report["target"] = {
            "pid": target_pid,
            "name": TARGET_NAME,
            "path": target_path,
            "initialCsflags": f"0x{flags:08x}",
            "startup": startup,
        }

        manager = frida.get_device_manager()
        device = manager.get_device(args.udid, timeout=20)
        if device.id != args.udid or device.type != "usb":
            raise SmokeError(
                f"Frida resolved the wrong transport: id={device.id!r} type={device.type!r}"
            )
        report["fridaDevice"] = {
            "id": device.id,
            "name": device.name,
            "type": device.type,
        }
        report["probe"] = run_interceptor_probe(device, target_pid)
        if process_path(ssh_port, args.ssh_key, target_pid) != target_path:
            raise SmokeError("disposable target died or changed identity after detach")
        report["target"]["aliveAfterDetach"] = True
        report["pid1AfterDetach"] = assert_pid1_healthy(ssh_port, args.ssh_key)
        report["status"] = "passed"
    except Exception as error:
        primary_error = error
        report["status"] = "failed"
        report["error"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
    finally:
        if target_pid is None and len(started_pids) == 1:
            target_pid = started_pids[0]
        if target_pid is not None and target_path is not None and ssh_port is not None:
            try:
                report["targetCleanup"] = cleanup_target(
                    ssh_port, args.ssh_key, target_pid, target_path
                )
                report["pid1AfterCleanup"] = assert_pid1_healthy(
                    ssh_port, args.ssh_key
                )
            except Exception as error:
                cleanup_error = error
                report["targetCleanup"] = {
                    "status": "failed",
                    "type": type(error).__name__,
                    "message": str(error),
                }
        if proxy is not None:
            proxy.terminate()
            try:
                proxy.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proxy.kill()
                proxy.wait(timeout=3)
            report["sshTransport"]["cleanupReturncode"] = proxy.returncode
        if proxy_log is not None:
            proxy_log.close()

    if cleanup_error is not None:
        report["status"] = "failed"
        if primary_error is None:
            report["error"] = {
                "type": type(cleanup_error).__name__,
                "message": str(cleanup_error),
            }
    report["finishedAtUtc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    write_report(output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"report={output}", file=sys.stderr)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
