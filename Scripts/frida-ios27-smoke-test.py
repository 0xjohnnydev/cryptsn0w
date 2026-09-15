#!/usr/bin/env python3
"""Run the bounded iOS 27 Frida get-task-allow A/B test.

This test only attaches to the two disposable targets embedded by build.sh. It
never looks up, attaches to, suspends, or otherwise touches PID 1.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import time
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_KEY = ROOT / "build" / "ssh" / "id_ed25519"
DEVICE_SSH_PORT = 2222
DEVICE_FRIDA_PORT = 27042
EXPECTED_FRIDA_VERSION = "17.17.0"
IDENTIFIER = "com.0xjohnnydev.untitled"
MOUNT_PREFIX = "/private/var/run/com.apple.security.cryptexd/mnt"
BUILD_VERSION_RELATIVE = "usr/local/share/untitled/build-version"
LAUNCHCTL_RELATIVE = (
    "usr/local/share/untitled/trust-only/procursus-shell/launchctl"
)
DISPOSABLE_TARGETS = frozenset(
    {
        "untitled-frida-debug-target",
        "untitled-frida-control-target",
    }
)


class SmokeError(RuntimeError):
    pass


def set_stage(report: dict[str, Any], stage: str) -> None:
    """Record the last operation attempted without discarding prior stages."""
    report["stage"] = stage
    history = report.setdefault("stageHistory", [])
    if not history or history[-1] != stage:
        history.append(stage)


def exception_record(error: Exception, stage: str) -> dict[str, str]:
    record = {
        "stage": stage,
        "type": type(error).__name__,
        "message": str(error),
    }
    cause = error.__cause__
    if cause is not None:
        record["causeType"] = type(cause).__name__
        record["causeMessage"] = str(cause)
    return record


def write_report(output: Path, report: dict[str, Any]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


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
        "ConnectTimeout=2",
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


def wait_for_ssh(proxy: subprocess.Popen[bytes], port: int, key: Path) -> None:
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        if proxy.poll() is not None:
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
    if not isinstance(version, str) or not re.fullmatch(r"[0-9.]+", version):
        raise SmokeError(f"invalid local Cryptex version: {version!r}")
    return version


def resolve_cryptex_root(
    port: int, key: Path, expected_version: str
) -> tuple[str, int]:
    marker_suffix = f"/{BUILD_VERSION_RELATIVE}"
    marker_glob = f"{MOUNT_PREFIX}/{IDENTIFIER}.*{marker_suffix}"
    output = ssh(
        port,
        key,
        "emulate -L zsh; setopt null_glob; selected=''; count=0; "
        f"for marker in {marker_glob}; do "
        "IFS= read -r version < \"$marker\" || continue; "
        f"[[ \"$version\" == {shlex.quote(expected_version)} ]] || continue; "
        f"root=\"${{marker%{marker_suffix}}}\"; "
        "test -x \"$root/usr/local/bin/untitled-frida\" || continue; "
        "test -x \"$root/usr/local/bin/untitled-frida-debug-target\" || "
        "continue; "
        "test -x \"$root/usr/local/bin/untitled-frida-control-target\" || "
        "continue; "
        "test -x \"$root/usr/local/libexec/untitled/frida/frida-policyd\" || "
        "continue; "
        f"test -x \"$root/{LAUNCHCTL_RELATIVE}\" || continue; "
        "(( count += 1 )); "
        "selected=\"$root\"; "
        "done; if (( count != 1 )); then "
        "printf 'expected one matching Cryptex mount, found %d\\n' "
        "\"$count\" >&2; exit 72; fi; "
        "printf 'count=%d\\nroot=%s\\n' \"$count\" "
        "\"$selected\"",
    )
    match = re.fullmatch(r"count=([0-9]+)\nroot=([^\n]+)", output)
    if match is None:
        raise SmokeError(f"invalid Cryptex mount selection: {output!r}")
    count = int(match.group(1))
    root = match.group(2)
    expected_root = re.compile(
        re.escape(f"{MOUNT_PREFIX}/{IDENTIFIER}.") + r"[^/]+"
    )
    if count != 1 or expected_root.fullmatch(root) is None:
        raise SmokeError(f"unsafe Cryptex mount selection: {output!r}")
    return root, count


def start_target(
    port: int, key: Path, cryptex_root: str, name: str
) -> tuple[int, int, str]:
    path = f"{cryptex_root}/usr/local/bin/{name}"
    log = f"/var/tmp/{name}.log"
    quoted_path = shlex.quote(path)
    quoted_log = shlex.quote(log)
    output = ssh(
        port,
        key,
        f"test -x {quoted_path} || exit 72; "
        f": > {quoted_log}; {quoted_path} </dev/null >{quoted_log} 2>&1 & "
        "printf '%s' $!",
    )
    try:
        pid = int(output)
    except ValueError as error:
        raise SmokeError(f"target returned an invalid pid: {output!r}") from error
    if pid <= 1:
        raise SmokeError(f"refusing unsafe target pid {pid}")

    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        status = ssh(
            port,
            key,
            f"if kill -0 {pid} 2>/dev/null && test -s {log}; "
            "then printf ready; fi",
            check=False,
        )
        if status == "ready":
            line = ssh(
                port,
                key,
                f"if IFS= read -r line < {quoted_log}; then "
                "printf '%s\\n' \"$line\"; fi",
                check=False,
            )
            if f"pid={pid}" in line:
                if "csopsStatus=0 " not in line:
                    raise SmokeError(
                        f"target {name} could not read its code-sign flags: {line!r}"
                    )
                match = re.search(r"(?:^| )csflags=0x([0-9a-fA-F]{8})(?: |$)", line)
                if match is None:
                    raise SmokeError(
                        f"target {name} emitted no parseable csflags: {line!r}"
                    )
                return pid, int(match.group(1), 16), line
        time.sleep(0.1)
    raise SmokeError(f"target {name} did not become ready (pid {pid})")


def target_alive(port: int, key: Path, pid: int) -> bool:
    if pid <= 1:
        raise SmokeError(f"refusing unsafe liveness query for pid {pid}")
    completed = subprocess.run(
        ssh_command(port, key, f"kill -0 {pid} 2>/dev/null"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=8,
    )
    return completed.returncode == 0


def read_policy_log(port: int, key: Path) -> list[str]:
    return ssh(
        port,
        key,
        "if test -r /var/tmp/untitled-frida-policyd.log; then "
        "while IFS= read -r line; do printf '%s\\n' \"$line\"; "
        "done < /var/tmp/untitled-frida-policyd.log; fi",
        check=False,
    ).splitlines()


def policy_lines_after_marker(
    raw_policy_lines: list[str], marker: str
) -> list[str]:
    try:
        boundary = max(
            index
            for index, line in enumerate(raw_policy_lines)
            if line == marker
        )
    except ValueError as error:
        raise SmokeError("fresh policy-log boundary was not retained") from error
    return raw_policy_lines[boundary + 1 :]


def policy_line(lines: list[str], pid: int) -> str:
    marker = f"frida-policyd pid={pid} "
    for line in reversed(lines):
        if marker in line:
            return line
    raise SmokeError(f"policy daemon emitted no diagnostic for target pid {pid}")


def installed_server_status(
    port: int, key: Path, cryptex_root: str
) -> tuple[int, list[int], str]:
    wrapper = shlex.quote(f"{cryptex_root}/usr/local/bin/untitled-frida")
    output = ssh(
        port,
        key,
        f"{wrapper} --status",
    )
    match = re.fullmatch(
        r"fridaServerStatus count=([0-9]+)((?: pid=[0-9]+)*)", output
    )
    if match is None:
        raise SmokeError(f"invalid Frida server status: {output!r}")
    count = int(match.group(1))
    pids = [int(pid) for pid in re.findall(r"pid=([0-9]+)", match.group(2))]
    if count != len(pids) or any(pid <= 1 for pid in pids):
        raise SmokeError(f"unsafe Frida server status: {output!r}")
    return count, pids, output


def wait_for_installed_server(
    port: int,
    key: Path,
    cryptex_root: str,
    *,
    expected_pid: int | None = None,
) -> tuple[int, str]:
    deadline = time.monotonic() + 10
    last_status = "not queried"
    while time.monotonic() < deadline:
        count, pids, last_status = installed_server_status(
            port, key, cryptex_root
        )
        if count == 1 and (expected_pid is None or pids[0] == expected_pid):
            return pids[0], last_status
        time.sleep(0.1)
    expectation = "exactly one new server"
    if expected_pid is not None:
        expectation = f"the same server pid {expected_pid}"
    raise SmokeError(
        f"did not observe {expectation} at the installed path: {last_status!r}"
    )


def resolve_launchctl(port: int, key: Path, cryptex_root: str) -> str:
    launchctl = f"{cryptex_root}/{LAUNCHCTL_RELATIVE}"
    quoted_launchctl = shlex.quote(launchctl)
    output = ssh(
        port,
        key,
        f"test -x {quoted_launchctl} || exit 72; "
        f"printf '%s' {quoted_launchctl}",
    )
    if output != launchctl:
        raise SmokeError(f"unexpected trusted launchctl path: {output!r}")
    return launchctl


def launchctl_job_program(
    port: int,
    key: Path,
    launchctl: str,
    label: str,
    *,
    required: bool,
) -> str | None:
    output = ssh(
        port,
        key,
        f"{shlex.quote(launchctl)} print {shlex.quote(label)}; "
        "print_status=$?; "
        "printf '\\nuntitledPrintStatus=%d\\n' \"$print_status\"; "
        "exit 0",
    )
    status_match = re.search(r"(?:^|\n)untitledPrintStatus=([0-9]+)$", output)
    if status_match is None:
        raise SmokeError(f"launchctl emitted no status for {label}: {output!r}")
    status = int(status_match.group(1))
    if status != 0:
        if required:
            raise SmokeError(f"required launchd job is absent: {label}")
        return None
    programs = re.findall(r"^[ \t]*program = ([^\r\n]+)$", output, re.MULTILINE)
    if len(programs) != 1:
        raise SmokeError(
            f"launchctl returned {len(programs)} program paths for {label}"
        )
    return programs[0]


def restart_frida(
    port: int, key: Path, cryptex_root: str
) -> tuple[str, str, int, str, str, dict[str, str | None]]:
    launchctl = resolve_launchctl(port, key, cryptex_root)
    quoted_launchctl = shlex.quote(launchctl)
    rootd_label = f"system/{IDENTIFIER}.rootd"
    policyd_label = "system/re.frida.policyd"
    legacy_label = "system/re.frida.server"
    expected_rootd = f"{cryptex_root}/usr/local/bin/untitled-rootd"
    expected_policyd = (
        f"{cryptex_root}/usr/local/libexec/untitled/frida/frida-policyd"
    )
    rootd_program = launchctl_job_program(
        port, key, launchctl, rootd_label, required=True
    )
    policyd_program = launchctl_job_program(
        port, key, launchctl, policyd_label, required=True
    )
    legacy_program = launchctl_job_program(
        port, key, launchctl, legacy_label, required=False
    )
    if rootd_program != expected_rootd:
        raise SmokeError(
            f"rootd belongs to a stale Cryptex root: {rootd_program!r}"
        )
    if policyd_program != expected_policyd:
        raise SmokeError(
            f"policyd belongs to a stale Cryptex root: {policyd_program!r}"
        )
    if legacy_program not in (None, "/var/jb/usr/sbin/frida-server"):
        raise SmokeError(
            f"legacy Frida job has an unexpected program: {legacy_program!r}"
        )
    legacy_bootout = ""
    if legacy_program is not None:
        legacy_bootout = f"{quoted_launchctl} bootout {legacy_label}; "
    launchctl_output = ssh(
        port,
        key,
        "set -e; "
        f"{legacy_bootout}"
        f"{quoted_launchctl} kickstart -k {policyd_label}; "
        "printf launchctl-ready",
    )
    if launchctl_output != "launchctl-ready":
        raise SmokeError(
            f"launchctl did not confirm policyd restart: {launchctl_output!r}"
        )
    restarted_policyd_program = launchctl_job_program(
        port, key, launchctl, policyd_label, required=True
    )
    if restarted_policyd_program != expected_policyd:
        raise SmokeError(
            "policyd changed Cryptex roots during restart: "
            f"{restarted_policyd_program!r}"
        )
    marker = f"untitled-frida-smoke-boundary-{secrets.token_hex(16)}"
    ssh(
        port,
        key,
        f"printf '%s\\n' {shlex.quote(marker)} "
        ">> /var/tmp/untitled-frida-policyd.log",
    )
    wrapper = shlex.quote(f"{cryptex_root}/usr/local/bin/untitled-frida")
    launcher = ssh(
        port,
        key,
        f"{wrapper}; launcher_status=$?; "
        "printf 'fridaLauncherExit=%d\\n' \"$launcher_status\"; "
        "exit \"$launcher_status\"",
    )
    if (
        "fridaLaunchMode=direct-opt-in" not in launcher
        or "fridaLauncherExit=0" not in launcher
    ):
        raise SmokeError(f"guarded Frida launcher did not confirm startup: {launcher}")
    server_pid, server_status = wait_for_installed_server(
        port, key, cryptex_root
    )
    provenance = {
        "rootdProgram": rootd_program,
        "policydProgramBeforeRestart": policyd_program,
        "policydProgramAfterRestart": restarted_policyd_program,
        "legacyServerProgram": legacy_program,
    }
    return (
        marker,
        launcher,
        server_pid,
        server_status,
        launchctl,
        provenance,
    )


def connect_frida(frida: Any, endpoint: str) -> Any:
    manager = frida.get_device_manager()
    deadline = time.monotonic() + 25
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return manager.add_remote_device(endpoint)
        except Exception as error:  # Frida exposes transport-specific errors.
            last_error = error
            time.sleep(0.25)
    error = SmokeError(f"Frida did not become ready at {endpoint}: {last_error}")
    if last_error is not None:
        raise error from last_error
    raise error


def attach_positive(
    device: Any,
    pid: int,
    stage: Callable[[str], None],
    resource_cleanup_errors: list[dict[str, str]],
) -> dict[str, Any]:
    if pid <= 1:
        raise SmokeError(f"refusing unsafe positive-control pid {pid}")
    stage("positive.attach")
    session = device.attach(pid)
    script = None
    operation_error: Exception | None = None
    cleanup_error_count = len(resource_cleanup_errors)
    try:
        stage("positive.script-create")
        script = session.create_script(
            "const nativeModule = new CModule(`"
            "int untitled_answer(void) { return 42; }"
            "`);"
            "const nativeAnswer = new NativeFunction("
            "nativeModule.untitled_answer, 'int', []);"
            "rpc.exports = { probe() { return { pid: Process.id, "
            "arch: Process.arch, platform: Process.platform, "
            "nativeAnswer: nativeAnswer() }; } };"
        )
        stage("positive.script-load")
        script.load()
        stage("positive.probe")
        identity = dict(script.exports_sync.probe())
    except Exception as error:
        operation_error = error
        raise
    finally:
        if script is not None:
            try:
                script.unload()
            except Exception as error:
                resource_cleanup_errors.append(
                    {
                        "resource": "positive-script",
                        "type": type(error).__name__,
                        "message": str(error),
                    }
                )
        try:
            session.detach()
        except Exception as error:
            resource_cleanup_errors.append(
                {
                    "resource": "positive-session",
                    "type": type(error).__name__,
                    "message": str(error),
                }
            )
        if (
            operation_error is None
            and len(resource_cleanup_errors) != cleanup_error_count
        ):
            stage("positive.resource-cleanup")
            raise SmokeError("positive-control Frida resource cleanup failed")
    stage("positive.validate-agent-result")
    if identity.get("pid") != pid:
        raise SmokeError(f"Frida agent reported the wrong pid: {identity!r}")
    if identity.get("nativeAnswer") != 42:
        raise SmokeError(f"Frida native probe returned the wrong value: {identity!r}")
    return identity


def attach_negative(
    device: Any,
    pid: int,
    stage: Callable[[str], None],
    resource_cleanup_errors: list[dict[str, str]],
) -> str:
    if pid <= 1:
        raise SmokeError(f"refusing unsafe negative-control pid {pid}")
    stage("negative.attach")
    try:
        session = device.attach(pid)
    except Exception as error:  # Expected AMFI policy rejection.
        return f"{type(error).__name__}: {error}"
    else:
        try:
            session.detach()
        except Exception as error:
            resource_cleanup_errors.append(
                {
                    "resource": "negative-session",
                    "type": type(error).__name__,
                    "message": str(error),
                }
            )
        raise SmokeError(
            "negative-control target unexpectedly attached; AMFI policy differs "
            "from the exact 24A435 production image"
        )


def collect_failure_evidence(
    report: dict[str, Any],
    port: int,
    key: Path,
    cryptex_root: str | None,
    policy_marker: str | None,
    targets: list[dict[str, Any]],
) -> None:
    """Collect bounded, read-only diagnostics without masking the failure."""
    errors: list[dict[str, str]] = []
    if cryptex_root is not None:
        try:
            count, pids, status = installed_server_status(
                port, key, cryptex_root
            )
            server = report.setdefault("server", {})
            server["statusAtFailure"] = status
            server["pidsAtFailure"] = pids
            server["countAtFailure"] = count
        except Exception as error:
            errors.append(
                {
                    "evidence": "server-status",
                    "type": type(error).__name__,
                    "message": str(error),
                }
            )

    try:
        raw_policy_lines = read_policy_log(port, key)
        report["policydLogTail"] = raw_policy_lines[-20:]
        if policy_marker is not None:
            try:
                fresh_policy_lines = policy_lines_after_marker(
                    raw_policy_lines, policy_marker
                )
            except SmokeError:
                report["policyRunMarkerRetained"] = False
            else:
                report["policyRunMarkerRetained"] = True
                report["policydLogAfterMarker"] = fresh_policy_lines[-20:]
    except Exception as error:
        errors.append(
            {
                "evidence": "policyd-log",
                "type": type(error).__name__,
                "message": str(error),
            }
        )

    for target in targets:
        pid = target["pid"]
        key_name = target["reportKey"]
        try:
            report.setdefault(key_name, {})["aliveAtFailure"] = target_alive(
                port, key, pid
            )
        except Exception as error:
            errors.append(
                {
                    "evidence": f"{key_name}-liveness",
                    "type": type(error).__name__,
                    "message": str(error),
                }
            )
    if errors:
        report["failureEvidenceErrors"] = errors


def cleanup_registered_targets(
    port: int,
    key: Path,
    cryptex_root: str | None,
    targets: list[dict[str, Any]],
) -> dict[str, Any]:
    """TERM only exact disposable PIDs registered after validated startup."""
    result: dict[str, Any] = {
        "pid1SignalAttempted": False,
        "targetActions": [],
        "errors": [],
    }
    seen: set[int] = set()
    for target in targets:
        action = {
            "name": target.get("name"),
            "pid": target.get("pid"),
            "signal": "SIGTERM",
        }
        result["targetActions"].append(action)
        pid = target.get("pid")
        name = target.get("name")
        path = target.get("path")
        expected_path = (
            f"{cryptex_root}/usr/local/bin/{name}"
            if cryptex_root is not None and name in DISPOSABLE_TARGETS
            else None
        )
        if (
            not isinstance(pid, int)
            or pid <= 1
            or pid in seen
            or name not in DISPOSABLE_TARGETS
            or expected_path is None
            or path != expected_path
        ):
            action["result"] = "refused"
            result["errors"].append(
                {
                    "resource": "target",
                    "type": "UnsafeCleanupTarget",
                    "message": f"refused unregistered or unsafe target: {target!r}",
                }
            )
            continue
        seen.add(pid)
        try:
            response = ssh(
                port,
                key,
                f"if (( {pid} <= 1 )); then printf refused; "
                f"elif kill -TERM {pid} 2>/dev/null; then printf signaled; "
                f"elif kill -0 {pid} 2>/dev/null; then printf failed; "
                "else printf absent; fi",
            )
        except Exception as error:
            action["result"] = "error"
            result["errors"].append(
                {
                    "resource": f"target:{name}:{pid}",
                    "type": type(error).__name__,
                    "message": str(error),
                }
            )
            continue
        action["result"] = response
        if response not in ("signaled", "absent"):
            result["errors"].append(
                {
                    "resource": f"target:{name}:{pid}",
                    "type": "TargetCleanupFailed",
                    "message": f"unexpected cleanup result: {response!r}",
                }
            )
            continue
        if response == "absent":
            action["terminationVerified"] = True
            continue
        time.sleep(0.1)
        try:
            still_alive = target_alive(port, key, pid)
        except Exception as error:
            action["terminationVerified"] = False
            result["errors"].append(
                {
                    "resource": f"target:{name}:{pid}",
                    "type": type(error).__name__,
                    "message": f"could not verify target termination: {error}",
                }
            )
            continue
        action["terminationVerified"] = not still_alive
        if still_alive:
            result["errors"].append(
                {
                    "resource": f"target:{name}:{pid}",
                    "type": "TargetStillAlive",
                    "message": "target remained alive after SIGTERM",
                }
            )
    return result


def cleanup_proxies(
    proxies: list[subprocess.Popen[bytes]],
) -> dict[str, Any]:
    result: dict[str, Any] = {"proxyActions": [], "errors": []}
    for index, proxy in enumerate(proxies):
        action: dict[str, Any] = {"index": index, "pid": proxy.pid}
        result["proxyActions"].append(action)
        try:
            if proxy.poll() is None:
                proxy.terminate()
                action["terminateSent"] = True
            else:
                action["terminateSent"] = False
        except Exception as error:
            action["terminateError"] = f"{type(error).__name__}: {error}"
            result["errors"].append(
                {
                    "resource": f"iproxy:{index}",
                    "type": type(error).__name__,
                    "message": str(error),
                }
            )
    for index, proxy in enumerate(proxies):
        action = result["proxyActions"][index]
        try:
            proxy.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                proxy.kill()
                action["killSentAfterTimeout"] = True
                proxy.wait(timeout=3)
            except Exception as error:
                result["errors"].append(
                    {
                        "resource": f"iproxy:{index}",
                        "type": type(error).__name__,
                        "message": str(error),
                    }
                )
        except Exception as error:
            result["errors"].append(
                {
                    "resource": f"iproxy:{index}",
                    "type": type(error).__name__,
                    "message": str(error),
                }
            )
        action["returncode"] = proxy.poll()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True, help="exact connected device UDID")
    parser.add_argument("--ssh-key", type=Path, default=DEFAULT_KEY)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    build_dir = ROOT / "build"
    output = args.output or (
        build_dir / f"frida-smoke-{time.strftime('%Y%m%d-%H%M%S')}.json"
    )
    report: dict[str, Any] = {
        "schemaVersion": 1,
        "status": "running",
        "stage": "preflight",
        "stageHistory": ["preflight"],
        "startedAtUtc": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
        ),
        "requestedUdid": args.udid,
        "pid1Touched": False,
    }
    proxies: list[subprocess.Popen[bytes]] = []
    proxy_log = None
    ssh_port: int | None = None
    frida_port: int | None = None
    ssh_ready = False
    cryptex_root: str | None = None
    policy_marker: str | None = None
    targets: list[dict[str, Any]] = []
    resource_cleanup_errors: list[dict[str, str]] = []
    primary_error: Exception | None = None
    primary_stage: str | None = None
    smoke_complete = False

    def stage(name: str) -> None:
        set_stage(report, name)

    try:
        stage("preflight.ssh-key")
        if not args.ssh_key.is_file():
            raise SmokeError(f"missing SSH key: {args.ssh_key}")

        stage("preflight.build-version")
        expected_version = expected_bundle_version()
        report["expectedCryptexVersion"] = expected_version

        stage("preflight.iproxy")
        iproxy = shutil.which("iproxy")
        if iproxy is None:
            raise SmokeError("iproxy is required (brew install libimobiledevice)")

        stage("preflight.frida-bindings")
        try:
            import frida
        except ImportError as error:
            raise SmokeError(
                "Frida Python bindings are missing; use the project .venv with "
                f"frida=={EXPECTED_FRIDA_VERSION}"
            ) from error
        if frida.__version__ != EXPECTED_FRIDA_VERSION:
            raise SmokeError(
                f"expected Frida {EXPECTED_FRIDA_VERSION}, "
                f"found {frida.__version__}"
            )
        report["fridaVersion"] = frida.__version__

        stage("transport.allocate-ports")
        ssh_port = available_port()
        frida_port = available_port()
        while frida_port == ssh_port:
            frida_port = available_port()
        report["transport"] = {
            "sshLocalPort": ssh_port,
            "fridaLocalPort": frida_port,
        }

        stage("transport.start-iproxy")
        output.parent.mkdir(parents=True, exist_ok=True)
        proxy_log_path = output.with_name(f"{output.stem}-iproxy.log")
        proxy_log = proxy_log_path.open("wb")
        report["transport"]["iproxyLog"] = str(proxy_log_path)
        for forwarding in (
            f"{ssh_port}:{DEVICE_SSH_PORT}",
            f"{frida_port}:{DEVICE_FRIDA_PORT}",
        ):
            proxies.append(
                subprocess.Popen(
                    [iproxy, "-u", args.udid, forwarding],
                    stdin=subprocess.DEVNULL,
                    stdout=proxy_log,
                    stderr=subprocess.STDOUT,
                )
            )
        report["transport"]["iproxyPids"] = [proxy.pid for proxy in proxies]

        stage("transport.wait-for-root-ssh")
        wait_for_ssh(proxies[0], ssh_port, args.ssh_key)
        ssh_ready = True

        stage("cryptex.resolve")
        cryptex_root, matching_mount_count = resolve_cryptex_root(
            ssh_port, args.ssh_key, expected_version
        )
        report["cryptex"] = {
            "identifier": IDENTIFIER,
            "version": expected_version,
            "root": cryptex_root,
            "matchingMountCount": matching_mount_count,
        }

        stage("frida.restart")
        (
            policy_marker,
            launcher_output,
            server_pid,
            server_status,
            launchctl,
            launchd_provenance,
        ) = restart_frida(ssh_port, args.ssh_key, cryptex_root)
        report["launchctl"] = launchctl
        report["launchdProvenance"] = launchd_provenance
        report["launcher"] = launcher_output.splitlines()
        report["server"] = {
            "pid": server_pid,
            "statusAfterLaunch": server_status,
        }
        report["policyRunMarker"] = policy_marker

        stage("positive.start")
        debug_pid, debug_flags, debug_startup = start_target(
            ssh_port,
            args.ssh_key,
            cryptex_root,
            "untitled-frida-debug-target",
        )
        targets.append(
            {
                "reportKey": "positiveControl",
                "name": "untitled-frida-debug-target",
                "pid": debug_pid,
                "path": (
                    f"{cryptex_root}/usr/local/bin/"
                    "untitled-frida-debug-target"
                ),
            }
        )
        report["positiveControl"] = {
            "pid": debug_pid,
            "getTaskAllow": True,
            "initialCsflags": f"0x{debug_flags:08x}",
            "startup": debug_startup,
        }

        stage("negative.start")
        control_pid, control_flags, control_startup = start_target(
            ssh_port,
            args.ssh_key,
            cryptex_root,
            "untitled-frida-control-target",
        )
        targets.append(
            {
                "reportKey": "negativeControl",
                "name": "untitled-frida-control-target",
                "pid": control_pid,
                "path": (
                    f"{cryptex_root}/usr/local/bin/"
                    "untitled-frida-control-target"
                ),
            }
        )
        report["negativeControl"] = {
            "pid": control_pid,
            "getTaskAllow": False,
            "initialCsflags": f"0x{control_flags:08x}",
            "startup": control_startup,
        }

        stage("controls.validate-csflags")
        cs_get_task_allow = 0x4
        if (debug_flags & cs_get_task_allow) == 0:
            raise SmokeError(
                "positive-control signature did not acquire CS_GET_TASK_ALLOW"
            )
        if (control_flags & cs_get_task_allow) != 0:
            raise SmokeError(
                "negative-control signature unexpectedly acquired CS_GET_TASK_ALLOW"
            )

        stage("frida.connect")
        device = connect_frida(frida, f"127.0.0.1:{frida_port}")
        stage("server.verify-after-connect")
        verified_server_pid, verified_server_status = wait_for_installed_server(
            ssh_port,
            args.ssh_key,
            cryptex_root,
            expected_pid=server_pid,
        )
        report["server"]["pid"] = verified_server_pid
        report["server"]["statusAfterConnect"] = verified_server_status

        positive = attach_positive(
            device,
            debug_pid,
            stage,
            resource_cleanup_errors,
        )
        stage("positive.verify-alive")
        if not target_alive(ssh_port, args.ssh_key, debug_pid):
            raise SmokeError("positive-control target died during Frida attach")
        report["positiveControl"]["agent"] = positive
        report["positiveControl"]["aliveAfterDetach"] = True

        negative = attach_negative(
            device,
            control_pid,
            stage,
            resource_cleanup_errors,
        )
        stage("negative.verify-alive")
        if not target_alive(ssh_port, args.ssh_key, control_pid):
            raise SmokeError("negative-control target died during rejected attach")
        report["negativeControl"]["attachError"] = negative
        report["negativeControl"]["aliveAfterRejection"] = True

        stage("policy.read")
        raw_policy_lines = read_policy_log(ssh_port, args.ssh_key)
        policy_lines = policy_lines_after_marker(raw_policy_lines, policy_marker)
        report["policydLogTail"] = policy_lines[-20:]

        stage("policy.validate-positive")
        positive_policy = policy_line(policy_lines, debug_pid)
        report["positiveControl"]["policy"] = positive_policy
        if "softened=1" not in positive_policy:
            raise SmokeError(
                f"positive-control policy transition was not proven: {positive_policy}"
            )

        stage("policy.validate-negative")
        negative_policy = policy_line(policy_lines, control_pid)
        report["negativeControl"]["policy"] = negative_policy
        if "softened=1" in negative_policy or not (
            "softened=0" in negative_policy
            or "outcome=attach-failed" in negative_policy
        ):
            raise SmokeError(
                f"negative-control policy rejection was not proven: {negative_policy}"
            )

        smoke_complete = True
    except Exception as error:
        primary_error = error
        primary_stage = str(report.get("stage", "unknown"))
        if ssh_ready and ssh_port is not None:
            try:
                collect_failure_evidence(
                    report,
                    ssh_port,
                    args.ssh_key,
                    cryptex_root,
                    policy_marker,
                    targets,
                )
            except Exception as evidence_error:
                report.setdefault("failureEvidenceErrors", []).append(
                    {
                        "evidence": "collector",
                        "type": type(evidence_error).__name__,
                        "message": str(evidence_error),
                    }
                )
    finally:
        cleanup: dict[str, Any] = {
            "pid1SignalAttempted": False,
            "targetActions": [],
            "errors": [],
        }
        if ssh_ready and ssh_port is not None:
            try:
                cleanup = cleanup_registered_targets(
                    ssh_port,
                    args.ssh_key,
                    cryptex_root,
                    targets,
                )
            except Exception as error:
                cleanup["errors"].append(
                    {
                        "resource": "target-cleanup",
                        "type": type(error).__name__,
                        "message": str(error),
                    }
                )
        else:
            cleanup["targetCleanupSkipped"] = "root SSH was not ready"
        try:
            proxy_cleanup = cleanup_proxies(proxies)
        except Exception as error:
            proxy_cleanup = {
                "proxyActions": [],
                "errors": [
                    {
                        "resource": "iproxy-cleanup",
                        "type": type(error).__name__,
                        "message": str(error),
                    }
                ],
            }
        cleanup["proxyActions"] = proxy_cleanup["proxyActions"]
        cleanup["errors"].extend(proxy_cleanup["errors"])
        if resource_cleanup_errors:
            cleanup["fridaResourceErrors"] = resource_cleanup_errors
            cleanup["errors"].extend(resource_cleanup_errors)
        if proxy_log is not None:
            try:
                proxy_log.close()
            except Exception as error:
                cleanup["errors"].append(
                    {
                        "resource": "iproxy-log",
                        "type": type(error).__name__,
                        "message": str(error),
                    }
                )
        cleanup["status"] = "complete" if not cleanup["errors"] else "failed"
        report["cleanup"] = cleanup

    if primary_error is not None:
        report["status"] = "failed"
        report["failure"] = exception_record(
            primary_error, primary_stage or "unknown"
        )
    elif not smoke_complete:
        report["status"] = "failed"
        report["failure"] = {
            "stage": str(report.get("stage", "unknown")),
            "type": "IncompleteSmokeRun",
            "message": "smoke run ended without a result",
        }
    elif report["cleanup"]["errors"]:
        set_stage(report, "cleanup")
        report["status"] = "failed"
        report["failure"] = {
            "stage": "cleanup",
            "type": "CleanupError",
            "message": "smoke checks passed but cleanup was incomplete",
        }
    else:
        set_stage(report, "complete")
        report["status"] = "passed"

    report["finishedAtUtc"] = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
    )
    try:
        write_report(output, report)
    except Exception as error:
        print(f"error: cannot write smoke report {output}: {error}", file=sys.stderr)
        if primary_error is not None:
            print(f"error: {primary_error}", file=sys.stderr)
        return 1

    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"report={output.resolve()}")
    if report["status"] != "passed":
        failure = report["failure"]
        print(
            f"error: {failure['stage']}: {failure['type']}: "
            f"{failure['message']}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
