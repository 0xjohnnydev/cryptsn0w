#!/usr/bin/env python3
"""Bootstrap the Frida CLI through Apple Python and the exact Fruity device."""

from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import typing

import typing_extensions


if not hasattr(typing, "NotRequired"):
    typing.NotRequired = typing_extensions.NotRequired  # type: ignore[attr-defined]
if not hasattr(typing, "ParamSpec"):
    typing.ParamSpec = typing_extensions.ParamSpec  # type: ignore[attr-defined]


DEVICE_UDID = "00008150-0018252C1130C01C"
EXPECTED_FRIDA_VERSION = "17.17.0"
EXPECTED_GADGET_SHA256 = (
    "10a34a745f3e2342004847ee921119ff50fc41ea6ffc949b0c6a4ccd37182c71"
)
CACHED_GADGET = Path.home() / ".cache" / "frida" / "gadget-ios.dylib"


def fail(message: str) -> None:
    print(f"frida-ios27-usb: {message}", file=sys.stderr)
    raise SystemExit(64)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def guarded_arguments(arguments: list[str]) -> list[str]:
    explicit_device: str | None = None
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in {"-U", "--usb", "-R", "--remote"}:
            fail("ambiguous USB and remote-server selectors are disabled")
        if argument in {"-H", "--host"} or argument.startswith("--host="):
            fail("remote frida-server mode is disabled for this wrapper")
        if argument in {"-O", "--options-file"} or argument.startswith(
            "--options-file="
        ):
            fail("options files are disabled because they bypass argument guards")
        if argument in {"-D", "--device"}:
            index += 1
            if index >= len(arguments):
                fail(f"{argument} requires a value")
            explicit_device = arguments[index]
        elif argument.startswith("--device="):
            explicit_device = argument.split("=", 1)[1]
        elif argument.startswith("-D") and argument != "-D":
            explicit_device = argument[2:]

        attach_pid: str | None = None
        if argument in {"-p", "--attach-pid"}:
            index += 1
            if index >= len(arguments):
                fail(f"{argument} requires a value")
            attach_pid = arguments[index]
        elif argument.startswith("--attach-pid="):
            attach_pid = argument.split("=", 1)[1]
        elif argument.startswith("-p") and argument != "-p":
            attach_pid = argument[2:]
        if attach_pid is not None:
            try:
                numeric_pid = int(attach_pid, 0)
            except ValueError:
                fail(f"invalid attach PID: {attach_pid!r}")
            if numeric_pid <= 1:
                fail(f"refusing unsafe attach PID {numeric_pid}")

        unsafe_target = (
            argument == "1"
            or argument.rsplit("/", 1)[-1] == "launchd"
            or argument.endswith("=launchd")
            or argument.endswith(".launchd")
            or argument == "-nlaunchd"
        )
        if unsafe_target:
            fail("launchd/PID 1 is permanently excluded")
        index += 1

    if explicit_device is not None and explicit_device != DEVICE_UDID:
        fail(
            f"refusing device {explicit_device!r}; this wrapper is pinned to "
            f"{DEVICE_UDID}"
        )
    if explicit_device is None:
        return ["-D", DEVICE_UDID, *arguments]
    return arguments


def main() -> None:
    import frida
    from frida_tools.repl import main as frida_main

    if frida.__version__ != EXPECTED_FRIDA_VERSION:
        fail(
            f"expected Frida {EXPECTED_FRIDA_VERSION}, found {frida.__version__}"
        )
    if not CACHED_GADGET.is_file():
        fail(f"missing cached Gadget: {CACHED_GADGET}")
    gadget_sha = sha256(CACHED_GADGET)
    if gadget_sha != EXPECTED_GADGET_SHA256:
        fail(
            f"cached Gadget SHA-256 is {gadget_sha}; select the proven patch "
            "with Scripts/select-frida-ios27-gadget.zsh patched"
        )
    sys.argv = [sys.argv[0], *guarded_arguments(sys.argv[1:])]
    frida_main()


if __name__ == "__main__":
    main()
