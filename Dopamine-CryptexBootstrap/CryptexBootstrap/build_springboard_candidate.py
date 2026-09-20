#!/usr/bin/env python3
"""Build an SBInject candidate from a device-matched Apple app bundle."""

from __future__ import annotations

import argparse
import os
import pathlib
import plistlib
import shutil
import subprocess
import tempfile
from typing import Any


COMMON_ENTITLEMENTS = (
    "get-task-allow",
    "com.apple.private.cs.debugger",
    "task_for_pid-allow",
    "platform-application",
    "com.apple.private.skip-library-validation",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.allow-jit",
    "dynamic-codesigning",
)
TARGETS = {
    "springboard": ("com.apple.springboard", COMMON_ENTITLEMENTS),
    "preferences": (
        "com.apple.Preferences",
        COMMON_ENTITLEMENTS + ("com.apple.private.debugger",),
    ),
}


class BuildError(RuntimeError):
    pass


def run(*arguments: str) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            arguments,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as error:
        output = getattr(error, "stdout", b"") + getattr(error, "stderr", b"")
        detail = output.decode("utf-8", "replace").strip()
        raise BuildError(
            f"command failed: {' '.join(arguments)}"
            + (f"\n{detail}" if detail else "")
        ) from error


def read_entitlements(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = plistlib.loads(run("ldid", "-e", os.fspath(path)).stdout)
    except Exception as error:
        raise BuildError(f"could not read entitlements from {path}") from error
    if not isinstance(value, dict):
        raise BuildError(f"entitlements are not a dictionary: {path}")
    return value


def basename(value: str, label: str) -> str:
    if pathlib.PurePath(value).name != value or value in {"", ".", ".."}:
        raise BuildError(f"{label} must be a basename")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=pathlib.Path)
    parser.add_argument("output_directory", type=pathlib.Path)
    parser.add_argument("--target", choices=tuple(TARGETS), required=True)
    parser.add_argument("--info-plist", required=True, type=pathlib.Path)
    parser.add_argument("--executable-name", required=True)
    parser.add_argument("--bundle-executable", required=True)
    parser.add_argument("--load-dylib", required=True)
    parser.add_argument("--load-dylib-patcher", required=True, type=pathlib.Path)
    args = parser.parse_args()

    source = args.source.resolve()
    info_source = args.info_plist.resolve()
    patcher = args.load_dylib_patcher.resolve()
    output = args.output_directory.resolve()
    executable_name = basename(args.executable_name, "executable name")
    bundle_executable = basename(args.bundle_executable, "bundle executable")
    if not source.is_file() or not info_source.is_file() or not patcher.is_file():
        raise BuildError("candidate source, Info.plist, or load-command patcher is missing")
    if not (
        args.load_dylib.startswith("/")
        or args.load_dylib.startswith("@loader_path/")
    ):
        raise BuildError("load dylib must be absolute or use @loader_path")

    identifier, added_entitlements = TARGETS[args.target]
    try:
        info = plistlib.loads(info_source.read_bytes())
    except Exception as error:
        raise BuildError(f"could not parse {info_source}") from error
    if not isinstance(info, dict) or info.get("CFBundleIdentifier") != identifier:
        raise BuildError(f"unexpected {args.target} bundle identifier")
    info["CFBundleExecutable"] = bundle_executable

    merged = read_entitlements(source)
    for entitlement in added_entitlements:
        merged[entitlement] = True

    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".candidate.", dir=output) as raw_temp:
        temporary = pathlib.Path(raw_temp)
        candidate = temporary / executable_name
        entitlements = temporary / "entitlements.plist"
        info_path = temporary / "Info.plist"
        shutil.copyfile(source, candidate)
        candidate.chmod(0o755)
        entitlements.write_bytes(
            plistlib.dumps(merged, fmt=plistlib.FMT_XML, sort_keys=False)
        )
        info_path.write_bytes(
            plistlib.dumps(info, fmt=plistlib.FMT_BINARY, sort_keys=False)
        )
        entitlements.chmod(0o644)
        info_path.chmod(0o644)

        run(
            os.fspath(pathlib.Path(os.sys.executable)),
            os.fspath(patcher),
            os.fspath(candidate),
            args.load_dylib,
        )
        run(
            "codesign",
            "--force",
            "--sign",
            "-",
            "--timestamp=none",
            "--pagesize",
            "4096",
            "--generate-entitlement-der",
            "--identifier",
            identifier,
            "--entitlements",
            os.fspath(entitlements),
            os.fspath(candidate),
        )
        run("codesign", "--verify", "--strict", os.fspath(candidate))
        signed = read_entitlements(candidate)
        if any(signed.get(key) is not True for key in added_entitlements):
            raise BuildError("candidate signature lost required entitlements")
        os.replace(candidate, output / executable_name)
        os.replace(entitlements, output / "entitlements.plist")
        os.replace(info_path, output / "Info.plist")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BuildError as error:
        raise SystemExit(f"error: {error}") from error
