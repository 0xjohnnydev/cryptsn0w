#!/usr/bin/env python3
"""Build a device-matched, debugger-enabled amfid replacement."""

from __future__ import annotations

import argparse
import os
import pathlib
import plistlib
import shutil
import subprocess
import tempfile
from typing import Any


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--load-dylib", required=True)
    parser.add_argument("--load-dylib-patcher", required=True, type=pathlib.Path)
    args = parser.parse_args()

    source = args.source.resolve()
    output = args.output.resolve()
    patcher = args.load_dylib_patcher.resolve()
    if not source.is_file() or not patcher.is_file():
        raise BuildError("amfid source or load-command patcher is missing")
    if not args.load_dylib.startswith("@loader_path/"):
        raise BuildError("amfid hook must use an @loader_path dependency")

    merged = read_entitlements(source)
    merged["get-task-allow"] = True

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".amfid-candidate.", dir=output.parent
    ) as raw_temp:
        temporary = pathlib.Path(raw_temp)
        candidate = temporary / output.name
        entitlements = temporary / "amfid-entitlements.plist"
        shutil.copyfile(source, candidate)
        candidate.chmod(0o755)
        entitlements.write_bytes(
            plistlib.dumps(merged, fmt=plistlib.FMT_XML, sort_keys=False)
        )

        run(
            os.fspath(pathlib.Path(os.sys.executable)),
            os.fspath(patcher),
            os.fspath(candidate),
            args.load_dylib,
        )
        run("ldid", "-r", os.fspath(candidate))
        run(
            "ldid",
            f"-S{entitlements}",
            "-P13",
            "-Cadhoc",
            "-Hsha256",
            "-Icom.apple.amfid",
            os.fspath(candidate),
        )
        run("codesign", "--verify", "--strict", os.fspath(candidate))
        details = run(
            "codesign", "--display", "--verbose=3", os.fspath(candidate)
        ).stderr
        if b"Platform identifier=13" not in details:
            raise BuildError("amfid candidate lost platform identifier 13")
        signed = read_entitlements(candidate)
        if signed.get("get-task-allow") is not True:
            raise BuildError("amfid candidate lost get-task-allow")
        os.replace(candidate, output)
        os.replace(entitlements, output.with_suffix(".entitlements.plist"))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BuildError as error:
        raise SystemExit(f"error: {error}") from error
