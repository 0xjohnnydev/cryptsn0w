#!/usr/bin/env python3
"""Reseal a target OS SpringBoard app for GTA and dynamic code signing."""

from __future__ import annotations

import argparse
import hashlib
import plistlib
import shutil
import subprocess
from pathlib import Path


def run(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(args, check=True, capture_output=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("entitlements", type=Path)
    args = parser.parse_args()

    source = args.source.resolve(strict=True)
    source_app = source.parent
    if (
        not source.is_file()
        or source.name != "SpringBoard"
        or source_app.name != "SpringBoard.app"
        or not (source_app / "Info.plist").is_file()
    ):
        parser.error("source must be a complete SpringBoard.app from the target OS")
    info = plistlib.loads((source_app / "Info.plist").read_bytes())
    if info.get("CFBundleIdentifier") != "com.apple.springboard":
        parser.error("source app has the wrong bundle identifier")
    if not run("file", "-b", str(source)).stdout.startswith(b"Mach-O"):
        parser.error("source is not a Mach-O executable")
    identifier = run("codesign", "-d", "--arch", "arm64e", "-vvv", str(source)).stderr
    if b"Identifier=com.apple.springboard\n" not in identifier:
        parser.error("source does not have the com.apple.springboard identifier")
    # Apple's shipped bundle uses legacy resource omit rules that the current
    # host codesign rejects. Verify its executable pages before resealing the
    # copied bundle with a fresh resource envelope below.
    run("codesign", "--verify", "--strict", "--ignore-resources",
        "--all-architectures", str(source_app))

    original = plistlib.loads(run("ldid", "-e", str(source)).stdout)
    if not isinstance(original, dict):
        parser.error("source entitlements are not a dictionary")
    if original.get("get-task-allow") is True:
        parser.error("source already has get-task-allow; expected an original OS binary")
    modified = dict(original)
    modified["get-task-allow"] = True
    modified["dynamic-codesigning"] = True

    args.entitlements.parent.mkdir(parents=True, exist_ok=True)
    args.destination.parent.parent.mkdir(parents=True, exist_ok=True)
    args.entitlements.write_bytes(plistlib.dumps(modified))
    shutil.copytree(source_app, args.destination.parent, symlinks=True)
    run(
        "codesign", "--force", "--sign", "-", "--timestamp=none",
        "--pagesize", "4096", "--identifier", "com.apple.springboard",
        "--entitlements", str(args.entitlements), str(args.destination.parent),
    )
    run("codesign", "--verify", "--strict", "--all-architectures", str(args.destination.parent))
    signed = plistlib.loads(run("ldid", "-e", str(args.destination)).stdout)
    if signed != modified:
        parser.error("resigned SpringBoard entitlements differ from intended values")
    digest = hashlib.sha256(args.destination.read_bytes()).hexdigest()
    print(f"SpringBoard SHA-256: {digest}")


if __name__ == "__main__":
    main()
