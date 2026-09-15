#!/usr/bin/env python3

"""Carry forward hashes produced by earlier managed Procursus builds."""

from __future__ import annotations

import hashlib
import os
import pathlib
import plistlib
import re
import stat
import sys
import tempfile


DIGEST = re.compile(r"[0-9a-f]{64}")


def safe_relative(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("baseline path is not nonempty text")
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"unsafe baseline path: {value!r}")
    if str(path) != value:
        raise ValueError(f"noncanonical baseline path: {value!r}")
    return value


def valid_digest(value: object) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise ValueError("invalid baseline SHA-256 digest")
    return value


def file_sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_history(root: pathlib.Path, manifest_path: pathlib.Path) -> dict[str, set[str]]:
    if not manifest_path.is_file() or not root.is_dir():
        return {}
    with manifest_path.open("rb") as stream:
        manifest = plistlib.load(stream)
    if not isinstance(manifest, dict) or manifest.get("Version") not in {1, 2}:
        raise ValueError("unsupported prior baseline manifest")
    executables = manifest.get("Executables")
    if not isinstance(executables, dict) or not executables:
        raise ValueError("prior baseline manifest has no executables")

    history: dict[str, set[str]] = {}
    for raw_relative, raw_digests in executables.items():
        relative = safe_relative(raw_relative)
        values = [raw_digests] if isinstance(raw_digests, str) else raw_digests
        if not isinstance(values, list) or not values:
            raise ValueError(f"invalid digest history for {relative}")
        digests = {valid_digest(value) for value in values}
        candidate = root.joinpath(*pathlib.PurePosixPath(relative).parts)
        try:
            status = candidate.lstat()
        except FileNotFoundError:
            status = None
        if status is not None and stat.S_ISREG(status.st_mode):
            digests.add(file_sha256(candidate))
        history[relative] = digests
    return history


def write_history(destination: pathlib.Path, history: dict[str, set[str]]) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            for relative in sorted(history):
                for digest in sorted(history[relative]):
                    stream.write(f"{digest}\t{relative}\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    if len(sys.argv) != 4:
        raise SystemExit(
            "usage: prepare_runtime_baseline_history.py ROOT MANIFEST OUTPUT"
        )
    root, manifest, output = map(pathlib.Path, sys.argv[1:])
    try:
        history = load_history(root, manifest)
        write_history(output, history)
    except (OSError, ValueError, plistlib.InvalidFileException) as error:
        raise SystemExit(f"runtime baseline history failed: {error}") from error
    print(
        f"prepared runtime baseline history: paths={len(history)} "
        f"hashes={sum(len(values) for values in history.values())}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
