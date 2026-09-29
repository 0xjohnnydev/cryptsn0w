"""Hash build artifacts and write the existing Cryptex build summary format."""

import argparse
import hashlib
import json
import re
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("summary", "bundle", "identifier", "version", "trustcache", "dump"):
        parser.add_argument(name)
    parser.add_argument("count", type=int)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--ssh-stage", action="store_true")
    mode.add_argument("--image-bytes", type=int)
    args = parser.parse_args()

    cdhashes = re.findall(
        r"^([0-9a-f]{40})\s+", Path(args.dump).read_text(), re.MULTILINE
    )
    if len(cdhashes) != args.count:
        prefix = "stage " if args.ssh_stage else ""
        raise SystemExit(f"{prefix}trust-cache count mismatch")
    summary = {
        "identifier": args.identifier,
        "version": args.version,
        "bundle": str(Path(args.bundle).resolve()),
        "trustCache": {
            "path": args.trustcache,
            "sha256": sha256_file(Path(args.trustcache)),
            "entryCount": args.count,
            "cdhashes": cdhashes,
        },
    }
    if args.ssh_stage:
        summary["stage"] = "ssh"
    else:
        summary["imageBytes"] = args.image_bytes
    Path(args.summary).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
