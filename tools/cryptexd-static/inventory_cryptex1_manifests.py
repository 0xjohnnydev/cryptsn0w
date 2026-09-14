#!/usr/bin/env python3
"""Print unique Cryptex1 identity tuples and personalized component digests."""

from __future__ import annotations

import argparse
import json
import plistlib
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifests", nargs="+", type=Path)
    args = parser.parse_args()
    rows = []
    for path in args.manifests:
        try:
            manifest = plistlib.loads(path.read_bytes())
        except Exception as exc:
            rows.append({"path": str(path), "error": str(exc)})
            continue
        for index, identity in enumerate(manifest.get("BuildIdentities", [])):
            if "Cryptex1,Type" not in identity:
                continue
            components = {}
            for key, entry in identity.get("Manifest", {}).items():
                if key.startswith("Cryptex1,"):
                    digest = entry.get("Digest")
                    components[key] = {
                        "personalize": entry.get("Info", {}).get("Personalize"),
                        "digest": digest.hex() if isinstance(digest, bytes) else digest,
                        "path": entry.get("Info", {}).get("Path"),
                    }
            rows.append({
                "path": str(path),
                "index": index,
                "variant": identity.get("Info", {}).get("Variant"),
                "board": identity.get("ApBoardID"),
                "chip": identity.get("ApChipID"),
                "securityDomain": identity.get("ApSecurityDomain"),
                "cryptex": {
                    key: value for key, value in identity.items()
                    if key.startswith("Cryptex1,") and key != "Manifest"
                },
                "components": components,
            })
    print(json.dumps(rows, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
