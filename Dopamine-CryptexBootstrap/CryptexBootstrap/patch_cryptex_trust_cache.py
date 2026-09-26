#!/usr/bin/env python3
"""Add exact SHA-256 CDHashes to a Cryptex1 generic trust cache."""

from __future__ import annotations

import argparse
import hashlib
import json
import plistlib
import tempfile
from pathlib import Path


ENTRY_SIZE = 22
SHA256_HASH_TYPE = 2
BEFORE_AND_AFTER_REM = 0xC0


def decode_length(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    width = first & 0x7F
    if width == 0 or width > 4:
        raise ValueError("unsupported DER length")
    start = offset + 1
    end = start + width
    if end > len(data):
        raise ValueError("truncated DER length")
    return int.from_bytes(data[start:end], "big"), end


def encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def parse_tlv(data: bytes, offset: int) -> tuple[int, bytes, bytes, int]:
    if offset >= len(data):
        raise ValueError("truncated DER object")
    tag = data[offset]
    length, value_offset = decode_length(data, offset + 1)
    end = value_offset + length
    if end > len(data):
        raise ValueError("truncated DER value")
    return tag, data[value_offset:end], data[offset:end], end


def encode_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + encode_length(len(value)) + value


def patch_gtcd(gtcd: bytes, cdhashes: list[str]) -> tuple[bytes, list[str]]:
    tag, sequence, _, end = parse_tlv(gtcd, 0)
    if tag != 0x30 or end != len(gtcd):
        raise ValueError("gtcd is not one DER sequence")

    children: list[tuple[int, bytes, bytes]] = []
    offset = 0
    while offset < len(sequence):
        child_tag, value, raw, offset = parse_tlv(sequence, offset)
        children.append((child_tag, value, raw))
    if [child[0] for child in children] != [0x16, 0x16, 0x16, 0x04]:
        raise ValueError("unexpected IM4P structure")
    if [children[index][1] for index in range(3)] != [
        b"IM4P",
        b"gtcd",
        b"cptx",
    ]:
        raise ValueError("unexpected IM4P identity")

    payload = children[3][1]
    if len(payload) < 24 or int.from_bytes(payload[:4], "little") != 1:
        raise ValueError("unsupported trust-cache payload")
    count = int.from_bytes(payload[20:24], "little")
    entries_bytes = payload[24:]
    if len(entries_bytes) != count * ENTRY_SIZE:
        raise ValueError("trust-cache entry count does not match payload")

    entries = {
        entries_bytes[index : index + ENTRY_SIZE]
        for index in range(0, len(entries_bytes), ENTRY_SIZE)
    }
    for cdhash in cdhashes:
        normalized = cdhash.lower()
        if len(normalized) != 40:
            raise ValueError(f"invalid CDHash length: {cdhash}")
        try:
            digest = bytes.fromhex(normalized)
        except ValueError as error:
            raise ValueError(f"invalid CDHash: {cdhash}") from error
        entries.add(digest + bytes([SHA256_HASH_TYPE, BEFORE_AND_AFTER_REM]))

    ordered = sorted(entries, key=lambda entry: (entry[:20], entry[20:]))
    updated_payload = (
        payload[:20]
        + len(ordered).to_bytes(4, "little")
        + b"".join(ordered)
    )
    updated_sequence = b"".join(child[2] for child in children[:3])
    updated_sequence += encode_tlv(0x04, updated_payload)
    updated = encode_tlv(0x30, updated_sequence)
    return updated, [entry[:20].hex() for entry in ordered]


def atomic_write(path: Path, data: bytes) -> None:
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(data)
        stream.flush()
    temporary.chmod(path.stat().st_mode)
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--build-summary", required=True, type=Path)
    parser.add_argument("--cdhash", required=True, action="append")
    args = parser.parse_args()

    restore = args.bundle / "Restore"
    manifest_path = restore / "BuildManifest.plist"
    manifest = plistlib.loads(manifest_path.read_bytes())
    identities = manifest.get("BuildIdentities")
    if not isinstance(identities, list) or len(identities) != 1:
        raise ValueError("expected one Cryptex build identity")
    identity = identities[0]
    component = identity["Manifest"]["Cryptex1,GenericTrustCache"]
    gtcd_path = restore / component["Info"]["Path"]

    updated_gtcd, entries = patch_gtcd(gtcd_path.read_bytes(), args.cdhash)
    atomic_write(gtcd_path, updated_gtcd)
    component["Digest"] = hashlib.sha384(updated_gtcd).digest()
    manifest_bytes = plistlib.dumps(
        manifest, fmt=plistlib.FMT_XML, sort_keys=False
    )
    atomic_write(manifest_path, manifest_bytes)

    summary = json.loads(args.build_summary.read_text())
    summary["trustCache"]["entryCount"] = len(entries)
    summary["trustCache"]["sha256"] = hashlib.sha256(updated_gtcd).hexdigest()
    summary["trustCache"]["cdhashes"] = entries
    atomic_write(
        args.build_summary,
        (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode(),
    )
    print(
        json.dumps(
            {
                "bundle": str(args.bundle),
                "entryCount": len(entries),
                "added": [value.lower() for value in args.cdhash],
                "gtcdSha256": hashlib.sha256(updated_gtcd).hexdigest(),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
