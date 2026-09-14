#!/usr/bin/env python3
"""Point the first APFS volume's newest superblock at another sealed volume.

This is a narrow host-image probe for the APFS revert-to-superblock mount path.
It discovers both OIDs from the newest container checkpoint, validates every
object checksum it uses, and updates only a caller-supplied copy of the image.
"""

from __future__ import annotations

import argparse
import json
import os
import struct
from pathlib import Path

from patch_apfs_max_filesystems import BLOCK_SIZE, fletcher64


def scan_objects(image: Path) -> list[tuple[int, bytes]]:
    objects: list[tuple[int, bytes]] = []
    with image.open("rb") as stream:
        block_index = 0
        while block := stream.read(BLOCK_SIZE):
            if len(block) != BLOCK_SIZE:
                raise SystemExit(f"short final block at {block_index}")
            if block[0x20:0x24] in (b"NXSB", b"APSB"):
                stored = struct.unpack_from("<Q", block, 0)[0]
                actual = fletcher64(block)
                if stored != actual:
                    raise SystemExit(
                        f"block {block_index} has invalid checksum: "
                        f"stored=0x{stored:016x} actual=0x{actual:016x}"
                    )
                objects.append((block_index, block))
            block_index += 1
    return objects


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("image", type=Path)
    args = parser.parse_args()

    image = args.image.resolve(strict=True)
    if not image.is_file() or image.stat().st_size % BLOCK_SIZE:
        raise SystemExit("image must be a regular file with a 4096-byte-aligned size")

    objects = scan_objects(image)
    nx = [(index, block) for index, block in objects if block[0x20:0x24] == b"NXSB"]
    newest_nx_xid = max(struct.unpack_from("<Q", block, 0x10)[0] for _, block in nx)
    newest_nx = next(
        block for _, block in nx if struct.unpack_from("<Q", block, 0x10)[0] == newest_nx_xid
    )
    source_oid, target_oid = struct.unpack_from("<QQ", newest_nx, 0xB8)
    if source_oid == 0 or target_oid == 0:
        raise SystemExit("newest NXSB does not contain two volume OIDs")

    apsb = [(index, block) for index, block in objects if block[0x20:0x24] == b"APSB"]

    def newest_for_oid(oid: int) -> tuple[int, bytes]:
        matches = [
            (index, block)
            for index, block in apsb
            if struct.unpack_from("<Q", block, 0x08)[0] == oid
        ]
        if not matches:
            raise SystemExit(f"no APSB found for volume OID {oid}")
        return max(matches, key=lambda item: struct.unpack_from("<Q", item[1], 0x10)[0])

    source_index, source = newest_for_oid(source_oid)
    target_index, target = newest_for_oid(target_oid)
    source_revert = struct.unpack_from("<QQ", source, 0xA0)
    if source_revert != (0, 0):
        raise SystemExit(f"source APSB already has a revert target: {source_revert}")

    target_xid = struct.unpack_from("<Q", target, 0x10)[0]
    target_sblock_oid = struct.unpack_from("<Q", target, 0x08)[0]
    patched = bytearray(source)
    struct.pack_into("<QQ", patched, 0xA0, target_xid, target_sblock_oid)
    struct.pack_into("<Q", patched, 0, fletcher64(patched))

    with image.open("r+b") as stream:
        stream.seek(source_index * BLOCK_SIZE)
        stream.write(patched)
        stream.flush()
        os.fsync(stream.fileno())

    print(
        json.dumps(
            {
                "image": str(image),
                "source": {"block": source_index, "oid": source_oid},
                "target": {
                    "block": target_index,
                    "oid": target_sblock_oid,
                    "xid": target_xid,
                },
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
