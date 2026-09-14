#!/usr/bin/env python3
"""Patch nx_max_file_systems in every valid NXSB checkpoint of an APFS image.

This is intentionally a narrow host-side experiment helper.  It refuses to
patch an image unless every discovered NXSB has the expected current value and
a valid Fletcher-64 object checksum.
"""

from __future__ import annotations

import argparse
import json
import os
import struct
from pathlib import Path


BLOCK_SIZE = 4096
NX_MAGIC_OFFSET = 0x20
NX_MAX_FILE_SYSTEMS_OFFSET = 0xB4
NX_FILE_SYSTEM_OIDS_OFFSET = 0xB8
FLETCHER_MODULUS = 0xFFFFFFFF


def fletcher64(block: bytes) -> int:
    """Return the APFS object checksum for one 4096-byte block."""
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"expected {BLOCK_SIZE} bytes, got {len(block)}")

    sum1 = 0
    sum2 = 0
    for (word,) in struct.iter_unpack("<I", block[8:]):
        sum1 = (sum1 + word) % FLETCHER_MODULUS
        sum2 = (sum2 + sum1) % FLETCHER_MODULUS

    check1 = (FLETCHER_MODULUS - ((sum1 + sum2) % FLETCHER_MODULUS)) % FLETCHER_MODULUS
    check2 = (FLETCHER_MODULUS - ((sum1 + check1) % FLETCHER_MODULUS)) % FLETCHER_MODULUS
    return (check2 << 32) | check1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("image", type=Path)
    parser.add_argument("--from-value", type=int, default=1)
    parser.add_argument("--to-value", type=int, default=100)
    parser.add_argument(
        "--swap-first-two-current",
        action="store_true",
        help="swap fs_oid slots 0/1 only in checkpoints having the newest transaction ID",
    )
    args = parser.parse_args()

    image = args.image.resolve(strict=True)
    if not image.is_file():
        raise SystemExit(f"not a regular file: {image}")
    if image.stat().st_size % BLOCK_SIZE:
        raise SystemExit("image size is not a multiple of 4096 bytes")

    discovered: list[tuple[int, int, bytes]] = []
    with image.open("rb") as stream:
        block_index = 0
        while block := stream.read(BLOCK_SIZE):
            if len(block) != BLOCK_SIZE:
                raise SystemExit(f"short final block at index {block_index}")
            if block[NX_MAGIC_OFFSET : NX_MAGIC_OFFSET + 4] == b"NXSB":
                stored_checksum = struct.unpack_from("<Q", block, 0)[0]
                actual_checksum = fletcher64(block)
                if stored_checksum != actual_checksum:
                    raise SystemExit(
                        f"NXSB block {block_index} has invalid checksum: "
                        f"stored=0x{stored_checksum:016x} actual=0x{actual_checksum:016x}"
                    )
                current = struct.unpack_from("<I", block, NX_MAX_FILE_SYSTEMS_OFFSET)[0]
                if current != args.from_value:
                    raise SystemExit(
                        f"NXSB block {block_index} has nx_max_file_systems={current}; "
                        f"expected {args.from_value}"
                    )
                transaction_id = struct.unpack_from("<Q", block, 0x10)[0]
                discovered.append((block_index, transaction_id, block))
            block_index += 1

    if not discovered:
        raise SystemExit("no valid NXSB blocks found")

    newest_transaction_id = max(transaction_id for _, transaction_id, _ in discovered)
    patched = []
    swapped = []
    with image.open("r+b") as stream:
        for block_index, transaction_id, original in discovered:
            block = bytearray(original)
            struct.pack_into("<I", block, NX_MAX_FILE_SYSTEMS_OFFSET, args.to_value)
            if args.swap_first_two_current and transaction_id == newest_transaction_id:
                first, second = struct.unpack_from("<QQ", block, NX_FILE_SYSTEM_OIDS_OFFSET)
                if first == 0 or second == 0:
                    raise SystemExit(
                        f"newest NXSB block {block_index} does not contain two volume OIDs"
                    )
                struct.pack_into("<QQ", block, NX_FILE_SYSTEM_OIDS_OFFSET, second, first)
                swapped.append(block_index)
            struct.pack_into("<Q", block, 0, fletcher64(block))
            stream.seek(block_index * BLOCK_SIZE)
            stream.write(block)
            patched.append(block_index)
        stream.flush()
        os.fsync(stream.fileno())

    print(
        json.dumps(
            {
                "image": str(image),
                "from": args.from_value,
                "to": args.to_value,
                "patchedNXSBBlocks": patched,
                "swappedCurrentNXSBBlocks": swapped,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
