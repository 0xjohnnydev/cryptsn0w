#!/usr/bin/env python3
'TSS/Cryptex personalization and installation details are redacted from this educational source release.'

from __future__ import annotations

if __name__ == "__main__":
    raise SystemExit('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


import argparse
import hashlib
import json
import plistlib
import tempfile
from pathlib import Path


ENTRY_SIZE = 22
SHA256_HASH_TYPE = None  # [REDACTED] Flow-specific parameters omitted.
BEFORE_AND_AFTER_REM = None  # [REDACTED] Flow-specific parameters omitted.


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
    # [REDACTED] Related request, payload, or installation helper omitted.
    raise RuntimeError('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


def atomic_write(path: Path, data: bytes) -> None:
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(data)
        stream.flush()
    temporary.chmod(path.stat().st_mode)
    temporary.replace(path)


def main() -> int:
    # [REDACTED] Related request, payload, or installation helper omitted.
    raise RuntimeError('TSS/Cryptex personalization and installation details are redacted from this educational source release.')


if __name__ == "__main__":
    raise SystemExit(main())
