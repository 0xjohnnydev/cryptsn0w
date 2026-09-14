#!/usr/bin/env python3
"""Mark one undefined Mach-O symbol as a weak import in place."""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path


MH_MAGIC_64 = 0xFEEDFACF
MH_EXECUTE = 2
LC_SYMTAB = 2
LC_DYLD_CHAINED_FIXUPS = 0x80000034
N_TYPE = 0x0E
N_UNDF = 0x00
N_EXT = 0x01
N_WEAK_REF = 0x0040


def patch(path: Path, symbol: str) -> dict[str, object]:
    data = bytearray(path.read_bytes())
    if len(data) < 32:
        raise ValueError("file is shorter than a Mach-O 64 header")
    magic, _cpu, _subcpu, filetype, ncmds, sizeofcmds, _flags, _reserved = (
        struct.unpack_from("<8I", data, 0)
    )
    if magic != MH_MAGIC_64:
        raise ValueError(f"expected little-endian MH_MAGIC_64, got 0x{magic:08x}")
    if filetype != MH_EXECUTE:
        raise ValueError(f"expected MH_EXECUTE, got filetype {filetype}")
    if 32 + sizeofcmds > len(data):
        raise ValueError("load commands extend beyond the file")

    symtab: tuple[int, int, int, int] | None = None
    chained_fixups: tuple[int, int] | None = None
    command_offset = 32
    for _ in range(ncmds):
        if command_offset + 8 > 32 + sizeofcmds:
            raise ValueError("truncated Mach-O load command")
        command, command_size = struct.unpack_from("<2I", data, command_offset)
        if command_size < 8 or command_offset + command_size > 32 + sizeofcmds:
            raise ValueError("invalid Mach-O load command size")
        if command == LC_SYMTAB:
            if command_size < 24 or symtab is not None:
                raise ValueError("invalid or duplicate LC_SYMTAB")
            symtab = struct.unpack_from("<4I", data, command_offset + 8)
        elif command == LC_DYLD_CHAINED_FIXUPS:
            if command_size < 16 or chained_fixups is not None:
                raise ValueError("invalid or duplicate LC_DYLD_CHAINED_FIXUPS")
            chained_fixups = struct.unpack_from("<2I", data, command_offset + 8)
        command_offset += command_size
    if symtab is None:
        raise ValueError("Mach-O has no LC_SYMTAB")
    if chained_fixups is None:
        raise ValueError("Mach-O has no LC_DYLD_CHAINED_FIXUPS")

    symbol_offset, symbol_count, string_offset, string_size = symtab
    if symbol_offset + symbol_count * 16 > len(data):
        raise ValueError("symbol table extends beyond the file")
    if string_offset + string_size > len(data):
        raise ValueError("string table extends beyond the file")

    matches: list[tuple[int, int]] = []
    for index in range(symbol_count):
        entry_offset = symbol_offset + index * 16
        string_index, symbol_type, _section, description, value = (
            struct.unpack_from("<IBBHQ", data, entry_offset)
        )
        if string_index >= string_size:
            raise ValueError(f"symbol {index} has an invalid string index")
        name_start = string_offset + string_index
        name_end = data.find(b"\0", name_start, string_offset + string_size)
        if name_end < 0:
            raise ValueError(f"symbol {index} has an unterminated name")
        name = data[name_start:name_end].decode("utf-8", errors="strict")
        if name == symbol:
            if symbol_type & N_TYPE != N_UNDF or not symbol_type & N_EXT or value != 0:
                raise ValueError(f"{symbol} is not an external undefined symbol")
            matches.append((entry_offset, description))
    if len(matches) != 1:
        raise ValueError(f"expected exactly one {symbol}, found {len(matches)}")

    entry_offset, old_description = matches[0]
    if old_description & N_WEAK_REF:
        raise ValueError(f"{symbol} is already a weak import")
    new_description = old_description | N_WEAK_REF
    struct.pack_into("<H", data, entry_offset + 6, new_description)

    fixups_offset, fixups_size = chained_fixups
    if fixups_offset + fixups_size > len(data) or fixups_size < 28:
        raise ValueError("chained-fixups data extends beyond the file")
    (
        fixups_version,
        _starts_offset,
        imports_offset,
        symbols_offset,
        imports_count,
        imports_format,
        symbols_format,
    ) = struct.unpack_from("<7I", data, fixups_offset)
    if fixups_version != 0:
        raise ValueError(f"unsupported chained-fixups version {fixups_version}")
    if symbols_format != 0:
        raise ValueError(f"unsupported chained symbols format {symbols_format}")
    entry_sizes = {1: 4, 2: 8, 3: 16}
    import_entry_size = entry_sizes.get(imports_format)
    if import_entry_size is None:
        raise ValueError(f"unsupported chained imports format {imports_format}")
    imports_start = fixups_offset + imports_offset
    symbols_start = fixups_offset + symbols_offset
    fixups_end = fixups_offset + fixups_size
    if (
        imports_start + imports_count * import_entry_size > fixups_end
        or not fixups_offset <= symbols_start < fixups_end
    ):
        raise ValueError("invalid chained import or symbols offsets")

    chained_matches: list[tuple[int, int, int]] = []
    for index in range(imports_count):
        chained_offset = imports_start + index * import_entry_size
        if imports_format in (1, 2):
            raw = struct.unpack_from("<I", data, chained_offset)[0]
            weak_bit = 1 << 8
            name_offset = raw >> 9
        else:
            raw = struct.unpack_from("<Q", data, chained_offset)[0]
            weak_bit = 1 << 16
            name_offset = raw >> 32
        name_start = symbols_start + name_offset
        if not symbols_start <= name_start < fixups_end:
            raise ValueError(f"chained import {index} has an invalid name offset")
        name_end = data.find(b"\0", name_start, fixups_end)
        if name_end < 0:
            raise ValueError(f"chained import {index} has an unterminated name")
        name = data[name_start:name_end].decode("utf-8", errors="strict")
        if name == symbol:
            chained_matches.append((chained_offset, raw, weak_bit))
    if len(chained_matches) != 1:
        raise ValueError(
            f"expected exactly one chained import for {symbol}, "
            f"found {len(chained_matches)}"
        )
    chained_offset, chained_raw, chained_weak_bit = chained_matches[0]
    if chained_raw & chained_weak_bit:
        raise ValueError(f"chained import for {symbol} is already weak")
    if imports_format in (1, 2):
        struct.pack_into("<I", data, chained_offset, chained_raw | chained_weak_bit)
    else:
        struct.pack_into("<Q", data, chained_offset, chained_raw | chained_weak_bit)

    path.write_bytes(data)
    return {
        "path": str(path),
        "symbol": symbol,
        "oldDescription": f"0x{old_description:04x}",
        "newDescription": f"0x{new_description:04x}",
        "chainedImportsFormat": imports_format,
        "chainedWeakImport": True,
        "weakImport": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("symbol")
    args = parser.parse_args()
    print(json.dumps(patch(args.path, args.symbol), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
