#!/usr/bin/env python3

import argparse
import json
import struct
from pathlib import Path


FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02
NLIST_64_SIZE = 16
RETURN_ZERO = struct.pack("<II", 0x52800000, 0xD65F03C0)


def slices(data: bytearray) -> list[tuple[int, int]]:
    if len(data) < 8:
        raise ValueError("file is too small")
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        return [(0, len(data))]
    count = struct.unpack_from(">I", data, 4)[0]
    entry_size = 32 if magic == FAT_MAGIC_64 else 20
    result = []
    for index in range(count):
        offset = 8 + index * entry_size
        if offset + entry_size > len(data):
            raise ValueError("fat architecture table is truncated")
        if magic == FAT_MAGIC_64:
            _, _, slice_offset, slice_size, _, _ = struct.unpack_from(
                ">IIQQII", data, offset
            )
        else:
            _, _, slice_offset, slice_size, _ = struct.unpack_from(
                ">IIIII", data, offset
            )
        if slice_offset + slice_size > len(data):
            raise ValueError("fat slice is outside the file")
        result.append((slice_offset, slice_size))
    return result


def patch_slice(data: bytearray, base: int, size: int, symbol: bytes) -> dict:
    if size < 32 or struct.unpack_from("<I", data, base)[0] != MH_MAGIC_64:
        raise ValueError("slice is not a 64-bit little-endian Mach-O")
    _, cpu_type, cpu_subtype, _, command_count, command_bytes, _, _ = (
        struct.unpack_from("<IiiIIIII", data, base)
    )
    cursor = base + 32
    command_end = cursor + command_bytes
    if command_end > base + size:
        raise ValueError("load commands are outside the slice")
    segments = []
    symtab = None
    for _ in range(command_count):
        if cursor + 8 > command_end:
            raise ValueError("load command header is truncated")
        command, command_size = struct.unpack_from("<II", data, cursor)
        if command_size < 8 or cursor + command_size > command_end:
            raise ValueError("invalid load command size")
        if command == LC_SEGMENT_64:
            if command_size < 72:
                raise ValueError("segment command is truncated")
            values = struct.unpack_from("<II16sQQQQiiII", data, cursor)
            segments.append((values[3], values[4], values[5], values[6]))
        elif command == LC_SYMTAB:
            if command_size < 24 or symtab is not None:
                raise ValueError("invalid or duplicate symbol table")
            symtab = struct.unpack_from("<IIIIII", data, cursor)[2:]
        cursor += command_size
    if symtab is None:
        raise ValueError("slice has no symbol table")
    symbol_offset, symbol_count, string_offset, string_size = symtab
    if symbol_offset + symbol_count * NLIST_64_SIZE > size:
        raise ValueError("symbol table is outside the slice")
    if string_offset + string_size > size:
        raise ValueError("string table is outside the slice")
    symbol_value = None
    for index in range(symbol_count):
        entry = base + symbol_offset + index * NLIST_64_SIZE
        string_index, _, _, _, value = struct.unpack_from("<IBBHQ", data, entry)
        if string_index >= string_size:
            continue
        start = base + string_offset + string_index
        end = data.find(b"\0", start, base + string_offset + string_size)
        if end >= 0 and bytes(data[start:end]) == symbol:
            symbol_value = value
            break
    if symbol_value is None:
        raise ValueError(f"symbol not found: {symbol.decode()}")
    file_offset = None
    for vm_address, vm_size, segment_offset, file_size in segments:
        if vm_address <= symbol_value < vm_address + min(vm_size, file_size):
            file_offset = base + segment_offset + symbol_value - vm_address
            break
    if file_offset is None or file_offset + len(RETURN_ZERO) > base + size:
        raise ValueError("symbol has no file-backed segment")
    previous = bytes(data[file_offset:file_offset + len(RETURN_ZERO)])
    if previous == RETURN_ZERO:
        raise ValueError("symbol already returns zero")
    data[file_offset:file_offset + len(RETURN_ZERO)] = RETURN_ZERO
    return {
        "cpuType": cpu_type,
        "cpuSubtype": cpu_subtype,
        "symbolAddress": f"0x{symbol_value:x}",
        "fileOffset": file_offset,
        "previousBytes": previous.hex(),
        "patchedBytes": RETURN_ZERO.hex(),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("symbol")
    arguments = parser.parse_args()
    symbol = arguments.symbol.encode()
    data = bytearray(arguments.path.read_bytes())
    results = [patch_slice(data, base, size, symbol)
               for base, size in slices(data)]
    arguments.path.write_bytes(data)
    print(json.dumps({"path": str(arguments.path), "slices": results},
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
