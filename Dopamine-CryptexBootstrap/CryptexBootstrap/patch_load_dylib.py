#!/usr/bin/env python3

"""Add a fixed LC_LOAD_DYLIB command without moving Mach-O file data."""

from __future__ import annotations

import argparse
import pathlib
import struct


MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA

LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0x0C
LC_RPATH = 0x1C | 0x80000000
DYLIB_COMMANDS = {
    LC_LOAD_DYLIB,
    0x18 | 0x80000000,  # LC_LOAD_WEAK_DYLIB
    0x1F | 0x80000000,  # LC_REEXPORT_DYLIB
    0x20,               # LC_LAZY_LOAD_DYLIB
    0x23 | 0x80000000,  # LC_LOAD_UPWARD_DYLIB
}
MACH_HEADER_64_SIZE = 32
SEGMENT_COMMAND_64_SIZE = 72
SECTION_64_SIZE = 80
DYLIB_COMMAND_PREFIX_SIZE = 24


class MachOError(RuntimeError):
    pass


def aligned(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def fat_slices(data: bytearray) -> list[tuple[int, int]]:
    if len(data) < 4:
        raise MachOError("file is too small")
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic not in {FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64}:
        return [(0, len(data))]

    endian = ">" if magic in {FAT_MAGIC, FAT_MAGIC_64} else "<"
    is_64 = magic in {FAT_MAGIC_64, FAT_CIGAM_64}
    if len(data) < 8:
        raise MachOError("fat header is truncated")
    count = struct.unpack_from(f"{endian}I", data, 4)[0]
    if count == 0 or count > 64:
        raise MachOError(f"invalid fat architecture count: {count}")
    entry_size = 32 if is_64 else 20
    if 8 + count * entry_size > len(data):
        raise MachOError("fat architecture table is truncated")

    result: list[tuple[int, int]] = []
    cursor = 8
    for _ in range(count):
        if is_64:
            offset, size = struct.unpack_from(f"{endian}QQ", data, cursor + 8)
        else:
            offset, size = struct.unpack_from(f"{endian}II", data, cursor + 8)
        if offset > len(data) or size > len(data) - offset:
            raise MachOError("fat slice exceeds file bounds")
        result.append((offset, size))
        cursor += entry_size
    return result


def slice_endian(data: bytearray, offset: int) -> str:
    if offset + 4 > len(data):
        raise MachOError("Mach-O header is truncated")
    magic = struct.unpack_from("<I", data, offset)[0]
    if magic == MH_MAGIC_64:
        return "<"
    if magic == MH_CIGAM_64:
        return ">"
    raise MachOError(f"unsupported Mach-O magic at {offset:#x}: {magic:#x}")


def command_name(
    data: bytearray,
    cursor: int,
    size: int,
    endian: str,
    minimum_offset: int = DYLIB_COMMAND_PREFIX_SIZE,
) -> str | None:
    if size < minimum_offset:
        return None
    name_offset = struct.unpack_from(f"{endian}I", data, cursor + 8)[0]
    if name_offset < minimum_offset or name_offset >= size:
        raise MachOError("invalid dylib load-command name offset")
    start = cursor + name_offset
    limit = cursor + size
    terminator = data.find(b"\0", start, limit)
    if terminator < 0:
        raise MachOError("unterminated dylib load-command name")
    try:
        return bytes(data[start:terminator]).decode("utf-8")
    except UnicodeDecodeError as error:
        raise MachOError("non-UTF-8 dylib load-command name") from error


def replace_unused_rpath(
    data: bytearray,
    rpaths: list[tuple[int, int, str]],
    dylib_names: list[str],
    dylib: str,
    endian: str,
) -> bool:
    """Reuse the target's fixed 40-byte, otherwise-unused LC_RPATH slot.

    The iOS 27 SpringBoard launcher has only sixteen bytes between its load
    commands and __text, but it carries `@executable_path/Frameworks` despite
    having no @rpath dependency.  SBInject's compact `@loader_path/g` load fits
    that command exactly.  Refuse the transformation for every other layout.
    """
    if any(name.startswith("@rpath/") for name in dylib_names):
        raise MachOError("cannot reuse LC_RPATH while @rpath dependencies exist")
    candidates = [
        (cursor, size)
        for cursor, size, path in rpaths
        if path == "@executable_path/Frameworks"
    ]
    encoded = dylib.encode("utf-8") + b"\0"
    required = aligned(DYLIB_COMMAND_PREFIX_SIZE + len(encoded), 8)
    if len(candidates) != 1 or required > candidates[0][1]:
        return False
    cursor, command_size = candidates[0]
    data[cursor:cursor + command_size] = b"\0" * command_size
    struct.pack_into(
        f"{endian}IIIIII",
        data,
        cursor,
        LC_LOAD_DYLIB,
        command_size,
        DYLIB_COMMAND_PREFIX_SIZE,
        0,
        0,
        0,
    )
    start = cursor + DYLIB_COMMAND_PREFIX_SIZE
    data[start:start + len(encoded)] = encoded
    return True


def patch_slice(data: bytearray, offset: int, size: int, dylib: str) -> bool:
    endian = slice_endian(data, offset)
    if size < MACH_HEADER_64_SIZE:
        raise MachOError("Mach-O slice is too small")
    _, _, _, file_type, command_count, command_bytes, _, _ = struct.unpack_from(
        f"{endian}IIIIIIII", data, offset
    )
    if file_type != 2:  # MH_EXECUTE
        raise MachOError(f"Mach-O slice is not an executable: {file_type}")
    commands_start = offset + MACH_HEADER_64_SIZE
    commands_end = commands_start + command_bytes
    slice_end = offset + size
    if commands_end > slice_end:
        raise MachOError("Mach-O load commands exceed slice bounds")

    cursor = commands_start
    first_file_data = slice_end
    already_loaded = False
    rpaths: list[tuple[int, int, str]] = []
    dylib_names: list[str] = []
    for _ in range(command_count):
        if cursor + 8 > commands_end:
            raise MachOError("Mach-O load-command header is truncated")
        command, command_size = struct.unpack_from(f"{endian}II", data, cursor)
        if command_size < 8 or command_size > commands_end - cursor:
            raise MachOError("invalid Mach-O load-command size")
        if command in DYLIB_COMMANDS:
            name = command_name(data, cursor, command_size, endian)
            if name is not None:
                dylib_names.append(name)
                already_loaded |= name == dylib
        elif command == LC_RPATH:
            name = command_name(data, cursor, command_size, endian, 12)
            if name is not None:
                rpaths.append((cursor, command_size, name))
        if command == LC_SEGMENT_64:
            if command_size < SEGMENT_COMMAND_64_SIZE:
                raise MachOError("LC_SEGMENT_64 is truncated")
            file_offset, file_size = struct.unpack_from(
                f"{endian}QQ", data, cursor + 40
            )
            if file_offset and file_size:
                first_file_data = min(first_file_data, offset + file_offset)
            section_count = struct.unpack_from(f"{endian}I", data, cursor + 64)[0]
            if (
                SEGMENT_COMMAND_64_SIZE + section_count * SECTION_64_SIZE
                > command_size
            ):
                raise MachOError("LC_SEGMENT_64 section table is truncated")
            section_cursor = cursor + SEGMENT_COMMAND_64_SIZE
            for _ in range(section_count):
                section_offset = struct.unpack_from(
                    f"{endian}I", data, section_cursor + 48
                )[0]
                if section_offset:
                    first_file_data = min(
                        first_file_data, offset + section_offset
                    )
                section_cursor += SECTION_64_SIZE
        cursor += command_size
    if cursor != commands_end:
        raise MachOError("Mach-O load-command size does not match header")
    if already_loaded:
        return False

    encoded = dylib.encode("utf-8") + b"\0"
    command_size = aligned(DYLIB_COMMAND_PREFIX_SIZE + len(encoded), 8)
    new_end = commands_end + command_size
    if new_end > first_file_data or new_end > slice_end:
        if replace_unused_rpath(data, rpaths, dylib_names, dylib, endian):
            return True
        raise MachOError(
            f"insufficient load-command padding: need {command_size} bytes"
        )
    if any(data[commands_end:new_end]):
        raise MachOError("load-command padding is not empty")

    command = bytearray(command_size)
    struct.pack_into(
        f"{endian}IIIIII",
        command,
        0,
        LC_LOAD_DYLIB,
        command_size,
        DYLIB_COMMAND_PREFIX_SIZE,
        0,
        0,
        0,
    )
    command[DYLIB_COMMAND_PREFIX_SIZE:DYLIB_COMMAND_PREFIX_SIZE + len(encoded)] = (
        encoded
    )
    data[commands_end:new_end] = command
    struct.pack_into(f"{endian}I", data, offset + 16, command_count + 1)
    struct.pack_into(f"{endian}I", data, offset + 20, command_bytes + command_size)
    return True


def loaded_in_slice(data: bytearray, offset: int, size: int, dylib: str) -> bool:
    endian = slice_endian(data, offset)
    command_count, command_bytes = struct.unpack_from(
        f"{endian}II", data, offset + 16
    )
    cursor = offset + MACH_HEADER_64_SIZE
    end = cursor + command_bytes
    if end > offset + size:
        return False
    for _ in range(command_count):
        if cursor + 8 > end:
            return False
        command, command_size = struct.unpack_from(f"{endian}II", data, cursor)
        if command_size < 8 or cursor + command_size > end:
            return False
        if command in DYLIB_COMMANDS and command_name(
            data, cursor, command_size, endian
        ) == dylib:
            return True
        cursor += command_size
    return False


def patch_binary(path: pathlib.Path, dylib: str) -> bool:
    data = bytearray(path.read_bytes())
    slices = fat_slices(data)
    changed = False
    for offset, size in slices:
        changed |= patch_slice(data, offset, size, dylib)
    for offset, size in slices:
        if not loaded_in_slice(data, offset, size, dylib):
            raise MachOError("post-patch dylib verification failed")
    if changed:
        with path.open("r+b") as stream:
            stream.write(data)
            stream.truncate()
    return changed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("dylib")
    arguments = parser.parse_args()
    if (
        not arguments.dylib.startswith("/")
        and not arguments.dylib.startswith("@loader_path/")
    ) or "\0" in arguments.dylib:
        raise SystemExit(
            "dylib install name must be absolute or use @loader_path"
        )
    try:
        changed = patch_binary(arguments.binary, arguments.dylib)
    except (OSError, MachOError) as error:
        raise SystemExit(f"{arguments.binary}: {error}") from error
    print(f"Mach-O load dependency {'added' if changed else 'current'}: "
          f"{arguments.binary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
