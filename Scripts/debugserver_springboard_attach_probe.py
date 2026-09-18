#!/usr/bin/env python3
"""Bounded direct-debugserver attach probe for one exact SpringBoard PID.

This tests whether Apple's Developer Disk Image debugserver grants a different
live debugging policy than an entitled root process calling PT_ATTACHEXC.  It
does not write target memory or registers.  The attached process is validated
by PID, uid, process name, exact executable path, Mach-O type, architecture,
and in-memory UUID before the session detaches.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import struct
import sys
import uuid

from pymobiledevice3.remote.remote_service_discovery import (
    RemoteServiceDiscoveryService,
)

from debugserver_carrier_spawn import (
    CPU_SUBTYPE_ARM64E,
    CPU_TYPE_ARM64,
    DEBUG_PROXY_SERVICE,
    GDBRemote,
    LC_UUID,
    MAX_LOAD_COMMAND_BYTES,
    MAX_LOAD_COMMANDS,
    MH_EXECUTE,
    MH_MAGIC_64,
    ProtocolError,
    StopState,
    expect_ok,
    parse_key_values,
    read_memory,
)


SPRINGBOARD_PATH = "/System/Library/CoreServices/SpringBoard.app/SpringBoard"
SPRINGBOARD_NAME = "SpringBoard"
MOBILE_UID = 501


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--timeout", type=float, default=20.0)
    return parser.parse_args()


def decode_process_name(value: str) -> str:
    if not value:
        return ""
    try:
        return bytes.fromhex(value).decode("utf-8", "strict")
    except (UnicodeDecodeError, ValueError):
        return value


def find_exact_image(response: str) -> tuple[int, str]:
    pattern = re.compile(
        r'\{"load_address":(?P<address>[0-9]+),'
        r'"mod_date":[0-9]+,'
        r'"pathname":(?P<path>"(?:\\.|[^"\\])*")',
    )
    matches: list[tuple[int, str]] = []
    for match in pattern.finditer(response):
        try:
            path = json.loads(match.group("path"))
        except json.JSONDecodeError as error:
            raise ProtocolError(
                "invalid image pathname in debugserver inventory"
            ) from error
        if path == SPRINGBOARD_PATH:
            matches.append((int(match.group("address")), path))
    if len(matches) != 1:
        raise ProtocolError(
            "expected exactly one exact SpringBoard image; "
            f"found={len(matches)}"
        )
    return matches[0]


async def validate_image(remote: GDBRemote, base: int) -> uuid.UUID:
    header = await read_memory(remote, base, 32)
    (
        magic,
        cpu_type,
        cpu_subtype,
        file_type,
        command_count,
        command_bytes,
        _flags,
        _reserved,
    ) = struct.unpack("<IiiIIIII", header)
    if magic != MH_MAGIC_64 or cpu_type != CPU_TYPE_ARM64:
        raise ProtocolError("SpringBoard has an invalid in-memory Mach-O header")
    if (cpu_subtype & 0x00FFFFFF) != CPU_SUBTYPE_ARM64E:
        raise ProtocolError(
            f"SpringBoard is not arm64e: subtype=0x{cpu_subtype:x}"
        )
    if file_type != MH_EXECUTE:
        raise ProtocolError(f"SpringBoard is not MH_EXECUTE: {file_type}")
    if not (0 < command_count <= MAX_LOAD_COMMANDS) or not (
        0 < command_bytes <= MAX_LOAD_COMMAND_BYTES
    ):
        raise ProtocolError("SpringBoard has invalid load-command bounds")

    commands = await read_memory(remote, base + 32, command_bytes)
    cursor = 0
    observed_uuid: uuid.UUID | None = None
    for _ in range(command_count):
        if cursor + 8 > len(commands):
            raise ProtocolError("SpringBoard load commands are truncated")
        command, command_size = struct.unpack_from("<II", commands, cursor)
        if command_size < 8 or cursor + command_size > len(commands):
            raise ProtocolError("SpringBoard has an invalid load command")
        if command == LC_UUID:
            if command_size != 24 or observed_uuid is not None:
                raise ProtocolError("SpringBoard has invalid UUID commands")
            observed_uuid = uuid.UUID(
                bytes=commands[cursor + 8 : cursor + 24]
            )
        cursor += command_size
    if cursor != len(commands) or observed_uuid is None:
        raise ProtocolError("SpringBoard has no unique in-memory UUID")
    return observed_uuid


async def run(args: argparse.Namespace) -> int:
    if args.pid <= 1:
        raise ProtocolError("refusing PID 1 or an invalid PID")
    if args.timeout <= 0 or args.timeout > 60:
        raise ProtocolError("timeout must be in the range (0, 60]")

    async with RemoteServiceDiscoveryService((args.host, args.port)) as rsd:
        connection = await rsd.create_service_connection(
            rsd.get_service_port(DEBUG_PROXY_SERVICE)
        )
        remote = GDBRemote(connection, args.timeout)
        attached = False
        primary_error: BaseException | None = None
        try:
            await connection.sendall(b"+")
            print(f"debugserver-supported={await remote.command('qSupported')}")
            optional = await remote.command("QEnableErrorStrings")
            if optional not in {"", "OK"}:
                raise ProtocolError(
                    f"QEnableErrorStrings failed: {optional!r}"
                )

            attach_response = await remote.command(f"vAttach;{args.pid:x}")
            state = StopState.parse(attach_response)
            attached = True
            process_response = await remote.command("qProcessInfo")
            process = parse_key_values(process_response)
            if "pid" not in process:
                raise ProtocolError(
                    f"qProcessInfo omitted PID: {process_response!r}"
                )
            actual_pid = int(process["pid"], 16)
            name = decode_process_name(process.get("name", ""))
            if actual_pid != args.pid or actual_pid <= 1:
                raise ProtocolError(
                    f"attached PID mismatch: expected={args.pid} got={actual_pid}"
                )
            if name != SPRINGBOARD_NAME:
                raise ProtocolError(
                    f"attached process is not SpringBoard: {name!r}"
                )
            for key in ("uid", "euid"):
                if key in process and int(process[key], 16) != MOBILE_UID:
                    raise ProtocolError(
                        f"unexpected SpringBoard {key}: {process[key]}"
                    )

            request = json.dumps(
                {"fetch_all_solibs": True}, separators=(",", ":")
            )
            inventory = await remote.command(
                "jGetLoadedDynamicLibrariesInfos:" + request
            )
            image_base, image_path = find_exact_image(inventory)
            observed_uuid = await validate_image(remote, image_base)
            print(
                "springboard-debugserver-attach=success "
                f"pid={actual_pid} thread={state.thread} signal={state.signal} "
                f"pc=0x{state.pc:x} base=0x{image_base:x} "
                f"uuid={observed_uuid} path={image_path}"
            )
            await expect_ok(remote, "D")
            attached = False
            print(f"springboard-debugserver-detach=success pid={actual_pid}")
            return 0
        except BaseException as error:
            primary_error = error
            raise
        finally:
            cleanup_errors: list[str] = []
            if attached:
                try:
                    await expect_ok(remote, "D")
                    print("cleanup-detach=success")
                except BaseException as error:
                    cleanup_errors.append(f"detach: {error}")
            try:
                await connection.close()
            except BaseException as error:
                cleanup_errors.append(f"connection close: {error}")
            if cleanup_errors:
                message = "; ".join(cleanup_errors)
                print(f"cleanup-error={message}", file=sys.stderr)
                if primary_error is None:
                    raise ProtocolError(message)


def main() -> int:
    args = parse_args()
    try:
        return asyncio.run(run(args))
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
