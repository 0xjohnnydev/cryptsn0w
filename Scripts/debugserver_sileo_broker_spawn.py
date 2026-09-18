#!/usr/bin/env python3
"""Call the installed Sileo root broker through its bound spawn interposer.

The bridge is deliberately limited to fixed recovery and live-proof operations:

* install the already-uploaded SpringBoard live precursor at its fixed path;
* stage and start the fixed supervising resident carrier launcher without
  waiting for it to exit.
* export that launcher's fixed diagnostic log to the Media recovery path.
* export the fixed root-broker diagnostic log to its Media recovery path.
* inspect that fixed canary in one explicitly selected SpringBoard PID.

Before either operation, the script binds the attachment to the exact Sileo
PID, uid, executable UUID, in-memory Mach-O, imported stub bytes, bundle-local
broker image, and the live stub targets inside that broker image.  It restores
the stopped thread, removes its breakpoint, releases scratch memory, and
detaches on every bounded exit path.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import struct
import sys
import uuid
from dataclasses import dataclass

from pymobiledevice3.remote.remote_service_discovery import (
    RemoteServiceDiscoveryService,
)
from pymobiledevice3.remote.rsd_tunnel import PreferredRsdTunnel

from debugserver_carrier_spawn import (
    CPU_TYPE_ARM64,
    DEBUG_PROXY_SERVICE,
    GDBRemote,
    LC_SEGMENT_64,
    LC_UUID,
    MAX_LOAD_COMMAND_BYTES,
    MAX_LOAD_COMMANDS,
    MH_EXECUTE,
    MH_MAGIC_64,
    ProtocolError,
    SCRATCH_SIZE,
    StopState,
    allocate_scratch,
    build_spawn_payload,
    decode_hex_le,
    expect_ok,
    parse_key_values,
    read_memory,
    read_register,
    set_register,
    write_memory,
)


EXPECTED_SILEO_UUID = uuid.UUID("F6EEDC94-62C3-38E4-82DF-99ED2FBFD2FE")
EXPECTED_SILEO_SUFFIX = "/Sileo.app/Sileo"
BROKER_IMAGE_LEAF = "F/libzstd.1.dylib"
MH_DYLIB = 6

EXPECTED_BROKER_UUIDS = {
    uuid.UUID("F4418229-5CB5-377C-9B89-979E821F27FA"),
    uuid.UUID("8CCC6170-E98B-3008-A486-D3CF666AA2E5"),
}
BROKER_POSIX_SPAWN_OFFSET = 0x41DC
EXPECTED_BROKER_POSIX_SPAWN_PREFIX = bytes.fromhex(
    "fc6fbea9fd7b01a9fd430091ffc316d168000090084540f9"
    "080140f9a8831ef8"
)
BROKER_WAITPID_OFFSET = 0x4B30
EXPECTED_BROKER_WAITPID_PREFIX = bytes.fromhex(
    "ff0301d1fd7b03a9fdc30091a0831fb8a1031ff8a2c31e"
    "b88000009000400291"
)
BROKER_RETURN_GATE_OFFSET = 0x6418
EXPECTED_BROKER_RETURN_GATE_CONTEXT = bytes.fromhex(
    "ff832791fd7b41a9fc6fc2a8c0035fd6"
)
BROKER_DIRECT_REQUEST_LAYOUTS = {
    uuid.UUID("F4418229-5CB5-377C-9B89-979E821F27FA"): 0x81F0,
    uuid.UUID("8CCC6170-E98B-3008-A486-D3CF666AA2E5"): 0x8464,
}
EXPECTED_BROKER_DIRECT_REQUEST_PREFIX = bytes.fromhex(
    "ff4307d1fc6f1ba9fd7b1ca9fd030791"
    "48000090084540f9080140f9a8831ef8"
)

POSIX_SPAWN_STUB_OFFSET = 0x2ED68C
EXPECTED_POSIX_SPAWN_STUB = bytes.fromhex(
    "1f2003d5d0a4425800021fd6"
)
WAITPID_STUB_OFFSET = 0x2EDFB0
EXPECTED_WAITPID_STUB = bytes.fromhex(
    "1f2003d5708c425800021fd6"
)

INSTALL_PATH = "/var/jb/usr/bin/install"
WORKER_PATH = "/var/jb/usr/libexec/codex-exec-worker"
PRECURSOR_UPLOAD_PATH = "/var/mobile/Media/codex-springboard-live-precursor"
PRECURSOR_DESTINATION_PATH = (
    "/var/jb/usr/libexec/codex-springboard-live-precursor"
)
CARRIER_LAUNCHER_PATH = (
    "/var/jb/usr/libexec/codex-carrier-ptrace-exec-probe"
)
CARRIER_SUPERVISOR_UPLOAD_PATH = (
    "/var/mobile/Media/codex-carrier-ptrace-exec-probe-v22"
)
CARRIER_SUPERVISOR_PATH = (
    "/var/jb/usr/libexec/codex-carrier-ptrace-exec-probe-v22"
)
CARRIER_LOG_SOURCE_PATH = (
    "/var/tmp/codex-carrier-ptrace-exec-probe.log"
)
CARRIER_LOG_EXPORT_PATH = (
    "/var/mobile/Media/codex-carrier-ptrace-exec-probe-recovery.log"
)
CARRIER_LAUNCHER_EXPORT_PATH = (
    "/var/mobile/Media/codex-carrier-ptrace-exec-probe-installed"
)
BOOTSTRAP_LOG_SOURCE_PATH = "/var/tmp/codex-dopamine-cryptex-bootstrap.log"
BOOTSTRAP_LOG_EXPORT_PATH = (
    "/var/mobile/Media/codex-dopamine-cryptex-bootstrap-recovery.log"
)
SHELL_PATH = "/var/jb/bin/sh"
ELLEKIT_LOADER_PATH = "/var/jb/usr/libexec/codex-ellekit-loader"
DYLD_ADMISSION_HOOK_PATH = "/var/jb/usr/lib/codex-dyld-jb-admission-hook.dylib"
FRESH_CANARY_UPLOAD_PATH = (
    "/var/mobile/Media/codex-springboard-live-canary.dylib"
)
FRESH_CANARY_DYLIB_PATH = "/var/jb/usr/lib/codex-springboard-live-canary.dylib"
FRESH_CANARY_SHA256 = (
    "c2666abf214765f7103ec1b77cabe5c56328941ef7fdd90a4778440be30bc6c4"
)


@dataclass(frozen=True)
class InventoryImage:
    base: int
    path: str
    identifier: uuid.UUID


@dataclass(frozen=True)
class ValidatedImage:
    identifier: uuid.UUID
    executable_ranges: tuple[tuple[int, int], ...]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", nargs="?", help="RSD host")
    parser.add_argument("port", nargs="?", type=int, help="RSD port")
    parser.add_argument(
        "--userspace-udid",
        help="establish a userspace RSD tunnel for this exact UDID",
    )
    parser.add_argument("--pid", required=True, type=int, help="exact Sileo PID")
    parser.add_argument(
        "--timeout",
        type=float,
        default=45.0,
        help="per-packet timeout in seconds (default: 45)",
    )
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument(
        "--validate-only",
        action="store_true",
        help="validate the exact process and bound broker stubs without mutation",
    )
    actions.add_argument(
        "--stage-springboard-live-precursor",
        action="store_true",
        help="install the fixed precursor upload at its fixed rootless path",
    )
    actions.add_argument(
        "--launch-runtime-carrier",
        action="store_true",
        help="start the fixed supervising carrier launcher and intentionally do not wait",
    )
    actions.add_argument(
        "--stage-runtime-carrier-supervisor",
        action="store_true",
        help="install the fixed supervising launcher upload at its fixed rootless path",
    )
    actions.add_argument(
        "--export-runtime-carrier-log",
        action="store_true",
        help="copy the fixed carrier launcher log to the Media recovery path",
    )
    actions.add_argument(
        "--export-runtime-carrier-launcher",
        action="store_true",
        help="copy the fixed installed carrier launcher to Media for verification",
    )
    actions.add_argument(
        "--export-bootstrap-log",
        action="store_true",
        help="copy the fixed root-broker log to the Media recovery path",
    )
    actions.add_argument(
        "--check-fresh-canary-in-springboard",
        metavar="PID",
        type=int,
        help="check whether the fixed fresh canary is loaded in this SpringBoard PID",
    )
    args = parser.parse_args()
    if args.userspace_udid:
        if args.host is not None or args.port is not None:
            parser.error("host/port cannot be combined with --userspace-udid")
    elif args.host is None or args.port is None:
        parser.error("provide host and port or --userspace-udid")
    return args


def parse_inventory(response: str) -> list[InventoryImage]:
    """Parse stable image prefixes from iOS 27's malformed segment JSON."""

    pattern = re.compile(
        r'\{"load_address":(?P<address>[0-9]+),'
        r'"mod_date":[0-9]+,'
        r'"pathname":(?P<path>"(?:\\.|[^"\\])*")'
        r',"uuid":"(?P<uuid>[0-9a-fA-F-]{36})"'
    )
    result: list[InventoryImage] = []
    for match in pattern.finditer(response):
        try:
            path = json.loads(match.group("path"))
            identifier = uuid.UUID(match.group("uuid"))
        except (json.JSONDecodeError, ValueError) as error:
            raise ProtocolError("invalid image inventory prefix") from error
        if not isinstance(path, str):
            raise ProtocolError("image inventory pathname is not a string")
        result.append(
            InventoryImage(
                base=int(match.group("address")),
                path=path,
                identifier=identifier,
            )
        )
    if not result:
        raise ProtocolError("debugserver returned no parseable image inventory")
    return result


def _signed(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def literal_pointer_slot(stub_address: int, stub: bytes) -> int:
    if len(stub) != 12:
        raise ProtocolError("unexpected import stub length")
    instruction = struct.unpack_from("<I", stub, 4)[0]
    if instruction & 0xFF00001F != 0x58000010:
        raise ProtocolError(
            f"import stub has no expected LDR x16 literal: 0x{instruction:08x}"
        )
    displacement = _signed((instruction >> 5) & 0x7FFFF, 19) << 2
    slot = stub_address + 4 + displacement
    if slot <= 0 or slot & 7:
        raise ProtocolError(f"invalid import pointer slot 0x{slot:x}")
    return slot


async def validate_macho(
    remote: GDBRemote,
    image: InventoryImage,
    expected_file_type: int,
    expected_identifier: uuid.UUID,
) -> ValidatedImage:
    if image.base <= 0 or image.base & 0x3FFF:
        raise ProtocolError(
            f"invalid image base for {image.path}: 0x{image.base:x}"
        )
    header = await read_memory(remote, image.base, 32)
    (
        magic,
        cpu_type,
        _cpu_subtype,
        file_type,
        command_count,
        command_bytes,
        _flags,
        _reserved,
    ) = struct.unpack("<IiiIIIII", header)
    if magic != MH_MAGIC_64 or cpu_type != CPU_TYPE_ARM64:
        raise ProtocolError(
            f"unexpected Mach-O header for {image.path}: "
            f"magic=0x{magic:x} cpu=0x{cpu_type:x}"
        )
    if file_type != expected_file_type:
        raise ProtocolError(
            f"unexpected Mach-O type for {image.path}: {file_type}"
        )
    if not (0 < command_count <= MAX_LOAD_COMMANDS) or not (
        0 < command_bytes <= MAX_LOAD_COMMAND_BYTES
    ):
        raise ProtocolError(f"invalid load commands for {image.path}")

    commands = await read_memory(remote, image.base + 32, command_bytes)
    cursor = 0
    identifier: uuid.UUID | None = None
    text_vmaddr: int | None = None
    segments: list[tuple[int, int, int]] = []
    for _ in range(command_count):
        if cursor + 8 > len(commands):
            raise ProtocolError(f"truncated load commands for {image.path}")
        command, command_size = struct.unpack_from("<II", commands, cursor)
        if command_size < 8 or cursor + command_size > len(commands):
            raise ProtocolError(f"invalid load command for {image.path}")
        if command == LC_UUID:
            if command_size != 24 or identifier is not None:
                raise ProtocolError(f"invalid or duplicate UUID for {image.path}")
            identifier = uuid.UUID(bytes=commands[cursor + 8 : cursor + 24])
        elif command == LC_SEGMENT_64 and command_size >= 72:
            name = (
                commands[cursor + 8 : cursor + 24]
                .split(b"\0", 1)[0]
                .decode("ascii", "strict")
            )
            vmaddr, vmsize = struct.unpack_from("<QQ", commands, cursor + 24)
            initprot = struct.unpack_from("<i", commands, cursor + 60)[0]
            if name == "__TEXT":
                if text_vmaddr is not None:
                    raise ProtocolError(f"duplicate __TEXT for {image.path}")
                text_vmaddr = vmaddr
            segments.append((vmaddr, vmsize, initprot))
        cursor += command_size
    if cursor != len(commands) or text_vmaddr is None:
        raise ProtocolError(f"invalid command extent for {image.path}")
    if identifier != expected_identifier or image.identifier != expected_identifier:
        raise ProtocolError(
            f"UUID mismatch for {image.path}: inventory={image.identifier} "
            f"memory={identifier} expected={expected_identifier}"
        )

    executable_ranges: list[tuple[int, int]] = []
    for vmaddr, vmsize, initprot in segments:
        if vmsize == 0 or initprot & 4 == 0:
            continue
        if vmaddr < text_vmaddr:
            raise ProtocolError(f"invalid executable segment for {image.path}")
        start = image.base + vmaddr - text_vmaddr
        end = start + vmsize
        if start <= 0 or end <= start:
            raise ProtocolError(f"overflowed executable segment for {image.path}")
        executable_ranges.append((start, end))
    if not executable_ranges:
        raise ProtocolError(f"no executable segment for {image.path}")
    return ValidatedImage(identifier, tuple(executable_ranges))


def validate_process_info(response: str, expected_pid: int) -> None:
    fields = parse_key_values(response)
    try:
        actual_pid = int(fields["pid"], 16)
        uid_key = "uid" if "uid" in fields else "real-uid"
        euid_key = "euid" if "euid" in fields else "effective-uid"
        uid = int(fields[uid_key], 16)
        euid = int(fields[euid_key], 16)
    except (KeyError, ValueError) as error:
        raise ProtocolError(f"incomplete Sileo process info: {response!r}") from error
    if actual_pid != expected_pid or actual_pid <= 1:
        raise ProtocolError(
            f"attached PID mismatch: expected {expected_pid}, got {actual_pid}"
        )
    if uid != 501 or euid != 501:
        raise ProtocolError(f"Sileo uid mismatch: uid={uid} euid={euid}")
    name = fields.get("name", "")
    if name and name.lower() != "sileo":
        try:
            decoded_name = bytes.fromhex(name).decode("utf-8", "strict")
        except (ValueError, UnicodeDecodeError):
            decoded_name = name
        if decoded_name.lower() != "sileo":
            raise ProtocolError(f"unexpected attached process name: {name!r}")
    print(
        f"process-info pid={actual_pid} uid={uid} euid={euid} "
        f"name={name or 'Sileo'}"
    )


async def continue_all(remote: GDBRemote) -> str:
    await remote.connection.sendall(b"$vCont;c#a8")
    while True:
        response = await remote.packet()
        if response.startswith("O") and len(response) > 1:
            try:
                output = bytes.fromhex(response[1:]).decode("utf-8", "replace")
            except ValueError:
                output = response
            print(f"sileo-output={output.rstrip()}")
            continue
        if response[:1] in {"T", "S", "W", "X"}:
            return response
        raise ProtocolError(f"unexpected continue response: {response!r}")


async def run(args: argparse.Namespace) -> int:
    if args.pid <= 1:
        raise ProtocolError("refusing PID 1 or an invalid PID")
    if args.timeout <= 0 or args.timeout > 120:
        raise ProtocolError("timeout must be in the range (0, 120]")

    rsd_context = (
        PreferredRsdTunnel(serial=args.userspace_udid, prefer_native=False)
        if args.userspace_udid
        else RemoteServiceDiscoveryService((args.host, args.port))
    )
    async with rsd_context as rsd:
        connection = await rsd.create_service_connection(
            rsd.get_service_port(DEBUG_PROXY_SERVICE)
        )
        remote = GDBRemote(connection, args.timeout)
        attached = False
        stopped = False
        state_saved = False
        save_identifier: str | None = None
        scratch: int | None = None
        breakpoint_address: int | None = None
        primary_error: BaseException | None = None
        try:
            await connection.sendall(b"+")
            supported = await remote.command("qSupported")
            print(f"debugserver-supported={supported}")
            optional = await remote.command("QEnableErrorStrings")
            if optional not in {"", "OK"}:
                raise ProtocolError(f"QEnableErrorStrings failed: {optional!r}")

            attach_response = await remote.command(f"vAttach;{args.pid:x}")
            attached = True
            stopped = True
            initial = StopState.parse(attach_response)
            validate_process_info(await remote.command("qProcessInfo"), args.pid)

            request = json.dumps({"fetch_all_solibs": True}, separators=(",", ":"))
            inventory = parse_inventory(
                await remote.command(f"jGetLoadedDynamicLibrariesInfos:{request}")
            )
            main_matches = [
                image
                for image in inventory
                if image.path.endswith(EXPECTED_SILEO_SUFFIX)
                and image.identifier == EXPECTED_SILEO_UUID
            ]
            if len(main_matches) != 1:
                raise ProtocolError(
                    "expected one exact Sileo main image; "
                    f"found {len(main_matches)}"
                )
            main_image = main_matches[0]
            app_directory = main_image.path.rsplit("/", 1)[0]
            helper_path = f"{app_directory}/giveMeRoot"
            expected_broker_path = f"{app_directory}/{BROKER_IMAGE_LEAF}"
            broker_matches = [
                image
                for image in inventory
                if image.path == expected_broker_path
                and image.identifier in EXPECTED_BROKER_UUIDS
            ]
            if not broker_matches:
                # A CoreDevice --start-stopped launch can be attached before
                # dyld has mapped the bundle-local broker.  Let dyld and the
                # constructor run briefly, then stop and re-bind every image
                # invariant before doing anything else.
                await remote.connection.sendall(b"$vCont;c#a8")
                stopped = False
                # The bundle image appears slightly before its constructor
                # consumes the mach-service sandbox extension.  The direct
                # broker call is rejected as "Connection invalid" in that
                # narrow interval, so allow the exact constructor a bounded
                # window to finish before rebinding every invariant below.
                await asyncio.sleep(0.35)
                initial = StopState.parse(await remote.interrupt())
                stopped = True
                validate_process_info(
                    await remote.command("qProcessInfo"), args.pid
                )
                inventory = parse_inventory(
                    await remote.command(
                        f"jGetLoadedDynamicLibrariesInfos:{request}"
                    )
                )
                broker_matches = [
                    image
                    for image in inventory
                    if image.path == expected_broker_path
                    and image.identifier in EXPECTED_BROKER_UUIDS
                ]
            if len(broker_matches) != 1:
                raise ProtocolError(
                    "expected one exact bundle-local broker image; "
                    f"found {len(broker_matches)} path={expected_broker_path}"
                )
            broker_image = broker_matches[0]

            await validate_macho(
                remote, main_image, MH_EXECUTE, EXPECTED_SILEO_UUID
            )
            broker = await validate_macho(
                remote, broker_image, MH_DYLIB, broker_image.identifier
            )
            expected_broker_targets = {
                "posix_spawn": broker_image.base + BROKER_POSIX_SPAWN_OFFSET,
                "waitpid": broker_image.base + BROKER_WAITPID_OFFSET,
            }
            for name, target, prefix in (
                (
                    "posix_spawn",
                    expected_broker_targets["posix_spawn"],
                    EXPECTED_BROKER_POSIX_SPAWN_PREFIX,
                ),
                (
                    "waitpid",
                    expected_broker_targets["waitpid"],
                    EXPECTED_BROKER_WAITPID_PREFIX,
                ),
            ):
                observed_prefix = await read_memory(remote, target, len(prefix))
                if observed_prefix != prefix:
                    raise ProtocolError(
                        f"exact Sileo broker {name} code mismatch at "
                        f"0x{target:x}: {observed_prefix.hex()}"
                    )
                if not any(
                    start <= target < end
                    for start, end in broker.executable_ranges
                ):
                    raise ProtocolError(
                        f"exact Sileo broker {name} is outside executable text"
                    )
            return_gate = broker_image.base + BROKER_RETURN_GATE_OFFSET
            gate_context = await read_memory(
                remote,
                return_gate - 12,
                len(EXPECTED_BROKER_RETURN_GATE_CONTEXT),
            )
            if gate_context != EXPECTED_BROKER_RETURN_GATE_CONTEXT:
                raise ProtocolError(
                    f"exact Sileo broker return gate mismatch at "
                    f"0x{return_gate:x}: {gate_context.hex()}"
                )
            if not any(
                start <= return_gate < end
                for start, end in broker.executable_ranges
            ):
                raise ProtocolError("Sileo broker return gate is not executable")
            direct_request_offset = BROKER_DIRECT_REQUEST_LAYOUTS.get(
                broker_image.identifier
            )
            if direct_request_offset is None:
                raise ProtocolError(
                    "exact broker UUID has no pinned direct-request layout"
                )
            direct_request = broker_image.base + direct_request_offset
            direct_request_prefix = await read_memory(
                remote,
                direct_request,
                len(EXPECTED_BROKER_DIRECT_REQUEST_PREFIX),
            )
            if direct_request_prefix != EXPECTED_BROKER_DIRECT_REQUEST_PREFIX:
                raise ProtocolError(
                    "exact Sileo broker direct-request code mismatch at "
                    f"0x{direct_request:x}: {direct_request_prefix.hex()}"
                )
            if not any(
                start <= direct_request < end
                for start, end in broker.executable_ranges
            ):
                raise ProtocolError(
                    "Sileo broker direct-request function is not executable"
                )

            spawn_stub = main_image.base + POSIX_SPAWN_STUB_OFFSET
            waitpid_stub = main_image.base + WAITPID_STUB_OFFSET
            spawn_bytes = await read_memory(
                remote, spawn_stub, len(EXPECTED_POSIX_SPAWN_STUB)
            )
            waitpid_bytes = await read_memory(
                remote, waitpid_stub, len(EXPECTED_WAITPID_STUB)
            )
            if spawn_bytes != EXPECTED_POSIX_SPAWN_STUB:
                raise ProtocolError(
                    f"Sileo posix_spawn stub mismatch: {spawn_bytes.hex()}"
                )
            if waitpid_bytes != EXPECTED_WAITPID_STUB:
                raise ProtocolError(
                    f"Sileo waitpid stub mismatch: {waitpid_bytes.hex()}"
                )

            pointer_slots: dict[str, int] = {}
            for name, stub, code in (
                ("posix_spawn", spawn_stub, spawn_bytes),
                ("waitpid", waitpid_stub, waitpid_bytes),
            ):
                pointer_slot = literal_pointer_slot(stub, code)
                raw_target = struct.unpack(
                    "<Q", await read_memory(remote, pointer_slot, 8)
                )[0]
                if raw_target <= 0 or raw_target >= (1 << 48) or raw_target & 3:
                    raise ProtocolError(
                        f"invalid bound {name} target 0x{raw_target:x}"
                    )
                region_response = await remote.command(
                    f"qMemoryRegionInfo:{raw_target:x}"
                )
                region = parse_key_values(region_response)
                if "x" not in region.get("permissions", ""):
                    raise ProtocolError(
                        f"bound {name} target is not executable: {region_response!r}"
                    )
                pointer_slots[name] = pointer_slot
                binding = (
                    "exact-broker"
                    if raw_target == expected_broker_targets[name]
                    else "unresolved-or-nonbroker"
                )
                print(
                    f"import-binding name={name} stub=0x{stub:x} "
                    f"slot=0x{pointer_slot:x} target=0x{raw_target:x} "
                    f"state={binding}"
                )

            print(
                f"validated-sileo pid={args.pid} thread={initial.thread} "
                f"pc=0x{initial.pc:x} base=0x{main_image.base:x} "
                f"uuid={main_image.identifier} path={main_image.path} "
                f"broker-base=0x{broker_image.base:x} "
                f"broker-uuid={broker_image.identifier} "
                f"broker-path={broker_image.path} helper={helper_path} "
                f"return-gate=0x{return_gate:x}"
            )
            if args.validate_only:
                print("validate-only=success")
                return 0

            save_response = await remote.command(
                f"QSaveRegisterState;thread:{initial.thread};"
            )
            if not re.fullmatch(r"[0-9]+", save_response):
                raise ProtocolError(
                    f"QSaveRegisterState failed: {save_response!r}"
                )
            save_identifier = save_response
            state_saved = True
            scratch = await allocate_scratch(remote)
            print(
                f"scratch-allocated address=0x{scratch:x} size=0x{SCRATCH_SIZE:x}"
            )

            if args.stage_springboard_live_precursor:
                root_arguments = (
                    INSTALL_PATH,
                    "-m",
                    "0755",
                    PRECURSOR_UPLOAD_PATH,
                    PRECURSOR_DESTINATION_PATH,
                )
            elif args.stage_runtime_carrier_supervisor:
                root_arguments = (
                    INSTALL_PATH,
                    "-m",
                    "0755",
                    CARRIER_SUPERVISOR_UPLOAD_PATH,
                    CARRIER_SUPERVISOR_PATH,
                )
            elif args.export_runtime_carrier_log:
                root_arguments = (
                    INSTALL_PATH,
                    "-m",
                    "0644",
                    CARRIER_LOG_SOURCE_PATH,
                    CARRIER_LOG_EXPORT_PATH,
                )
            elif args.export_runtime_carrier_launcher:
                root_arguments = (
                    INSTALL_PATH,
                    "-m",
                    "0644",
                    CARRIER_LAUNCHER_PATH,
                    CARRIER_LAUNCHER_EXPORT_PATH,
                )
            elif args.export_bootstrap_log:
                root_arguments = (
                    INSTALL_PATH,
                    "-m",
                    "0644",
                    BOOTSTRAP_LOG_SOURCE_PATH,
                    BOOTSTRAP_LOG_EXPORT_PATH,
                )
            elif args.check_fresh_canary_in_springboard is not None:
                if args.check_fresh_canary_in_springboard <= 1:
                    raise ProtocolError("forbidden SpringBoard PID")
                root_arguments = (
                    ELLEKIT_LOADER_PATH,
                    "--check-pid-image",
                    str(args.check_fresh_canary_in_springboard),
                    FRESH_CANARY_DYLIB_PATH,
                )
            elif args.launch_runtime_carrier:
                root_arguments = (
                    WORKER_PATH,
                    "--macho",
                    CARRIER_SUPERVISOR_PATH,
                )
            else:
                raise ProtocolError("unhandled broker action")
            # The resident carrier deliberately does not return.  Dispatch it
            # through Sileo's proven virtual-job wrapper, whose interposed
            # waitpid can be entered for a bounded window and then interrupted.
            # Keep the exact direct broker call for commands that are expected
            # to finish synchronously.
            direct_mode = not args.launch_runtime_carrier
            spawn_arguments = (
                root_arguments
                if direct_mode
                else (helper_path, *root_arguments)
            )
            payload, argv_address, envp_address, pid_address = (
                build_spawn_payload(scratch, spawn_arguments)
            )
            await write_memory(remote, scratch, payload)
            await expect_ok(remote, f"Z1,{return_gate:x},4")
            breakpoint_address = return_gate

            async def call_bound(
                name: str,
                function: int,
                values: tuple[int, ...],
                *,
                selected_thread_only: bool = False,
            ) -> StopState:
                nonlocal stopped
                if len(values) > 8:
                    raise ProtocolError(f"too many register arguments for {name}")
                registers = {f"{index:x}": value for index, value in enumerate(values)}
                registers["1e"] = return_gate
                registers["20"] = function
                for register, value in registers.items():
                    await set_register(remote, register, value, initial.thread)
                for register, expected in registers.items():
                    observed = await read_register(remote, register, initial.thread)
                    if observed != expected:
                        raise ProtocolError(
                            f"{name} register {register} mismatch: "
                            f"expected=0x{expected:x} got=0x{observed:x}"
                        )
                stopped = False
                returned = StopState.parse(
                    await (
                        remote.continue_thread(initial.thread)
                        if selected_thread_only
                        else continue_all(remote)
                    )
                )
                stopped = True
                if returned.thread.lower() != initial.thread.lower():
                    raise ProtocolError(
                        f"{name} stopped unexpected thread {returned.thread}"
                    )
                if returned.signal != 5:
                    raise ProtocolError(
                        f"{name} returned with signal {returned.signal}, expected 5"
                    )
                if returned.pc != return_gate:
                    raise ProtocolError(
                        f"{name} did not return to the exact breakpoint: "
                        f"pc=0x{returned.pc:x} expected=0x{return_gate:x}"
                    )
                print(
                    f"sileo-call name={name} function=0x{function:x} "
                    f"result=0x{returned.x0:x}"
                )
                return returned

            if direct_mode:
                descriptors_address = pid_address + 8
                descriptor_numbers_address = descriptors_address + 8
                status_address = descriptor_numbers_address + 8
                if status_address + 8 > scratch + SCRATCH_SIZE:
                    raise ProtocolError("direct broker payload exceeds scratch")
                await write_memory(
                    remote,
                    descriptors_address,
                    struct.pack("<ii", 1, 2),
                )
                await write_memory(
                    remote,
                    descriptor_numbers_address,
                    struct.pack("<ii", 1, 2),
                )
                await write_memory(remote, status_address, b"\0" * 8)
                direct_result = await call_bound(
                    "broker_direct_request",
                    direct_request,
                    (
                        argv_address,
                        len(root_arguments),
                        0,
                        0,
                        descriptors_address,
                        descriptor_numbers_address,
                        2,
                        status_address,
                    ),
                )
                direct_ok = (direct_result.x0 & 0xFF) == 1
                wait_status = struct.unpack(
                    "<I", await read_memory(remote, status_address, 4)
                )[0]
                print(
                    f"direct-request result={int(direct_ok)} "
                    f"status=0x{wait_status:08x} "
                    f"command={' '.join(root_arguments)}"
                )
                if not direct_ok:
                    raise ProtocolError("broker direct request was rejected")
                if wait_status & 0x7F:
                    raise ProtocolError(
                        "brokered command terminated by signal: "
                        f"status=0x{wait_status:08x}"
                    )
                exit_status = (wait_status >> 8) & 0xFF
                if exit_status != 0:
                    raise ProtocolError(
                        f"brokered command exited {exit_status}: "
                        f"status=0x{wait_status:08x}"
                    )
                observed_direct_prefix = await read_memory(
                    remote,
                    direct_request,
                    len(EXPECTED_BROKER_DIRECT_REQUEST_PREFIX),
                )
                if observed_direct_prefix != EXPECTED_BROKER_DIRECT_REQUEST_PREFIX:
                    raise ProtocolError(
                        "direct-request code changed during broker call"
                    )
                if args.export_runtime_carrier_log:
                    print(
                        "runtime-carrier-log-export=success request=direct "
                        f"destination={CARRIER_LOG_EXPORT_PATH}"
                    )
                elif args.export_runtime_carrier_launcher:
                    print(
                        "runtime-carrier-launcher-export=success request=direct "
                        f"destination={CARRIER_LAUNCHER_EXPORT_PATH}"
                    )
                elif args.export_bootstrap_log:
                    print(
                        "bootstrap-log-export=success request=direct "
                        f"destination={BOOTSTRAP_LOG_EXPORT_PATH}"
                    )
                elif args.check_fresh_canary_in_springboard is not None:
                    print(
                        "fresh-canary-image-check=success request=direct "
                        f"target-pid={args.check_fresh_canary_in_springboard} "
                        f"dylib={FRESH_CANARY_DYLIB_PATH}"
                    )
                elif args.stage_runtime_carrier_supervisor:
                    print(
                        "runtime-carrier-supervisor-stage=success request=direct "
                        f"destination={CARRIER_SUPERVISOR_PATH}"
                    )
                else:
                    print(
                        "springboard-live-precursor-stage=success request=direct "
                        f"destination={PRECURSOR_DESTINATION_PATH}"
                    )
                return 0
            else:
                spawned = await call_bound(
                    "brokered_posix_spawn",
                    spawn_stub,
                    (
                        pid_address,
                        scratch,
                        0,
                        0,
                        argv_address,
                        envp_address,
                    ),
                )
                spawn_result = spawned.x0 & 0xFFFFFFFF
                fake_pid = struct.unpack(
                    "<i", await read_memory(remote, pid_address, 4)
                )[0]
                print(
                    f"spawn-return result={spawn_result} fake-pid={fake_pid} "
                    f"command={' '.join(root_arguments)}"
                )
                if spawn_result != 0:
                    raise ProtocolError(
                        f"brokered posix_spawn returned error {spawn_result}"
                    )
                if not (0x3F000000 <= fake_pid < 0x40000000):
                    raise ProtocolError(
                        f"brokered spawn returned invalid fake PID {fake_pid}"
                    )
                observed_spawn_target = struct.unpack(
                    "<Q",
                    await read_memory(remote, pointer_slots["posix_spawn"], 8),
                )[0]
                if observed_spawn_target != expected_broker_targets["posix_spawn"]:
                    raise ProtocolError(
                        "posix_spawn stub did not bind to the exact broker after call: "
                        f"target=0x{observed_spawn_target:x} "
                        f"expected=0x{expected_broker_targets['posix_spawn']:x}"
                    )
                print(
                    "post-call-binding name=posix_spawn state=exact-broker "
                    f"target=0x{observed_spawn_target:x}"
                )

            if args.launch_runtime_carrier:
                # The virtual job's worker must get CPU time after the
                # interposed spawn returns.  Its root peer intentionally
                # remains blocked supervising the resident carrier, so a
                # normal waitpid would never return.  Enter that wait anyway
                # for three bounded seconds so every thread (especially the
                # virtual-job worker) runs, then interrupt and restore the
                # exact pre-call Sileo state.
                status_address = pid_address + 4
                await write_memory(remote, status_address, b"\0" * 4)
                dispatch_registers = {
                    "0": fake_pid,
                    "1": status_address,
                    "2": 0,
                    "1e": return_gate,
                    "20": waitpid_stub,
                }
                for register, value in dispatch_registers.items():
                    await set_register(
                        remote, register, value, initial.thread
                    )
                for register, expected in dispatch_registers.items():
                    observed = await read_register(
                        remote, register, initial.thread
                    )
                    if observed != expected:
                        raise ProtocolError(
                            "carrier dispatch register mismatch: "
                            f"{register} expected=0x{expected:x} "
                            f"got=0x{observed:x}"
                        )
                await remote.connection.sendall(b"$vCont;c#a8")
                stopped = False
                await asyncio.sleep(3.0)
                dispatch_stop = await remote.interrupt()
                if dispatch_stop[:1] not in {"T", "S"}:
                    raise ProtocolError(
                        "Sileo exited during the bounded carrier dispatch: "
                        f"{dispatch_stop!r}"
                    )
                stopped = True
                await expect_ok(remote, f"z1,{breakpoint_address:x},4")
                breakpoint_address = None
                await expect_ok(
                    remote,
                    f"QRestoreRegisterState:{save_identifier};"
                    f"thread:{initial.thread};",
                )
                state_saved = False
                await expect_ok(remote, f"_m{scratch:x}")
                scratch = None
                print(
                    f"runtime-carrier-request=accepted fake-pid={fake_pid} "
                    "waited=0 dispatch-window=3.0"
                )
                return 0

            status_address = pid_address + 4
            await write_memory(remote, status_address, b"\0" * 4)
            waited = await call_bound(
                "brokered_waitpid",
                waitpid_stub,
                (fake_pid, status_address, 0),
            )
            wait_result = struct.unpack(
                "<i", struct.pack("<I", waited.x0 & 0xFFFFFFFF)
            )[0]
            wait_status = struct.unpack(
                "<I", await read_memory(remote, status_address, 4)
            )[0]
            if wait_result != fake_pid:
                raise ProtocolError(
                    f"brokered waitpid returned {wait_result}, expected {fake_pid}"
                )
            observed_waitpid_target = struct.unpack(
                "<Q", await read_memory(remote, pointer_slots["waitpid"], 8)
            )[0]
            if observed_waitpid_target != expected_broker_targets["waitpid"]:
                raise ProtocolError(
                    "waitpid stub did not bind to the exact broker after call: "
                    f"target=0x{observed_waitpid_target:x} "
                    f"expected=0x{expected_broker_targets['waitpid']:x}"
                )
            print(
                "post-call-binding name=waitpid state=exact-broker "
                f"target=0x{observed_waitpid_target:x}"
            )
            if wait_status & 0x7F:
                raise ProtocolError(
                    f"brokered command terminated by signal: status=0x{wait_status:08x}"
                )
            exit_status = (wait_status >> 8) & 0xFF
            if exit_status != 0:
                raise ProtocolError(
                    f"brokered command exited {exit_status}: "
                    f"status=0x{wait_status:08x}"
                )
            if args.export_runtime_carrier_log:
                print(
                    f"runtime-carrier-log-export=success fake-pid={fake_pid} "
                    f"destination={CARRIER_LOG_EXPORT_PATH}"
                )
            elif args.export_bootstrap_log:
                print(
                    f"bootstrap-log-export=success fake-pid={fake_pid} "
                    f"destination={BOOTSTRAP_LOG_EXPORT_PATH}"
                )
            elif args.check_fresh_canary_in_springboard is not None:
                print(
                    f"fresh-canary-image-check=success fake-pid={fake_pid} "
                    f"target-pid={args.check_fresh_canary_in_springboard} "
                    f"dylib={FRESH_CANARY_DYLIB_PATH}"
                )
            elif args.stage_runtime_carrier_supervisor:
                print(
                    "runtime-carrier-supervisor-stage=success "
                    f"fake-pid={fake_pid} "
                    f"destination={CARRIER_SUPERVISOR_PATH}"
                )
            else:
                print(
                    "springboard-live-precursor-stage=success "
                    f"fake-pid={fake_pid} "
                    f"destination={PRECURSOR_DESTINATION_PATH}"
                )
            return 0
        except BaseException as error:
            primary_error = error
            raise
        finally:
            cleanup_errors: list[str] = []
            if attached and not stopped:
                try:
                    response = await remote.interrupt()
                    stopped = response[:1] in {"T", "S"}
                    print(f"cleanup-interrupt={response}")
                except BaseException as error:
                    cleanup_errors.append(f"interrupt: {error}")

            if attached and stopped:
                if breakpoint_address is not None:
                    try:
                        await expect_ok(remote, f"z1,{breakpoint_address:x},4")
                        print("cleanup-breakpoint=removed")
                    except BaseException as error:
                        cleanup_errors.append(f"breakpoint: {error}")

                if state_saved and save_identifier is not None:
                    try:
                        await expect_ok(
                            remote,
                            f"QRestoreRegisterState:{save_identifier};"
                            f"thread:{initial.thread};",
                        )
                        state_saved = False
                        print("cleanup-register-state=restored")
                    except BaseException as error:
                        cleanup_errors.append(f"register restore: {error}")

                if scratch is not None:
                    try:
                        await expect_ok(remote, f"_m{scratch:x}")
                        scratch = None
                        print("cleanup-scratch=deallocated")
                    except BaseException as error:
                        cleanup_errors.append(f"scratch deallocation: {error}")

                try:
                    await expect_ok(remote, "D")
                    attached = False
                    print("cleanup-detach=success")
                except BaseException as error:
                    cleanup_errors.append(f"detach: {error}")

            try:
                await connection.close()
            except BaseException as error:
                cleanup_errors.append(f"connection close: {error}")

            if cleanup_errors:
                message = "; ".join(cleanup_errors)
                print(f"cleanup-error: {message}", file=sys.stderr)
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
    sys.exit(main())
