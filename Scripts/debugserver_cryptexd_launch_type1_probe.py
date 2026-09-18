#!/usr/bin/env python3
"""Register one dormant launch-type-1 job through the exact 24A437 cryptexd.

The probe attaches only to a caller-supplied, non-PID-1 cryptexd process.  It
validates the process identity, exact executable path, in-memory UUID, Mach-O
architecture, and every function/stub used below before changing state.

Submission uses only already-signed code resident in cryptexd and its loaded
frameworks.  Debugserver supplies one RW scratch page; no executable memory or
new code is introduced.  Every registered job deliberately omits RunAtLoad and
KeepAlive, so this script never starts its selected program.  A later, separate
launchctl kickstart is required to test launch admission.
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
from pymobiledevice3.remote.rsd_tunnel import PreferredRsdTunnel

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
    allocate_scratch,
    expect_ok,
    parse_key_values,
    read_memory,
    read_register,
    set_register,
    write_memory,
)


CRYPTEXD_PATH = "/usr/libexec/cryptexd"
CRYPTEXD_NAME = "cryptexd"
CRYPTEXD_UUID = uuid.UUID("261f91f3-7016-35a2-9a84-c85d2b6a834e")
ROOT_UID = 0

JOB_LABEL = "com.openai.codex.launch-type-canary"
CANARY_PROGRAM = "/var/jb/usr/libexec/codex-xpcproxy-launch-canary"
SESSION_NAME = "com.openai.codex.launch-type1-probe"
SPRINGBOARD_CANDIDATE_JOB_LABEL = (
    "com.openai.codex.springboard-live-candidate"
)
SPRINGBOARD_CANDIDATE_PROGRAM = (
    "/var/jb/usr/libexec/codex-springboard-candidate/"
    "SpringBoard.app/SpringBoard"
)
SPRINGBOARD_CANDIDATE_SESSION_NAME = (
    "com.openai.codex.springboard-live-proof"
)
SEALED_SPRINGBOARD_JOB_LABEL = (
    "com.openai.codex.springboard-sealed-admission-24a437"
)
SEALED_SPRINGBOARD_PROGRAM = (
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard"
)
SEALED_SPRINGBOARD_SESSION_NAME = (
    "com.openai.codex.springboard-sealed-admission-session-24a437"
)

# All offsets are relative to the exact 24A437 cryptexd image base.
LAUNCHD_SESSION_CREATE_JOB_OFFSET = 0x4A7E8
XPC_DICTIONARY_CREATE_EMPTY_OFFSET = 0x6D794
XPC_DICTIONARY_SET_INT64_OFFSET = 0x6D874
XPC_DICTIONARY_SET_STRING_OFFSET = 0x6D894
XPC_RELEASE_OFFSET = 0x6D974
OBJC_AUTORELEASE_POOL_POP_OFFSET = 0x6CBC4
OBJC_AUTORELEASE_POOL_PUSH_OFFSET = 0x6CBD4
NSARRAY_ARRAY_WITH_OBJECTS_COUNT_OFFSET = 0x6DCE0
OSLAUNCHDJOB_SUBMIT_ALL_ERROR_OFFSET = 0x6EFC0
NSARRAY_CLASS_SLOT_OFFSET = 0x8CDE0
OSLAUNCHDJOB_CLASS_SLOT_OFFSET = 0x8CFB8

EXPECTED_CODE = {
    "launchd_session_create_job": (
        LAUNCHD_SESSION_CREATE_JOB_OFFSET,
        bytes.fromhex("7f2303d5ff4302d1fa6704a9f85f05a9"),
    ),
    "xpc_dictionary_create_empty": (
        XPC_DICTIONARY_CREATE_EMPTY_OFFSET,
        bytes.fromhex("f10000f031222891300240f9110a1fd7"),
    ),
    "xpc_dictionary_set_int64": (
        XPC_DICTIONARY_SET_INT64_OFFSET,
        bytes.fromhex("f10000f031e22991300240f9110a1fd7"),
    ),
    "xpc_dictionary_set_string": (
        XPC_DICTIONARY_SET_STRING_OFFSET,
        bytes.fromhex("f10000f031222a91300240f9110a1fd7"),
    ),
    "xpc_release": (
        XPC_RELEASE_OFFSET,
        bytes.fromhex("f10000f031e22b91300240f9110a1fd7"),
    ),
    "objc_autoreleasePoolPop": (
        OBJC_AUTORELEASE_POOL_POP_OFFSET,
        bytes.fromhex("f10000f031423591300240f9110a1fd7"),
    ),
    "objc_autoreleasePoolPush": (
        OBJC_AUTORELEASE_POOL_PUSH_OFFSET,
        bytes.fromhex("f10000f031623591300240f9110a1fd7"),
    ),
    "NSArray_arrayWithObjects_count": (
        NSARRAY_ARRAY_WITH_OBJECTS_COUNT_OFFSET,
        bytes.fromhex("2101009021e842f9f10000d031823691"),
    ),
    "OSLaunchdJob_submitAll_error": (
        OSLAUNCHDJOB_SUBMIT_ALL_ERROR_OFFSET,
        bytes.fromhex("010100f0214445f9f10000b031823691"),
    ),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument(
        "--userspace-udid",
        help=(
            "establish an in-process USB tunnel for this UDID; host and "
            "port are ignored"
        ),
    )
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--timeout", type=float, default=30.0)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--validate-only",
        action="store_true",
        help="validate the exact live cryptexd and detach without mutation",
    )
    mode.add_argument(
        "--submit-inert-job",
        action="store_true",
        help="register the fixed launch-type-1 job without starting it",
    )
    mode.add_argument(
        "--submit-springboard-candidate-job",
        action="store_true",
        help=(
            "register the fixed dormant SpringBoard candidate job without "
            "starting it"
        ),
    )
    mode.add_argument(
        "--submit-sealed-springboard-job",
        action="store_true",
        help=(
            "register a uniquely labeled dormant launch-type-1 job for the "
            "canonical sealed system SpringBoard without starting it"
        ),
    )
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
        r'"pathname":(?P<path>"(?:\\.|[^"\\])*")'
        r',"uuid":"(?P<uuid>[0-9a-fA-F-]+)"',
    )
    matches: list[tuple[int, str]] = []
    for match in pattern.finditer(response):
        try:
            path = json.loads(match.group("path"))
            image_uuid = uuid.UUID(match.group("uuid"))
        except (json.JSONDecodeError, ValueError) as error:
            raise ProtocolError(
                "invalid cryptexd image identity in debugserver inventory"
            ) from error
        if path == CRYPTEXD_PATH and image_uuid == CRYPTEXD_UUID:
            matches.append((int(match.group("address")), path))
    if len(matches) != 1:
        raise ProtocolError(
            "expected exactly one exact 24A437 cryptexd image; "
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
        raise ProtocolError("cryptexd has an invalid in-memory Mach-O header")
    if (cpu_subtype & 0x00FFFFFF) != CPU_SUBTYPE_ARM64E:
        raise ProtocolError(
            f"cryptexd is not arm64e: subtype=0x{cpu_subtype:x}"
        )
    if file_type != MH_EXECUTE:
        raise ProtocolError(f"cryptexd is not MH_EXECUTE: {file_type}")
    if not (0 < command_count <= MAX_LOAD_COMMANDS) or not (
        0 < command_bytes <= MAX_LOAD_COMMAND_BYTES
    ):
        raise ProtocolError("cryptexd has invalid load-command bounds")

    commands = await read_memory(remote, base + 32, command_bytes)
    cursor = 0
    observed_uuid: uuid.UUID | None = None
    for _ in range(command_count):
        if cursor + 8 > len(commands):
            raise ProtocolError("cryptexd load commands are truncated")
        command, command_size = struct.unpack_from("<II", commands, cursor)
        if command_size < 8 or cursor + command_size > len(commands):
            raise ProtocolError("cryptexd has an invalid load command")
        if command == LC_UUID:
            if command_size != 24 or observed_uuid is not None:
                raise ProtocolError("cryptexd has invalid UUID commands")
            observed_uuid = uuid.UUID(
                bytes=commands[cursor + 8 : cursor + 24]
            )
        cursor += command_size
    if cursor != len(commands) or observed_uuid != CRYPTEXD_UUID:
        raise ProtocolError(
            f"cryptexd in-memory UUID mismatch: {observed_uuid}"
        )

    for name, (offset, expected) in EXPECTED_CODE.items():
        address = base + offset
        observed = await read_memory(remote, address, len(expected))
        if observed != expected:
            raise ProtocolError(
                f"{name} bytes mismatch at 0x{address:x}: {observed.hex()}"
            )
    return observed_uuid


def validate_process_info(response: str, expected_pid: int) -> None:
    process = parse_key_values(response)
    if "pid" not in process:
        raise ProtocolError(f"qProcessInfo omitted PID: {response!r}")
    actual_pid = int(process["pid"], 16)
    name = decode_process_name(process.get("name", ""))
    if actual_pid != expected_pid or actual_pid <= 1:
        raise ProtocolError(
            f"attached PID mismatch: expected={expected_pid} got={actual_pid}"
        )
    if name != CRYPTEXD_NAME:
        raise ProtocolError(f"attached process is not cryptexd: {name!r}")
    for key in ("uid", "euid"):
        if key in process and int(process[key], 16) != ROOT_UID:
            raise ProtocolError(
                f"unexpected cryptexd {key}: {process[key]}"
            )


def build_scratch(
    base: int, label: str, program: str, session: str
) -> tuple[bytes, dict[str, int]]:
    payload = bytearray(0x1000)
    cursor = 0
    addresses: dict[str, int] = {}
    values = {
        "label_key": "Label",
        "program_key": "Program",
        "launch_type_key": "_LaunchType",
        "label": label,
        "program": program,
        "session": session,
    }
    for name, value in values.items():
        encoded = value.encode("utf-8") + b"\0"
        payload[cursor : cursor + len(encoded)] = encoded
        addresses[name] = base + cursor
        cursor += len(encoded)

    cursor = (cursor + 15) & ~15
    for name in ("job_out", "object_slot", "error_out"):
        addresses[name] = base + cursor
        cursor += 8
    used = (cursor + 15) & ~15
    return bytes(payload[:used]), addresses


async def run(args: argparse.Namespace) -> int:
    if args.pid <= 1:
        raise ProtocolError("refusing PID 1 or an invalid PID")
    if args.timeout <= 0 or args.timeout > 60:
        raise ProtocolError("timeout must be in the range (0, 60]")
    if args.submit_springboard_candidate_job:
        job_label = SPRINGBOARD_CANDIDATE_JOB_LABEL
        job_program = SPRINGBOARD_CANDIDATE_PROGRAM
        session_name = SPRINGBOARD_CANDIDATE_SESSION_NAME
        registration_mode = "springboard-candidate"
    elif args.submit_sealed_springboard_job:
        job_label = SEALED_SPRINGBOARD_JOB_LABEL
        job_program = SEALED_SPRINGBOARD_PROGRAM
        session_name = SEALED_SPRINGBOARD_SESSION_NAME
        registration_mode = "sealed-springboard-dormant"
    else:
        job_label = JOB_LABEL
        job_program = CANARY_PROGRAM
        session_name = SESSION_NAME
        registration_mode = "inert-canary"

    rsd_context = (
        PreferredRsdTunnel(
            serial=args.userspace_udid,
            prefer_native=False,
        )
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
        pool_token: int | None = None
        dictionary: int | None = None
        initial: StopState | None = None
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
            if re.match(r"^T[0-9a-fA-F]{2}", attach_response):
                attached = True
                stopped = True
            initial = StopState.parse(attach_response)
            validate_process_info(
                await remote.command("qProcessInfo"), args.pid
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
                "cryptexd-validation=success "
                f"pid={args.pid} thread={initial.thread} "
                f"signal={initial.signal} pc=0x{initial.pc:x} "
                f"base=0x{image_base:x} uuid={observed_uuid} "
                f"path={image_path}"
            )
            if args.validate_only:
                await expect_ok(remote, "D")
                attached = False
                stopped = False
                print(f"cryptexd-debugserver-detach=success pid={args.pid}")
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
            payload, slots = build_scratch(
                scratch, job_label, job_program, session_name
            )
            await write_memory(remote, scratch, payload)
            print(
                f"scratch-allocated address=0x{scratch:x} "
                f"size=0x1000 payload=0x{len(payload):x}"
            )

            await expect_ok(remote, f"Z1,{initial.pc:x},4")
            breakpoint_address = initial.pc

            async def remote_call(
                name: str, offset: int, arguments: tuple[int, ...]
            ) -> int:
                nonlocal stopped
                if len(arguments) > 8:
                    raise ProtocolError(f"too many arguments for {name}")
                register_values = {
                    f"{index:x}": value
                    for index, value in enumerate(arguments)
                }
                register_values["1e"] = initial.pc
                register_values["20"] = image_base + offset
                for register, value in register_values.items():
                    await set_register(
                        remote, register, value, initial.thread
                    )
                for register, expected in register_values.items():
                    observed = await read_register(
                        remote, register, initial.thread
                    )
                    if observed != expected:
                        raise ProtocolError(
                            f"{name} register {register} mismatch: "
                            f"expected=0x{expected:x} got=0x{observed:x}"
                        )
                stopped = False
                response = await remote.continue_thread(initial.thread)
                returned = StopState.parse(response)
                stopped = True
                if returned.thread.lower() != initial.thread.lower():
                    raise ProtocolError(
                        f"{name} stopped unexpected thread {returned.thread}"
                    )
                if returned.pc != initial.pc:
                    raise ProtocolError(
                        f"{name} did not return to the breakpoint: "
                        f"pc=0x{returned.pc:x} signal={returned.signal}"
                    )
                print(
                    f"cryptexd-call name={name} "
                    f"function=0x{image_base + offset:x} "
                    f"result=0x{returned.x0:x}"
                )
                return returned.x0

            pool_token = await remote_call(
                "objc_autoreleasePoolPush",
                OBJC_AUTORELEASE_POOL_PUSH_OFFSET,
                (),
            )
            if pool_token == 0:
                raise ProtocolError("objc_autoreleasePoolPush returned null")

            dictionary = await remote_call(
                "xpc_dictionary_create_empty",
                XPC_DICTIONARY_CREATE_EMPTY_OFFSET,
                (),
            )
            if dictionary == 0:
                raise ProtocolError("xpc_dictionary_create_empty returned null")

            await remote_call(
                "set_Label",
                XPC_DICTIONARY_SET_STRING_OFFSET,
                (dictionary, slots["label_key"], slots["label"]),
            )
            await remote_call(
                "set_Program",
                XPC_DICTIONARY_SET_STRING_OFFSET,
                (dictionary, slots["program_key"], slots["program"]),
            )
            await remote_call(
                "set__LaunchType",
                XPC_DICTIONARY_SET_INT64_OFFSET,
                (dictionary, slots["launch_type_key"], 1),
            )

            create_error = await remote_call(
                "launchd_session_create_job",
                LAUNCHD_SESSION_CREATE_JOB_OFFSET,
                (dictionary, 0, slots["session"], slots["job_out"]),
            )
            job = struct.unpack(
                "<Q", await read_memory(remote, slots["job_out"], 8)
            )[0]
            if create_error != 0 or job == 0:
                raise ProtocolError(
                    "launchd_session_create_job failed: "
                    f"error=0x{create_error:x} job=0x{job:x}"
                )
            print(f"launchd-job-created object=0x{job:x}")

            await write_memory(
                remote, slots["object_slot"], struct.pack("<Q", job)
            )
            nsarray_class = struct.unpack(
                "<Q",
                await read_memory(
                    remote, image_base + NSARRAY_CLASS_SLOT_OFFSET, 8
                ),
            )[0]
            oslaunchdjob_class = struct.unpack(
                "<Q",
                await read_memory(
                    remote, image_base + OSLAUNCHDJOB_CLASS_SLOT_OFFSET, 8
                ),
            )[0]
            if nsarray_class == 0 or oslaunchdjob_class == 0:
                raise ProtocolError(
                    "required Objective-C class pointer was not resolved"
                )
            jobs = await remote_call(
                "NSArray_arrayWithObjects_count",
                NSARRAY_ARRAY_WITH_OBJECTS_COUNT_OFFSET,
                (nsarray_class, 0, slots["object_slot"], 1),
            )
            if jobs == 0:
                raise ProtocolError("NSArray construction returned null")

            submit_result = await remote_call(
                "OSLaunchdJob_submitAll_error",
                OSLAUNCHDJOB_SUBMIT_ALL_ERROR_OFFSET,
                (oslaunchdjob_class, 0, jobs, slots["error_out"]),
            )
            submit_error = struct.unpack(
                "<Q", await read_memory(remote, slots["error_out"], 8)
            )[0]
            if submit_result == 0 or submit_error != 0:
                raise ProtocolError(
                    "OSLaunchdJob submission failed: "
                    f"result=0x{submit_result:x} error=0x{submit_error:x}"
                )
            print(
                "launch-type1-job-registration=success "
                f"mode={registration_mode} label={job_label} "
                f"session={session_name} launch-type=1 "
                "run-at-load=false keep-alive=false started=false "
                f"program={job_program}"
            )

            await remote_call(
                "xpc_release_dictionary", XPC_RELEASE_OFFSET, (dictionary,)
            )
            dictionary = None
            await remote_call(
                "objc_autoreleasePoolPop",
                OBJC_AUTORELEASE_POOL_POP_OFFSET,
                (pool_token,),
            )
            pool_token = None
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

            # Best-effort Objective-C/XPC lifetime cleanup is only safe while
            # the call-return breakpoint and saved thread state are intact.
            if (
                attached
                and stopped
                and initial is not None
                and breakpoint_address is not None
            ):
                async def cleanup_call(
                    name: str, offset: int, arguments: tuple[int, ...]
                ) -> None:
                    nonlocal stopped
                    register_values = {
                        f"{index:x}": value
                        for index, value in enumerate(arguments)
                    }
                    register_values["1e"] = initial.pc
                    register_values["20"] = image_base + offset
                    for register, value in register_values.items():
                        await set_register(
                            remote, register, value, initial.thread
                        )
                    stopped = False
                    response = await remote.continue_thread(initial.thread)
                    returned = StopState.parse(response)
                    stopped = True
                    if returned.pc != initial.pc:
                        raise ProtocolError(
                            f"cleanup {name} returned to 0x{returned.pc:x}"
                        )
                    print(f"cleanup-call={name}")

                if dictionary is not None:
                    try:
                        await cleanup_call(
                            "xpc_release_dictionary",
                            XPC_RELEASE_OFFSET,
                            (dictionary,),
                        )
                        dictionary = None
                    except BaseException as error:
                        cleanup_errors.append(f"dictionary release: {error}")
                if pool_token is not None:
                    try:
                        await cleanup_call(
                            "objc_autoreleasePoolPop",
                            OBJC_AUTORELEASE_POOL_POP_OFFSET,
                            (pool_token,),
                        )
                        pool_token = None
                    except BaseException as error:
                        cleanup_errors.append(f"autorelease pool pop: {error}")

            if attached and stopped and initial is not None:
                if breakpoint_address is not None:
                    try:
                        await expect_ok(
                            remote, f"z1,{breakpoint_address:x},4"
                        )
                        breakpoint_address = None
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
                    stopped = False
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
