#!/usr/bin/env python3
"""Drive the iOS 26+ debugserver JIT-page preparation protocol.

This is deliberately a narrow proof harness.  It will only attach to a
non-PID-1 process, expects the two universal-protocol BRK instructions emitted
by execution-probe --jit26, prepares a bounded RX allocation one 16 KiB page
at a time, and detaches.  It never attaches to launchd or injects a library.
"""

from __future__ import annotations

import argparse
import asyncio
import re
import sys
from dataclasses import dataclass

from pymobiledevice3.remote.userspace_tunnel import UserspaceRsdTunnel


DEBUG_PROXY_SERVICE = "com.apple.internal.dt.remote.debugproxy"
JIT_PAGE_SIZE = 16 * 1024
MAX_PREPARE_SIZE = 16 * 1024 * 1024
BRK_MASK = 0xFFE0001F
BRK_OPCODE = 0xD4200000
UNIVERSAL_BRK_IMMEDIATE = 0xF00D
CMD_DETACH = 0
CMD_PREPARE_REGION = 1


class ProtocolError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--udid", required=True)
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--expected-name", default="execution-probe-dynamic-only")
    parser.add_argument("--timeout", type=float, default=20.0)
    inspection_modes = parser.add_mutually_exclusive_group()
    inspection_modes.add_argument(
        "--attach-detach-only",
        action="store_true",
        help="validate debugger attachment, then detach without continuing the target",
    )
    inspection_modes.add_argument(
        "--inspect-read-only",
        action="store_true",
        help="read the stopped PC/register and four instruction bytes, then detach",
    )
    inspection_modes.add_argument(
        "--same-value-register-write",
        action="store_true",
        help="write x8's exact current value back, verify it is unchanged, then detach",
    )
    inspection_modes.add_argument(
        "--same-value-memory-write",
        action="store_true",
        help="write eight stack bytes back unchanged, verify them, then detach",
    )
    inspection_modes.add_argument(
        "--same-value-full-register-write",
        action="store_true",
        help="write the complete register blob back unchanged, verify it, then detach",
    )
    inspection_modes.add_argument(
        "--save-restore-register-state",
        action="store_true",
        help="transactionally save and restore all register sets, then detach",
    )
    return parser.parse_args()


def frame_packet(payload: str) -> bytes:
    encoded = payload.encode("ascii")
    checksum = sum(encoded) & 0xFF
    return b"$" + encoded + b"#" + f"{checksum:02x}".encode("ascii")


def decode_hex_le(value: str) -> int:
    try:
        return int.from_bytes(bytes.fromhex(value), "little")
    except ValueError as error:
        raise ProtocolError(f"invalid little-endian register value: {value!r}") from error


def encode_hex_le(value: int) -> str:
    return value.to_bytes(8, "little", signed=False).hex()


def parse_key_values(response: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in response.split(";"):
        if ":" in item:
            key, value = item.split(":", 1)
            result[key] = value
    return result


@dataclass
class StopState:
    signal: int
    thread: str
    x0: int
    x1: int
    x16: int
    pc: int

    @classmethod
    def parse(cls, response: str) -> "StopState":
        if not re.match(r"^T[0-9a-fA-F]{2}", response):
            raise ProtocolError(f"expected detailed stop reply, got {response!r}")
        fields = parse_key_values(response[3:])
        missing = [key for key in ("thread", "00", "01", "10", "20") if key not in fields]
        if missing:
            raise ProtocolError(f"stop reply omitted {missing}: {response!r}")
        return cls(
            signal=int(response[1:3], 16),
            thread=fields["thread"],
            x0=decode_hex_le(fields["00"]),
            x1=decode_hex_le(fields["01"]),
            x16=decode_hex_le(fields["10"]),
            pc=decode_hex_le(fields["20"]),
        )


class GDBRemote:
    def __init__(self, connection, timeout: float) -> None:
        self.connection = connection
        self.timeout = timeout
        self.buffer = bytearray()

    async def _fill(self) -> None:
        chunk = await asyncio.wait_for(self.connection.recv_any(65536), self.timeout)
        if not chunk:
            raise ProtocolError("debugserver closed the connection")
        self.buffer.extend(chunk)

    async def _packet(self) -> str:
        while True:
            while self.buffer and self.buffer[0] in (ord("+"), ord("-")):
                marker = self.buffer.pop(0)
                if marker == ord("-"):
                    raise ProtocolError("debugserver rejected the previous packet checksum")

            start = self.buffer.find(b"$")
            if start < 0:
                self.buffer.clear()
                await self._fill()
                continue
            if start:
                del self.buffer[:start]

            checksum_offset = self.buffer.find(b"#", 1)
            if checksum_offset < 0 or len(self.buffer) < checksum_offset + 3:
                await self._fill()
                continue

            payload = bytes(self.buffer[1:checksum_offset])
            checksum_text = bytes(self.buffer[checksum_offset + 1 : checksum_offset + 3])
            del self.buffer[: checksum_offset + 3]
            try:
                received_checksum = int(checksum_text, 16)
            except ValueError as error:
                raise ProtocolError(f"invalid packet checksum {checksum_text!r}") from error
            if (sum(payload) & 0xFF) != received_checksum:
                await self.connection.sendall(b"-")
                raise ProtocolError("debugserver response checksum mismatch")
            await self.connection.sendall(b"+")
            return payload.decode("ascii")

    async def command(self, payload: str) -> str:
        await self.connection.sendall(frame_packet(payload))
        return await self._packet()

    async def continue_until_stop(self) -> str:
        await self.connection.sendall(frame_packet("c"))
        while True:
            response = await self._packet()
            if response.startswith("O") and len(response) > 1:
                try:
                    output = bytes.fromhex(response[1:]).decode("utf-8", "replace")
                except ValueError:
                    output = response
                print(f"target-output={output.rstrip()}")
                continue
            if response[:1] in {"T", "S", "W", "X"}:
                return response
            raise ProtocolError(f"unexpected continue response: {response!r}")


def validate_process_info(response: str, expected_pid: int, expected_name: str) -> None:
    fields = parse_key_values(response)
    if "pid" not in fields:
        raise ProtocolError(f"qProcessInfo omitted pid: {response!r}")
    actual_pid = int(fields["pid"], 16)
    if actual_pid != expected_pid:
        raise ProtocolError(f"attached pid changed: expected {expected_pid}, got {actual_pid}")

    encoded_name = fields.get("name")
    if encoded_name:
        try:
            actual_name = bytes.fromhex(encoded_name).decode("utf-8", "replace")
        except ValueError as error:
            raise ProtocolError(f"invalid qProcessInfo name: {encoded_name!r}") from error
        if actual_name != expected_name:
            raise ProtocolError(
                f"unexpected executable: expected {expected_name!r}, got {actual_name!r}"
            )
        print(f"validated-process pid={actual_pid} name={actual_name}")
    else:
        print(f"validated-process pid={actual_pid} name=unreported")


def validate_brk(instruction_hex: str) -> None:
    try:
        instruction = int.from_bytes(bytes.fromhex(instruction_hex), "little")
    except ValueError as error:
        raise ProtocolError(f"invalid instruction bytes: {instruction_hex!r}") from error
    if instruction & BRK_MASK != BRK_OPCODE:
        raise ProtocolError(f"stop PC is not BRK: instruction=0x{instruction:08x}")
    immediate = (instruction >> 5) & 0xFFFF
    if immediate != UNIVERSAL_BRK_IMMEDIATE:
        raise ProtocolError(f"unexpected BRK immediate: 0x{immediate:x}")


async def set_register(remote: GDBRemote, register: str, value: int, thread: str) -> None:
    response = await remote.command(f"P{register}={encode_hex_le(value)};thread:{thread};")
    if response != "OK":
        raise ProtocolError(f"failed to write register {register}: {response!r}")


async def prepare_region(remote: GDBRemote, state: StopState) -> int:
    if state.x1 <= 0 or state.x1 > MAX_PREPARE_SIZE:
        raise ProtocolError(f"refusing invalid JIT allocation size 0x{state.x1:x}")
    if state.x1 % JIT_PAGE_SIZE != 0:
        raise ProtocolError(f"JIT allocation is not 16 KiB aligned: 0x{state.x1:x}")

    execute_address = state.x0
    if execute_address == 0:
        response = await remote.command(f"_M{state.x1:x},rx")
        try:
            execute_address = int(response, 16)
        except ValueError as error:
            raise ProtocolError(f"RX allocation failed: {response!r}") from error
    if execute_address % JIT_PAGE_SIZE != 0:
        raise ProtocolError(f"RX allocation is not page aligned: 0x{execute_address:x}")

    for offset in range(0, state.x1, JIT_PAGE_SIZE):
        page = execute_address + offset
        response = await remote.command(f"M{page:x},1:69")
        if response != "OK":
            raise ProtocolError(f"failed to prepare JIT page 0x{page:x}: {response!r}")

    await set_register(remote, "0", execute_address, state.thread)
    print(
        f"prepared-region address=0x{execute_address:x} size=0x{state.x1:x} "
        f"pages={state.x1 // JIT_PAGE_SIZE}"
    )
    return execute_address


async def run(args: argparse.Namespace) -> int:
    if args.pid <= 1:
        raise ProtocolError("refusing to attach to PID 1 or an invalid PID")

    async with UserspaceRsdTunnel(
        serial=args.udid, autopair=True, remotepairing_fallback=False
    ) as rsd:
        connection = await rsd.create_service_connection(
            rsd.get_service_port(DEBUG_PROXY_SERVICE)
        )
        remote = GDBRemote(connection, args.timeout)
        attached = False
        stopped_pc: int | None = None
        stopped_thread: str | None = None
        try:
            await connection.sendall(b"+")
            supported = await remote.command("qSupported")
            print(f"debugserver-supported={supported}")

            attach_response = await remote.command(f"vAttach;{args.pid:x}")
            attached = True
            initial_state = StopState.parse(attach_response)
            validate_process_info(
                await remote.command("qProcessInfo"), args.pid, args.expected_name
            )

            if args.inspect_read_only:
                instruction = await remote.command(f"m{initial_state.pc:x},4")
                pc_register = await remote.command(
                    f"p20;thread:{initial_state.thread};"
                )
                print(
                    "read-only-inspection "
                    f"thread={initial_state.thread} pc=0x{initial_state.pc:x} "
                    f"instruction={instruction!r} pc-register={pc_register!r}"
                )

            if args.same_value_register_write:
                x8_before = await remote.command(
                    f"p8;thread:{initial_state.thread};"
                )
                if not re.fullmatch(r"[0-9a-fA-F]{16}", x8_before):
                    raise ProtocolError(
                        f"unexpected x8 register value: {x8_before!r}"
                    )
                write_response = await remote.command(
                    f"P8={x8_before};thread:{initial_state.thread};"
                )
                if write_response != "OK":
                    raise ProtocolError(
                        f"same-value x8 write failed: {write_response!r}"
                    )
                x8_after = await remote.command(
                    f"p8;thread:{initial_state.thread};"
                )
                if x8_after.lower() != x8_before.lower():
                    raise ProtocolError(
                        f"x8 changed after same-value write: "
                        f"before={x8_before!r} after={x8_after!r}"
                    )
                print(
                    "same-value-register-write "
                    f"thread={initial_state.thread} x8={x8_after} status=success"
                )

            if args.same_value_memory_write:
                sp_raw = await remote.command(
                    f"p1f;thread:{initial_state.thread};"
                )
                if not re.fullmatch(r"[0-9a-fA-F]{16}", sp_raw):
                    raise ProtocolError(
                        f"unexpected sp register value: {sp_raw!r}"
                    )
                sp = decode_hex_le(sp_raw)
                if sp == 0 or sp & 0xF:
                    raise ProtocolError(f"refusing invalid stack pointer 0x{sp:x}")
                stack_bytes = await remote.command(f"m{sp:x},8")
                if not re.fullmatch(r"[0-9a-fA-F]{16}", stack_bytes):
                    raise ProtocolError(
                        f"unexpected stack bytes: {stack_bytes!r}"
                    )
                write_response = await remote.command(
                    f"M{sp:x},8:{stack_bytes}"
                )
                if write_response != "OK":
                    raise ProtocolError(
                        f"same-value stack write failed: {write_response!r}"
                    )
                stack_after = await remote.command(f"m{sp:x},8")
                if stack_after.lower() != stack_bytes.lower():
                    raise ProtocolError(
                        f"stack changed after same-value write: "
                        f"before={stack_bytes!r} after={stack_after!r}"
                    )
                print(
                    "same-value-memory-write "
                    f"thread={initial_state.thread} sp=0x{sp:x} "
                    f"bytes={stack_after} status=success"
                )

            if args.same_value_full_register_write:
                registers_before = await remote.command(
                    f"g;thread:{initial_state.thread};"
                )
                if (
                    len(registers_before) < 128
                    or len(registers_before) % 2 != 0
                    or not re.fullmatch(r"[0-9a-fA-F]+", registers_before)
                ):
                    raise ProtocolError(
                        f"unexpected full register blob: {registers_before!r}"
                    )
                write_response = await remote.command(
                    f"G{registers_before};thread:{initial_state.thread};"
                )
                if write_response != "OK":
                    raise ProtocolError(
                        f"same-value full register write failed: {write_response!r}"
                    )
                registers_after = await remote.command(
                    f"g;thread:{initial_state.thread};"
                )
                if registers_after.lower() != registers_before.lower():
                    raise ProtocolError("register blob changed after same-value write")
                print(
                    "same-value-full-register-write "
                    f"thread={initial_state.thread} bytes={len(registers_after) // 2} "
                    "status=success"
                )

            if args.save_restore_register_state:
                pc_before = await remote.command(
                    f"p20;thread:{initial_state.thread};"
                )
                save_identifier = await remote.command(
                    f"QSaveRegisterState;thread:{initial_state.thread};"
                )
                if not re.fullmatch(r"[0-9]+", save_identifier):
                    raise ProtocolError(
                        f"register-state save failed: {save_identifier!r}"
                    )
                restore_response = await remote.command(
                    f"QRestoreRegisterState:{save_identifier};"
                    f"thread:{initial_state.thread};"
                )
                if restore_response != "OK":
                    raise ProtocolError(
                        f"register-state restore failed: {restore_response!r}"
                    )
                pc_after = await remote.command(
                    f"p20;thread:{initial_state.thread};"
                )
                if pc_after.lower() != pc_before.lower():
                    raise ProtocolError(
                        f"PC changed across save/restore: "
                        f"before={pc_before!r} after={pc_after!r}"
                    )
                print(
                    "save-restore-register-state "
                    f"thread={initial_state.thread} save={save_identifier} "
                    f"pc={pc_after} status=success"
                )

            if (
                args.attach_detach_only
                or args.inspect_read_only
                or args.same_value_register_write
                or args.same_value_memory_write
                or args.same_value_full_register_write
                or args.save_restore_register_state
            ):
                response = await remote.command("D")
                if response not in {"OK", ""}:
                    raise ProtocolError(f"detach failed: {response!r}")
                attached = False
                if args.inspect_read_only:
                    mode = "inspect-read-only"
                elif args.same_value_register_write:
                    mode = "same-value-register-write"
                elif args.same_value_memory_write:
                    mode = "same-value-memory-write"
                elif args.same_value_full_register_write:
                    mode = "same-value-full-register-write"
                elif args.save_restore_register_state:
                    mode = "save-restore-register-state"
                else:
                    mode = "attach-detach-only"
                print(f"{mode}=success")
                return 0

            prepare_count = 0
            while True:
                state = StopState.parse(await remote.continue_until_stop())
                stopped_pc = state.pc
                stopped_thread = state.thread
                instruction = await remote.command(f"m{state.pc:x},4")
                validate_brk(instruction)
                print(
                    f"universal-brk thread={state.thread} pc=0x{state.pc:x} "
                    f"command={state.x16} x0=0x{state.x0:x} x1=0x{state.x1:x}"
                )

                if state.x16 == CMD_PREPARE_REGION:
                    if prepare_count != 0:
                        raise ProtocolError("probe requested more than one JIT region")
                    await prepare_region(remote, state)
                    prepare_count += 1
                    await set_register(remote, "20", state.pc + 4, state.thread)
                    stopped_pc = None
                    stopped_thread = None
                    continue

                if state.x16 == CMD_DETACH:
                    if prepare_count != 1:
                        raise ProtocolError("probe detached before preparing exactly one region")
                    await set_register(remote, "20", state.pc + 4, state.thread)
                    stopped_pc = None
                    stopped_thread = None
                    response = await remote.command("D")
                    if response not in {"OK", ""}:
                        raise ProtocolError(f"detach failed: {response!r}")
                    attached = False
                    print("detached=1")
                    return 0

                raise ProtocolError(f"unsupported universal command {state.x16}")
        finally:
            if attached:
                if stopped_pc is not None and stopped_thread is not None:
                    try:
                        await set_register(remote, "20", stopped_pc + 4, stopped_thread)
                    except Exception:
                        pass
                try:
                    await remote.command("D")
                except Exception:
                    pass
            await connection.close()


def main() -> int:
    args = parse_args()
    try:
        return asyncio.run(run(args))
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
