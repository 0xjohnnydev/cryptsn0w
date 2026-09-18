"""Register-only command execution through the resident debugged carrier.

This LLDB command is intentionally narrow: it invokes the already imported
``posix_spawn`` stub in the exact codex-ellekit-loader image, then restores the
selected thread's complete general-register state.  It does not read or write
another process, and it explicitly refuses PID 1.

Usage after attaching LLDB to the carrier process::

    carrier-spawn /absolute/program arg0 [arg1 ...]

The first argument is both the executable path and argv[0].
"""

from __future__ import annotations

import shlex
import struct

import lldb


_EXPECTED_STOP_OFFSET = 0x4084
_STORE_X8_X9_OFFSET = 0x4294
_POSIX_SPAWN_STUB_OFFSET = 0xB388
_SCRATCH_DISTANCE = 0x1000
_SCRATCH_LIMIT = 0xC00


class CarrierSpawnError(RuntimeError):
    pass


def _command(debugger: lldb.SBDebugger, command: str) -> None:
    response = lldb.SBCommandReturnObject()
    debugger.GetCommandInterpreter().HandleCommand(command, response)
    if not response.Succeeded():
        raise CarrierSpawnError(
            f"LLDB command failed: {command}: {response.GetError().strip()}"
        )


def _register(frame: lldb.SBFrame, name: str) -> int:
    value = frame.FindRegister(name)
    if not value.IsValid():
        raise CarrierSpawnError(f"register unavailable: {name}")
    return value.GetValueAsUnsigned()


def _set_register(debugger: lldb.SBDebugger, name: str, value: int) -> None:
    _command(debugger, f"register write {name} 0x{value:x}")


def _selected_frame(process: lldb.SBProcess) -> lldb.SBFrame:
    thread = process.GetSelectedThread()
    if not thread.IsValid():
        raise CarrierSpawnError("no selected thread")
    frame = thread.GetFrameAtIndex(0)
    if not frame.IsValid():
        raise CarrierSpawnError("no selected frame")
    return frame


def _step_store(
    debugger: lldb.SBDebugger,
    process: lldb.SBProcess,
    gadget: int,
    address: int,
    value: int,
) -> None:
    _set_register(debugger, "x8", value)
    _set_register(debugger, "x9", address)
    _set_register(debugger, "pc", gadget)
    thread = process.GetSelectedThread()
    thread.StepInstruction(False)
    if process.GetState() != lldb.eStateStopped:
        raise CarrierSpawnError(
            f"store single-step did not stop (state={process.GetState()})"
        )
    frame = _selected_frame(process)
    stopped_pc = _register(frame, "pc")
    if stopped_pc != gadget + 4:
        raise CarrierSpawnError(
            f"store single-step stopped at 0x{stopped_pc:x}, "
            f"expected 0x{gadget + 4:x}"
        )


def _write_bytes(
    debugger: lldb.SBDebugger,
    process: lldb.SBProcess,
    gadget: int,
    address: int,
    data: bytes,
) -> None:
    padded = data + b"\0" * ((-len(data)) % 8)
    for offset in range(0, len(padded), 8):
        value = struct.unpack_from("<Q", padded, offset)[0]
        _step_store(debugger, process, gadget, address + offset, value)


def _align(value: int, alignment: int = 8) -> int:
    return (value + alignment - 1) & -alignment


def _continue_to(
    process: lldb.SBProcess, address: int, attempts: int = 12
) -> None:
    for _ in range(attempts):
        error = process.Continue()
        if error.Fail():
            raise CarrierSpawnError(f"continue failed: {error.GetCString()}")
        if process.GetState() != lldb.eStateStopped:
            raise CarrierSpawnError(
                f"carrier did not stop after continue (state={process.GetState()})"
            )
        if _register(_selected_frame(process), "pc") == address:
            return
    raise CarrierSpawnError(f"carrier did not return to 0x{address:x}")


def carrier_spawn(
    debugger: lldb.SBDebugger,
    command: str,
    result: lldb.SBCommandReturnObject,
    internal_dict: dict,
) -> None:
    del internal_dict
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    if not process.IsValid() or process.GetState() != lldb.eStateStopped:
        result.SetError("carrier-spawn requires a stopped attached process")
        return
    if process.GetProcessID() <= 1:
        result.SetError("carrier-spawn refuses PID 1")
        return

    try:
        arguments = shlex.split(command)
    except ValueError as error:
        result.SetError(str(error))
        return
    if not arguments or any(not item.startswith("/") for item in arguments[:1]):
        result.SetError("usage: carrier-spawn /absolute/program [arg ...]")
        return
    if any("\0" in item for item in arguments):
        result.SetError("arguments may not contain NUL bytes")
        return

    register_names = [f"x{index}" for index in range(29)] + [
        "fp",
        "lr",
        "sp",
        "pc",
        "cpsr",
    ]
    frame = _selected_frame(process)
    saved = {name: _register(frame, name) for name in register_names}
    original_pc = saved["pc"]
    original_sp = saved["sp"]
    image_base = original_pc - _EXPECTED_STOP_OFFSET
    if image_base <= 0 or image_base & 0x3FFF:
        result.SetError(
            f"unexpected carrier stop PC 0x{original_pc:x}; refusing to infer slide"
        )
        return

    store_gadget = image_base + _STORE_X8_X9_OFFSET
    spawn_stub = image_base + _POSIX_SPAWN_STUB_OFFSET
    scratch = (original_sp - _SCRATCH_DISTANCE) & ~0xF
    cursor = scratch
    string_addresses: list[int] = []
    for argument in arguments:
        encoded = argument.encode("utf-8") + b"\0"
        string_addresses.append(cursor)
        cursor += _align(len(encoded))
    argv_address = _align(cursor, 16)
    cursor = argv_address + 8 * (len(arguments) + 1)
    pid_address = _align(cursor, 8)
    cursor = pid_address + 8
    if cursor - scratch > _SCRATCH_LIMIT:
        result.SetError("encoded spawn request exceeds carrier scratch limit")
        return

    breakpoint = None
    spawn_result = None
    try:
        for address, argument in zip(string_addresses, arguments):
            _write_bytes(
                debugger,
                process,
                store_gadget,
                address,
                argument.encode("utf-8") + b"\0",
            )
        argv = b"".join(
            struct.pack("<Q", address) for address in string_addresses
        ) + struct.pack("<Q", 0)
        _write_bytes(debugger, process, store_gadget, argv_address, argv)
        _write_bytes(debugger, process, store_gadget, pid_address, b"\0" * 8)

        breakpoint = target.BreakpointCreateByAddress(original_pc)
        if not breakpoint.IsValid():
            raise CarrierSpawnError("could not create return breakpoint")
        if not breakpoint.SetIsHardware(True):
            raise CarrierSpawnError("could not request a hardware return breakpoint")

        _set_register(debugger, "x0", pid_address)
        _set_register(debugger, "x1", string_addresses[0])
        _set_register(debugger, "x2", 0)
        _set_register(debugger, "x3", 0)
        _set_register(debugger, "x4", argv_address)
        _set_register(debugger, "x5", 0)
        _set_register(debugger, "lr", original_pc)
        _set_register(debugger, "pc", spawn_stub)
        _continue_to(process, original_pc)
        spawn_result = _register(_selected_frame(process), "x0") & 0xFFFFFFFF
    except Exception as error:
        result.SetError(str(error))
    finally:
        if breakpoint is not None and breakpoint.IsValid():
            target.BreakpointDelete(breakpoint.GetID())
        if process.IsValid() and process.GetState() == lldb.eStateStopped:
            for name in register_names:
                if name in ("pc", "cpsr"):
                    continue
                try:
                    _set_register(debugger, name, saved[name])
                except Exception:
                    pass
            try:
                _set_register(debugger, "cpsr", saved["cpsr"])
                _set_register(debugger, "pc", saved["pc"])
            except Exception:
                pass

    if spawn_result is not None:
        result.AppendMessage(
            f"carrier-spawn posix_spawn={spawn_result} "
            f"image_base=0x{image_base:x} scratch=0x{scratch:x}"
        )


def __lldb_init_module(debugger: lldb.SBDebugger, internal_dict: dict) -> None:
    del internal_dict
    debugger.HandleCommand(
        "command script add -f lldb_carrier_spawn.carrier_spawn carrier-spawn"
    )
    print("carrier-spawn command installed")
