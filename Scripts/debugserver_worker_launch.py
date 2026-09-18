#!/usr/bin/env python3
"""Probe executable launch through Apple's debug proxy.

This is a deliberately narrow bootstrap probe. It only launches the exact
``/var/jb/usr/libexec/codex-exec-worker`` path in ``--self-test`` mode,
Apple's read-only ``/bin/df`` as a control, or the exact installed ElleKit
loader in ``--page-probe-pid`` mode for a validated non-PID-1 SpringBoard.
"""

from __future__ import annotations

import argparse
import asyncio
import re
import sys

from pymobiledevice3.remote.remote_service_discovery import (
    RemoteServiceDiscoveryService,
)
from pymobiledevice3.remote.rsd_tunnel import PreferredRsdTunnel


DEBUG_PROXY_SERVICE = "com.apple.internal.dt.remote.debugproxy"
WORKER_PATH = "/var/jb/usr/libexec/codex-exec-worker"
EXPECTED_NAME = "codex-exec-worker"
DONOR_REMAP_PAGE_PATH = (
    "/var/jb/usr/share/codex-donor-remap-page.bin"
)
LOADER_PATH = "/var/jb/usr/libexec/codex-ellekit-loader"
LOADER_NAME = "codex-ellekit-loader"
SPRINGBOARD_COPY_PATH = "/var/jb/usr/libexec/codex-sb-test"
SPRINGBOARD_COPY_NAME = "codex-sb-test"
INSTALL_PATH = "/var/jb/usr/bin/install"
SPRINGBOARD_LIVE_PRECURSOR_UPLOAD_PATH = (
    "/var/mobile/Media/codex-springboard-live-precursor"
)
SPRINGBOARD_LIVE_PRECURSOR_PATH = (
    "/var/jb/usr/libexec/codex-springboard-live-precursor"
)
CANDIDATE_INJECTION_BRIDGE_UPLOAD_PATH = (
    "/var/mobile/Media/codex-candidate-injection-bridge.dylib"
)
CANDIDATE_INJECTION_BRIDGE_PATH = (
    "/var/jb/usr/lib/codex-candidate-injection-bridge.dylib"
)


class ProtocolError(RuntimeError):
    pass


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
    parser.add_argument("--timeout", type=float, default=20.0)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument(
        "--self-test",
        action="store_true",
        help="run the worker's bounded executable-page self-test",
    )
    modes.add_argument(
        "--system-df",
        action="store_true",
        help="launch Apple's /bin/df as a read-only control",
    )
    modes.add_argument(
        "--donor-remap-hold",
        action="store_true",
        help=(
            "host the fixed unsigned low-power-loop/return-42 page in an "
            "owned debug-authorized worker child until the remap probe "
            "terminates it"
        ),
    )
    modes.add_argument(
        "--copied-springboard-preflight",
        action="store_true",
        help=(
            "launch the fixed non-system SpringBoard copy only through its "
            "initial debug stop, then close the owned inferior"
        ),
    )
    modes.add_argument(
        "--springboard-page-probe",
        metavar="PID",
        type=int,
        help="run the installed loader's bounded page probe on SpringBoard",
    )
    modes.add_argument(
        "--stage-springboard-live-precursor",
        action="store_true",
        help="install the fixed Media upload at the managed precursor path",
    )
    modes.add_argument(
        "--stage-candidate-injection-bridge",
        action="store_true",
        help="install the fixed Media bridge at its managed rootless path",
    )
    modes.add_argument(
        "--soften-cryptexd",
        metavar="PID",
        type=int,
        help="run the managed precursor's exact cryptexd attach/detach pass",
    )
    return parser.parse_args()


def frame_packet(payload: str) -> bytes:
    encoded = payload.encode("ascii")
    checksum = sum(encoded) & 0xFF
    return b"$" + encoded + b"#" + f"{checksum:02x}".encode("ascii")


def parse_key_values(response: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in response.split(";"):
        if ":" in item:
            key, value = item.split(":", 1)
            result[key] = value
    return result


def launch_arguments_packet(arguments: list[str]) -> str:
    pieces = ["A"]
    for index, argument in enumerate(arguments):
        encoded = argument.encode("utf-8").hex()
        pieces.append(f"{len(encoded)},{index},{encoded}")
        if index + 1 != len(arguments):
            pieces.append(",")
    return "".join(pieces)


class GDBRemote:
    def __init__(self, connection, timeout: float) -> None:
        self.connection = connection
        self.timeout = timeout
        self.buffer = bytearray()

    async def _fill(self) -> None:
        chunk = await asyncio.wait_for(
            self.connection.recv_any(65536), self.timeout
        )
        if not chunk:
            raise ProtocolError("debugserver closed the connection")
        self.buffer.extend(chunk)

    async def _packet(self) -> str:
        while True:
            while self.buffer and self.buffer[0] in (ord("+"), ord("-")):
                marker = self.buffer.pop(0)
                if marker == ord("-"):
                    raise ProtocolError(
                        "debugserver rejected the previous packet checksum"
                    )

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
            checksum_text = bytes(
                self.buffer[checksum_offset + 1 : checksum_offset + 3]
            )
            del self.buffer[: checksum_offset + 3]
            try:
                received_checksum = int(checksum_text, 16)
            except ValueError as error:
                raise ProtocolError(
                    f"invalid packet checksum {checksum_text!r}"
                ) from error
            if (sum(payload) & 0xFF) != received_checksum:
                await self.connection.sendall(b"-")
                raise ProtocolError("debugserver response checksum mismatch")
            await self.connection.sendall(b"+")
            return payload.decode("ascii")

    async def command(self, payload: str) -> str:
        await self.connection.sendall(frame_packet(payload))
        return await self._packet()

    async def continue_until_stop(self) -> str:
        await self.connection.sendall(frame_packet("vCont;c"))
        while True:
            response = await self._packet()
            if response.startswith("O") and len(response) > 1:
                try:
                    output = bytes.fromhex(response[1:]).decode(
                        "utf-8", "replace"
                    )
                except ValueError:
                    output = response
                print(f"target-output={output.rstrip()}")
                continue
            if response[:1] in {"T", "S", "W", "X"}:
                return response
            raise ProtocolError(
                f"unexpected continue response: {response!r}"
            )


async def expect_ok(remote: GDBRemote, payload: str) -> None:
    response = await remote.command(payload)
    if response != "OK":
        raise ProtocolError(f"{payload!r} failed: {response!r}")


def validate_process_info(response: str, expected_name: str) -> int:
    fields = parse_key_values(response)
    if "pid" not in fields:
        raise ProtocolError(f"qProcessInfo omitted pid: {response!r}")
    pid = int(fields["pid"], 16)
    if pid <= 1:
        raise ProtocolError(f"refusing invalid or PID-1 inferior: {pid}")

    encoded_name = fields.get("name", "")
    name = (
        bytes.fromhex(encoded_name).decode("utf-8", "replace")
        if encoded_name
        else ""
    )
    if name != expected_name:
        raise ProtocolError(
            f"unexpected inferior name: expected {expected_name!r}, got {name!r}"
        )
    print(
        "inferior "
        f"pid={pid} name={name} uid={fields.get('uid', 'unreported')} "
        f"euid={fields.get('euid', 'unreported')} "
        f"parent={fields.get('parent-pid', 'unreported')}"
    )
    return pid


async def run(args: argparse.Namespace) -> int:
    if args.self_test:
        launch_arguments = [WORKER_PATH, "--self-test"]
        expected_name = EXPECTED_NAME
    elif args.system_df:
        launch_arguments = ["/bin/df"]
        expected_name = "df"
    elif args.donor_remap_hold:
        launch_arguments = [
            WORKER_PATH,
            "--raw",
            DONOR_REMAP_PAGE_PATH,
        ]
        expected_name = EXPECTED_NAME
    elif args.copied_springboard_preflight:
        launch_arguments = [SPRINGBOARD_COPY_PATH]
        expected_name = SPRINGBOARD_COPY_NAME
    elif args.springboard_page_probe is not None:
        if args.springboard_page_probe <= 1:
            raise ProtocolError("refusing PID 1 or an invalid target PID")
        launch_arguments = [
            LOADER_PATH,
            "--page-probe-pid",
            str(args.springboard_page_probe),
        ]
        expected_name = LOADER_NAME
    elif args.stage_springboard_live_precursor:
        launch_arguments = [
            INSTALL_PATH,
            "-m",
            "0755",
            SPRINGBOARD_LIVE_PRECURSOR_UPLOAD_PATH,
            SPRINGBOARD_LIVE_PRECURSOR_PATH,
        ]
        expected_name = "install"
    elif args.stage_candidate_injection_bridge:
        launch_arguments = [
            INSTALL_PATH,
            "-m",
            "0644",
            CANDIDATE_INJECTION_BRIDGE_UPLOAD_PATH,
            CANDIDATE_INJECTION_BRIDGE_PATH,
        ]
        expected_name = "install"
    else:
        if args.soften_cryptexd <= 1:
            raise ProtocolError("refusing PID 1 or an invalid cryptexd PID")
        launch_arguments = [
            WORKER_PATH,
            "--macho",
            SPRINGBOARD_LIVE_PRECURSOR_PATH,
            "--soften-cryptexd",
            str(args.soften_cryptexd),
        ]
        expected_name = EXPECTED_NAME

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
        inferior_pid: int | None = None
        try:
            await connection.sendall(b"+")
            supported = await remote.command("qSupported")
            print(f"debugserver-supported={supported}")

            optional = await remote.command("QEnableErrorStrings")
            if optional not in {"OK", ""}:
                raise ProtocolError(
                    f"QEnableErrorStrings failed: {optional!r}"
                )
            await expect_ok(remote, "QLaunchArch:arm64")
            await expect_ok(remote, "QSetDisableASLR:0")

            launch_packet = launch_arguments_packet(launch_arguments)
            await expect_ok(remote, launch_packet)
            await expect_ok(remote, "qLaunchSuccess")
            inferior_pid = validate_process_info(
                await remote.command("qProcessInfo"), expected_name
            )

            if args.copied_springboard_preflight:
                print(
                    "copied-springboard-exec-admission=success "
                    f"path={SPRINGBOARD_COPY_PATH}"
                )
                return 0

            final = await remote.continue_until_stop()
            print(f"inferior-final={final}")
            expected_final = (
                r"W89(?:;.*)?"
                if args.donor_remap_hold
                else r"W00(?:;.*)?"
            )
            if not re.fullmatch(expected_final, final):
                raise ProtocolError(
                    f"debugproxy inferior had an unexpected exit: {final!r}"
                )
            return 0
        finally:
            # Closing debugserver kills only an unfinished inferior that this
            # session launched. No pre-existing process is ever attached.
            if inferior_pid is not None:
                print(f"validated-inferior-pid={inferior_pid}")
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
