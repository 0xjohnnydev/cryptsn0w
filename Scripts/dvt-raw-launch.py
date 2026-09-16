#!/usr/bin/env python3
"""Launch an exact executable path through Instruments process control."""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
import time
from typing import Any

from pymobiledevice3.remote.userspace_tunnel import establish_userspace_rsd
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl


async def launch(args: argparse.Namespace) -> dict[str, Any]:
    rsd = await establish_userspace_rsd(serial=args.udid)
    output: list[str] = []
    started = time.monotonic()
    try:
        async with DvtProvider(rsd) as dvt:
            async with ProcessControl(dvt) as process_control:
                async with DeviceInfo(dvt) as device_info:
                    bundle_id = None if args.nil_bundle_id else args.bundle_id
                    pid = await process_control.service.launch_suspended_process_with_device_path_bundle_identifier_environment_arguments_options_(
                        args.path,
                        bundle_id,
                        dict(item.split("=", 1) for item in args.env),
                        args.arguments,
                        {
                            "StartSuspendedKey": True,
                            "KillExisting": False,
                        },
                    )
                    if not pid:
                        raise RuntimeError("device returned an empty PID")

                    await process_control.service.startObservingPid_(pid)
                    await process_control.signal(pid, int(signal.SIGCONT))

                    deadline = time.monotonic() + args.timeout
                    timed_out = False
                    while True:
                        while True:
                            try:
                                event = process_control.service.output_events.get_nowait()
                            except asyncio.QueueEmpty:
                                break
                            output.append(event[0])

                        if not await device_info.is_running_pid(pid):
                            break
                        if time.monotonic() >= deadline:
                            timed_out = True
                            break
                        await asyncio.sleep(0.1)

                    await asyncio.sleep(0.15)
                    while True:
                        try:
                            event = process_control.service.output_events.get_nowait()
                        except asyncio.QueueEmpty:
                            break
                        output.append(event[0])

                    try:
                        await process_control.service.stopObservingPid_(pid)
                    except Exception:
                        pass

                    return {
                        "arguments": args.arguments,
                        "bundleID": bundle_id,
                        "elapsedSeconds": round(time.monotonic() - started, 3),
                        "environment": args.env,
                        "output": output,
                        "path": args.path,
                        "pid": pid,
                        "timedOut": timed_out,
                    }
    finally:
        await rsd.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--udid", required=True)
    parser.add_argument("--path", required=True)
    parser.add_argument("--bundle-id", default="")
    parser.add_argument(
        "--nil-bundle-id",
        action="store_true",
        help="encode the bundle identifier as nil so Instruments uses --path",
    )
    parser.add_argument("--timeout", type=float, default=45.0)
    parser.add_argument("--env", action="append", default=[])
    parser.add_argument("arguments", nargs="*")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        result = asyncio.run(launch(args))
    except Exception as error:
        print(
            json.dumps(
                {
                    "error": str(error),
                    "errorType": type(error).__name__,
                    "path": args.path,
                },
                indent=2,
                sort_keys=True,
            )
        )
        raise SystemExit(1) from error
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
