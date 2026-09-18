#!/usr/bin/env python3
"""Invoke CoreDevice's raw spawn-executable feature for a device path."""

from __future__ import annotations

import argparse
import asyncio
import json
import plistlib

from pymobiledevice3.remote.core_device.app_service import AppServiceService
from pymobiledevice3.remote.remote_service_discovery import (
    RemoteServiceDiscoveryService,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("executable")
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    parser.add_argument("--user", default="active")
    return parser.parse_args()


async def run(args: argparse.Namespace) -> None:
    if args.user == "active":
        user = {"active": True}
    else:
        user = {"shortName": args.user}

    request = {
        "executableItem": {
            "url": {
                "_0": {
                    "relative": args.executable,
                },
            },
        },
        "standardIOIdentifiers": {},
        "options": {
            "arguments": args.arguments,
            "environmentVariables": {},
            "standardIOUsesPseudoterminals": True,
            "startStopped": False,
            "user": user,
            "platformSpecificOptions": plistlib.dumps({}),
        },
    }

    async with RemoteServiceDiscoveryService((args.host, args.port)) as rsd:
        async with AppServiceService(rsd) as service:
            result = await service.invoke(
                "com.apple.coredevice.feature.spawnexecutable",
                request,
            )
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(run(parse_args()))
