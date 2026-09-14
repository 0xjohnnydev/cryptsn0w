#!/usr/bin/env python3
"""Apply the pinned RemoteXPC outbound flow-control accounting fix.

HTTP/2 flow control covers every DATA frame on a connection. pymobiledevice3
11.12.4 accounts for file-transfer frames, but its XPC request and handshake
DATA frames bypass the same counters. A large Cryptex transfer can therefore
exceed the device's advertised connection window and receive GOAWAY error 3.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path


def replace_once(source: str, before: str, after: str, label: str) -> str:
    if after in source:
        return source
    count = source.count(before)
    if count != 1:
        raise SystemExit(
            f"cannot apply {label}: expected one pinned source block, found {count}"
        )
    return source.replace(before, after, 1)


def main() -> int:
    spec = importlib.util.find_spec("pymobiledevice3.remote.remotexpc")
    if spec is None or spec.origin is None:
        raise SystemExit("pymobiledevice3.remote.remotexpc is unavailable")
    path = Path(spec.origin).resolve()
    source = path.read_text()

    source = replace_once(
        source,
        '''    async def send_request(self, data: dict[str, Any], wanting_reply: bool = False) -> None:
        xpc_wrapper = create_xpc_wrapper(
            data, message_id=self.next_message_id[ROOT_CHANNEL], wanting_reply=wanting_reply
        )
        writer = self.writer
        writer.write(DataFrame(stream_id=ROOT_CHANNEL, data=xpc_wrapper).serialize())
        await writer.drain()
        self.next_message_id[ROOT_CHANNEL] += 1
''',
        '''    async def send_request(self, data: dict[str, Any], wanting_reply: bool = False) -> None:
        xpc_wrapper = create_xpc_wrapper(
            data, message_id=self.next_message_id[ROOT_CHANNEL], wanting_reply=wanting_reply
        )
        offset = 0
        while offset < len(xpc_wrapper):
            offset += await self._send_flow_controlled(
                ROOT_CHANNEL, xpc_wrapper, offset, len(xpc_wrapper)
            )
        self.next_message_id[ROOT_CHANNEL] += 1
''',
        "XPC request accounting",
    )
    source = replace_once(
        source,
        '''        await self._send_frame(
            DataFrame(stream_id=ROOT_CHANNEL, data=XpcWrapper.build({"size": 0, "flags": 0x0201, "payload": None}))
        )
        await self._send_frame(
            DataFrame(
                stream_id=REPLY_CHANNEL,
                data=XpcWrapper.build({
                    "size": 0,
                    "flags": XpcFlags.ALWAYS_SET | XpcFlags.INIT_HANDSHAKE,
                    "payload": None,
                }),
            )
        )
''',
        '''        termination = XpcWrapper.build({"size": 0, "flags": 0x0201, "payload": None})
        await self._send_flow_controlled(
            ROOT_CHANNEL, termination, 0, len(termination)
        )
        reply_handshake = XpcWrapper.build({
            "size": 0,
            "flags": XpcFlags.ALWAYS_SET | XpcFlags.INIT_HANDSHAKE,
            "payload": None,
        })
        await self._send_flow_controlled(
            REPLY_CHANNEL, reply_handshake, 0, len(reply_handshake)
        )
''',
        "RemoteXPC handshake accounting",
    )
    source = replace_once(
        source,
        '''        flags |= XpcFlags.ALWAYS_SET
        await self._send_frame(HeadersFrame(stream_id=stream_id, flags=["END_HEADERS"]))
        await self._send_frame(
            DataFrame(stream_id=stream_id, data=XpcWrapper.build({"size": 0, "flags": flags, "payload": None}))
        )
''',
        '''        flags |= XpcFlags.ALWAYS_SET
        await self._send_frame(HeadersFrame(stream_id=stream_id, flags=["END_HEADERS"]))
        preamble = XpcWrapper.build({"size": 0, "flags": flags, "payload": None})
        await self._send_flow_controlled(
            stream_id, preamble, 0, len(preamble)
        )
''',
        "file-channel preamble accounting",
    )

    compile(source, str(path), "exec")
    if path.read_text() == source:
        print(f"RemoteXPC flow-control patch is current: {path}")
        return 0

    temporary = path.with_name(f".{path.name}.codex-{os.getpid()}")
    temporary.write_text(source)
    temporary.chmod(path.stat().st_mode)
    os.replace(temporary, path)
    print(f"Applied RemoteXPC flow-control patch: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
