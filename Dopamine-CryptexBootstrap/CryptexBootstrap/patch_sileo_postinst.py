#!/usr/bin/env python3
"""Make Sileo's control-channel parser tolerate malformed environment data."""

from __future__ import annotations

import pathlib
import sys


NEEDLE = '\t[ "${ver}" -ge 1 ] || return\n'
REPLACEMENT = """\tcase "${fd}" in
\t\t''|*[!0-9]*) return ;;
\tesac
\tcase "${ver}" in
\t\t''|*[!0-9]*) return ;;
\tesac
\t[ "${ver}" -ge 1 ] || return
"""
UICACHE_NEEDLE = """if [ -z "${SILEO}" ]; then echo "Not running in Sileo. Trigger UICache"; fi
if [ -z "${SILEO}" ]; then uicache -p /Applications/Sileo.app; fi
"""
UICACHE_REPLACEMENT = """# The fixed-trust system app is registered by
# codex-dopamine-bootstrap from its byte-verified application-container copy.
"""


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {pathlib.Path(sys.argv[0]).name} POSTINST")
    postinst = pathlib.Path(sys.argv[1])
    source = postinst.read_text()
    if source.count(NEEDLE) != 1:
        raise SystemExit("unexpected Sileo postinst control-channel parser")
    if source.count(UICACHE_NEEDLE) != 1:
        raise SystemExit("unexpected Sileo postinst uicache handoff")
    postinst.write_text(
        source.replace(NEEDLE, REPLACEMENT).replace(
            UICACHE_NEEDLE, UICACHE_REPLACEMENT
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
