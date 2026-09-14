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


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {pathlib.Path(sys.argv[0]).name} POSTINST")
    postinst = pathlib.Path(sys.argv[1])
    source = postinst.read_text()
    if source.count(NEEDLE) != 1:
        raise SystemExit("unexpected Sileo postinst control-channel parser")
    postinst.write_text(source.replace(NEEDLE, REPLACEMENT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
