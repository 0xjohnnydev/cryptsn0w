#!/bin/zsh

set -euo pipefail

script_dir=${0:A:h}
project_root=${script_dir:h}
site_packages=("$project_root"/build/frida-host-venv/lib/python*/site-packages(N))

if (( ${#site_packages} != 1 )); then
    print -u2 -- "expected exactly one Frida host site-packages directory"
    print -u2 -- "install it with: uv pip install --python build/frida-host-venv/bin/python -r requirements-frida.txt"
    exit 69
fi

if [[ -n ${PYTHONPATH:-} ]]; then
    export PYTHONPATH="${site_packages[1]}:$PYTHONPATH"
else
    export PYTHONPATH="${site_packages[1]}"
fi

exec /usr/bin/python3 "$script_dir/frida-ios27-usb-smoke.py" "$@"
