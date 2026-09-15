#!/var/jb/usr/bin/zsh

emulate -L zsh
set -euo pipefail

readonly SCRIPT_PATH=${0:A}
readonly SOURCE_ROOT=${SCRIPT_PATH:h:h}/libexec/untitled/frida
readonly LAUNCHER=$SOURCE_ROOT/frida-launcher

if (( EUID != 0 )); then
    print -u2 -- "error: Frida staging requires UID 0"
    exit 77
fi

if [[ ! -x $LAUNCHER ]]; then
    print -u2 -- "error: missing trusted Frida launcher: $LAUNCHER"
    exit 72
fi

exec "$LAUNCHER" "$@"
