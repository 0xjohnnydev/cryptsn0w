#!/var/jb/bin/sh
set -eu

exec /var/jb/usr/libexec/codex-exec-worker \
    --macho /var/jb/usr/libexec/customctl "$@"
