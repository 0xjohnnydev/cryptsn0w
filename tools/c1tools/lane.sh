#!/usr/bin/env bash
# lane.sh - move files to and from the jailbreak lane, and run commands there.
#
# The lane's sshd has no scp and no SFTP subsystem, so `scp` fails and so does anything
# built on it. What it does have is a working shell, and a shell is enough: a file goes
# over with `cat > path` fed from stdin, and comes back with `cat path` on stdout. Both
# are binary-safe, which is the property that matters - a Mach-O that survives a transfer
# as text would not survive being executed.
#
#   lane.sh check                     is the device reachable at all, and which build
#   lane.sh run '<command>'           run a command, output on stdout
#   lane.sh push <local> <remote>     upload, then verify the byte count
#   lane.sh pull <remote> <local>     download, then verify the byte count
#   lane.sh ls [<remote-dir>]         list a directory
#   lane.sh shell                     interactive shell on the device
#
# Environment: LANE_KEY, LANE_PORT (2222), LANE_HOST (127.0.0.1), LANE_USER (root).
#
# The verification step is not decoration. A `cat >` transfer that is truncated - by a
# dying forwarder, a full filesystem, or an interrupted session - leaves a file that
# looks present and is not whole, and on this device that surfaces later as an
# unexplained SIGKILL or a crash, because a Mach-O with a torn tail fails its code
# signature. Comparing byte counts costs nothing and removes that whole class.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LANE_KEY="${LANE_KEY:-$here/../../build/ssh/id_ed25519}"
LANE_PORT="${LANE_PORT:-2222}"
LANE_HOST="${LANE_HOST:-127.0.0.1}"
LANE_USER="${LANE_USER:-root}"

[[ -f "$LANE_KEY" ]] || { echo "lane.sh: no ssh key at $LANE_KEY (set LANE_KEY)" >&2; exit 1; }

# -o LogLevel=ERROR keeps the known-hosts and post-quantum banners out of every capture.
lane_ssh() {
    ssh -i "$LANE_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        -p "$LANE_PORT" "$LANE_USER@$LANE_HOST" "$@"
}

# Single-quote a path for the device's shell, which is zsh. Handles embedded quotes.
q() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

cmd="${1:-}"
case "$cmd" in

check)
    # A device that has dropped off USB makes every lane command return EMPTY OUTPUT
    # rather than an error, because the port forward stays open with nothing behind it.
    # Checking here once beats debugging the tool that produced the silence.
    if ! nc -z -G 3 "$LANE_HOST" "$LANE_PORT" 2>/dev/null; then
        echo "lane.sh: nothing listening on $LANE_HOST:$LANE_PORT" >&2
        echo "  the usbmux forward is probably gone: run" >&2
        echo "    pymobiledevice3 usbmux forward $LANE_PORT $LANE_PORT --serial <UDID>" >&2
        exit 1
    fi
    if ! out="$(lane_ssh 'uname -a; echo ---; id' 2>&1)"; then
        echo "lane.sh: ssh failed on port $LANE_PORT:" >&2
        echo "$out" >&2
        echo "  (an empty reply with the port open means the DEVICE is disconnected)" >&2
        exit 1
    fi
    echo "$out"
    ;;

run)
    [[ $# -ge 2 ]] || { echo "usage: lane.sh run '<command>'" >&2; exit 2; }
    lane_ssh "$2"
    ;;

push)
    [[ $# -eq 3 ]] || { echo "usage: lane.sh push <local> <remote>" >&2; exit 2; }
    local_file="$2"; remote_file="$3"
    [[ -f "$local_file" ]] || { echo "lane.sh: no such local file: $local_file" >&2; exit 1; }
    lane_ssh "cat > $(q "$remote_file")" < "$local_file"
    want=$(wc -c < "$local_file" | tr -d ' ')
    got=$(lane_ssh "wc -c < $(q "$remote_file")" | tr -d ' \r')
    if [[ "$want" != "$got" ]]; then
        echo "lane.sh: TRUNCATED TRANSFER: $local_file is $want bytes, $remote_file is $got" >&2
        exit 1
    fi
    echo "pushed $local_file -> $remote_file ($got bytes)"
    ;;

pull)
    [[ $# -eq 3 ]] || { echo "usage: lane.sh pull <remote> <local>" >&2; exit 2; }
    remote_file="$2"; local_file="$3"
    lane_ssh "cat $(q "$remote_file")" > "$local_file"
    want=$(lane_ssh "wc -c < $(q "$remote_file")" | tr -d ' \r') || true
    got=$(wc -c < "$local_file" | tr -d ' ')
    if [[ -n "${want:-}" && "$want" != "$got" ]]; then
        echo "lane.sh: TRUNCATED TRANSFER: $remote_file is $want bytes, $local_file is $got" >&2
        exit 1
    fi
    echo "pulled $remote_file -> $local_file ($got bytes)"
    ;;

ls)
    lane_ssh "ls -l ${2:-/var/jb}"
    ;;

shell)
    exec ssh -i "$LANE_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR -p "$LANE_PORT" -t "$LANE_USER@$LANE_HOST"
    ;;

*)
    sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
