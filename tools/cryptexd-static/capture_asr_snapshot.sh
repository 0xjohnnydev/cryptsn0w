#!/bin/zsh
set -euo pipefail

if [[ $# -ne 5 ]]; then
    print -u2 "usage: $0 SOURCE_MOUNT TARGET_VOLUME LOG_FILE SOURCE_RAW_DEVICE RETAINED_COPY"
    exit 64
fi

source_mount=$1
target_volume=$2
log_file=$3
source_raw_device=$4
retained_copy=$5

if [[ $source_mount != /Volumes/Codex* ]]; then
    print -u2 "refusing source outside /Volumes/Codex*: $source_mount"
    exit 64
fi
if [[ $target_volume != /dev/disk<->s<-> ]]; then
    print -u2 "refusing non-volume target: $target_volume"
    exit 64
fi
if [[ ! -d $source_mount || ! -e $target_volume ]]; then
    print -u2 "source mount or target device is missing"
    exit 66
fi
if [[ $source_raw_device != /dev/rdisk<-> || ! -e $source_raw_device ]]; then
    print -u2 "refusing non-whole raw source device: $source_raw_device"
    exit 64
fi
if [[ $retained_copy != /tmp/codex-ddi-volume-probe.*/*.raw || -e $retained_copy ]]; then
    print -u2 "refusing retained-copy path: $retained_copy"
    exit 64
fi

target_info=$(/usr/sbin/diskutil info "$target_volume")
if ! print -r -- "$target_info" | /usr/bin/grep -Eq '^[[:space:]]*Protocol:[[:space:]]+Disk Image[[:space:]]*$'; then
    print -u2 "refusing target that is not a disk image: $target_volume"
    exit 64
fi
source_info=$(/usr/sbin/diskutil info "${source_raw_device#/dev/r}")
if ! print -r -- "$source_info" | /usr/bin/grep -Eq '^[[:space:]]*Protocol:[[:space:]]+Disk Image[[:space:]]*$'; then
    print -u2 "refusing source that is not a disk image: $source_raw_device"
    exit 64
fi
source_block_device="/dev/${source_raw_device#/dev/r}"

/usr/sbin/asr restore \
    --source "$source_mount" \
    --target "$target_volume" \
    --erase \
    --noprompt \
    --noverify \
    --useReplication \
    >"$log_file" 2>&1 &
asr_pid=$!
snapshot_name="com.apple.asr.${asr_pid}"

for attempt in {1..1200}; do
    # IDA confirms ASR prints this only after fs_snapshot_create succeeds and
    # APFSStreamCreatePrepare has accepted the source. Stop it before the
    # unified cleanup block can call fs_snapshot_delete on the source.
    if /usr/bin/grep -Fq 'Replicating' "$log_file" 2>/dev/null; then
        /bin/kill -STOP "$asr_pid" 2>/dev/null || true
        {
            print "\n--- paused source snapshot listing ---"
            /usr/sbin/diskutil apfs listSnapshots "$source_mount" 2>&1 || true
            print "--- end paused source snapshot listing ---"
        } >>"$log_file"
        /bin/sync
        /usr/bin/python3 -c 'import os,sys; fd=os.open(sys.argv[1], os.O_RDONLY); os.fsync(fd); os.close(fd)' \
            "$source_block_device" >>"$log_file" 2>&1 || true
        /bin/dd if="$source_raw_device" of="$retained_copy" bs=4m 2>>"$log_file"
        /bin/sync
        /bin/kill -KILL "$asr_pid" 2>/dev/null || true
        wait "$asr_pid" 2>/dev/null || true
        print "snapshot_expected=$snapshot_name"
        print "retained_copy=$retained_copy"
        exit 0
    fi
    if ! /bin/kill -0 "$asr_pid" 2>/dev/null; then
        wait "$asr_pid" 2>/dev/null || true
        print -u2 "asr exited before the snapshot could be retained; see $log_file"
        exit 1
    fi
    /bin/sleep 0.01
done

/bin/kill -KILL "$asr_pid" 2>/dev/null || true
wait "$asr_pid" 2>/dev/null || true
print -u2 "timed out waiting for $snapshot_name; see $log_file"
exit 1
