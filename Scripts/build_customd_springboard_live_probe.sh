#!/bin/sh
set -eu

SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPOSITORY_ROOT=$(CDPATH= cd -- "$SCRIPT_DIRECTORY/.." && pwd)
OUTPUT_DIRECTORY=${1:-"$REPOSITORY_ROOT/build/customd-springboard-live-probe"}
ACCEPTANCE_NONCE=${2:-"20260918-customd-springboard-live-probe-v1"}
SOURCE="$REPOSITORY_ROOT/Sources/worker-fresh-dylib-canary.c"
OUTPUT="$OUTPUT_DIRECTORY/customd-springboard-live-probe.dylib"
SDKROOT_TASK=$(xcrun --sdk iphoneos --show-sdk-path)

mkdir -p "$OUTPUT_DIRECTORY"

xcrun --sdk iphoneos clang \
    -target arm64e-apple-ios27.0 \
    -isysroot "$SDKROOT_TASK" \
    -std=c17 -Os -Wall -Wextra -Werror \
    -dynamiclib \
    -install_name /var/jb/usr/lib/customd-springboard-live-probe.dylib \
    "-DCODEX_ACCEPTANCE_NONCE=\"$ACCEPTANCE_NONCE\"" \
    -DCODEX_EXPECTED_UID=501U \
    '-DCODEX_MARKER_PATH="/var/mobile/Media/customd-springboard-live-probe.marker"' \
    "$SOURCE" \
    -o "$OUTPUT"

codesign --force --sign - --timestamp=none --pagesize 4096 "$OUTPUT"
codesign --verify --strict "$OUTPUT"
file "$OUTPUT"
stat -f 'size=%z' "$OUTPUT"
shasum -a 256 "$OUTPUT"
xcrun otool -l "$OUTPUT" | sed -n '/cmd LC_UUID/,+3p'
codesign -dvvv "$OUTPUT" 2>&1 | grep -E '^(Identifier|CDHash|Signature)='
printf 'acceptance_nonce=%s\n' "$ACCEPTANCE_NONCE"
