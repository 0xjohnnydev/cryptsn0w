#!/bin/sh
set -eu

SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPOSITORY_ROOT=$(CDPATH= cd -- "$SCRIPT_DIRECTORY/.." && pwd)
SOURCE="$REPOSITORY_ROOT/Sources/worker-fresh-dylib-canary.c"
OUTPUT_DIRECTORY=${1:-"$REPOSITORY_ROOT/build/springboard-direct-live-canary"}
OUTPUT="$OUTPUT_DIRECTORY/codex-springboard-live-canary.dylib"
SDKROOT_TASK=$(xcrun --sdk iphoneos --show-sdk-path)

mkdir -p "$OUTPUT_DIRECTORY"

xcrun --sdk iphoneos clang \
    -target arm64e-apple-ios27.0 \
    -isysroot "$SDKROOT_TASK" \
    -std=c17 -Os -Wall -Wextra -Werror \
    -dynamiclib \
    -install_name /var/jb/usr/lib/codex-springboard-live-canary.dylib \
    '-DCODEX_MARKER_PATH="/var/tmp/codex-springboard-direct-live-canary.marker"' \
    "$SOURCE" \
    -o "$OUTPUT"

codesign --force --sign - --timestamp=none --pagesize 4096 "$OUTPUT"
codesign --verify --strict "$OUTPUT"
file "$OUTPUT"
stat -f 'size=%z' "$OUTPUT"
shasum -a 256 "$OUTPUT"
xcrun otool -l "$OUTPUT" | sed -n '/cmd LC_UUID/,+3p'
codesign -dvvv "$OUTPUT" 2>&1 | grep -E '^(Identifier|CDHash|Signature)='
