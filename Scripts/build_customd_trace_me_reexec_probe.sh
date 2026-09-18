#!/bin/sh
set -eu

SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPOSITORY_ROOT=$(CDPATH= cd -- "$SCRIPT_DIRECTORY/.." && pwd)
OUTPUT_DIRECTORY=${1:-"$REPOSITORY_ROOT/build/customd-trace-me-reexec-probe"}
OUTPUT="$OUTPUT_DIRECTORY/customd-trace-me-reexec-probe"
SOURCE="$REPOSITORY_ROOT/Sources/customd-trace-me-reexec-probe.c"
SDKROOT_TASK=$(xcrun --sdk iphoneos --show-sdk-path)

mkdir -p "$OUTPUT_DIRECTORY"

xcrun --sdk iphoneos clang \
    -target arm64e-apple-ios27.0 \
    -isysroot "$SDKROOT_TASK" \
    -std=c17 -Os -Wall -Wextra -Werror -fno-common \
    -Wl,-dead_strip \
    "$SOURCE" \
    -o "$OUTPUT"

codesign --force --sign - --timestamp=none --pagesize 4096 \
    --identifier com.openai.customd.trace-me-reexec-probe \
    "$OUTPUT"
codesign --verify --strict "$OUTPUT"
lipo -verify_arch arm64e "$OUTPUT"
file "$OUTPUT"
stat -f 'size=%z' "$OUTPUT"
shasum -a 256 "$OUTPUT"
xcrun otool -l "$OUTPUT" | sed -n '/cmd LC_UUID/,+3p'
codesign -dvvv "$OUTPUT" 2>&1 | grep -E '^(Identifier|CDHash|Signature)='
