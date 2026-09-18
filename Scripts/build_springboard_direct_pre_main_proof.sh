#!/bin/sh
set -eu

SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPOSITORY_ROOT=$(CDPATH= cd -- "$SCRIPT_DIRECTORY/.." && pwd)
SOURCE="$REPOSITORY_ROOT/Sources/carrier-ptrace-exec-probe.c"
REMOTE_SOURCE="$REPOSITORY_ROOT/Sources/carrier-loader-remote.S"
OUTPUT_DIRECTORY=${1:-"$REPOSITORY_ROOT/build/springboard-direct-pre-main-proof"}
OUTPUT="$OUTPUT_DIRECTORY/codex-springboard-direct-pre-main-proof"
SDKROOT_TASK=$(xcrun --sdk iphoneos --show-sdk-path)

mkdir -p "$OUTPUT_DIRECTORY"

xcrun --sdk iphoneos clang \
    -target arm64e-apple-ios27.0 \
    -isysroot "$SDKROOT_TASK" \
    -std=c17 -O2 -g0 -Wall -Wextra -Werror \
    -Wl,-dead_strip \
    -DCODEX_DIRECT_SPRINGBOARD_PROOF=1 \
    '-DCODEX_CARRIER_PATH="/var/jb/usr/lib/codex-springboard-live-canary.dylib"' \
    '-DCODEX_LOG_PATH="/var/tmp/codex-springboard-direct-pre-main-proof.log"' \
    "$SOURCE" "$REMOTE_SOURCE" \
    -o "$OUTPUT"

codesign --force --sign - --timestamp=none --pagesize 16384 \
    --identifier com.openai.codex.springboard-direct-pre-main-proof \
    "$OUTPUT"

codesign --verify --strict --verbose=2 "$OUTPUT"
file "$OUTPUT"
shasum -a 256 "$OUTPUT"
codesign -dvvv "$OUTPUT" 2>&1 | \
    grep -E '^(Identifier|CDHash|Signature)='
