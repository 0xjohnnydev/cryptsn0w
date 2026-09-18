#!/bin/sh
set -eu

SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPOSITORY_ROOT=$(CDPATH= cd -- "$SCRIPT_DIRECTORY/.." && pwd)
SOURCE="$REPOSITORY_ROOT/Sources/springboard-live-precursor.c"
ENTITLEMENTS="$REPOSITORY_ROOT/Sources/springboard-live-precursor-entitlements.plist"
OUTPUT_DIRECTORY=${1:-"$REPOSITORY_ROOT/build/springboard-live-precursor"}
OUTPUT="$OUTPUT_DIRECTORY/codex-springboard-live-precursor"

mkdir -p "$OUTPUT_DIRECTORY"

xcrun --sdk iphoneos clang \
    -target arm64e-apple-ios27.0 \
    -std=c17 \
    -Wall -Wextra -Werror \
    -O2 -fno-common \
    -Wl,-dead_strip \
    "$SOURCE" \
    -o "$OUTPUT"

codesign --force --sign - \
    --identifier com.openai.codex.springboard-live-precursor \
    --entitlements "$ENTITLEMENTS" \
    --generate-entitlement-der \
    --timestamp=none \
    "$OUTPUT"

codesign --verify --strict "$OUTPUT"
file "$OUTPUT"
shasum -a 256 "$OUTPUT"
codesign -dvvv "$OUTPUT" 2>&1 | grep -E '^(Identifier|CDHash|Signature)='
