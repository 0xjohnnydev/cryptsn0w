#!/bin/sh
set -eu

SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPOSITORY_ROOT=$(CDPATH= cd -- "$SCRIPT_DIRECTORY/.." && pwd)
OUTPUT_DIRECTORY=${1:-"$REPOSITORY_ROOT/build/customd-load-canary"}
OUTPUT="$OUTPUT_DIRECTORY/customd-load-canary.dylib"
NONCE=${CUSTOMD_LOAD_CANARY_NONCE:-"20260918T-customd-v1"}

mkdir -p "$OUTPUT_DIRECTORY"
xcrun --sdk iphoneos clang \
    -target arm64e-apple-ios27.0 \
    -std=c17 -Wall -Wextra -Werror -Os -fno-common \
    -dynamiclib \
    -install_name /var/jb/usr/lib/customd/customd-load-canary.dylib \
    "-DCUSTOMD_LOAD_CANARY_NONCE=\"$NONCE\"" \
    "$REPOSITORY_ROOT/Sources/customd-load-canary.c" \
    -o "$OUTPUT"
codesign --force --sign - --identifier com.openai.customd.load-canary \
    --generate-entitlement-der --timestamp=none "$OUTPUT"
codesign --verify --strict "$OUTPUT"
file "$OUTPUT"
shasum -a 256 "$OUTPUT"
