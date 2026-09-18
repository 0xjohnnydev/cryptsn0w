#!/bin/zsh

set -euo pipefail

SCRIPT_DIRECTORY=${0:A:h}
REPOSITORY_ROOT=${SCRIPT_DIRECTORY:h}
SOURCE="$REPOSITORY_ROOT/Sources/worker-fresh-dylib-canary.c"
CONTROL="$REPOSITORY_ROOT/Packaging/SpringBoardLiveCanary/control"
OUTPUT_DIRECTORY=${1:-"$REPOSITORY_ROOT/build/springboard-live-canary"}
PACKAGE_ROOT="$OUTPUT_DIRECTORY/root"
DYLIB_DIRECTORY="$PACKAGE_ROOT/var/jb/usr/lib"
CONTROL_DIRECTORY="$PACKAGE_ROOT/DEBIAN"
DYLIB="$DYLIB_DIRECTORY/codex-springboard-live-canary.dylib"
PACKAGE="$OUTPUT_DIRECTORY/codex-springboard-live-canary.deb"
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
ACCEPTANCE_NONCE="20260918T042559Z-e73aabd5726d4bee"
EXPECTED_UID=501

rm -rf "$PACKAGE_ROOT"
mkdir -p "$DYLIB_DIRECTORY" "$CONTROL_DIRECTORY"

xcrun --sdk iphoneos clang \
    -target arm64e-apple-ios15.0 \
    -isysroot "$SDK" \
    -std=c17 -Os -Wall -Wextra -Werror \
    -dynamiclib \
    -install_name /var/jb/usr/lib/codex-springboard-live-canary.dylib \
    "-DCODEX_ACCEPTANCE_NONCE=\"${ACCEPTANCE_NONCE}\"" \
    "-DCODEX_EXPECTED_UID=${EXPECTED_UID}U" \
    "$SOURCE" \
    -o "$DYLIB"

codesign --force --sign - --timestamp=none --pagesize 4096 "$DYLIB"
install -m 0644 "$CONTROL" "$CONTROL_DIRECTORY/control"
dpkg-deb --root-owner-group --build "$PACKAGE_ROOT" "$PACKAGE"

codesign --verify --strict "$DYLIB"
file "$DYLIB" "$PACKAGE"
shasum -a 256 "$DYLIB" "$PACKAGE"
codesign -dvvv "$DYLIB" 2>&1 | grep -E '^(Identifier|CDHash|Signature)='
printf 'acceptance_nonce=%s expected_uid=%s\n' \
    "$ACCEPTANCE_NONCE" "$EXPECTED_UID"
