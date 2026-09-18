#!/bin/sh
set -eu

SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPOSITORY_ROOT=$(CDPATH= cd -- "$SCRIPT_DIRECTORY/.." && pwd)
OUTPUT_DIRECTORY=${1:-"$REPOSITORY_ROOT/build/customd-ptrauth-context-probe"}
MARKER_OUTPUT="$OUTPUT_DIRECTORY/customd-ptrauth-context-marker.dylib"
LAUNCHER_OUTPUT="$OUTPUT_DIRECTORY/customd-ptrauth-context-launcher"
MARKER_INSTALL_NAME=/var/jb/usr/lib/customd-ptrauth-context-marker.dylib

: "${CODEX_PTRAUTH_PROBE_LOADER_PATH:?set CODEX_PTRAUTH_PROBE_LOADER_PATH to the exact trusted codex-ellekit-loader artifact}"

for REQUIRED_FILE in \
    "$CODEX_PTRAUTH_PROBE_LOADER_PATH" \
    "$REPOSITORY_ROOT/Sources/customd-ptrauth-context-probe.h" \
    "$REPOSITORY_ROOT/Sources/customd-ptrauth-context-marker.c" \
    "$REPOSITORY_ROOT/Sources/customd-ptrauth-context-launcher.c" \
    "$REPOSITORY_ROOT/Dopamine-CryptexBootstrap/CryptexBootstrap/ellekit-compat-loader-entitlements.plist"; do
    [ -f "$REQUIRED_FILE" ] || {
        echo "error: missing ptrauth context probe input: $REQUIRED_FILE" >&2
        exit 1
    }
done
codesign --verify --strict "$CODEX_PTRAUTH_PROBE_LOADER_PATH"
lipo -verify_arch arm64e "$CODEX_PTRAUTH_PROBE_LOADER_PATH"

mkdir -p "$OUTPUT_DIRECTORY"
SDKROOT=$(xcrun --sdk iphoneos --show-sdk-path)
COMMON_FLAGS="-target arm64e-apple-ios27.0 -std=c17 -Wall -Wextra -Werror -Os -fno-common"

xcrun --sdk iphoneos clang $COMMON_FLAGS \
    -isysroot "$SDKROOT" \
    -I "$REPOSITORY_ROOT/Sources" \
    -dynamiclib \
    -install_name "$MARKER_INSTALL_NAME" \
    -current_version 1.0.0 \
    -compatibility_version 1.0.0 \
    -Wl,-dead_strip \
    "$REPOSITORY_ROOT/Sources/customd-ptrauth-context-marker.c" \
    -o "$MARKER_OUTPUT"
codesign --force --sign - \
    --identifier com.openai.customd.ptrauth-context-marker \
    --generate-entitlement-der --timestamp=none --pagesize 4096 \
    "$MARKER_OUTPUT"
codesign --verify --strict "$MARKER_OUTPUT"

LOADER_SHA256=$(shasum -a 256 "$CODEX_PTRAUTH_PROBE_LOADER_PATH" | awk '{print $1}')
MARKER_SHA256=$(shasum -a 256 "$MARKER_OUTPUT" | awk '{print $1}')
LOADER_SIZE=$(stat -f '%z' "$CODEX_PTRAUTH_PROBE_LOADER_PATH")
MARKER_SIZE=$(stat -f '%z' "$MARKER_OUTPUT")
for PINNED_SHA256 in "$LOADER_SHA256" "$MARKER_SHA256"; do
    case "$PINNED_SHA256" in
        *[!0-9a-f]*|'')
            echo "error: invalid pinned SHA-256" >&2
            exit 1
            ;;
    esac
    [ "${#PINNED_SHA256}" -eq 64 ] || {
        echo "error: invalid pinned SHA-256 length" >&2
        exit 1
    }
done
for PINNED_SIZE in "$LOADER_SIZE" "$MARKER_SIZE"; do
    case "$PINNED_SIZE" in
        *[!0-9]*|'')
            echo "error: invalid pinned artifact size" >&2
            exit 1
            ;;
    esac
done

xcrun --sdk iphoneos clang $COMMON_FLAGS \
    -isysroot "$SDKROOT" \
    -I "$REPOSITORY_ROOT/Sources" \
    "-DCODEX_PTRAUTH_PROBE_EXPECTED_LOADER_SHA256_HEX=\"$LOADER_SHA256\"" \
    "-DCODEX_PTRAUTH_PROBE_EXPECTED_MARKER_SHA256_HEX=\"$MARKER_SHA256\"" \
    "-DCODEX_PTRAUTH_PROBE_EXPECTED_LOADER_SIZE=$LOADER_SIZE" \
    "-DCODEX_PTRAUTH_PROBE_EXPECTED_MARKER_SIZE=$MARKER_SIZE" \
    -Wl,-dead_strip \
    "$REPOSITORY_ROOT/Sources/customd-ptrauth-context-launcher.c" \
    -o "$LAUNCHER_OUTPUT"
codesign --force --sign - \
    --identifier com.openai.customd.ptrauth-context-launcher \
    --entitlements "$REPOSITORY_ROOT/Dopamine-CryptexBootstrap/CryptexBootstrap/ellekit-compat-loader-entitlements.plist" \
    --generate-entitlement-der --timestamp=none --pagesize 4096 \
    "$LAUNCHER_OUTPUT"
codesign --verify --strict "$LAUNCHER_OUTPUT"

lipo -verify_arch arm64e "$MARKER_OUTPUT"
lipo -verify_arch arm64e "$LAUNCHER_OUTPUT"
[ "$(otool -D "$MARKER_OUTPUT" | tail -n 1)" = "$MARKER_INSTALL_NAME" ]
file "$MARKER_OUTPUT" "$LAUNCHER_OUTPUT"
shasum -a 256 \
    "$CODEX_PTRAUTH_PROBE_LOADER_PATH" \
    "$MARKER_OUTPUT" \
    "$LAUNCHER_OUTPUT"
