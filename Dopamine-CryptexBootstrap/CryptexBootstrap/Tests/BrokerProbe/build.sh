#!/bin/zsh

set -euo pipefail

SCRIPT_DIR=${0:A:h}
BOOTSTRAP_DIR=${SCRIPT_DIR:h:h}
OUTPUT_DIR="$BOOTSTRAP_DIR/out/broker-probe"
PACKAGE_ROOT="$OUTPUT_DIR/root"
DYLIB_DIRECTORY="$PACKAGE_ROOT/var/jb/Library/MobileSubstrate/DynamicLibraries"
PROBE_DIRECTORY="$PACKAGE_ROOT/var/jb/usr/libexec/codex-broker-probe"
CONTROL_DIRECTORY="$PACKAGE_ROOT/DEBIAN"
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
MINIMUM_VERSION=15.0
INSTALL_NAME=/var/jb/Library/MobileSubstrate/DynamicLibraries/BrokerProbe.dylib
PACKAGE_VERSION=1.0.14

rm -rf "$PACKAGE_ROOT"
mkdir -p "$DYLIB_DIRECTORY" "$PROBE_DIRECTORY" "$CONTROL_DIRECTORY"

for architecture in arm64 arm64e; do
    xcrun --sdk iphoneos clang \
        -target "${architecture}-apple-ios${MINIMUM_VERSION}" \
        -isysroot "$SDK" \
        -Os -Wall -Wextra -Werror \
        -dynamiclib \
        -install_name "$INSTALL_NAME" \
        "$SCRIPT_DIR/BrokerProbe.c" \
        -o "$OUTPUT_DIR/BrokerProbe.${architecture}.dylib"
done

lipo -create \
    "$OUTPUT_DIR/BrokerProbe.arm64.dylib" \
    "$OUTPUT_DIR/BrokerProbe.arm64e.dylib" \
    -output "$DYLIB_DIRECTORY/BrokerProbe.dylib"
codesign --force --sign - --timestamp=none --pagesize 4096 \
    "$DYLIB_DIRECTORY/BrokerProbe.dylib"
xcrun --sdk iphoneos clang \
    -target "arm64-apple-ios${MINIMUM_VERSION}" \
    -isysroot "$SDK" \
    -Os -Wall -Wextra -Werror \
    "$SCRIPT_DIR/ArbitraryExecProbe.c" \
    -o "$PROBE_DIRECTORY/ArbitraryExecProbe"
codesign --force --sign - --timestamp=none --pagesize 4096 \
    "$PROBE_DIRECTORY/ArbitraryExecProbe"
install -m 0644 "$SCRIPT_DIR/BrokerProbe.plist" \
    "$DYLIB_DIRECTORY/BrokerProbe.plist"
install -m 0644 "$SCRIPT_DIR/control" "$CONTROL_DIRECTORY/control"
install -m 0755 "$SCRIPT_DIR/postinst" "$CONTROL_DIRECTORY/postinst"

dpkg-deb --root-owner-group --build "$PACKAGE_ROOT" \
    "$OUTPUT_DIR/com.openai.codex.broker-probe_${PACKAGE_VERSION}_iphoneos-arm64.deb"

codesign -d --verbose=4 "$DYLIB_DIRECTORY/BrokerProbe.dylib" 2>&1
codesign -d --verbose=4 "$PROBE_DIRECTORY/ArbitraryExecProbe" 2>&1
shasum -a 256 \
    "$OUTPUT_DIR/com.openai.codex.broker-probe_${PACKAGE_VERSION}_iphoneos-arm64.deb"
