#!/bin/zsh

set -euo pipefail

SCRIPT_DIR=${0:A:h}
REPOSITORY_ROOT=${SCRIPT_DIR:h}
OUTPUT_DIRECTORY="$REPOSITORY_ROOT/dist"
APP="$OUTPUT_DIRECTORY/CryptexSn0w.app"
LEGACY_APP="$OUTPUT_DIRECTORY/SBInject.app"
CONTENTS="$APP/Contents"
RESOURCES="$CONTENTS/Resources"
MACOS="$CONTENTS/MacOS"
LOGO="$SCRIPT_DIR/Resources/PineappleLogo.png"
export CLANG_MODULE_CACHE_PATH="$SCRIPT_DIR/.build/module-cache"
export SWIFTPM_MODULECACHE_OVERRIDE="$SCRIPT_DIR/.build/module-cache"
export XDG_CACHE_HOME="$SCRIPT_DIR/.build/cache"

[[ -f "$LOGO" ]] || {
    print -u2 -- "error: missing $LOGO"
    exit 1
}

mkdir -p "$CLANG_MODULE_CACHE_PATH" "$XDG_CACHE_HOME"
swift build --disable-sandbox --package-path "$SCRIPT_DIR" \
    --configuration release -debug-info-format none
BIN_DIRECTORY=$(swift build --package-path "$SCRIPT_DIR" \
    --disable-sandbox --configuration release -debug-info-format none \
    --show-bin-path)
EXECUTABLE="$BIN_DIRECTORY/CryptexSn0w"
[[ -x "$EXECUTABLE" ]] || {
    print -u2 -- "error: Swift build did not emit $EXECUTABLE"
    exit 1
}

rm -rf "$APP" "$LEGACY_APP"
mkdir -p "$MACOS" "$RESOURCES"
cp "$EXECUTABLE" "$MACOS/CryptexSn0w"
cp "$SCRIPT_DIR/Info.plist" "$CONTENTS/Info.plist"
cp "$LOGO" "$RESOURCES/PineappleLogo.png"

TEMP_DIRECTORY=$(mktemp -d)
trap 'rm -rf "$TEMP_DIRECTORY"' EXIT
ICONSET="$TEMP_DIRECTORY/AppIcon.iconset"
mkdir -p "$ICONSET"
for specification in \
    '16 icon_16x16.png' \
    '32 icon_16x16@2x.png' \
    '32 icon_32x32.png' \
    '64 icon_32x32@2x.png' \
    '128 icon_128x128.png' \
    '256 icon_128x128@2x.png' \
    '256 icon_256x256.png' \
    '512 icon_256x256@2x.png' \
    '512 icon_512x512.png' \
    '1024 icon_512x512@2x.png'; do
    size=${specification%% *}
    name=${specification#* }
    sips -z "$size" "$size" "$LOGO" --out "$ICONSET/$name" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$RESOURCES/AppIcon.icns"

codesign --force --deep --sign - --timestamp=none "$APP"
codesign --verify --deep --strict "$APP"
print -- "$APP"
