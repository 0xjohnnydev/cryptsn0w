#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROJECT_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
SOURCE="$PROJECT_ROOT/Sources/codex-dyld-jb-admission-hook.c"
OUTPUT_DIR=${CODEX_DYLD_HOOK_OUTPUT_DIR:-$PROJECT_ROOT/build/dyld-jb-admission-hook}
OUTPUT="$OUTPUT_DIR/codex-dyld-jb-admission-hook.dylib"
INSTALL_NAME=/var/jb/usr/lib/codex-dyld-jb-admission-hook.dylib
DYLD_REFERENCE=${CODEX_DYLD_REFERENCE:-$PROJECT_ROOT/build/dyld-24A437}
DYLD_REFERENCE_SHA256=ab9887ed96c9c08ad68d4c6a5c27e8289fb0c9e55ec3e134547292a1ec579608
DYLD_REFERENCE_UUID=D3F59B02-EE07-371B-B091-3F150A078ED8
DYLD_MMAP_STUB_OFFSET=83924   # 0x147d4
DYLD_FCNTL_STUB_OFFSET=46796  # 0xb6cc
SDKROOT=$(xcrun --sdk iphoneos --show-sdk-path)

[[ -f "$DYLD_REFERENCE" ]]
[[ "$(shasum -a 256 "$DYLD_REFERENCE" | awk '{print $1}')" == \
   "$DYLD_REFERENCE_SHA256" ]]
[[ "$(otool -l "$DYLD_REFERENCE" | awk '/cmd LC_UUID/{getline; getline; print $2; exit}')" == \
   "$DYLD_REFERENCE_UUID" ]]

mkdir -p "$OUTPUT_DIR"
xcrun --sdk iphoneos clang \
    -arch arm64e \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -dynamiclib \
    -install_name "$INSTALL_NAME" \
    -Os -fvisibility=hidden -Wall -Wextra -Werror \
    "$SOURCE" \
    -o "$OUTPUT"
codesign --force --sign - --timestamp=none --pagesize 4096 "$OUTPUT"
codesign --verify --strict --all-architectures "$OUTPUT"

[[ "$(lipo -archs "$OUTPUT")" == "arm64e" ]]
[[ "$(otool -D "$OUTPUT" | tail -n 1)" == "$INSTALL_NAME" ]]
for symbol in \
    _codex_dyld_jb_hook_copy_status \
    _codex_dyld_jb_hook_install \
    _codex_dyld_jb_hook_marker \
    _codex_dyld_jb_hook_restore \
    _codex_dyld_jb_hook_status_word; do
    nm -gU "$OUTPUT" | grep -q " $symbol$"
done

read -r mmap_anchor_count fcntl_anchor_count mmap_count fcntl_count \
    mmap_anchor_offset fcntl_anchor_offset < <(
    perl -0777 -ne '
        while (/\xb0\x18\x80\xd2\x01\x10\x00\xd4/g) {
            if (((pos($_) - 8) % 4) == 0) {
                ++$mmap_anchor;
                $mmap_offset = pos($_) - 8;
            }
        }
        while (/\x90\x0b\x80\xd2\x01\x10\x00\xd4/g) {
            if (((pos($_) - 8) % 4) == 0) {
                ++$fcntl_anchor;
                $fcntl_offset = pos($_) - 8;
            }
        }
        while (/\xb0\x18\x80\xd2\x01\x10\x00\xd4\x03\x01\x00\x54\x7f\x23\x03\xd5\xfd\x7b\xbf\xa9/g) {
            ++$mmap if ((pos($_) - 20) % 4) == 0;
        }
        while (/\x90\x0b\x80\xd2\x01\x10\x00\xd4\x03\x01\x00\x54\x7f\x23\x03\xd5\xfd\x7b\xbf\xa9/g) {
            ++$fcntl if ((pos($_) - 20) % 4) == 0;
        }
        END {
            print(($mmap_anchor || 0), " ", ($fcntl_anchor || 0), " ",
                  ($mmap || 0), " ", ($fcntl || 0), " ",
                  (defined($mmap_offset) ? $mmap_offset : -1), " ",
                  (defined($fcntl_offset) ? $fcntl_offset : -1), "\n");
        }
    ' "$DYLD_REFERENCE"
)
[[ "$mmap_anchor_count" == 1 && "$fcntl_anchor_count" == 1 &&
   "$mmap_count" == 1 && "$fcntl_count" == 1 &&
   "$mmap_anchor_offset" == "$DYLD_MMAP_STUB_OFFSET" &&
   "$fcntl_anchor_offset" == "$DYLD_FCNTL_STUB_OFFSET" ]]

printf 'output=%s\n' "$OUTPUT"
shasum -a 256 "$OUTPUT"
