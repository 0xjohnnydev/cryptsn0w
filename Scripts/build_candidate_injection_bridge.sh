#!/bin/zsh

set -euo pipefail

SCRIPT_DIRECTORY=${0:A:h}
REPOSITORY_ROOT=${SCRIPT_DIRECTORY:h}
BOOTSTRAP_DIRECTORY="$REPOSITORY_ROOT/Dopamine-CryptexBootstrap/CryptexBootstrap"
DEFAULT_OPAINJECT_DIRECTORY="$REPOSITORY_ROOT/Dopamine-upstream/BaseBin/opainject"
OPAINJECT_DIRECTORY=${CODEX_OPAINJECT_DIRECTORY:-$DEFAULT_OPAINJECT_DIRECTORY}
OUTPUT_DIRECTORY=${1:-"$REPOSITORY_ROOT/build/candidate-injection-bridge"}
PATCHED_DIRECTORY="$OUTPUT_DIRECTORY/opainject-ios27"
OUTPUT="$OUTPUT_DIRECTORY/codex-candidate-injection-bridge.dylib"
INSTALL_NAME=/var/jb/usr/lib/codex-candidate-injection-bridge.dylib
SDKROOT=$(xcrun --sdk iphoneos --show-sdk-path)

LOADER_SOURCE="$BOOTSTRAP_DIRECTORY/ellekit_compat_loader.m"
PATCH_DYLD="$BOOTSTRAP_DIRECTORY/patch_opainject_dyld.py"
PATCH_RUNTIME="$BOOTSTRAP_DIRECTORY/patch_opainject_runtime.py"
PATCHED_DYLD="$PATCHED_DIRECTORY/dyld.m"
PATCHED_ROP="$PATCHED_DIRECTORY/rop_inject.m"
PATCHED_THREAD_UTILS="$PATCHED_DIRECTORY/thread_utils.m"

required_files=(
    "$REPOSITORY_ROOT/Sources/candidate-injection-bridge.m"
    "$LOADER_SOURCE"
    "$PATCH_DYLD"
    "$PATCH_RUNTIME"
    "$OPAINJECT_DIRECTORY/dyld.m"
    "$OPAINJECT_DIRECTORY/rop_inject.m"
    "$OPAINJECT_DIRECTORY/thread_utils.m"
    "$OPAINJECT_DIRECTORY/task_utils.m"
    "$OPAINJECT_DIRECTORY/arm64.m"
)
for required_file in "${required_files[@]}"; do
    [[ -f "$required_file" ]] || {
        print -u2 -- "error: missing build input: $required_file"
        exit 1
    }
done

mkdir -p "$OUTPUT_DIRECTORY" "$PATCHED_DIRECTORY"
python3 "$PATCH_DYLD" \
    "$OPAINJECT_DIRECTORY/dyld.m" "$PATCHED_DYLD"
python3 "$PATCH_RUNTIME" \
    "$OPAINJECT_DIRECTORY/thread_utils.m" \
    "$OPAINJECT_DIRECTORY/rop_inject.m" \
    "$PATCHED_DIRECTORY"

# Build the compatibility loader into the dylib with only its entry point
# renamed.  This keeps the exact current loader implementation and patched
# opainject lane while allowing the bridge constructor to invoke it in-process.
xcrun --sdk iphoneos clang \
    -arch arm64 \
    -arch arm64e \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -fobjc-arc \
    -fblocks \
    -include stdint.h \
    -I "$OPAINJECT_DIRECTORY" \
    -Dmain=codex_ellekit_compat_loader_main \
    -DCODEX_CANDIDATE_BRIDGE_BUILD=1 \
    -dynamiclib \
    -install_name "$INSTALL_NAME" \
    -current_version 1.0.0 \
    -compatibility_version 1.0.0 \
    -Os \
    -Wl,-dead_strip \
    -framework Foundation \
    -framework CoreFoundation \
    -lsandbox \
    "$REPOSITORY_ROOT/Sources/candidate-injection-bridge.m" \
    "$LOADER_SOURCE" \
    "$PATCHED_DYLD" \
    "$PATCHED_ROP" \
    "$PATCHED_THREAD_UTILS" \
    "$OPAINJECT_DIRECTORY/task_utils.m" \
    "$OPAINJECT_DIRECTORY/arm64.m" \
    -o "$OUTPUT"

codesign --force --sign - \
    --identifier com.openai.codex.candidate-injection-bridge \
    --timestamp=none \
    --pagesize 4096 \
    "$OUTPUT"
codesign --verify --strict --all-architectures "$OUTPUT"
lipo -verify_arch arm64 "$OUTPUT"
lipo -verify_arch arm64e "$OUTPUT"
[[ "$(otool -D "$OUTPUT" | tail -n 1)" == "$INSTALL_NAME" ]]
arm64e_symbols=$(nm -arch arm64e "$OUTPUT")
rg -q '_codex_ellekit_compat_loader_main$' <<<"$arm64e_symbols"
if rg -q '[[:space:]]_main$' <<<"$arm64e_symbols"; then
    print -u2 -- "error: bridge unexpectedly exports a main entry point"
    exit 1
fi

file "$OUTPUT"
shasum -a 256 "$OUTPUT"
codesign -dvvv "$OUTPUT" 2>&1 | \
    rg '^(Identifier|CDHash|Signature)='
