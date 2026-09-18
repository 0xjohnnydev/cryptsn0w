#!/bin/zsh

set -euo pipefail

SCRIPT_DIRECTORY=${0:A:h}
REPOSITORY_ROOT=${SCRIPT_DIRECTORY:h}
BOOTSTRAP_DIRECTORY="$REPOSITORY_ROOT/Dopamine-CryptexBootstrap/CryptexBootstrap"
DEFAULT_OPAINJECT_DIRECTORY="$REPOSITORY_ROOT/Dopamine-upstream/BaseBin/opainject"
OPAINJECT_DIRECTORY=${CODEX_OPAINJECT_DIRECTORY:-$DEFAULT_OPAINJECT_DIRECTORY}
OUTPUT_DIRECTORY=${1:-"$REPOSITORY_ROOT/build/customd"}
PATCHED_DIRECTORY="$OUTPUT_DIRECTORY/opainject-ios27-registrar"
OUTPUT="$OUTPUT_DIRECTORY/customd-candidate-registrar"

required_files=(
    "$REPOSITORY_ROOT/Sources/customd-candidate-registrar.m"
    "$BOOTSTRAP_DIRECTORY/patch_opainject_dyld.py"
    "$BOOTSTRAP_DIRECTORY/patch_opainject_runtime.py"
    "$OPAINJECT_DIRECTORY/dyld.m"
    "$OPAINJECT_DIRECTORY/rop_inject.m"
    "$OPAINJECT_DIRECTORY/thread_utils.m"
    "$OPAINJECT_DIRECTORY/task_utils.m"
    "$OPAINJECT_DIRECTORY/arm64.m"
)
for required_file in "${required_files[@]}"; do
    [[ -f "$required_file" ]] || {
        print -u2 -- "error: missing registrar build input: $required_file"
        exit 1
    }
done

mkdir -p "$OUTPUT_DIRECTORY" "$PATCHED_DIRECTORY"
python3 "$BOOTSTRAP_DIRECTORY/patch_opainject_dyld.py" \
    "$OPAINJECT_DIRECTORY/dyld.m" "$PATCHED_DIRECTORY/dyld.m"
python3 "$BOOTSTRAP_DIRECTORY/patch_opainject_runtime.py" \
    "$OPAINJECT_DIRECTORY/thread_utils.m" \
    "$OPAINJECT_DIRECTORY/rop_inject.m" \
    "$PATCHED_DIRECTORY"

xcrun --sdk iphoneos clang \
    -target arm64e-apple-ios27.0 \
    -std=gnu17 \
    -Wall -Wextra -Werror \
    -Wno-sign-compare -Wno-unused-parameter \
    -O2 \
    -fobjc-arc \
    -fblocks \
    -include stdint.h \
    -I "$OPAINJECT_DIRECTORY" \
    -Wl,-dead_strip \
    -framework Foundation \
    -framework CoreFoundation \
    -lsandbox \
    "$REPOSITORY_ROOT/Sources/customd-candidate-registrar.m" \
    "$PATCHED_DIRECTORY/dyld.m" \
    "$PATCHED_DIRECTORY/rop_inject.m" \
    "$PATCHED_DIRECTORY/thread_utils.m" \
    "$OPAINJECT_DIRECTORY/task_utils.m" \
    "$OPAINJECT_DIRECTORY/arm64.m" \
    -o "$OUTPUT"

codesign --force --sign - \
    --identifier com.openai.customd.candidate-registrar \
    --generate-entitlement-der --timestamp=none "$OUTPUT"
codesign --verify --strict "$OUTPUT"
lipo -verify_arch arm64e "$OUTPUT"
file "$OUTPUT"
shasum -a 256 "$OUTPUT"
