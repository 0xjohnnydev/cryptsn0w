#!/bin/zsh

set -euo pipefail

readonly SCRIPT_DIR=${0:A:h}
readonly PROJECT_ROOT=${SCRIPT_DIR:h}
readonly CRYPTEXCTL=/System/Library/SecurityResearch/usr/bin/cryptexctl.research

die() {
    print -u2 -- "error: $*"
    exit 1
}

if (( $# != 3 )); then
    print -u2 -- "usage: $0 OUT_DIR IDENTIFIER VERSION"
    exit 64
fi

readonly OUT_DIR=${1:A}
readonly IDENTIFIER=$2
readonly VERSION=$3
readonly IMAGE_ROOT=$OUT_DIR/image-root
readonly UNSIGNED_DIR=$OUT_DIR/unsigned
readonly BIN_DIR=$IMAGE_ROOT/usr/local/bin
readonly DATA_DIR=$IMAGE_ROOT/usr/local/share/untitled

[[ ! -e $OUT_DIR ]] || die "output already exists: $OUT_DIR"
[[ -x $CRYPTEXCTL ]] || die "missing Cryptex builder: $CRYPTEXCTL"
[[ -x /usr/bin/codesign ]] || die "codesign is not available"

mkdir -p "$BIN_DIR" "$DATA_DIR" "$UNSIGNED_DIR"

# Very small APFS images were rejected by the device's hdi layer. Keep the
# container above that observed floor without adding another executable or
# trust-cache entry.
/usr/sbin/mkfile 4m "$DATA_DIR/apfs-size-floor.bin"

readonly SDKROOT=$(xcrun --sdk iphoneos --show-sdk-path)
readonly BASE_PROBE=$OUT_DIR/execution-probe.unsigned
xcrun --sdk iphoneos clang \
    -arch arm64 \
    -miphoneos-version-min=17.4 \
    -isysroot "$SDKROOT" \
    -Wall -Wextra -Werror \
    "$PROJECT_ROOT/Sources/execution-probe.c" \
    -o "$BASE_PROBE"

typeset -A variants
variants=(
    execution-probe-compat "$PROJECT_ROOT/Sources/execution-probe-entitlements.plist"
    execution-probe-dynamic-only "$PROJECT_ROOT/Sources/execution-probe-dynamic-only-entitlements.plist"
    execution-probe-explicit-jit "$PROJECT_ROOT/Sources/execution-probe-explicit-jit-entitlements.plist"
)

for name entitlement_file in ${(kv)variants}; do
    destination=$BIN_DIR/$name
    cp "$BASE_PROBE" "$destination"
    /usr/bin/codesign \
        --force \
        --sign - \
        --identifier "$name" \
        --entitlements "$entitlement_file" \
        --generate-entitlement-der \
        "$destination"
    chmod 0755 "$destination"
    /usr/bin/codesign --verify --strict "$destination"
done

# [REDACTED] Packaging, payload selection, and validation details omitted.
printf '%s\n' 'TSS/Cryptex personalization and installation details are redacted from this educational source release.' >&2
exit 1
