#!/bin/zsh

set -euo pipefail

readonly ROOT=${0:A:h:h}
readonly FRIDA_VERSION=17.17.0
readonly FRIDA_CORE_COMMIT=c812943c457376c906802f7bb79d13c67a6e4d22
readonly PATCH=$ROOT/Patches/frida-core-17.17.0-ios27-pid1-guard.patch
readonly OUTPUT=$ROOT/cache/frida-server_17.17.0_ios27-pid1-guard

die() {
    print -u2 -- "error: $*"
    exit 1
}

for tool in awk chmod codesign git lipo make mkdir mktemp mv rg shasum strings; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done
[[ -f $PATCH ]] || die "missing patch: $PATCH"
for marker in \
    'phase=service-start' \
    'phase=service-ready' \
    'phase=request-enter' \
    'phase=attach-complete' \
    'phase=detach-slow-path' \
    'FRIDA_DETACH_RETRY_LIMIT' \
    'flags_after_attach=0x%08x' \
    'flags_after_detach=0x%08x softened=%d'; do
    rg -Fq -- "$marker" "$PATCH" || \
        die "policy patch is missing marker: $marker"
done
if rg -Fq -- 'waitpid (' "$PATCH"; then
    die "policy patch must not block in waitpid after PT_ATTACHEXC"
fi

NODE=$(command -v node 2>/dev/null || true)
if [[ -z $NODE ]]; then
    for candidate in \
        /Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node \
        /Applications/Cursor.app/Contents/Resources/app/resources/helpers/node; do
        if [[ -x $candidate ]]; then
            NODE=$candidate
            break
        fi
    done
fi
[[ -n $NODE ]] || die "Node.js 18 or newer is required"
NODE_VERSION=$($NODE --version)
NODE_MAJOR=${${NODE_VERSION#v}%%.*}
[[ $NODE_MAJOR == <-> && $NODE_MAJOR -ge 18 ]] || \
    die "Node.js 18 or newer is required"
readonly NODE_BIN=${NODE:h}

TEMP_ROOT=$(mktemp -d /tmp/untitled-frida-ios27.XXXXXX)
cleanup() {
    [[ $TEMP_ROOT == /tmp/untitled-frida-ios27.* ]] && rm -rf -- "$TEMP_ROOT"
}
trap cleanup EXIT INT TERM

readonly SOURCE=$TEMP_ROOT/frida-core
git clone --quiet --depth 1 --branch "$FRIDA_VERSION" \
    https://github.com/frida/frida-core.git "$SOURCE"
[[ $(git -C "$SOURCE" rev-parse HEAD) == $FRIDA_CORE_COMMIT ]] || \
    die "unexpected frida-core commit"
git -C "$SOURCE" apply --check "$PATCH"
git -C "$SOURCE" apply "$PATCH"
git -C "$SOURCE" submodule update --init --recursive --depth 1

configure_and_build() {
    local architecture=$1
    (
        cd "$SOURCE"
        PATH=$NODE_BIN:$PATH ./configure \
            --host="ios-$architecture" \
            --prefix=/usr \
            --with-frida-version="$FRIDA_VERSION" \
            --enable-local-backend \
            --disable-simmy-backend \
            --disable-fruity-backend \
            --disable-droidy-backend \
            --disable-socket-backend \
            --disable-barebone-backend \
            --disable-compiler-backend \
            --with-assets=installed \
            --with-compat=disabled \
            --enable-server \
            --disable-gadget \
            --disable-portal \
            --disable-inject \
            --disable-connectivity \
            --disable-tests
        PATH=$NODE_BIN:$PATH IOS_CERTID=- make -j8
        mv build "build-$architecture"
    )
}

configure_and_build arm64
configure_and_build arm64e

mkdir -p "$ROOT/cache"
readonly PARTIAL=$OUTPUT.partial.$$
lipo -create \
    "$SOURCE/build-arm64/server/frida-server" \
    "$SOURCE/build-arm64e/server/frida-server" \
    -output "$PARTIAL"
[[ $(lipo -archs "$PARTIAL") == "arm64 arm64e" ]] || \
    die "unexpected guarded server architectures"
rg -a -Fq 'PID 1 injection is disabled by the iOS 27 safety guard' \
    "$PARTIAL" || \
    die "guard marker is absent"
rg -a -Fq 'outcome=pid-guard' "$PARTIAL" || \
    die "policy PID guard marker is absent"
rg -a -Fq 'phase=service-start' "$PARTIAL" || \
    die "policy service-start marker is absent"
rg -a -Fq 'phase=service-ready' "$PARTIAL" || \
    die "policy service-ready marker is absent"
rg -a -Fq 'phase=request-enter' "$PARTIAL" || \
    die "policy request-entry marker is absent"
rg -a -Fq 'phase=attach-complete' "$PARTIAL" || \
    die "policy attach-phase marker is absent"
rg -a -Fq 'phase=detach-slow-path' "$PARTIAL" || \
    die "policy detach slow-path marker is absent"
rg -a -Fq 'flags_after_attach=0x%08x' "$PARTIAL" || \
    die "policy post-attach diagnostic marker is absent"
rg -a -Fq 'flags_after_detach=0x%08x softened=%d' \
    "$PARTIAL" || \
    die "policy diagnostic marker is absent"
codesign --verify --all-architectures --verbose=2 "$PARTIAL"
mv "$PARTIAL" "$OUTPUT"
chmod 0755 "$OUTPUT"

print -- "output=$OUTPUT"
print -- "sha256=$(shasum -a 256 "$OUTPUT" | awk '{print $1}')"
