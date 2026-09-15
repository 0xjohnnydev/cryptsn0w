#!/bin/zsh

# Build the Frida 17.17.0 universal iOS Gadget with the iOS 27 Gum page-plan
# fix.  The output is staged separately from the already-proven artifact.

set -euo pipefail

script_dir=${0:A:h}
project_root=${script_dir:h}
frida_tag=17.17.0
frida_commit=03f16b3b11c5bb945cdb7f6158a84dd57655de4c
frida_core_commit=c812943c457376c906802f7bb79d13c67a6e4d22
frida_gum_commit=ddc10c5559cbb41a3dd72866bfba6ff3945ffa5c
node_version=26.8.2
node_archive="node-v${node_version}-darwin-arm64.tar.gz"
node_sha256=974b6d5fb2fc7c33ff2354db0902b4e91c2de01ec8acc6de48e543c97e18c9e1
node_cache="$project_root/build/frida-ios27-toolchain"
node_root="$node_cache/node-v${node_version}-darwin-arm64"
patch_path="$project_root/Patches/frida-gum-17.17.0-ios27-code-page-plan.patch"
output="$project_root/build/frida-ios27-host/gadget-ios.${frida_tag}.rebuilt.dylib"

if (( $# > 1 )); then
    print -u2 -- "usage: $0 [output.dylib]"
    exit 64
fi
if (( $# == 1 )); then
    output=${1:A}
fi

if [[ -z ${IOS_CERTID:-} ]]; then
    print -u2 -- "IOS_CERTID must name an installed Apple Development signing identity"
    print -u2 -- "use a SHA-1 from: security find-identity -v -p codesigning"
    exit 64
fi
if [[ ! -f $patch_path ]]; then
    print -u2 -- "missing Gum patch: $patch_path"
    exit 66
fi

for tool in git curl shasum tar make security codesign lipo python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        print -u2 -- "missing required tool: $tool"
        exit 69
    fi
done

valid_identities=$(security find-identity -v -p codesigning)
if [[ $valid_identities != *"$IOS_CERTID"* ]]; then
    print -u2 -- "IOS_CERTID is not a currently valid code-signing identity"
    exit 65
fi

mkdir -p -- "$node_cache"
if [[ ! -x "$node_root/bin/node" ]]; then
    archive="$node_cache/$node_archive"
    partial="$archive.partial"
    curl --fail --location --proto '=https' --tlsv1.2 \
        "https://nodejs.org/dist/v${node_version}/${node_archive}" \
        --output "$partial"
    actual=$(shasum -a 256 "$partial" | awk '{ print $1 }')
    if [[ $actual != $node_sha256 ]]; then
        print -u2 -- "Node archive SHA-256 mismatch: $actual"
        rm -f -- "$partial"
        exit 65
    fi
    mv -- "$partial" "$archive"
    tar -xzf "$archive" -C "$node_cache"
fi

if [[ $("$node_root/bin/node" --version) != "v${node_version}" ]]; then
    print -u2 -- "cached Node version does not match v${node_version}"
    exit 65
fi

work_parent=$(mktemp -d "${TMPDIR:-/private/tmp}/frida-ios27-gadget.XXXXXX")
source_root="$work_parent/frida"
cleanup() {
    if [[ -n ${work_parent:-} && -d $work_parent && \
          $work_parent == ${TMPDIR:-/private/tmp}/frida-ios27-gadget.* ]]; then
        rm -rf -- "$work_parent"
    fi
}
trap cleanup EXIT INT TERM

git clone --quiet --branch "$frida_tag" --depth 1 \
    https://github.com/frida/frida.git "$source_root"
if [[ $(git -C "$source_root" rev-parse HEAD) != $frida_commit ]]; then
    print -u2 -- "unexpected Frida commit"
    exit 65
fi

python3 "$source_root/tools/ensure-submodules.py" frida-core frida-gum
core_root="$source_root/subprojects/frida-core"
gum_root="$source_root/subprojects/frida-gum"
if [[ $(git -C "$core_root" rev-parse HEAD) != $frida_core_commit ]]; then
    print -u2 -- "unexpected frida-core commit"
    exit 65
fi
if [[ $(git -C "$gum_root" rev-parse HEAD) != $frida_gum_commit ]]; then
    print -u2 -- "unexpected frida-gum commit"
    exit 65
fi

git -C "$gum_root" apply --check "$patch_path"
git -C "$gum_root" apply "$patch_path"

export PATH="$node_root/bin:$PATH"
export IOS_CERTID
(
    cd "$source_root"
    ./configure \
        --prefix=/usr \
        --host=ios-arm64e \
        --enable-gadget \
        --disable-server \
        --disable-inject \
        --disable-frida-python \
        --disable-frida-tools \
        --disable-graft-tool \
        -- \
        -Dfrida-core:compiler_backend=disabled
    make -j"$(sysctl -n hw.logicalcpu)"
)

built="$source_root/build/subprojects/frida-core/lib/gadget/frida-gadget.dylib"
if [[ ! -f $built ]]; then
    print -u2 -- "Frida build produced no universal Gadget"
    exit 70
fi
architectures=$(lipo -archs "$built")
if [[ " $architectures " != *" arm64 "* || " $architectures " != *" arm64e "* ]]; then
    print -u2 -- "Gadget is missing arm64 or arm64e: $architectures"
    exit 70
fi
codesign --verify --strict --verbose=2 "$built"

mkdir -p -- "${output:h}"
install -m 0644 "$built" "$output"
digest=$(shasum -a 256 "$output" | awk '{ print $1 }')

print -- "built=$output"
print -- "sha256=$digest"
print -- "architectures=$architectures"
print -- "The signature timestamp may change the whole-file SHA-256 on a rebuild."
print -- "Validate the rebuilt artifact with the USB smoke test before replacing the proven staged Gadget."
