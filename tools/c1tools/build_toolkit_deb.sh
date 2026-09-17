#!/usr/bin/env bash
# Build c1tools_1.0_iphoneos-arm64.deb - the three tools, packaged for the lane's
# trusted-package mechanism.
#
# Why a deb and not just files: the lane installs a cryptex whose trust cache is
# immutable after personalization. New executables get in by embedding exact copies of a
# deb's payload, hashing them into that cache, and re-activating the same bytes at their
# installed destination. So the deb is the unit of delivery, and changing anything in it
# costs a lane rebuild.
#
# Two details the lane's pipeline imposes on us:
#
#  1. It re-signs every Mach-O in the normalized root with
#     `codesign --force --sign - --timestamp=none --pagesize 4096 --identifier X
#      --entitlements Y`, where Y comes from `ldid -e` on the incoming payload.
#     We therefore sign with the SAME flags here, so their normalization is idempotent
#     and the CDHash we print is the CDHash that lands in the cache. Asserted below:
#     ldid must be able to read the entitlements back, because if it cannot, their
#     pipeline silently re-signs WITHOUT them and the tool is weaker than it looks.
#
#  2. Their build activates the *normalized* copies, not the deb's, so a plain
#     `dpkg -i` of this deb installs our bytes, whose CDHashes are only in the cache if
#     the normalization was a no-op. The build prints both so that is checkable.
#
# What rides in it:
#
#   cs-loader   run an arbitrary UNSIGNED Mach-O as the code of a debug-authorised
#               child. This is the reason the package exists: once the loader is
#               admitted, the payloads it runs need no trust cache entry and no
#               signature, so they cost no rebuild.
#   tfpid       task ports and real cross-process reads, including pid 1.
#   injprobe    injection into a process we did not spawn. Needs libagent.dylib, which
#               is the fourth artifact here.
#
# Output: build/c1tools_1.0_iphoneos-arm64.deb plus every CDHash printed.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out_dir="${OUT_DIR:-$script_dir/../../build}"
ent_dir="$script_dir/entitlements"
stage="$out_dir/c1tools-deb-root"
deb_name="c1tools_1.0_iphoneos-arm64.deb"

# --- toolchain (invoke clang by path with an explicit -isysroot, because xcrun can fail
# on the licence prompt) ---------------------------------------------------------------
clang_bin="${CLANG:-}"
if [[ -z "$clang_bin" ]]; then
    if clang_bin="$(xcrun --sdk iphoneos --find clang 2>/dev/null)" && [[ -n "$clang_bin" ]]; then
        iphoneos_sdk="$(xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)"
    else
        clang_bin="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang"
        iphoneos_sdk="$(ls -d /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk 2>/dev/null)"
    fi
fi
[[ -x "$clang_bin" ]] || { echo "[-] no clang at $clang_bin" >&2; exit 1; }
[[ -n "${iphoneos_sdk:-}" ]] || { echo "[-] no iPhoneOS SDK found" >&2; exit 1; }
clang_flags=(-target arm64-apple-ios17.0 -isysroot "$iphoneos_sdk")

command -v dpkg-deb >/dev/null || { echo "[-] dpkg-deb not found (brew install dpkg)" >&2; exit 1; }
command -v ldid >/dev/null || { echo "[-] ldid not found (brew install ldid)" >&2; exit 1; }

# --- the lane's normalization flags, verbatim -----------------------------------------
sign_like_lane() { # sign_like_lane <path> <identifier> [entitlements-plist]
    local path="$1" id="$2" ent="${3:-}"
    local args=(--force --sign - --timestamp=none --pagesize 4096 --identifier "$id")
    [[ -n "$ent" ]] && args+=(--entitlements "$ent")
    codesign "${args[@]}" "$path"
    if [[ -n "$ent" ]]; then
        local seen
        seen="$(ldid -e "$path" 2>/dev/null || true)"
        [[ -n "$seen" ]] || { echo "[-] ldid -e sees no entitlements on $path - the lane would drop them" >&2; exit 1; }
        echo "    ldid round-trip ok: $(printf '%s' "$seen" | tr -d '\n' | cut -c1-60)..."
    fi
}

cdhash_of() { codesign -d --arch arm64 -vvvv "$1" 2>&1 | sed -n 's/^CDHash=//p'; }

# --- stage ---------------------------------------------------------------------------
rm -rf "$stage"
mkdir -p "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/lib"

build() { # build <src.c> <dest-relative> <identifier> <ent|-> [extra clang args]
    local src="$1" rel="$2" id="$3" ent="${4:-}"; shift 4
    local dest="$stage/$rel"
    mkdir -p "$(dirname "$dest")"
    "$clang_bin" "${clang_flags[@]}" -Os "$@" "$src" -o "$dest"
    sign_like_lane "$dest" "$id" "$([[ "$ent" == "-" ]] && echo "" || echo "$ent_dir/$ent")"
    printf '  %-28s %s\n' "$rel" "$(cdhash_of "$dest")"
}

echo "=== payload ==="
# cs-loader: get-task-allow is the prerequisite its forked child inherits, and the
# rest is the debug-client set for the attach that softens it.
build "$script_dir/cs-loader.c"   usr/bin/cs-loader   com.example.c1sh-csloader   anchor-worker.entitlements
build "$script_dir/tfpid_probe.c" usr/bin/tfpid       com.example.c1sh-tfpid       debug-client.entitlements
build "$script_dir/injprobe.c"    usr/bin/injprobe    com.example.c1sh-injprobe    debug-client.entitlements
# ...and the dylib injprobe injects. Its default agent path resolves to
# /var/jb/usr/lib/libagent.dylib, which is where this lands.
build "$script_dir/agent.c"       usr/lib/libagent.dylib com.example.c1sh-agent    - -dynamiclib

# --- control + package ----------------------------------------------------------------
cat >"$stage/DEBIAN/control" <<'CONTROL'
Package: com.research.c1tools
Version: 1.0
Architecture: iphoneos-arm64
Maintainer: research
Section: Utilities
Priority: optional
Description: c1 research toolkit - cs-loader (run an arbitrary unsigned Mach-O as the
 code of a debug-authorised child), tfpid (task ports and cross-process reads),
 injprobe (injection into a foreign process) and the agent dylib it injects.
 Delivered through the lane's trusted-package mechanism.
CONTROL

deb="$out_dir/$deb_name"
rm -f "$deb"
if ! dpkg-deb --build --root-owner-group "$stage" "$deb" >/dev/null 2>&1; then
    dpkg-deb --build "$stage" "$deb" >/dev/null
fi

echo
echo "=== $deb_name ==="
dpkg-deb -f "$deb" Package Version Architecture | sed 's/^/  /'
echo "  sha256: $(shasum -a 256 "$deb" | awk '{print $1}')"
echo "  size:   $(stat -f%z "$deb") bytes"
echo
echo "The lane build refuses a deb whose sha256 does not match its C1TOOLS_SHA256 pin."
echo "Bump that pin in Dopamine-CryptexBootstrap/CryptexBootstrap/build_cryptex.sh to the"
echo "value above, or export C1TOOLS_SHA256 when running setup.sh."
