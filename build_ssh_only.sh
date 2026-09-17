#!/bin/zsh
set -euo pipefail

ROOT=${0:A:h}
CRYPTEXCTL=/System/Library/SecurityResearch/usr/bin/cryptexctl.research
IDENTIFIER=com.0xjohnnydev.untitled
VERSION=${UNTITLED_CRYPTEX_VERSION:-1.0.$(date -u +%Y%m%d%H%M%S)}
BOOTSTRAP_URL=https://apt.procurs.us/bootstraps/1900/bootstrap-iphoneos-arm64.tar.zst
BOOTSTRAP_SHA256=8354c3aa1ecdad8ebc47d9a76dfca6f830a2b757278068bd33b98bf1d638a9cb
OPENSSH_URL=https://apt.procurs.us/pool/main/iphoneos-arm64-rootless/1900/openssh/openssh-server_9.7p1-1_iphoneos-arm64.deb
OPENSSH_SHA256=578a172e679c961d2966caaf300bd0a43cfdf0a311741712690cfdb6e16eca54
LIBMD_URL=https://apt.procurs.us/pool/main/iphoneos-arm64-rootless/1900/libmd/libmd0_1.1.0_iphoneos-arm64.deb
LIBMD_SHA256=3c7644b30fd6498b995ed73763b5667f7183a986efdace8309aa8731421cc507

CACHE=$ROOT/cache
BUILD=$ROOT/build
WORK=$BUILD/ssh-only-work
IMAGE=$BUILD/image-root
SSH=$BUILD/ssh
UNSIGNED=$BUILD/unsigned
BIN=$IMAGE/usr/local/libexec/untitled/bin
LIB=$IMAGE/usr/local/libexec/untitled/lib
ROOTD=$IMAGE/usr/local/bin/untitled-rootd
SSHD=$BIN/sshd
SUMMARY=$BUILD/build-summary.json

die() { print -u2 -- "error: $*"; exit 1; }
sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
fetch() {
    local url=$1 expected=$2 destination=$3
    if [[ ! -f $destination ]]; then
        curl --fail --location --retry 3 --silent --show-error \
            --output "$destination.partial.$$" "$url"
        [[ $(sha256 "$destination.partial.$$") == $expected ]] || \
            die "download hash mismatch: ${destination:t}"
        mv "$destination.partial.$$" "$destination"
    fi
    [[ $(sha256 "$destination") == $expected ]] || \
        die "cached hash mismatch: ${destination:t}"
}

for tool in codesign curl dpkg-deb file install install_name_tool ldid lipo \
    perl plutil python3 rg security shasum ssh-keygen strings tar xcrun zstd; do
    command -v "$tool" >/dev/null || die "missing tool: $tool"
done
[[ -x $CRYPTEXCTL ]] || die "missing cryptexctl.research"
mkdir -p "$CACHE" "$BUILD" "$SSH"
fetch "$BOOTSTRAP_URL" "$BOOTSTRAP_SHA256" "$CACHE/bootstrap-iphoneos-arm64.tar.zst"
fetch "$OPENSSH_URL" "$OPENSSH_SHA256" "$CACHE/openssh-server.deb"
fetch "$LIBMD_URL" "$LIBMD_SHA256" "$CACHE/libmd0.deb"

if [[ ! -f $SSH/id_ed25519 ]]; then
    ssh-keygen -q -t ed25519 -N '' -C untitled-client -f "$SSH/id_ed25519"
fi
if [[ ! -f $SSH/ssh_host_ed25519_key ]]; then
    ssh-keygen -q -t ed25519 -N '' -C untitled-host \
        -f "$SSH/ssh_host_ed25519_key"
fi
chmod 0600 "$SSH/id_ed25519" "$SSH/ssh_host_ed25519_key"

rm -rf -- "$WORK" "$IMAGE" "$UNSIGNED"
mkdir -p "$WORK/bootstrap" "$WORK/packages" "$BIN" "$LIB" \
    "$IMAGE/Library/LaunchDaemons" "$IMAGE/usr/local/bin" "$UNSIGNED"
zstd -dc "$CACHE/bootstrap-iphoneos-arm64.tar.zst" | \
    tar -xf - -C "$WORK/bootstrap"
dpkg-deb -x "$CACHE/openssh-server.deb" "$WORK/packages"
dpkg-deb -x "$CACHE/libmd0.deb" "$WORK/packages"
BASE=$WORK/bootstrap/var/jb
PACKAGE=$WORK/packages/var/jb
install -m 0755 "$PACKAGE/usr/sbin/sshd" "$SSHD"
for library in libiosexec.1.dylib libcrypt.2.dylib libpam.2.dylib \
    libssl.3.dylib libcrypto.3.dylib; do
    install -m 0755 "$BASE/usr/lib/$library" "$LIB/$library"
done
install -m 0755 "$PACKAGE/usr/lib/libmd.0.dylib" "$LIB/libmd.0.dylib"
install_name_tool -delete_rpath /var/jb/usr/lib "$SSHD" 2>/dev/null || true
install_name_tool -add_rpath @executable_path/../lib "$SSHD"
for library in "$LIB"/*.dylib; do
    install_name_tool -delete_rpath /var/jb/usr/lib "$library" 2>/dev/null || true
    install_name_tool -add_rpath @loader_path "$library"
done

OLD_PRIVSEP=/var/jb/var/empty
NEW_PRIVSEP=/var/tmp/untitled
[[ ${#OLD_PRIVSEP} -eq ${#NEW_PRIVSEP} ]] || die "privsep path length mismatch"
OLD_PRIVSEP=$OLD_PRIVSEP NEW_PRIVSEP=$NEW_PRIVSEP LC_ALL=C \
    perl -0pi -e 's|\Q$ENV{OLD_PRIVSEP}\E|$ENV{NEW_PRIVSEP}|g' "$SSHD"
strings -a "$SSHD" | rg -q '^/var/tmp/untitled$' || \
    die "sshd privsep path patch failed"
python3 - "$SSHD" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
data = path.read_bytes()
for old, new in (
    (b"sshd\0Privilege separation user", b"root\0Privilege separation user"),
    (bytes.fromhex("d92d01941f04003180040054"),
     bytes.fromhex("000080521f04003180040054")),
):
    if data.count(old) != 1:
        raise SystemExit("unexpected pinned OpenSSH patch site")
    data = data.replace(old, new)
path.write_bytes(data)
PY

python3 - "$WORK/embedded_payload.h" "$SSH/ssh_host_ed25519_key" \
    "$SSH/id_ed25519.pub" "$ROOT/Sources/sshd_config" <<'PY'
from pathlib import Path
import sys
output, host_key, public_key, config = map(Path, sys.argv[1:])
def declaration(name: str, path: Path) -> str:
    data = path.read_bytes()
    rows = [", ".join(f"0x{byte:02x}" for byte in data[i:i + 12])
            for i in range(0, len(data), 12)]
    return (f"static const unsigned char {name}[] = {{\n    " +
            ",\n    ".join(rows) +
            f"\n}};\nstatic const size_t {name}Length = sizeof({name});\n")
text = "#pragma once\n#include <stddef.h>\n"
text += declaration("kUntitledHostKey", host_key)
text += declaration("kUntitledAuthorizedKeys", public_key)
text += declaration("kUntitledSshdConfig", config)
output.write_text(text)
PY

SDK=$(xcrun --sdk iphoneos --show-sdk-path)
xcrun --sdk iphoneos clang -arch arm64 -miphoneos-version-min=17.0 \
    -isysroot "$SDK" -fobjc-arc -Wall -Wextra -Werror \
    -I"$WORK" -framework Foundation "$ROOT/Sources/rootd.m" -o "$ROOTD"
for executable in "$ROOTD" "$SSHD"; do
    ldid -S"$ROOT/Sources/runtime-entitlements.plist" -Cadhoc "$executable"
    chmod 0755 "$executable"
    codesign --verify --strict --all-architectures "$executable" || \
        die "invalid executable signature: $executable"
done
for library in "$LIB"/*.dylib; do
    codesign --force --sign - --timestamp=none --pagesize 4096 "$library"
    codesign --verify --strict --all-architectures "$library" || \
        die "invalid library signature: $library"
done
install -m 0644 "$ROOT/Sources/rootd.plist" \
    "$IMAGE/Library/LaunchDaemons/com.0xjohnnydev.untitled.rootd.plist"

# [REDACTED] Packaging, payload selection, and validation details omitted.
printf '%s\n' 'TSS/Cryptex personalization and installation details are redacted from this educational source release.' >&2
exit 1
