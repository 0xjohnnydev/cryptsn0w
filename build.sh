#!/bin/zsh

set -euo pipefail

ROOT=${0:A:h}
CRYPTEXCTL=/System/Library/SecurityResearch/usr/bin/cryptexctl.research
IDENTIFIER=com.0xjohnnydev.untitled
VERSION=${UNTITLED_CRYPTEX_VERSION:-1.0.20260914.1}

BOOTSTRAP_URL=https://apt.procurs.us/bootstraps/1900/bootstrap-iphoneos-arm64.tar.zst
BOOTSTRAP_SHA256=8354c3aa1ecdad8ebc47d9a76dfca6f830a2b757278068bd33b98bf1d638a9cb
OPENSSH_SERVER_URL=https://apt.procurs.us/pool/main/iphoneos-arm64-rootless/1900/openssh/openssh-server_9.7p1-1_iphoneos-arm64.deb
OPENSSH_SERVER_SHA256=578a172e679c961d2966caaf300bd0a43cfdf0a311741712690cfdb6e16eca54
LIBMD_URL=https://apt.procurs.us/pool/main/iphoneos-arm64-rootless/1900/libmd/libmd0_1.1.0_iphoneos-arm64.deb
LIBMD_SHA256=3c7644b30fd6498b995ed73763b5667f7183a986efdace8309aa8731421cc507

CACHE_DIR=$ROOT/cache
BUILD_DIR=$ROOT/build
WORK_DIR=$BUILD_DIR/work
IMAGE_ROOT=$BUILD_DIR/image-root
SSH_DIR=$BUILD_DIR/ssh
UNSIGNED_DIR=$BUILD_DIR/unsigned
GENERATED_DIR=$BUILD_DIR/generated
SUMMARY=$BUILD_DIR/build-summary.json

die() {
    print -u2 -- "error: $*"
    exit 1
}

sha256_of() {
    shasum -a 256 "$1" | awk '{print $1}'
}

fetch_pinned() {
    local url=$1
    local expected=$2
    local destination=$3
    if [[ ! -f $destination ]]; then
        local partial="$destination.partial.$$"
        curl --fail --location --retry 3 --silent --show-error \
            --output "$partial" "$url"
        [[ $(sha256_of "$partial") == $expected ]] || \
            die "download hash mismatch: ${destination:t}"
        mv "$partial" "$destination"
    fi
    [[ $(sha256_of "$destination") == $expected ]] || \
        die "cached hash mismatch: ${destination:t}"
}

for tool in awk codesign curl dpkg-deb file find install install_name_tool \
    ldid perl plutil python3 rg security shasum ssh-keygen strings tar xcrun \
    zstd; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done
[[ -x $CRYPTEXCTL ]] || die "missing Cryptex builder: $CRYPTEXCTL"

mkdir -p "$CACHE_DIR" "$BUILD_DIR" "$SSH_DIR"
fetch_pinned "$BOOTSTRAP_URL" "$BOOTSTRAP_SHA256" \
    "$CACHE_DIR/bootstrap-iphoneos-arm64.tar.zst"
fetch_pinned "$OPENSSH_SERVER_URL" "$OPENSSH_SERVER_SHA256" \
    "$CACHE_DIR/openssh-server.deb"
fetch_pinned "$LIBMD_URL" "$LIBMD_SHA256" "$CACHE_DIR/libmd0.deb"

if [[ ! -f $SSH_DIR/id_ed25519 ]]; then
    ssh-keygen -q -t ed25519 -N '' -C untitled-client \
        -f "$SSH_DIR/id_ed25519"
fi
if [[ ! -f $SSH_DIR/ssh_host_ed25519_key ]]; then
    ssh-keygen -q -t ed25519 -N '' -C untitled-host \
        -f "$SSH_DIR/ssh_host_ed25519_key"
fi
chmod 0600 "$SSH_DIR/id_ed25519" "$SSH_DIR/ssh_host_ed25519_key"

rm -rf "$WORK_DIR" "$IMAGE_ROOT" "$UNSIGNED_DIR" "$GENERATED_DIR"
mkdir -p \
    "$WORK_DIR/bootstrap" \
    "$WORK_DIR/packages" \
    "$IMAGE_ROOT/Library/LaunchDaemons" \
    "$IMAGE_ROOT/usr/local/bin" \
    "$IMAGE_ROOT/usr/local/libexec/untitled/bin" \
    "$IMAGE_ROOT/usr/local/libexec/untitled/lib" \
    "$GENERATED_DIR" \
    "$UNSIGNED_DIR"

zstd -dc "$CACHE_DIR/bootstrap-iphoneos-arm64.tar.zst" | \
    tar -xf - -C "$WORK_DIR/bootstrap"
dpkg-deb -x "$CACHE_DIR/openssh-server.deb" "$WORK_DIR/packages"
dpkg-deb -x "$CACHE_DIR/libmd0.deb" "$WORK_DIR/packages"

BASE_ROOT=$WORK_DIR/bootstrap/var/jb
PACKAGE_ROOT=$WORK_DIR/packages/var/jb
BIN_DIR=$IMAGE_ROOT/usr/local/libexec/untitled/bin
LIB_DIR=$IMAGE_ROOT/usr/local/libexec/untitled/lib

install -m 0755 "$PACKAGE_ROOT/usr/sbin/sshd" "$BIN_DIR/sshd"
for library in libiosexec.1.dylib libcrypt.2.dylib libpam.2.dylib \
    libssl.3.dylib libcrypto.3.dylib; do
    [[ -f $BASE_ROOT/usr/lib/$library ]] || \
        die "bootstrap library is missing: $library"
    install -m 0755 "$BASE_ROOT/usr/lib/$library" "$LIB_DIR/$library"
done
install -m 0755 "$PACKAGE_ROOT/usr/lib/libmd.0.dylib" \
    "$LIB_DIR/libmd.0.dylib"

for executable in "$BIN_DIR/sshd"; do
    install_name_tool -delete_rpath /var/jb/usr/lib "$executable" \
        2>/dev/null || true
    install_name_tool -add_rpath @executable_path/../lib "$executable"
done
for library in "$LIB_DIR"/*.dylib; do
    install_name_tool -delete_rpath /var/jb/usr/lib "$library" \
        2>/dev/null || true
    install_name_tool -add_rpath @loader_path "$library"
done

OLD_PRIVSEP=/var/jb/var/empty
NEW_PRIVSEP=/var/tmp/untitled
[[ ${#OLD_PRIVSEP} -eq ${#NEW_PRIVSEP} ]] || \
    die "privilege-separation path lengths differ"
OLD_PRIVSEP="$OLD_PRIVSEP" NEW_PRIVSEP="$NEW_PRIVSEP" \
    LC_ALL=C perl -0pi -e \
    's|\Q$ENV{OLD_PRIVSEP}\E|$ENV{NEW_PRIVSEP}|g' \
    "$BIN_DIR/sshd"
strings -a "$BIN_DIR/sshd" | rg -q '^/var/tmp/untitled$' || \
    die "sshd privilege-separation path patch failed"
if strings -a "$BIN_DIR/sshd" | rg -q '^/var/jb/var/empty$'; then
    die "sshd retains the old privilege-separation path"
fi
python3 - "$BIN_DIR/sshd" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
data = path.read_bytes()
old = b"sshd\0Privilege separation user"
new = b"root\0Privilege separation user"
if data.count(old) != 1:
    raise SystemExit("unexpected compiled privilege-separation user layout")
path.write_bytes(data.replace(old, new))
PY
strings -a "$BIN_DIR/sshd" | rg -q '^root$' || \
    die "sshd privilege-separation user patch failed"
python3 - "$BIN_DIR/sshd" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
data = path.read_bytes()
# OpenSSH 9.7p1 ssh_sandbox_child: BL sandbox_init; CMN W0,#1; B.EQ fatal.
# iOS 27 removed the named pure-computation profile. Preserve the following
# resource-limit setup, but make the pinned call return success without asking
# the OS for the absent profile.
old = bytes.fromhex("d92d01941f04003180040054")
new = bytes.fromhex("000080521f04003180040054")  # MOV W0,#0
if data.count(old) != 1:
    raise SystemExit("unexpected OpenSSH sandbox call-site layout")
patched = data.replace(old, new)
if patched.count(new) != 1:
    raise SystemExit("OpenSSH sandbox compatibility patch failed")
path.write_bytes(patched)
PY

SDKROOT=$(xcrun --sdk iphoneos --show-sdk-path)
python3 - \
    "$GENERATED_DIR/embedded_payload.h" \
    "$SSH_DIR/ssh_host_ed25519_key" \
    "$SSH_DIR/id_ed25519.pub" \
    "$ROOT/Sources/sshd_config" <<'PY'
from pathlib import Path
import sys

output, host_key, authorized_keys, config = map(Path, sys.argv[1:])

def declaration(name: str, path: Path) -> str:
    data = path.read_bytes()
    rows = []
    for offset in range(0, len(data), 12):
        values = ", ".join(f"0x{value:02x}" for value in data[offset:offset + 12])
        rows.append(f"    {values},")
    body = "\n".join(rows)
    return (
        f"static const unsigned char {name}[] = {{\n{body}\n}};\n"
        f"static const size_t {name}Length = sizeof({name});\n"
    )

text = "#pragma once\n\n#include <stddef.h>\n\n"
text += declaration("kUntitledHostKey", host_key)
text += "\n" + declaration("kUntitledAuthorizedKeys", authorized_keys)
text += "\n" + declaration("kUntitledSshdConfig", config)
output.write_text(text)
PY

xcrun --sdk iphoneos clang \
    -arch arm64 \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -fobjc-arc \
    -Wall -Wextra -Werror \
    -I"$GENERATED_DIR" \
    -framework Foundation \
    "$ROOT/Sources/rootd.m" \
    -o "$IMAGE_ROOT/usr/local/bin/untitled-rootd"

for executable in \
    "$IMAGE_ROOT/usr/local/bin/untitled-rootd" \
    "$BIN_DIR/sshd"; do
    ldid -S"$ROOT/Sources/runtime-entitlements.plist" -Cadhoc "$executable"
    chmod 0755 "$executable"
done
for library in "$LIB_DIR"/*.dylib; do
    codesign --force --sign - --timestamp=none --pagesize 4096 "$library"
    chmod 0755 "$library"
done

install -m 0644 "$ROOT/Sources/rootd.plist" \
    "$IMAGE_ROOT/Library/LaunchDaemons/com.0xjohnnydev.untitled.rootd.plist"
for executable in \
    "$IMAGE_ROOT/usr/local/bin/untitled-rootd" \
    "$BIN_DIR/sshd"; do
    file "$executable" | rg -q 'Mach-O 64-bit executable arm64' || \
        die "unexpected executable format: ${executable:t}"
    codesign -d --verbose=2 "$executable" >/dev/null 2>&1 || \
        die "could not read embedded signature: ${executable:t}"
    ldid -e "$executable" | plutil -lint - >/dev/null || \
        die "invalid embedded entitlements: ${executable:t}"
done

# [REDACTED] Packaging, payload selection, and validation details omitted.
printf '%s\n' 'TSS/Cryptex personalization and installation details are redacted from this educational source release.' >&2
exit 1
