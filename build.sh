#!/bin/zsh

set -euo pipefail

ROOT=${0:A:h}
CRYPTEXCTL=/System/Library/SecurityResearch/usr/bin/cryptexctl.research
IDENTIFIER=com.0xjohnnydev.untitled
VERSION=${UNTITLED_CRYPTEX_VERSION:-1.0.20260914.11}

BOOTSTRAP_URL=https://apt.procurs.us/bootstraps/1900/bootstrap-iphoneos-arm64.tar.zst
BOOTSTRAP_SHA256=8354c3aa1ecdad8ebc47d9a76dfca6f830a2b757278068bd33b98bf1d638a9cb
OPENSSH_SERVER_URL=https://apt.procurs.us/pool/main/iphoneos-arm64-rootless/1900/openssh/openssh-server_9.7p1-1_iphoneos-arm64.deb
OPENSSH_SERVER_SHA256=578a172e679c961d2966caaf300bd0a43cfdf0a311741712690cfdb6e16eca54
LIBMD_URL=https://apt.procurs.us/pool/main/iphoneos-arm64-rootless/1900/libmd/libmd0_1.1.0_iphoneos-arm64.deb
LIBMD_SHA256=3c7644b30fd6498b995ed73763b5667f7183a986efdace8309aa8731421cc507
FRIDA_VERSION=17.17.0
FRIDA_URL=https://github.com/frida/frida/releases/download/$FRIDA_VERSION/frida_${FRIDA_VERSION}_iphoneos-arm64.deb
FRIDA_SHA256=a737aa0c2635ebca03be0abe19a22afeeeae8fe04fff4d8ced34a5a9b8f264a4
FRIDA_GUARDED_SERVER_SHA256=b77af30099a01f54c146a5a6b59b015ecdd8a8d53bb32ef7e4da1d4d2d6d4bbd
TRUSTED_LAUNCHCTL_CDHASH=b93ba39fa52164b7aa6550fd3002603c85aa15b2

CACHE_DIR=$ROOT/cache
BUILD_DIR=$ROOT/build
WORK_DIR=$BUILD_DIR/work
IMAGE_ROOT=$BUILD_DIR/image-root
SSH_DIR=$BUILD_DIR/ssh
UNSIGNED_DIR=$BUILD_DIR/unsigned
GENERATED_DIR=$BUILD_DIR/generated
SUMMARY=$BUILD_DIR/build-summary.json
FRIDA_GUARDED_SERVER=$CACHE_DIR/frida-server_${FRIDA_VERSION}_ios27-pid1-guard

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
    ldid lipo nm perl plutil python3 rg security shasum ssh-keygen strings tar \
    xcrun zstd; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done
[[ -x $CRYPTEXCTL ]] || die "missing Cryptex builder: $CRYPTEXCTL"

mkdir -p "$CACHE_DIR" "$BUILD_DIR" "$SSH_DIR"
fetch_pinned "$BOOTSTRAP_URL" "$BOOTSTRAP_SHA256" \
    "$CACHE_DIR/bootstrap-iphoneos-arm64.tar.zst"
fetch_pinned "$OPENSSH_SERVER_URL" "$OPENSSH_SERVER_SHA256" \
    "$CACHE_DIR/openssh-server.deb"
fetch_pinned "$LIBMD_URL" "$LIBMD_SHA256" "$CACHE_DIR/libmd0.deb"
fetch_pinned "$FRIDA_URL" "$FRIDA_SHA256" \
    "$CACHE_DIR/frida_${FRIDA_VERSION}_iphoneos-arm64.deb"
[[ -f $FRIDA_GUARDED_SERVER ]] || \
    die "missing guarded Frida server; run Scripts/build-frida-ios27-pid1-guard.zsh"
[[ $(sha256_of "$FRIDA_GUARDED_SERVER") == $FRIDA_GUARDED_SERVER_SHA256 ]] || \
    die "guarded Frida server hash mismatch"

[[ $(dpkg-deb -f "$CACHE_DIR/frida_${FRIDA_VERSION}_iphoneos-arm64.deb" Package) == \
    re.frida.server ]] || die "unexpected Frida package identifier"
[[ $(dpkg-deb -f "$CACHE_DIR/frida_${FRIDA_VERSION}_iphoneos-arm64.deb" Version) == \
    $FRIDA_VERSION ]] || die "unexpected Frida package version"
[[ $(dpkg-deb -f "$CACHE_DIR/frida_${FRIDA_VERSION}_iphoneos-arm64.deb" Architecture) == \
    iphoneos-arm64 ]] || die "unexpected Frida package architecture"

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
    "$WORK_DIR/frida-package" \
    "$WORK_DIR/packages" \
    "$IMAGE_ROOT/Library/LaunchDaemons" \
    "$IMAGE_ROOT/usr/local/bin" \
    "$IMAGE_ROOT/usr/local/libexec/untitled/bin" \
    "$IMAGE_ROOT/usr/local/libexec/untitled/lib" \
    "$IMAGE_ROOT/usr/local/share/untitled/trust-only/procursus-shell" \
    "$GENERATED_DIR" \
    "$UNSIGNED_DIR"

zstd -dc "$CACHE_DIR/bootstrap-iphoneos-arm64.tar.zst" | \
    tar -xf - -C "$WORK_DIR/bootstrap"
dpkg-deb -x "$CACHE_DIR/openssh-server.deb" "$WORK_DIR/packages"
dpkg-deb -x "$CACHE_DIR/libmd0.deb" "$WORK_DIR/packages"
dpkg-deb -x "$CACHE_DIR/frida_${FRIDA_VERSION}_iphoneos-arm64.deb" \
    "$WORK_DIR/frida-package"

BASE_ROOT=$WORK_DIR/bootstrap/var/jb
PACKAGE_ROOT=$WORK_DIR/packages/var/jb
BIN_DIR=$IMAGE_ROOT/usr/local/libexec/untitled/bin
LIB_DIR=$IMAGE_ROOT/usr/local/libexec/untitled/lib
FRIDA_PACKAGE_ROOT=$WORK_DIR/frida-package/var/jb
FRIDA_DIR=$IMAGE_ROOT/usr/local/libexec/untitled/frida
FRIDA_SERVER=$FRIDA_DIR/frida-server
FRIDA_POLICYD=$FRIDA_DIR/frida-policyd
FRIDA_AGENT=$FRIDA_DIR/frida-agent.dylib
FRIDA_DEBUG_TARGET=$IMAGE_ROOT/usr/local/bin/untitled-frida-debug-target
FRIDA_CONTROL_TARGET=$IMAGE_ROOT/usr/local/bin/untitled-frida-control-target
EXECUTION_PROBE=$IMAGE_ROOT/usr/local/bin/untitled-execution-probe
DEBUGGER_COW_PROBE=$IMAGE_ROOT/usr/local/bin/untitled-debugger-cow-probe
SHELL_TRUST_DIR=$IMAGE_ROOT/usr/local/share/untitled/trust-only/procursus-shell

print -r -- "$VERSION" > "$IMAGE_ROOT/usr/local/share/untitled/build-version"

for relative in \
    usr/bin/zsh \
    usr/bin/launchctl \
    usr/lib/libiosexec.1.dylib \
    usr/lib/libpcre.1.dylib \
    usr/lib/libncursesw.6.dylib; do
    source=$BASE_ROOT/$relative
    destination=$SHELL_TRUST_DIR/${relative:t}
    [[ -f $source ]] || die "bootstrap control-path artifact is missing: $relative"
    install -m 0755 "$source" "$destination"
    codesign -d --verbose=2 "$destination" >/dev/null 2>&1 || \
        die "control-path artifact has no readable code signature: $relative"
done

TRUSTED_LAUNCHCTL=$SHELL_TRUST_DIR/launchctl
python3 \
    "$ROOT/Dopamine-CryptexBootstrap/CryptexBootstrap/patch_weak_import.py" \
    "$TRUSTED_LAUNCHCTL" _launch_active_user_switch >/dev/null
codesign --force --sign - --timestamp=none --pagesize 4096 \
    --preserve-metadata=identifier,entitlements "$TRUSTED_LAUNCHCTL"
nm -m "$TRUSTED_LAUNCHCTL" | \
    rg -q '\(undefined\) weak external _launch_active_user_switch' || \
    die "trusted launchctl compatibility import is not weak"
ldid -e "$TRUSTED_LAUNCHCTL" | \
    rg -q '<key>com.apple.private.xpc.launchd.enable-disable-system-services</key>' || \
    die "trusted launchctl lost its launchd-control entitlement"
launchctl_cdhash=$(codesign -d --verbose=4 "$TRUSTED_LAUNCHCTL" 2>&1 | \
    sed -n 's/^CDHash=//p')
[[ $launchctl_cdhash == $TRUSTED_LAUNCHCTL_CDHASH ]] || \
    die "trusted launchctl CDHash changed: $launchctl_cdhash"
codesign --verify --strict --verbose=2 "$TRUSTED_LAUNCHCTL" || \
    die "trusted launchctl signature verification failed"

mkdir -p "$FRIDA_DIR"
install -m 0755 "$FRIDA_GUARDED_SERVER" "$FRIDA_SERVER"
ln -s frida-server "$FRIDA_POLICYD"
install -m 0755 \
    "$FRIDA_PACKAGE_ROOT/usr/lib/frida-1.0/frida-agent.dylib" \
    "$FRIDA_AGENT"
install -m 0644 \
    "$FRIDA_PACKAGE_ROOT/Library/LaunchDaemons/re.frida.server.plist" \
    "$FRIDA_DIR/re.frida.server.plist"
install -m 0755 "$ROOT/Sources/start-frida.zsh" \
    "$IMAGE_ROOT/usr/local/bin/untitled-frida"
install -m 0644 "$ROOT/Sources/frida-policyd.plist" \
    "$IMAGE_ROOT/Library/LaunchDaemons/re.frida.policyd.plist"

[[ -L $FRIDA_POLICYD && ${FRIDA_POLICYD:A} == ${FRIDA_SERVER:A} ]] || \
    die "Frida policy daemon is not linked to the guarded server"

for binary in "$FRIDA_SERVER" "$FRIDA_AGENT"; do
    [[ $(lipo -archs "$binary") == "arm64 arm64e" ]] || \
        die "Frida payload is not universal arm64/arm64e: ${binary:t}"
    codesign -d --verbose=2 "$binary" >/dev/null 2>&1 || \
        die "Frida payload has no readable code signature: ${binary:t}"
done
rg -a -Fq 'PID 1 injection is disabled by the iOS 27 safety guard' \
    "$FRIDA_SERVER" || \
    die "Frida server is missing the iOS 27 PID 1 guard"
rg -a -Fq 'outcome=pid-guard' "$FRIDA_SERVER" || \
    die "Frida policy daemon is missing its PID guard"
rg -a -Fq 'flags_after_detach=0x%08x softened=%d' \
    "$FRIDA_SERVER" || \
    die "Frida server is missing the iOS 27 policy diagnostic"
FRIDA_ENTITLEMENTS=$WORK_DIR/frida-server-entitlements.plist
codesign -d --entitlements :- "$FRIDA_SERVER" > "$FRIDA_ENTITLEMENTS" \
    2>/dev/null
python3 - "$FRIDA_ENTITLEMENTS" <<'PY'
import plistlib
import sys

with open(sys.argv[1], "rb") as stream:
    entitlements = plistlib.load(stream)
required = {
    "com.apple.private.amfi.can-execute-cdhash",
    "com.apple.private.amfi.can-load-cdhash",
    "dynamic-codesigning",
    "get-task-allow",
    "platform-application",
    "research.com.apple.license-to-operate",
    "run-unsigned-code",
    "task_for_pid-allow",
}
missing = sorted(key for key in required if entitlements.get(key) is not True)
if missing:
    raise SystemExit(
        "Frida server is missing required entitlements: " + ", ".join(missing)
    )
PY
[[ $(plutil -extract Program raw -o - \
    "$FRIDA_DIR/re.frida.server.plist") == /var/jb/usr/sbin/frida-server ]] || \
    die "Frida launch daemon has an unexpected program path"
FRIDA_POLICYD_PLIST=$IMAGE_ROOT/Library/LaunchDaemons/re.frida.policyd.plist
python3 - "$FRIDA_POLICYD_PLIST" <<'PY'
import plistlib
import sys

with open(sys.argv[1], "rb") as stream:
    policy = plistlib.load(stream)
expected_program = "/usr/local/libexec/untitled/frida/frida-policyd"
if policy.get("ProgramArguments") != [expected_program]:
    raise SystemExit("Frida policy daemon has an unexpected program path")
if policy.get("MachServices", {}).get("re.frida.policyd") is not True:
    raise SystemExit("Frida policy daemon does not publish re.frida.policyd")
PY

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
xcrun --sdk iphoneos clang \
    -arch arm64 \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -Wall -Wextra -Werror \
    "$ROOT/Sources/frida-launcher.c" \
    -o "$FRIDA_DIR/frida-launcher"
xcrun --sdk iphoneos clang \
    -arch arm64 \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -Wall -Wextra -Werror \
    -DUNTITLED_EXPECT_GET_TASK_ALLOW=1 \
    "$ROOT/Sources/frida-debug-target.c" \
    -o "$FRIDA_DEBUG_TARGET"
xcrun --sdk iphoneos clang \
    -arch arm64 \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -Wall -Wextra -Werror \
    -DUNTITLED_EXPECT_GET_TASK_ALLOW=0 \
    "$ROOT/Sources/frida-debug-target.c" \
    -o "$FRIDA_CONTROL_TARGET"
xcrun --sdk iphoneos clang \
    -arch arm64 \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -Wall -Wextra -Werror \
    "$ROOT/Sources/execution-probe.c" \
    -o "$EXECUTION_PROBE"
xcrun --sdk iphoneos clang \
    -arch arm64 \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -Wall -Wextra -Werror \
    "$ROOT/Sources/debugger-cow-probe.c" \
    -o "$DEBUGGER_COW_PROBE"

for executable in \
    "$IMAGE_ROOT/usr/local/bin/untitled-rootd" \
    "$FRIDA_DIR/frida-launcher" \
    "$FRIDA_CONTROL_TARGET" \
    "$BIN_DIR/sshd"; do
    ldid -S"$ROOT/Sources/runtime-entitlements.plist" -Cadhoc "$executable"
    chmod 0755 "$executable"
done
ldid -S"$ROOT/Sources/frida-debuggee-entitlements.plist" -Cadhoc \
    "$FRIDA_DEBUG_TARGET"
ldid -S"$ROOT/Sources/execution-probe-entitlements.plist" -Cadhoc \
    "$EXECUTION_PROBE"
ldid -S"$ROOT/Sources/debugger-cow-probe-entitlements.plist" -Cadhoc \
    "$DEBUGGER_COW_PROBE"
chmod 0755 "$FRIDA_DEBUG_TARGET" "$EXECUTION_PROBE" \
    "$DEBUGGER_COW_PROBE"
for library in "$LIB_DIR"/*.dylib; do
    codesign --force --sign - --timestamp=none --pagesize 4096 "$library"
    chmod 0755 "$library"
done

install -m 0644 "$ROOT/Sources/rootd.plist" \
    "$IMAGE_ROOT/Library/LaunchDaemons/com.0xjohnnydev.untitled.rootd.plist"
for executable in \
    "$IMAGE_ROOT/usr/local/bin/untitled-rootd" \
    "$FRIDA_DIR/frida-launcher" \
    "$FRIDA_DEBUG_TARGET" \
    "$FRIDA_CONTROL_TARGET" \
    "$EXECUTION_PROBE" \
    "$DEBUGGER_COW_PROBE" \
    "$BIN_DIR/sshd"; do
    file "$executable" | rg -q 'Mach-O 64-bit executable arm64' || \
        die "unexpected executable format: ${executable:t}"
    codesign -d --verbose=2 "$executable" >/dev/null 2>&1 || \
        die "could not read embedded signature: ${executable:t}"
    ldid -e "$executable" | plutil -lint - >/dev/null || \
        die "invalid embedded entitlements: ${executable:t}"
done

python3 - "$FRIDA_DEBUG_TARGET" "$FRIDA_CONTROL_TARGET" \
    "$EXECUTION_PROBE" <<'PY'
import plistlib
import subprocess
import sys

debug_target, control_target, execution_probe = sys.argv[1:]

def entitlements(path: str) -> dict:
    output = subprocess.run(
        ["ldid", "-e", path],
        check=True,
        capture_output=True,
    ).stdout
    return plistlib.loads(output)

debug = entitlements(debug_target)
control = entitlements(control_target)
execution = entitlements(execution_probe)
if debug.get("get-task-allow") is not True:
    raise SystemExit("Frida positive-control target lacks get-task-allow")
if control.get("get-task-allow") is not None:
    raise SystemExit("Frida negative-control target unexpectedly has get-task-allow")
debug_without_gta = dict(debug)
debug_without_gta.pop("get-task-allow")
if debug_without_gta != control:
    raise SystemExit(
        "Frida controls differ by more than get-task-allow: "
        f"positive={debug_without_gta!r} negative={control!r}"
    )
expected_execution = {
    "com.apple.developer.web-browser-engine.webcontent": True,
    "com.apple.private.security.no-container": True,
    "com.apple.private.skip-library-validation": True,
    "dynamic-codesigning": True,
    "get-task-allow": True,
    "platform-application": True,
    "run-unsigned-code": True,
}
if execution != expected_execution:
    raise SystemExit(
        "execution probe entitlement mismatch: "
        f"expected={expected_execution!r} actual={execution!r}"
    )
PY

python3 - "$DEBUGGER_COW_PROBE" <<'PY'
import plistlib
import subprocess
import sys

output = subprocess.run(
    ["ldid", "-e", sys.argv[1]],
    check=True,
    capture_output=True,
).stdout
actual = plistlib.loads(output)
expected = {
    "com.apple.private.cs.debugger": True,
    "com.apple.private.security.no-container": True,
    "get-task-allow": True,
    "platform-application": True,
}
if actual != expected:
    raise SystemExit(
        "debugger COW probe entitlement mismatch: "
        f"expected={expected!r} actual={actual!r}"
    )
PY

# [REDACTED] Packaging, payload selection, and validation details omitted.
printf '%s\n' 'TSS/Cryptex personalization and installation details are redacted from this educational source release.' >&2
exit 1
