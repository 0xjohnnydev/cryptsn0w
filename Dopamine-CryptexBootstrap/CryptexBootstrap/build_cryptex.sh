#!/bin/zsh

set -euo pipefail

SCRIPT_DIR=${0:A:h}
REPO_DIR=${SCRIPT_DIR:h}
CRYPTEXCTL=/System/Library/SecurityResearch/usr/bin/cryptexctl.research
BOOTSTRAP_URL=https://apt.procurs.us/bootstraps/1900/bootstrap-iphoneos-arm64.tar.zst
BOOTSTRAP_SHA256=8354c3aa1ecdad8ebc47d9a76dfca6f830a2b757278068bd33b98bf1d638a9cb
SILEO_SHA256=8e3c90e5a7d32f4ca207a0ac30d3cfa8a13dca86a2b4e11cb3f9e5c68d7bc97a
IDENTIFIER=com.openai.codex.dopamine.bootstrap
VERSION=${CODEX_CRYPTEX_VERSION:-1.0.$(date -u +%Y%m%d%H%M%S)}
SILEO_DEVELOPMENT_IDENTITY=${CODEX_SILEO_DEVELOPMENT_IDENTITY:-}
SILEO_PROVISIONING_PROFILE=${CODEX_SILEO_PROVISIONING_PROFILE:-}
SILEO_DEVELOPMENT_ENTITLEMENTS=${CODEX_SILEO_DEVELOPMENT_ENTITLEMENTS:-}

CACHE_DIR="$SCRIPT_DIR/cache"
WORK_DIR="$SCRIPT_DIR/work"
OUT_DIR="$SCRIPT_DIR/out"
BOOTSTRAP_ARCHIVE="$CACHE_DIR/bootstrap_1900.tar.zst"
SILEO_DEB="$REPO_DIR/Application/Dopamine/Resources/sileo.deb"
IMAGE_ROOT="$WORK_DIR/image-root"
PACKAGE_ROOT="$WORK_DIR/sileo-package"
REPACKED_SILEO="$WORK_DIR/sileo.launchable.deb"
UNSIGNED_OUT="$OUT_DIR/unsigned"
SUMMARY="$OUT_DIR/build-summary.json"
SIGNING_DIR="$WORK_DIR/signing"
SIGNING_CONFIG="$SIGNING_DIR/config.json"
GENERATED_ENTITLEMENTS="$SIGNING_DIR/sileo-development-entitlements.plist"

die() {
    print -u2 -- "error: $*"
    exit 1
}

sha256_of() {
    shasum -a 256 "$1" | awk '{print $1}'
}

json_field() {
    python3 - "$1" "$2" <<'PY'
import json
import pathlib
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text())[sys.argv[2]]
if not isinstance(value, str) or not value:
    raise SystemExit(f"missing string field {sys.argv[2]}")
print(value)
PY
}

for tool in awk codesign curl dpkg-deb file find ldid nm plutil python3 rg security shasum tar xcrun zstd; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done
[[ -x "$CRYPTEXCTL" ]] || die "missing SRD cryptexctl: $CRYPTEXCTL"
[[ -f "$SILEO_DEB" ]] || die "missing opa334 Sileo package: $SILEO_DEB"

mkdir -p "$CACHE_DIR" "$WORK_DIR" "$OUT_DIR" "$SIGNING_DIR"
SIGNING_ARGS=(
    --bundle-id org.coolstar.SileoStore
    --output-json "$SIGNING_CONFIG"
    --output-entitlements "$GENERATED_ENTITLEMENTS"
)
[[ -z "$SILEO_DEVELOPMENT_IDENTITY" ]] || \
    SIGNING_ARGS+=(--identity "$SILEO_DEVELOPMENT_IDENTITY")
[[ -z "$SILEO_PROVISIONING_PROFILE" ]] || \
    SIGNING_ARGS+=(--profile "$SILEO_PROVISIONING_PROFILE")
[[ -z "$SILEO_DEVELOPMENT_ENTITLEMENTS" ]] || \
    SIGNING_ARGS+=(--entitlements "$SILEO_DEVELOPMENT_ENTITLEMENTS")
python3 "$SCRIPT_DIR/configure_signing.py" "${SIGNING_ARGS[@]}"
SILEO_DEVELOPMENT_IDENTITY=$(json_field "$SIGNING_CONFIG" identitySha1)
SILEO_PROVISIONING_PROFILE=$(json_field "$SIGNING_CONFIG" profile)
SILEO_DEVELOPMENT_ENTITLEMENTS=$(json_field "$SIGNING_CONFIG" entitlements)
SILEO_APPLICATION_IDENTIFIER=$(plutil -extract application-identifier raw -o - \
    "$SILEO_DEVELOPMENT_ENTITLEMENTS")

[[ -f "$SILEO_PROVISIONING_PROFILE" ]] || \
    die "missing Sileo provisioning profile: $SILEO_PROVISIONING_PROFILE"
[[ -f "$SILEO_DEVELOPMENT_ENTITLEMENTS" ]] || \
    die "missing Sileo development entitlements: $SILEO_DEVELOPMENT_ENTITLEMENTS"
security find-identity -v -p codesigning | \
    rg -q "$SILEO_DEVELOPMENT_IDENTITY" || \
    die "Sileo development identity is unavailable: $SILEO_DEVELOPMENT_IDENTITY"
if [[ ! -f "$BOOTSTRAP_ARCHIVE" ]]; then
    curl --fail --location --retry 3 --output "$BOOTSTRAP_ARCHIVE" "$BOOTSTRAP_URL"
fi
[[ "$(sha256_of "$BOOTSTRAP_ARCHIVE")" == "$BOOTSTRAP_SHA256" ]] || \
    die "Procursus archive hash mismatch"
[[ "$(sha256_of "$SILEO_DEB")" == "$SILEO_SHA256" ]] || \
    die "opa334 Sileo package hash mismatch"
zstd -t "$BOOTSTRAP_ARCHIVE" >/dev/null

rm -rf "$IMAGE_ROOT" "$PACKAGE_ROOT" "$UNSIGNED_OUT" "$REPACKED_SILEO"
mkdir -p \
    "$IMAGE_ROOT/Library/LaunchDaemons" \
    "$IMAGE_ROOT/usr/local/bin" \
    "$IMAGE_ROOT/usr/local/share/codex-bootstrap" \
    "$PACKAGE_ROOT" \
    "$UNSIGNED_OUT"

zstd -dc "$BOOTSTRAP_ARCHIVE" | \
    tar -xf - -C "$WORK_DIR"
[[ -d "$WORK_DIR/var/jb" ]] || die "archive did not extract var/jb"
ditto --noqtn "$WORK_DIR/var/jb" \
    "$IMAGE_ROOT/usr/local/share/codex-bootstrap/procursus"
rm -rf "$WORK_DIR/var"

# iOS 27 removed launch_active_user_switch from libSystem. Procursus launchctl
# does not use it for bootout/bootstrap, but its strong unused import prevents
# dyld from starting the executable at all. Make only that import weak, retain
# the original launchctl entitlements, and let the generated Cryptex trust
# cache cover the resulting exact code directory.
LAUNCHCTL="$IMAGE_ROOT/usr/local/share/codex-bootstrap/procursus/usr/bin/launchctl"
[[ -x "$LAUNCHCTL" ]] || die "Procursus launchctl is missing"
python3 "$SCRIPT_DIR/patch_weak_import.py" \
    "$LAUNCHCTL" _launch_active_user_switch
codesign --force --sign - --timestamp=none --pagesize 4096 \
    --preserve-metadata=identifier,entitlements "$LAUNCHCTL"
nm -m "$LAUNCHCTL" | \
    rg -q '\(undefined\) weak external _launch_active_user_switch' || \
    die "launchctl compatibility import is not weak"
ldid -e "$LAUNCHCTL" | \
    rg -q '<key>com.apple.private.xpc.launchd.enable-disable-system-services</key>' || \
    die "launchctl lost its launchd-control entitlement"

dpkg-deb -R "$SILEO_DEB" "$PACKAGE_ROOT"
APP_DIR="$PACKAGE_ROOT/var/jb/Applications/Sileo.app"
[[ -x "$APP_DIR/Sileo" && -x "$APP_DIR/giveMeRoot" ]] || \
    die "Sileo package is missing expected executables"

SDKROOT=$(xcrun --sdk iphoneos --show-sdk-path)
xcrun --sdk iphoneos clang \
    -arch arm64 \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -Wall -Wextra -Werror \
    "$SCRIPT_DIR/sileo_root_helper.c" \
    -o "$APP_DIR/giveMeRoot"
codesign --force --deep --sign - --timestamp=none --pagesize 4096 \
    --preserve-metadata=identifier,entitlements "$APP_DIR"
codesign --force --sign "$SILEO_DEVELOPMENT_IDENTITY" --timestamp=none \
    --pagesize 4096 "$APP_DIR/giveMeRoot"
chmod 0755 "$APP_DIR/giveMeRoot"
cp "$SILEO_PROVISIONING_PROFILE" "$APP_DIR/embedded.mobileprovision"
codesign --force --sign "$SILEO_DEVELOPMENT_IDENTITY" --timestamp=none \
    --pagesize 4096 --entitlements "$SILEO_DEVELOPMENT_ENTITLEMENTS" \
    "$APP_DIR"
if ldid -e "$APP_DIR/Sileo" | rg -q \
    'platform-application|no-sandbox|task_for_pid-allow'; then
    die "Sileo retains privileged runtime entitlements"
fi
ldid -e "$APP_DIR/Sileo" | rg -q \
    -F -- "<string>$SILEO_APPLICATION_IDENTIFIER</string>" || \
    die "Sileo development application identifier is missing"
codesign --verify --deep --strict --verbose=2 "$APP_DIR"
dpkg-deb -b "$PACKAGE_ROOT" "$REPACKED_SILEO" >/dev/null
cp "$REPACKED_SILEO" \
    "$IMAGE_ROOT/usr/local/share/codex-bootstrap/sileo.deb"
# cryptexctl does not recurse into a Debian archive when it constructs the
# trust cache. Keep an exact extracted copy so the helper and rootless package
# executables are represented; the provisioned app's main executable remains
# untouched in its MobileInstallation container.
ditto --noqtn "$APP_DIR" \
    "$IMAGE_ROOT/usr/local/share/codex-bootstrap/trusted/Sileo.app"

xcrun --sdk iphoneos clang \
    -arch arm64 \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -fobjc-arc \
    -Wall -Wextra -Werror \
    -framework Foundation \
    -framework IOKit \
    -lsandbox \
    "$SCRIPT_DIR/codex_dopamine_bootstrap.m" \
    -o "$IMAGE_ROOT/usr/local/bin/codex-dopamine-bootstrap"
ldid -S"$SCRIPT_DIR/installer-entitlements.plist" -Cadhoc \
    "$IMAGE_ROOT/usr/local/bin/codex-dopamine-bootstrap"
cp "$SCRIPT_DIR/com.openai.codex.dopamine.bootstrap.plist" \
    "$IMAGE_ROOT/Library/LaunchDaemons/"

# [REDACTED] Packaging, payload selection, and validation details omitted.
printf '%s\n' 'TSS/Cryptex personalization and installation details are redacted from this educational source release.' >&2
exit 1
