#!/bin/zsh

set -euo pipefail

SCRIPT_DIR=${0:A:h}
REPO_DIR=${SCRIPT_DIR:h}
CRYPTEXCTL=/System/Library/SecurityResearch/usr/bin/cryptexctl.research
BOOTSTRAP_URL=https://apt.procurs.us/bootstraps/1900/bootstrap-iphoneos-arm64.tar.zst
BOOTSTRAP_SHA256=8354c3aa1ecdad8ebc47d9a76dfca6f830a2b757278068bd33b98bf1d638a9cb
SILEO_SHA256=8e3c90e5a7d32f4ca207a0ac30d3cfa8a13dca86a2b4e11cb3f9e5c68d7bc97a
ELLEKIT_URL=https://ellekit.space/pool/ellekit_1.2_iphoneos-arm64.deb
ELLEKIT_SHA256=e21dc91bdc1be193dc915daecfff45256239b4fe583a36861e662ab1f43906dc
PREFERENCELOADER_URL=http://apt.thebigboss.org/repofiles/cydia/debs2.0-rootless/preferenceloader_2.2.8_iphoneos-arm64.deb
PREFERENCELOADER_SHA256=b8b934b4c1d2da649044997f01b7bf995afbdb732e653b2b35368deb354e1882
CHOICY_URL=http://apt.thebigboss.org/repofiles/cydia/debs2.0-rootless/choicy_1.5.4-2_iphoneos-arm64.deb
CHOICY_SHA256=de7a5cdcbd35fa99d97a20650ff6415da43ef3dd359c68ed6ed3e7f1b54dc1bb
ALTLIST_URL=http://apt.thebigboss.org/repofiles/cydia/debs2.0-rootless/altlist_1.0.11_iphoneos-arm64.deb
ALTLIST_SHA256=26718f617288f93b91f961d8a363d04c11d295f0de76acda4f5df057a5189975
ELLEKIT_KEY_FINGERPRINT=71C9AF96CD2F3A8A837EFFBB015D4A9B1D4A2370
BIGBOSS_KEY_FINGERPRINT=A9C96A37115894A23B894107694D17D38764B4F4
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
ELLEKIT_DEB="$CACHE_DIR/ellekit_1.2_iphoneos-arm64.deb"
PREFERENCELOADER_DEB="$CACHE_DIR/preferenceloader_2.2.8_iphoneos-arm64.deb"
CHOICY_DEB="$CACHE_DIR/choicy_1.5.4-2_iphoneos-arm64.deb"
ALTLIST_DEB="$CACHE_DIR/altlist_1.0.11_iphoneos-arm64.deb"
DEFAULT_SOURCES="$SCRIPT_DIR/dopamine-default.sources"
REPOSITORY_COMPAT_CONFIG="$SCRIPT_DIR/dopamine-repository-compat.conf"
ELLEKIT_KEY="$SCRIPT_DIR/keyrings/ellekit.asc"
BIGBOSS_KEY="$SCRIPT_DIR/keyrings/bigboss.asc"
OPAINJECT_DIR="$REPO_DIR/BaseBin/opainject"
IMAGE_ROOT="$WORK_DIR/image-root"
EMBEDDED_DEFAULT_SOURCES="$IMAGE_ROOT/usr/local/share/codex-bootstrap/dopamine-default.sources"
EMBEDDED_APT_CONFIG_DIR="$IMAGE_ROOT/usr/local/share/codex-bootstrap/apt"
EMBEDDED_REPOSITORY_COMPAT_CONFIG="$EMBEDDED_APT_CONFIG_DIR/99dopamine-repository-compat"
EMBEDDED_KEYRING_DIR="$IMAGE_ROOT/usr/local/share/codex-bootstrap/keyrings"
EMBEDDED_ELLEKIT_KEY="$EMBEDDED_KEYRING_DIR/ellekit.gpg"
EMBEDDED_BIGBOSS_KEY="$EMBEDDED_KEYRING_DIR/bigboss.gpg"
ORIGINAL_TRUSTED_PACKAGE_ROOT="$WORK_DIR/trusted-packages-original"
TRUSTED_PACKAGE_ROOT="$WORK_DIR/trusted-packages-normalized"
EMBEDDED_ORIGINAL_TRUSTED_PACKAGES="$IMAGE_ROOT/usr/local/share/codex-bootstrap/trusted-packages-original"
EMBEDDED_TRUSTED_PACKAGES="$IMAGE_ROOT/usr/local/share/codex-bootstrap/trusted-packages"
TRUSTED_PACKAGE_CDHASHES="$WORK_DIR/trusted-package-cdhashes.txt"
TRUSTED_RUNTIME_CDHASHES="$WORK_DIR/trusted-runtime-cdhashes.txt"
ELLEKIT_COMPAT_LOADER="$IMAGE_ROOT/usr/local/bin/codex-ellekit-loader"
LAUNCHD_INJECTION_CANARY="$IMAGE_ROOT/usr/local/lib/codex-launchd-injection-canary.dylib"
PATCHED_OPAINJECT_DIR="$WORK_DIR/opainject-ios27"
PATCHED_OPAINJECT_DYLD="$PATCHED_OPAINJECT_DIR/dyld.m"
PATCHED_OPAINJECT_ROP="$PATCHED_OPAINJECT_DIR/rop_inject.m"
PATCHED_OPAINJECT_THREAD_UTILS="$PATCHED_OPAINJECT_DIR/thread_utils.m"
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

fetch_pinned() {
    local url=$1
    local expected=$2
    local destination=$3
    if [[ ! -f "$destination" ]]; then
        local partial="$destination.partial.$$"
        curl --fail --location --retry 3 --silent --show-error \
            --output "$partial" "$url"
        [[ "$(sha256_of "$partial")" == "$expected" ]] || \
            die "download hash mismatch: ${destination:t}"
        mv "$partial" "$destination"
    fi
    [[ "$(sha256_of "$destination")" == "$expected" ]] || \
        die "cached hash mismatch: ${destination:t}"
}

verify_deb_identity() {
    local archive=$1
    local expected_package=$2
    local expected_version=$3
    local package
    local version
    local architecture
    package=$(dpkg-deb -f "$archive" Package)
    version=$(dpkg-deb -f "$archive" Version)
    architecture=$(dpkg-deb -f "$archive" Architecture)
    [[ "$package" == "$expected_package" ]] || \
        die "unexpected package in ${archive:t}: $package"
    [[ "$version" == "$expected_version" ]] || \
        die "unexpected version in ${archive:t}: $version"
    [[ "$architecture" == iphoneos-arm64 ]] || \
        die "unexpected architecture in ${archive:t}: $architecture"
}

verify_keyring() {
    local keyring=$1
    local expected=$2
    local fingerprint
    fingerprint=$(gpg --batch --show-keys --with-colons --fingerprint \
        "$keyring" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }')
    [[ "$fingerprint" == "$expected" ]] || \
        die "unexpected primary fingerprint in ${keyring:t}: $fingerprint"
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

for tool in awk codesign curl dpkg-deb file find gpg ldid lipo nm plutil python3 rg security shasum tar xcrun zstd; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done
[[ -x "$CRYPTEXCTL" ]] || die "missing SRD cryptexctl: $CRYPTEXCTL"
[[ -f "$SILEO_DEB" ]] || die "missing opa334 Sileo package: $SILEO_DEB"
[[ -f "$DEFAULT_SOURCES" ]] || die "missing Dopamine default APT sources"
[[ -f "$REPOSITORY_COMPAT_CONFIG" ]] || \
    die "missing Dopamine repository compatibility configuration"
[[ -f "$ELLEKIT_KEY" ]] || die "missing ElleKit repository keyring"
[[ -f "$BIGBOSS_KEY" ]] || die "missing BigBoss repository keyring"
verify_keyring "$ELLEKIT_KEY" "$ELLEKIT_KEY_FINGERPRINT"
verify_keyring "$BIGBOSS_KEY" "$BIGBOSS_KEY_FINGERPRINT"
[[ -f "$SCRIPT_DIR/patch_sileo_postinst.py" ]] || \
    die "missing Sileo maintainer-script compatibility patch"
for source in dyld.m rop_inject.m thread_utils.m task_utils.m arm64.m; do
    [[ -f "$OPAINJECT_DIR/$source" ]] || \
        die "missing pinned opa334/opainject source: $source"
done

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
fetch_pinned "$BOOTSTRAP_URL" "$BOOTSTRAP_SHA256" "$BOOTSTRAP_ARCHIVE"
fetch_pinned "$ELLEKIT_URL" "$ELLEKIT_SHA256" "$ELLEKIT_DEB"
fetch_pinned "$PREFERENCELOADER_URL" "$PREFERENCELOADER_SHA256" \
    "$PREFERENCELOADER_DEB"
fetch_pinned "$CHOICY_URL" "$CHOICY_SHA256" "$CHOICY_DEB"
fetch_pinned "$ALTLIST_URL" "$ALTLIST_SHA256" "$ALTLIST_DEB"
verify_deb_identity "$ELLEKIT_DEB" ellekit 1.2
verify_deb_identity "$PREFERENCELOADER_DEB" preferenceloader 2.2.8
verify_deb_identity "$CHOICY_DEB" com.opa334.choicy 1.5.4-2
verify_deb_identity "$ALTLIST_DEB" com.opa334.altlist 1.0.11
[[ "$(sha256_of "$SILEO_DEB")" == "$SILEO_SHA256" ]] || \
    die "opa334 Sileo package hash mismatch"
zstd -t "$BOOTSTRAP_ARCHIVE" >/dev/null

rm -rf "$IMAGE_ROOT" "$PACKAGE_ROOT" "$ORIGINAL_TRUSTED_PACKAGE_ROOT" \
    "$TRUSTED_PACKAGE_ROOT" \
    "$UNSIGNED_OUT" "$REPACKED_SILEO" "$TRUSTED_PACKAGE_CDHASHES" \
    "$TRUSTED_RUNTIME_CDHASHES"
mkdir -p \
    "$IMAGE_ROOT/Library/LaunchDaemons" \
    "$IMAGE_ROOT/usr/local/bin" \
    "$IMAGE_ROOT/usr/local/lib" \
    "$IMAGE_ROOT/usr/local/share/codex-bootstrap" \
    "$EMBEDDED_APT_CONFIG_DIR" \
    "$EMBEDDED_KEYRING_DIR" \
    "$PACKAGE_ROOT" \
    "$ORIGINAL_TRUSTED_PACKAGE_ROOT" \
    "$TRUSTED_PACKAGE_ROOT" \
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
python3 "$SCRIPT_DIR/patch_sileo_postinst.py" \
    "$PACKAGE_ROOT/DEBIAN/postinst"
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

# A Cryptex trust cache is immutable after personalization. Embed exact copies
# of the default tweak stack's package payloads so their later /var/jb copies
# carry code directories already represented by this Cryptex.
dpkg-deb -x "$ELLEKIT_DEB" "$ORIGINAL_TRUSTED_PACKAGE_ROOT/ellekit"
dpkg-deb -x "$PREFERENCELOADER_DEB" \
    "$ORIGINAL_TRUSTED_PACKAGE_ROOT/preferenceloader"
dpkg-deb -x "$CHOICY_DEB" "$ORIGINAL_TRUSTED_PACKAGE_ROOT/choicy"
dpkg-deb -x "$ALTLIST_DEB" "$ORIGINAL_TRUSTED_PACKAGE_ROOT/altlist"
ditto --noqtn "$ORIGINAL_TRUSTED_PACKAGE_ROOT" "$TRUSTED_PACKAGE_ROOT"

# These jailbreak packages use legacy signatures that iOS 27 rejects even
# when the old cdhash is present in a Cryptex trust cache. Re-sign exact copies
# with a current ad-hoc CodeDirectory, retaining any declared entitlements.
for candidate in "$TRUSTED_PACKAGE_ROOT"/**/*(.); do
    file -b "$candidate" | rg -q '^Mach-O' || continue
    architectures=($(lipo -archs "$candidate"))
    (( ${#architectures} > 0 )) || die "Mach-O has no architectures: $candidate"
    identifier=$(codesign -d --arch "${architectures[1]}" -vvv "$candidate" \
        2>&1 | sed -n 's/^Identifier=//p')
    [[ -n "$identifier" ]] || die "Mach-O has no code identifier: $candidate"
    entitlements="$SIGNING_DIR/trusted-package-entitlements.plist"
    ldid -arch "${architectures[1]}" -e "$candidate" >"$entitlements"
    signing_args=(
        --force
        --sign -
        --timestamp=none
        --pagesize 4096
        --identifier "$identifier"
    )
    if [[ -s "$entitlements" ]]; then
        plutil -lint "$entitlements" >/dev/null || \
            die "invalid package entitlements: $candidate"
        signing_args+=(--entitlements "$entitlements")
    fi
    codesign "${signing_args[@]}" "$candidate"
    codesign --verify --strict --all-architectures "$candidate" || \
        die "normalized package signature is invalid: $candidate"
done
rm -f "$SIGNING_DIR/trusted-package-entitlements.plist"

ditto --noqtn "$ORIGINAL_TRUSTED_PACKAGE_ROOT" \
    "$EMBEDDED_ORIGINAL_TRUSTED_PACKAGES"
ditto --noqtn "$TRUSTED_PACKAGE_ROOT" "$EMBEDDED_TRUSTED_PACKAGES"

python3 "$SCRIPT_DIR/patch_opainject_dyld.py" \
    "$OPAINJECT_DIR/dyld.m" "$PATCHED_OPAINJECT_DYLD"
python3 "$SCRIPT_DIR/patch_opainject_runtime.py" \
    "$OPAINJECT_DIR/thread_utils.m" \
    "$OPAINJECT_DIR/rop_inject.m" \
    "$PATCHED_OPAINJECT_DIR"

# ElleKit's legacy loader writes an anonymous launchd page and then requests
# executable protection. iOS 27 enforces W^X on that transition. Build the
# pinned Dopamine opainject ROP lane so launchd can call its existing dlopen
# implementation without creating writable-and-executable code.
xcrun --sdk iphoneos clang \
    -arch arm64 \
    -arch arm64e \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -fobjc-arc \
    -fblocks \
    -include stdint.h \
    -I "$OPAINJECT_DIR" \
    -framework Foundation \
    -framework CoreFoundation \
    -lsandbox \
    "$SCRIPT_DIR/ellekit_compat_loader.m" \
    "$PATCHED_OPAINJECT_DYLD" \
    "$PATCHED_OPAINJECT_ROP" \
    "$PATCHED_OPAINJECT_THREAD_UTILS" \
    "$OPAINJECT_DIR/task_utils.m" \
    "$OPAINJECT_DIR/arm64.m" \
    -o "$ELLEKIT_COMPAT_LOADER"
codesign --force --sign - --timestamp=none --pagesize 4096 \
    --entitlements "$SCRIPT_DIR/ellekit-compat-loader-entitlements.plist" \
    "$ELLEKIT_COMPAT_LOADER"
codesign --verify --strict --all-architectures "$ELLEKIT_COMPAT_LOADER" || \
    die "ElleKit compatibility loader signature is invalid"

xcrun --sdk iphoneos clang \
    -arch arm64 \
    -arch arm64e \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -dynamiclib \
    "$SCRIPT_DIR/launchd_injection_canary.c" \
    -o "$LAUNCHD_INJECTION_CANARY"
codesign --force --sign - --timestamp=none --pagesize 4096 \
    "$LAUNCHD_INJECTION_CANARY"
codesign --verify --strict --all-architectures \
    "$LAUNCHD_INJECTION_CANARY" || \
    die "launchd injection canary signature is invalid"

typeset -a trusted_runtime_cdhashes
for candidate in \
    "$ELLEKIT_COMPAT_LOADER" \
    "$LAUNCHD_INJECTION_CANARY"; do
    for architecture in $(lipo -archs "$candidate"); do
        cdhash=$(codesign -d --arch "$architecture" -vvvv "$candidate" \
            2>&1 | sed -n 's/^CDHash=//p')
        print -r -- "$cdhash" | rg -q '^[0-9a-f]{40}$' || \
            die "could not derive $architecture cdhash for $candidate"
        trusted_runtime_cdhashes+=("$cdhash")
    done
done
printf '%s\n' "${trusted_runtime_cdhashes[@]}" | sort -u \
    >"$TRUSTED_RUNTIME_CDHASHES"

typeset -a trusted_cdhashes
for candidate in "$TRUSTED_PACKAGE_ROOT"/**/*(.); do
    file -b "$candidate" | rg -q '^Mach-O' || continue
    for architecture in $(lipo -archs "$candidate"); do
        cdhash=$(codesign -d --arch "$architecture" -vvvv "$candidate" \
            2>&1 | sed -n 's/^CDHash=//p')
        print -r -- "$cdhash" | rg -q '^[0-9a-f]{40}$' || \
            die "could not derive $architecture cdhash for $candidate"
        trusted_cdhashes+=("$cdhash")
    done
done
(( ${#trusted_cdhashes} > 0 )) || die "trusted package set has no Mach-O inputs"
printf '%s\n' "${trusted_cdhashes[@]}" | sort -u \
    >"$TRUSTED_PACKAGE_CDHASHES"

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
cp "$DEFAULT_SOURCES" \
    "$EMBEDDED_DEFAULT_SOURCES"
cp "$REPOSITORY_COMPAT_CONFIG" \
    "$EMBEDDED_REPOSITORY_COMPAT_CONFIG"
chmod 0644 "$EMBEDDED_DEFAULT_SOURCES" \
    "$EMBEDDED_REPOSITORY_COMPAT_CONFIG"
gpg --batch --yes --dearmor --output "$EMBEDDED_ELLEKIT_KEY" "$ELLEKIT_KEY"
gpg --batch --yes --dearmor --output "$EMBEDDED_BIGBOSS_KEY" "$BIGBOSS_KEY"
chmod 0644 "$EMBEDDED_ELLEKIT_KEY" "$EMBEDDED_BIGBOSS_KEY"
verify_keyring "$EMBEDDED_ELLEKIT_KEY" "$ELLEKIT_KEY_FINGERPRINT"
verify_keyring "$EMBEDDED_BIGBOSS_KEY" "$BIGBOSS_KEY_FINGERPRINT"

# [REDACTED] Packaging, payload selection, and validation details omitted.
printf '%s\n' 'TSS/Cryptex personalization and installation details are redacted from this educational source release.' >&2
exit 1
