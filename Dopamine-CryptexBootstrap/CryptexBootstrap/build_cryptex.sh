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
PREFERENCELOADER_URL=https://github.com/Yves000/preferenceloader/releases/download/2.3.3/preferenceloader_2.3.3_iphoneos-arm64.deb
PREFERENCELOADER_SHA256=eaacb5204e13dee166cc44763566bbbd565fbf3cf1ecc25b1a2f432b6bee6f86
ELLEKIT_KEY_FINGERPRINT=71C9AF96CD2F3A8A837EFFBB015D4A9B1D4A2370
BIGBOSS_KEY_FINGERPRINT=A9C96A37115894A23B894107694D17D38764B4F4
IDENTIFIER=com.openai.codex.dopamine.bootstrap
VERSION=${CODEX_CRYPTEX_VERSION:-1.0.$(date -u +%Y%m%d%H%M%S)}
SILEO_BUNDLE_IDENTIFIER=org.coolstar.SileoStore
SILEO_UPSTREAM_PACKAGE_VERSION=2.5.1
SILEO_PACKAGE_VERSION=2.5.1+codex1
FORCE_CLEAN_INSTALL=${CODEX_FORCE_CLEAN_INSTALL:-0}
MAX_CRYPTEX_IMAGE_BYTES=$((128 * 1024 * 1024))
MAX_PREFERENCES_BRIDGE_BYTES=$((1024 * 1024))

CACHE_DIR="$SCRIPT_DIR/cache"
GPG_HOME="$CACHE_DIR/gnupg"
WORK_DIR="$SCRIPT_DIR/work"
OUT_DIR="$SCRIPT_DIR/out"
BOOTSTRAP_ARCHIVE="$CACHE_DIR/bootstrap_1900.tar.zst"
ELLEKIT_DEB="$CACHE_DIR/ellekit_1.2_iphoneos-arm64.deb"
PREFERENCELOADER_DEB="$CACHE_DIR/preferenceloader_2.3.3_iphoneos-arm64.deb"
SILEO_DEB="$REPO_DIR/Application/Dopamine/Resources/sileo.deb"
DEFAULT_SOURCES="$SCRIPT_DIR/dopamine-default.sources"
REPOSITORY_COMPAT_CONFIG="$SCRIPT_DIR/dopamine-repository-compat.conf"
SBINJECT_APT_CONFIG="$SCRIPT_DIR/sbinject-package.conf"
PREFERENCELOADER_PIN="$SCRIPT_DIR/preferenceloader.pref"
SILEO_PIN="$SCRIPT_DIR/sileo.pref"
APT_LIST_NORMALIZER="$SCRIPT_DIR/normalize_apt_lists.sh"
ELLEKIT_KEY="$SCRIPT_DIR/keyrings/ellekit.asc"
BIGBOSS_KEY="$SCRIPT_DIR/keyrings/bigboss.asc"
OPAINJECT_DIR="$REPO_DIR/BaseBin/opainject"
IMAGE_ROOT="$WORK_DIR/image-root"
EMBEDDED_DEFAULT_SOURCES="$IMAGE_ROOT/usr/local/share/codex-bootstrap/dopamine-default.sources"
EMBEDDED_APT_CONFIG_DIR="$IMAGE_ROOT/usr/local/share/codex-bootstrap/apt"
EMBEDDED_REPOSITORY_COMPAT_CONFIG="$EMBEDDED_APT_CONFIG_DIR/99dopamine-repository-compat"
EMBEDDED_SBINJECT_APT_CONFIG="$EMBEDDED_APT_CONFIG_DIR/98sbinject-packages"
EMBEDDED_PREFERENCELOADER_PIN="$EMBEDDED_APT_CONFIG_DIR/99preferenceloader"
EMBEDDED_SILEO_PIN="$EMBEDDED_APT_CONFIG_DIR/99codex-system-sileo"
EMBEDDED_APT_LIST_NORMALIZER="$IMAGE_ROOT/usr/local/share/codex-bootstrap/normalize-apt-lists.sh"
EMBEDDED_CLEAN_INSTALL_TOKEN="$IMAGE_ROOT/usr/local/share/codex-bootstrap/clean-install-token.txt"
EMBEDDED_KEYRING_DIR="$IMAGE_ROOT/usr/local/share/codex-bootstrap/keyrings"
EMBEDDED_ELLEKIT_KEY="$EMBEDDED_KEYRING_DIR/ellekit.gpg"
EMBEDDED_BIGBOSS_KEY="$EMBEDDED_KEYRING_DIR/bigboss.gpg"
EMBEDDED_ELLEKIT_DEB="$IMAGE_ROOT/usr/local/share/codex-bootstrap/ellekit.deb"
EMBEDDED_PREFERENCELOADER_DEB="$IMAGE_ROOT/usr/local/share/codex-bootstrap/preferenceloader.deb"
TRUSTED_ELLEKIT_ROOT="$IMAGE_ROOT/usr/local/share/codex-bootstrap/trusted/ellekit-root"
SYSTEM_SILEO_APP="$IMAGE_ROOT/Applications/Sileo.app"
SILEO_SYSTEM_ENTITLEMENTS="$WORK_DIR/sileo-system-entitlements.plist"
SILEO_ASSET_INFO="$WORK_DIR/sileo-asset-info.json"
SILEO_NORMALIZED_ICON="$WORK_DIR/AppIcon60x60@2x.png"
TRUSTED_RUNTIME_CDHASHES="$WORK_DIR/trusted-runtime-cdhashes.txt"
ELLEKIT_COMPAT_LOADER="$IMAGE_ROOT/usr/local/bin/codex-ellekit-loader"
EXEC_WORKER="$IMAGE_ROOT/usr/local/bin/codex-exec-worker"
CUSTOMD_BUILDER="$SCRIPT_DIR/../../Scripts/build_customd.sh"
CUSTOMD_TRACE_REEXEC_BUILDER="$SCRIPT_DIR/../../Scripts/build_customd_trace_me_reexec_probe.sh"
CUSTOMD_SETEXEC_BUILDER="$SCRIPT_DIR/../../Scripts/build_customd_springboard_setexec.sh"
CUSTOMD_BUILD_DIRECTORY="$WORK_DIR/customd-build"
CUSTOMD_BUILD_EXECUTABLE="$CUSTOMD_BUILD_DIRECTORY/customd"
CUSTOMCTL_BUILD_EXECUTABLE="$CUSTOMD_BUILD_DIRECTORY/customctl"
CUSTOMD_REGISTRAR_BUILD_EXECUTABLE="$CUSTOMD_BUILD_DIRECTORY/customd-candidate-registrar"
CUSTOMD_TRACE_REEXEC_BUILD_EXECUTABLE="$CUSTOMD_BUILD_DIRECTORY/customd-trace-me-reexec-probe"
CUSTOMD_SETEXEC_BUILD_EXECUTABLE="$CUSTOMD_BUILD_DIRECTORY/customd-springboard-setexec"
CUSTOMD_EXECUTABLE="$IMAGE_ROOT/usr/local/bin/customd"
CUSTOMCTL_EXECUTABLE="$IMAGE_ROOT/usr/local/bin/customctl"
CUSTOMD_REGISTRAR_EXECUTABLE="$IMAGE_ROOT/usr/local/bin/customd-candidate-registrar"
CUSTOMD_TRACE_REEXEC_EXECUTABLE="$IMAGE_ROOT/usr/local/bin/customd-trace-me-reexec-probe"
CUSTOMD_SETEXEC_EXECUTABLE="$IMAGE_ROOT/usr/local/bin/customd-springboard-setexec"
CUSTOMD_JOB_PLIST_SOURCE="$SCRIPT_DIR/../../Sources/com.openai.customd.plist"
EMBEDDED_CUSTOMD_JOB_PLIST="$IMAGE_ROOT/usr/local/share/codex-bootstrap/com.openai.customd.plist"
ELLEKIT_COMPAT_ENTITLEMENTS="$SCRIPT_DIR/ellekit-compat-loader-entitlements.plist"
EXEC_WORKER_ENTITLEMENTS="$SCRIPT_DIR/exec-worker-entitlements.plist"
SBINJECT_PACKAGE_VALIDATOR="$IMAGE_ROOT/usr/local/bin/sbinject-package-validator"
SBINJECT_SOURCE_DIR="$SCRIPT_DIR/SBInject"
SBINJECT_GENERALHOOK="$IMAGE_ROOT/usr/local/lib/sbinject/generalhook.dylib"
SBINJECT_LAUNCHDHOOK="$IMAGE_ROOT/usr/local/lib/sbinject/launchdhook-v3.dylib"
SBINJECT_LSD_REGISTRATION_HOOK="$IMAGE_ROOT/usr/local/lib/sbinject/lsd-registration-hook.dylib"
SBINJECT_PREFERENCES_BRIDGE="$IMAGE_ROOT/usr/local/lib/sbinject/preferences-bridge.dylib"
PREFERENCES_BRIDGE_SUPPORT_DIR="$SBINJECT_SOURCE_DIR/PreferenceBridgeSupport"
PREFERENCES_BRIDGE_BUILD_DIRECTORY="$WORK_DIR/preferences-bridge-build"
SBINJECT_JITTERD="$IMAGE_ROOT/usr/local/bin/sbinject-jitterd"
SBINJECT_JITTERD_ENTITLEMENTS="$SBINJECT_SOURCE_DIR/jitterd-entitlements.plist"
SBINJECT_JITTERD_PLIST_SOURCE="$SBINJECT_SOURCE_DIR/com.openai.codex.sbinject.jitterd.plist"
EMBEDDED_SBINJECT_ROOT="$IMAGE_ROOT/usr/local/share/codex-bootstrap/sbinject"
EMBEDDED_SBINJECT_JITTERD_PLIST="$EMBEDDED_SBINJECT_ROOT/com.openai.codex.sbinject.jitterd.plist"
SPRINGBOARD_CANDIDATE_BUILDER="$SCRIPT_DIR/../../Scripts/build_springboard_candidate.py"
SPRINGBOARD_CANDIDATE_SOURCE=${CODEX_SPRINGBOARD_CANDIDATE_SOURCE:-"$SCRIPT_DIR/../../build/iphone13-24A435/SpringBoard.app/SpringBoard"}
SPRINGBOARD_CANDIDATE_INFO_SOURCE=${CODEX_SPRINGBOARD_CANDIDATE_INFO_SOURCE:-"$SCRIPT_DIR/../../build/iphone13-24A435/SpringBoard.app/Info.plist"}
SPRINGBOARD_CANDIDATE_BUNDLE_SOURCE=${CODEX_SPRINGBOARD_CANDIDATE_BUNDLE_SOURCE:-${SPRINGBOARD_CANDIDATE_SOURCE:h}}
SPRINGBOARD_CANDIDATE_DIRECTORY="$EMBEDDED_SBINJECT_ROOT/SpringBoard.app"
SPRINGBOARD_CANDIDATE="$SPRINGBOARD_CANDIDATE_DIRECTORY/notSpringBoard"
SPRINGBOARD_CANDIDATE_INFO="$SPRINGBOARD_CANDIDATE_DIRECTORY/Info.plist"
SPRINGBOARD_CANDIDATE_ENTITLEMENTS="$SPRINGBOARD_CANDIDATE_DIRECTORY/entitlements.plist"
SPRINGBOARD_CANDIDATE_MANIFEST="$SPRINGBOARD_CANDIDATE_DIRECTORY/build-manifest.json"
SPRINGBOARD_CANDIDATE_GENERALHOOK="$SPRINGBOARD_CANDIDATE_DIRECTORY/g"
PREFERENCES_CANDIDATE_SOURCE=${CODEX_PREFERENCES_CANDIDATE_SOURCE:-"$SCRIPT_DIR/../../build/iphone13-24A435/Preferences.app/Preferences"}
PREFERENCES_CANDIDATE_INFO_SOURCE=${CODEX_PREFERENCES_CANDIDATE_INFO_SOURCE:-"$SCRIPT_DIR/../../build/iphone13-24A435/Preferences.app/Info.plist"}
PREFERENCES_CANDIDATE_BUNDLE_SOURCE=${CODEX_PREFERENCES_CANDIDATE_BUNDLE_SOURCE:-${PREFERENCES_CANDIDATE_SOURCE:h}}
PREFERENCES_CANDIDATE_DIRECTORY="$EMBEDDED_SBINJECT_ROOT/Preferences.app"
PREFERENCES_CANDIDATE="$PREFERENCES_CANDIDATE_DIRECTORY/notPreferences"
PREFERENCES_CANDIDATE_INFO="$PREFERENCES_CANDIDATE_DIRECTORY/Info.plist"
PREFERENCES_CANDIDATE_ENTITLEMENTS="$PREFERENCES_CANDIDATE_DIRECTORY/entitlements.plist"
PREFERENCES_CANDIDATE_MANIFEST="$PREFERENCES_CANDIDATE_DIRECTORY/build-manifest.json"
PREFERENCES_CANDIDATE_GENERALHOOK="$PREFERENCES_CANDIDATE_DIRECTORY/g"
PATCHED_OPAINJECT_DIR="$WORK_DIR/opainject-ios27"
PATCHED_OPAINJECT_DYLD="$PATCHED_OPAINJECT_DIR/dyld.m"
PATCHED_OPAINJECT_ROP="$PATCHED_OPAINJECT_DIR/rop_inject.m"
PATCHED_OPAINJECT_THREAD_UTILS="$PATCHED_OPAINJECT_DIR/thread_utils.m"
PACKAGE_ROOT="$WORK_DIR/sileo-package"
REPACKED_SILEO="$WORK_DIR/sileo.launchable.deb"
ELLEKIT_PACKAGE_ROOT="$WORK_DIR/ellekit-package"
REPACKED_ELLEKIT="$WORK_DIR/ellekit.cryptex-signed.deb"
UNSIGNED_OUT="$OUT_DIR/unsigned"
SUMMARY="$OUT_DIR/build-summary.json"

die() {
    print -u2 -- "error: $*"
    exit 1
}

[[ "$FORCE_CLEAN_INSTALL" == 0 || "$FORCE_CLEAN_INSTALL" == 1 ]] || \
    die "CODEX_FORCE_CLEAN_INSTALL must be 0 or 1"

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

verify_keyring() {
    local keyring=$1
    local expected=$2
    local fingerprint
    fingerprint=$(gpg --batch --show-keys --with-colons --fingerprint \
        "$keyring" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }')
    [[ "$fingerprint" == "$expected" ]] || \
        die "unexpected primary fingerprint in ${keyring:t}: $fingerprint"
}

require_true_entitlement() {
    local plist=$1
    local key_path=$2
    local display_name=$3
    local value
    value=$(plutil -extract "$key_path" raw -o - "$plist" 2>/dev/null) || \
        die "missing required entitlement $display_name in ${plist:t}"
    [[ "$value" == true ]] || \
        die "required entitlement $display_name is not true in ${plist:t}"
}

for tool in awk codesign curl dpkg-deb dwarfdump file find gpg ldid lipo nm plutil python3 rg shasum sips stat tar xcrun zstd; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done
for plist in "$ELLEKIT_COMPAT_ENTITLEMENTS" "$EXEC_WORKER_ENTITLEMENTS"; do
    [[ -f "$plist" ]] || die "missing runtime entitlement file: $plist"
    plutil -lint "$plist" >/dev/null || \
        die "invalid runtime entitlement file: $plist"
done
require_true_entitlement "$ELLEKIT_COMPAT_ENTITLEMENTS" \
    'com\.apple\.private\.cs\.debugger' \
    'com.apple.private.cs.debugger'
require_true_entitlement "$EXEC_WORKER_ENTITLEMENTS" \
    'com\.apple\.private\.cs\.debugger' \
    'com.apple.private.cs.debugger'
require_true_entitlement "$EXEC_WORKER_ENTITLEMENTS" 'get-task-allow' \
    'get-task-allow'
[[ -x "$CRYPTEXCTL" ]] || die "missing SRD cryptexctl: $CRYPTEXCTL"
[[ -f "$SILEO_DEB" ]] || die "missing opa334 Sileo package: $SILEO_DEB"
[[ -f "$DEFAULT_SOURCES" ]] || die "missing Dopamine default APT sources"
[[ -f "$REPOSITORY_COMPAT_CONFIG" ]] || \
    die "missing Dopamine repository compatibility configuration"
[[ -f "$SBINJECT_APT_CONFIG" ]] || \
    die "missing SBInject APT package configuration"
[[ -f "$APT_LIST_NORMALIZER" ]] || \
    die "missing APT package-list normalizer"
[[ -f "$SPRINGBOARD_CANDIDATE_BUILDER" ]] || \
    die "missing SpringBoard candidate builder"
[[ -f "$SPRINGBOARD_CANDIDATE_SOURCE" ]] || \
    die "missing pinned iPhone 13 SpringBoard source"
[[ -f "$SPRINGBOARD_CANDIDATE_INFO_SOURCE" ]] || \
    die "missing pinned iPhone 13 SpringBoard Info.plist source"
[[ -d "$SPRINGBOARD_CANDIDATE_BUNDLE_SOURCE" ]] || \
    die "missing pinned iPhone 13 SpringBoard.app source"
[[ -f "$PREFERENCES_CANDIDATE_SOURCE" ]] || \
    die "missing pinned iPhone 13 Preferences source"
[[ -f "$PREFERENCES_CANDIDATE_INFO_SOURCE" ]] || \
    die "missing pinned iPhone 13 Preferences Info.plist source"
[[ -d "$PREFERENCES_CANDIDATE_BUNDLE_SOURCE" ]] || \
    die "missing pinned iPhone 13 Preferences.app source"
[[ -x "$CUSTOMD_BUILDER" ]] || die "missing customd builder"
[[ -x "$CUSTOMD_TRACE_REEXEC_BUILDER" ]] || \
    die "missing customd trace/re-exec builder"
[[ -x "$CUSTOMD_SETEXEC_BUILDER" ]] || \
    die "missing customd SpringBoard SETEXEC builder"
[[ -f "$CUSTOMD_JOB_PLIST_SOURCE" ]] || die "missing customd job plist"
sh -n "$CUSTOMD_BUILDER"
sh -n "$CUSTOMD_TRACE_REEXEC_BUILDER"
zsh -n "$CUSTOMD_SETEXEC_BUILDER"
plutil -lint "$CUSTOMD_JOB_PLIST_SOURCE" >/dev/null || \
    die "invalid customd job plist"
sh -n "$APT_LIST_NORMALIZER"
[[ -f "$ELLEKIT_KEY" ]] || die "missing ElleKit repository keyring"
[[ -f "$BIGBOSS_KEY" ]] || die "missing BigBoss repository keyring"
mkdir -p "$GPG_HOME"
chmod 0700 "$GPG_HOME"
export GNUPGHOME="$GPG_HOME"
verify_keyring "$ELLEKIT_KEY" "$ELLEKIT_KEY_FINGERPRINT"
verify_keyring "$BIGBOSS_KEY" "$BIGBOSS_KEY_FINGERPRINT"
[[ -f "$SCRIPT_DIR/patch_sileo_postinst.py" ]] || \
    die "missing Sileo maintainer-script compatibility patch"
[[ -f "$SCRIPT_DIR/patch_load_dylib.py" ]] || \
    die "missing deterministic Mach-O load-command patcher"
[[ -f "$SCRIPT_DIR/sileo_broker_constructor.c" ]] || \
    die "missing Sileo root-broker constructor"
[[ -f "$SCRIPT_DIR/sileo_zstd_reexport.c" ]] || \
    die "missing Sileo zstd re-export source"
[[ -f "$SCRIPT_DIR/sbinject_package_validator.c" ]] || \
    die "missing SBInject package validator source"
[[ -f "$PREFERENCELOADER_PIN" ]] || \
    die "missing PreferenceLoader version pin"
[[ -f "$SILEO_PIN" ]] || die "missing fixed system Sileo version pin"
for source in \
    sbinject_protocol.h \
    litehook_rebind.h litehook_rebind.c \
    sbinject_launchdhook.c \
    sbinject_lsd_registration_hook.m \
    sbinject_dyld_bypass.h sbinject_dyld_bypass.c \
    sbinject_generalhook.c sbinject_jitterd.m \
    sbinject_preferences_bridge.m sbinject_preferences_bridge.swift; do
    [[ -f "$SBINJECT_SOURCE_DIR/$source" ]] || \
        die "missing supplied SBInject integration source: $source"
done
for source in PLHeap.h PLHeap.m PLSwiftMeta.h PLSwiftMeta.m \
              PLSwiftString.swift LICENSE UPSTREAM.md; do
    [[ -f "$PREFERENCES_BRIDGE_SUPPORT_DIR/$source" ]] || \
        die "missing pinned PreferenceLoader bridge support: $source"
done
for plist in "$SBINJECT_JITTERD_ENTITLEMENTS" \
             "$SBINJECT_JITTERD_PLIST_SOURCE"; do
    [[ -f "$plist" ]] || die "missing SBInject plist: $plist"
    plutil -lint "$plist" >/dev/null || die "invalid SBInject plist: $plist"
done
[[ -f "$SCRIPT_DIR/patch_load_dylib.py" ]] || \
    die "missing SpringBoard load-command patch"
for source in dyld.m rop_inject.m thread_utils.m task_utils.m arm64.m; do
    [[ -f "$OPAINJECT_DIR/$source" ]] || \
        die "missing pinned opa334/opainject source: $source"
done

mkdir -p "$CACHE_DIR" "$WORK_DIR" "$OUT_DIR"
fetch_pinned "$BOOTSTRAP_URL" "$BOOTSTRAP_SHA256" "$BOOTSTRAP_ARCHIVE"
fetch_pinned "$ELLEKIT_URL" "$ELLEKIT_SHA256" "$ELLEKIT_DEB"
fetch_pinned "$PREFERENCELOADER_URL" "$PREFERENCELOADER_SHA256" \
    "$PREFERENCELOADER_DEB"
[[ "$(sha256_of "$SILEO_DEB")" == "$SILEO_SHA256" ]] || \
    die "opa334 Sileo package hash mismatch"
zstd -t "$BOOTSTRAP_ARCHIVE" >/dev/null

rm -rf "$IMAGE_ROOT" "$PACKAGE_ROOT" "$ELLEKIT_PACKAGE_ROOT" \
    "$CUSTOMD_BUILD_DIRECTORY" "$PREFERENCES_BRIDGE_BUILD_DIRECTORY" \
    "$UNSIGNED_OUT" "$REPACKED_SILEO" \
    "$REPACKED_ELLEKIT" "$TRUSTED_RUNTIME_CDHASHES" \
    "$SILEO_SYSTEM_ENTITLEMENTS" "$SILEO_ASSET_INFO" \
    "$SILEO_NORMALIZED_ICON"
mkdir -p \
    "$IMAGE_ROOT/Applications" \
    "$IMAGE_ROOT/Library/LaunchDaemons" \
    "$IMAGE_ROOT/usr/local/bin" \
    "$IMAGE_ROOT/usr/local/lib" \
    "$IMAGE_ROOT/usr/local/lib/sbinject" \
    "$IMAGE_ROOT/usr/local/share/codex-bootstrap" \
    "$EMBEDDED_SBINJECT_ROOT" \
    "$EMBEDDED_APT_CONFIG_DIR" \
    "$EMBEDDED_KEYRING_DIR" \
    "$TRUSTED_ELLEKIT_ROOT" \
    "$PREFERENCES_BRIDGE_BUILD_DIRECTORY/module-cache" \
    "$PACKAGE_ROOT" \
    "$UNSIGNED_OUT"

SDKROOT=$(xcrun --sdk iphoneos --show-sdk-path)

# ElleKit is the one package-level fixed-trust exception.  Re-sign every
# universal Mach-O in the pinned upstream package so both arm64 slices have a
# valid ad-hoc CodeDirectory, while preserving the loader's task-port
# entitlements.  The package installed into /var/jb and the extracted copy
# scanned by cryptexctl are then byte-identical.
dpkg-deb -R "$ELLEKIT_DEB" "$ELLEKIT_PACKAGE_ROOT"
typeset -a ellekit_package_machos=(
    "$ELLEKIT_PACKAGE_ROOT/var/jb/usr/lib/ellekit/MobileSafety.dylib"
    "$ELLEKIT_PACKAGE_ROOT/var/jb/usr/lib/ellekit/libinjector.dylib"
    "$ELLEKIT_PACKAGE_ROOT/var/jb/usr/lib/ellekit/pspawn.dylib"
    "$ELLEKIT_PACKAGE_ROOT/var/jb/usr/lib/libellekit.dylib"
    "$ELLEKIT_PACKAGE_ROOT/var/jb/usr/libexec/ellekit/loader"
)
for candidate in "${ellekit_package_machos[@]}"; do
    [[ -f "$candidate" ]] || \
        die "pinned ElleKit package is missing ${candidate:t}"
    codesign --force --sign - --timestamp=none --pagesize 4096 \
        --generate-entitlement-der --preserve-metadata=entitlements \
        "$candidate"
    codesign --verify --strict --all-architectures "$candidate" || \
        die "fixed ElleKit signature is invalid: ${candidate:t}"
done
[[ "$(dpkg-deb -f "$ELLEKIT_DEB" Package)" == ellekit && \
   "$(dpkg-deb -f "$ELLEKIT_DEB" Version)" == 1.2 && \
   "$(dpkg-deb -f "$ELLEKIT_DEB" Architecture)" == iphoneos-arm64 ]] || \
    die "pinned ElleKit package identity changed"
dpkg-deb --root-owner-group -b "$ELLEKIT_PACKAGE_ROOT" \
    "$REPACKED_ELLEKIT" >/dev/null
cp "$REPACKED_ELLEKIT" "$EMBEDDED_ELLEKIT_DEB"
[[ "$(dpkg-deb -f "$PREFERENCELOADER_DEB" Package)" == preferenceloader && \
   "$(dpkg-deb -f "$PREFERENCELOADER_DEB" Version)" == 2.3.3 && \
   "$(dpkg-deb -f "$PREFERENCELOADER_DEB" Architecture)" == \
       iphoneos-arm64 ]] || \
    die "pinned PreferenceLoader package identity changed"
cp "$PREFERENCELOADER_DEB" "$EMBEDDED_PREFERENCELOADER_DEB"
chmod 0644 "$EMBEDDED_PREFERENCELOADER_DEB"
dpkg-deb -x "$REPACKED_ELLEKIT" "$TRUSTED_ELLEKIT_ROOT"
typeset -a trusted_ellekit_machos=(
    "$TRUSTED_ELLEKIT_ROOT/var/jb/usr/lib/ellekit/MobileSafety.dylib"
    "$TRUSTED_ELLEKIT_ROOT/var/jb/usr/lib/ellekit/libinjector.dylib"
    "$TRUSTED_ELLEKIT_ROOT/var/jb/usr/lib/ellekit/pspawn.dylib"
    "$TRUSTED_ELLEKIT_ROOT/var/jb/usr/lib/libellekit.dylib"
    "$TRUSTED_ELLEKIT_ROOT/var/jb/usr/libexec/ellekit/loader"
)
for (( index = 1; index <= ${#ellekit_package_machos}; ++index )); do
    [[ "$(sha256_of "${ellekit_package_machos[$index]}")" == \
       "$(sha256_of "${trusted_ellekit_machos[$index]}")" ]] || \
        die "embedded ElleKit payload changed after repacking"
done

# Build the supplied SBInject chain as thin arm64e artifacts.  The launchd
# component contains only SpringBoard path redirection, jitterd accepts only a
# self-request from the exact replacement path, and generalhook performs the
# pre-main JIT/dyld-bypass/ElleKit handoff.
xcrun --sdk iphoneos clang \
    -arch arm64e \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -dynamiclib \
    -Os -Wall -Wextra -Werror \
    -I "$SBINJECT_SOURCE_DIR" \
    "$SBINJECT_SOURCE_DIR/sbinject_launchdhook.c" \
    "$SBINJECT_SOURCE_DIR/litehook_rebind.c" \
    -install_name /var/jb/usr/lib/sbinject/launchdhook-v3.dylib \
    -o "$SBINJECT_LAUNCHDHOOK"
codesign --force --sign - --timestamp=none --pagesize 4096 \
    "$SBINJECT_LAUNCHDHOOK"

xcrun --sdk iphoneos clang \
    -arch arm64e \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -dynamiclib \
    -fobjc-arc -fblocks -x objective-c \
    -Os -Wall -Wextra -Werror \
    -I "$SBINJECT_SOURCE_DIR" \
    "$SBINJECT_SOURCE_DIR/sbinject_generalhook.c" \
    "$SBINJECT_SOURCE_DIR/sbinject_dyld_bypass.c" \
    -lsandbox \
    -framework Foundation \
    -framework UIKit \
    -install_name /var/jb/usr/lib/sbinject/generalhook.dylib \
    -o "$SBINJECT_GENERALHOOK"
codesign --force --sign - --timestamp=none --pagesize 4096 \
    "$SBINJECT_GENERALHOOK"

xcrun --sdk iphoneos clang \
    -arch arm64e \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -dynamiclib \
    -fobjc-arc -fblocks \
    -Os -Wall -Wextra -Werror \
    "$SBINJECT_SOURCE_DIR/sbinject_lsd_registration_hook.m" \
    -framework Foundation \
    -install_name /var/jb/usr/lib/sbinject/lsd-registration-hook.dylib \
    -o "$SBINJECT_LSD_REGISTRATION_HOOK"
codesign --force --sign - --timestamp=none --pagesize 4096 \
    "$SBINJECT_LSD_REGISTRATION_HOOK"

# Build the iOS 27 SwiftUI Settings bridge as a small, fixed arm64e control
# plane dylib. PreferenceLoader 2.3.3 still supplies libprefs and constructs the
# legacy preference controllers; this bridge publishes those entries in
# SettingsSidebarListState and routes selections to the existing controllers.
xcrun --sdk iphoneos clang \
    -arch arm64e \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -fobjc-arc -fblocks \
    -Wall -Wextra -Werror \
    -I "$PREFERENCES_BRIDGE_SUPPORT_DIR" \
    -c "$SBINJECT_SOURCE_DIR/sbinject_preferences_bridge.m" \
    -o "$PREFERENCES_BRIDGE_BUILD_DIRECTORY/bridge.o"
xcrun --sdk iphoneos clang \
    -arch arm64e \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -fobjc-arc -fblocks \
    -Wall -Wextra -Werror \
    -I "$SBINJECT_SOURCE_DIR" \
    -c "$SBINJECT_SOURCE_DIR/litehook_rebind.c" \
    -o "$PREFERENCES_BRIDGE_BUILD_DIRECTORY/litehook_rebind.o"
for source in PLHeap PLSwiftMeta; do
    xcrun --sdk iphoneos clang \
        -arch arm64e \
        -miphoneos-version-min=17.0 \
        -isysroot "$SDKROOT" \
        -fobjc-arc -fblocks \
        -Wall -Wextra -Werror \
        -I "$PREFERENCES_BRIDGE_SUPPORT_DIR" \
        -c "$PREFERENCES_BRIDGE_SUPPORT_DIR/${source}.m" \
        -o "$PREFERENCES_BRIDGE_BUILD_DIRECTORY/${source}.o"
done
xcrun --sdk iphoneos swiftc \
    -target arm64e-apple-ios17.0 \
    -sdk "$SDKROOT" \
    -module-cache-path "$PREFERENCES_BRIDGE_BUILD_DIRECTORY/module-cache" \
    -Osize \
    -emit-library \
    "$SBINJECT_SOURCE_DIR/sbinject_preferences_bridge.swift" \
    "$PREFERENCES_BRIDGE_SUPPORT_DIR/PLSwiftString.swift" \
    "$PREFERENCES_BRIDGE_BUILD_DIRECTORY/bridge.o" \
    "$PREFERENCES_BRIDGE_BUILD_DIRECTORY/litehook_rebind.o" \
    "$PREFERENCES_BRIDGE_BUILD_DIRECTORY/PLHeap.o" \
    "$PREFERENCES_BRIDGE_BUILD_DIRECTORY/PLSwiftMeta.o" \
    -Xlinker -framework -Xlinker UIKit \
    -Xlinker -framework -Xlinker QuartzCore \
    -Xlinker -install_name \
    -Xlinker /var/jb/usr/lib/sbinject/preferences-bridge.dylib \
    -o "$SBINJECT_PREFERENCES_BRIDGE"
codesign --force --sign - --timestamp=none --pagesize 4096 \
    "$SBINJECT_PREFERENCES_BRIDGE"
(( $(stat -f %z "$SBINJECT_PREFERENCES_BRIDGE") <= \
   MAX_PREFERENCES_BRIDGE_BYTES )) || \
    die "iOS 27 Settings bridge exceeds its 1 MiB size ceiling"

xcrun --sdk iphoneos clang \
    -arch arm64e \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -fno-objc-arc -fblocks \
    -Os -Wall -Wextra -Werror \
    -I "$SBINJECT_SOURCE_DIR" \
    "$SBINJECT_SOURCE_DIR/sbinject_jitterd.m" \
    -framework Foundation \
    -o "$SBINJECT_JITTERD"
codesign --force --sign - --timestamp=none --pagesize 4096 \
    --generate-entitlement-der \
    --entitlements "$SBINJECT_JITTERD_ENTITLEMENTS" \
    "$SBINJECT_JITTERD"
for artifact in "$SBINJECT_LAUNCHDHOOK" "$SBINJECT_GENERALHOOK" \
                "$SBINJECT_PREFERENCES_BRIDGE" \
                "$SBINJECT_JITTERD"; do
    codesign --verify --strict --all-architectures "$artifact" || \
        die "SBInject artifact signature is invalid: ${artifact:t}"
    [[ "$(lipo -archs "$artifact")" == arm64e ]] || \
        die "SBInject artifact is not exactly arm64e: ${artifact:t}"
done
cp "$SBINJECT_JITTERD_PLIST_SOURCE" "$EMBEDDED_SBINJECT_JITTERD_PLIST"
chmod 0644 "$EMBEDDED_SBINJECT_JITTERD_PLIST"

# Preserve the exact target SpringBoard bundle resources, replace only its
# tiny launcher executable, and put the one signed pre-main dylib beside it.
# The launcher has only sixteen bytes of header padding, so the pinned patcher
# safely converts its otherwise-unused 40-byte LC_RPATH into
# `LC_LOAD_DYLIB @loader_path/g` before deterministic ad-hoc signing.
ditto --noqtn "$SPRINGBOARD_CANDIDATE_BUNDLE_SOURCE" \
    "$SPRINGBOARD_CANDIDATE_DIRECTORY"
rm -f "$SPRINGBOARD_CANDIDATE_DIRECTORY/SpringBoard"
rm -rf "$SPRINGBOARD_CANDIDATE_DIRECTORY/_CodeSignature"
cp "$SBINJECT_GENERALHOOK" "$SPRINGBOARD_CANDIDATE_GENERALHOOK"
chmod 0755 "$SPRINGBOARD_CANDIDATE_GENERALHOOK"
python3 "$SPRINGBOARD_CANDIDATE_BUILDER" \
    "$SPRINGBOARD_CANDIDATE_SOURCE" \
    "$SPRINGBOARD_CANDIDATE_DIRECTORY" \
    --info-plist "$SPRINGBOARD_CANDIDATE_INFO_SOURCE" \
    --executable-name notSpringBoard \
    --bundle-executable notSpringBoard \
    --load-dylib @loader_path/g \
    --load-dylib-patcher "$SCRIPT_DIR/patch_load_dylib.py" >/dev/null
[[ -x "$SPRINGBOARD_CANDIDATE" ]] || \
    die "SpringBoard candidate was not produced"
[[ -f "$SPRINGBOARD_CANDIDATE_INFO" ]] || \
    die "SpringBoard candidate Info.plist was not produced"
[[ -f "$SPRINGBOARD_CANDIDATE_ENTITLEMENTS" ]] || \
    die "SpringBoard candidate entitlements were not produced"
[[ -f "$SPRINGBOARD_CANDIDATE_MANIFEST" ]] || \
    die "SpringBoard candidate manifest was not produced"
[[ -x "$SPRINGBOARD_CANDIDATE_GENERALHOOK" ]] || \
    die "SpringBoard candidate generalhook was not produced"
codesign --verify --strict --all-architectures --ignore-resources \
    "$SPRINGBOARD_CANDIDATE" || \
    die "SpringBoard candidate signature is invalid"
otool -L "$SPRINGBOARD_CANDIDATE" | rg -q \
    '^\s+@loader_path/g ' || \
    die "SpringBoard candidate does not preload the SBInject generalhook"
[[ "$(sha256_of "$SPRINGBOARD_CANDIDATE_GENERALHOOK")" == \
   "$(sha256_of "$SBINJECT_GENERALHOOK")" ]] || \
    die "SpringBoard bundle generalhook changed while copying"

# Build the Settings replacement through the same supplied SBInject pre-main
# lane.  Preserve its exact on-device bundle and entitlement dictionary, add
# only the target's debugger/JIT policy, preload the compact general hook, and
# retain a separate launchd crash-loop fallback from SpringBoard.
ditto --noqtn "$PREFERENCES_CANDIDATE_BUNDLE_SOURCE" \
    "$PREFERENCES_CANDIDATE_DIRECTORY"
rm -f "$PREFERENCES_CANDIDATE_DIRECTORY/Preferences"
rm -rf "$PREFERENCES_CANDIDATE_DIRECTORY/_CodeSignature"
cp "$SBINJECT_GENERALHOOK" "$PREFERENCES_CANDIDATE_GENERALHOOK"
chmod 0755 "$PREFERENCES_CANDIDATE_GENERALHOOK"
python3 "$SPRINGBOARD_CANDIDATE_BUILDER" \
    "$PREFERENCES_CANDIDATE_SOURCE" \
    "$PREFERENCES_CANDIDATE_DIRECTORY" \
    --target preferences \
    --info-plist "$PREFERENCES_CANDIDATE_INFO_SOURCE" \
    --executable-name notPreferences \
    --bundle-executable notPreferences \
    --load-dylib @loader_path/g \
    --load-dylib-patcher "$SCRIPT_DIR/patch_load_dylib.py" >/dev/null
[[ -x "$PREFERENCES_CANDIDATE" ]] || \
    die "Preferences candidate was not produced"
[[ -f "$PREFERENCES_CANDIDATE_INFO" ]] || \
    die "Preferences candidate Info.plist was not produced"
[[ -f "$PREFERENCES_CANDIDATE_ENTITLEMENTS" ]] || \
    die "Preferences candidate entitlements were not produced"
[[ -f "$PREFERENCES_CANDIDATE_MANIFEST" ]] || \
    die "Preferences candidate manifest was not produced"
[[ -x "$PREFERENCES_CANDIDATE_GENERALHOOK" ]] || \
    die "Preferences candidate generalhook was not produced"
codesign --verify --strict --all-architectures --ignore-resources \
    "$PREFERENCES_CANDIDATE" || \
    die "Preferences candidate signature is invalid"
otool -L "$PREFERENCES_CANDIDATE" | rg -q \
    '^\s+@loader_path/g ' || \
    die "Preferences candidate does not preload the SBInject generalhook"
ldid -e "$PREFERENCES_CANDIDATE" | rg -q \
    '<key>com.apple.private.debugger</key>' || \
    die "Preferences candidate lacks com.apple.private.debugger"
ldid -e "$PREFERENCES_CANDIDATE" | rg -q \
    '<key>get-task-allow</key>' || \
    die "Preferences candidate lacks get-task-allow"
[[ "$(sha256_of "$PREFERENCES_CANDIDATE_GENERALHOOK")" == \
   "$(sha256_of "$SBINJECT_GENERALHOOK")" ]] || \
    die "Preferences bundle generalhook changed while copying"

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
[[ "$(dpkg-deb -f "$SILEO_DEB" Version)" == \
    "$SILEO_UPSTREAM_PACKAGE_VERSION" ]] || \
    die "upstream Sileo package version changed"
python3 - "$PACKAGE_ROOT/DEBIAN/control" "$SILEO_UPSTREAM_PACKAGE_VERSION" \
    "$SILEO_PACKAGE_VERSION" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
upstream = sys.argv[2]
replacement = sys.argv[3]
text = path.read_text()
text, count = re.subn(
    rf"(?m)^Version: {re.escape(upstream)}$",
    f"Version: {replacement}",
    text,
)
if count != 1:
    raise SystemExit("Sileo control file has an unexpected Version field")
path.write_text(text)
PY
python3 "$SCRIPT_DIR/patch_sileo_postinst.py" \
    "$PACKAGE_ROOT/DEBIAN/postinst"
APP_DIR="$PACKAGE_ROOT/var/jb/Applications/Sileo.app"
[[ -x "$APP_DIR/Sileo" && -x "$APP_DIR/giveMeRoot" ]] || \
    die "Sileo package is missing expected executables"
[[ "$(plutil -extract CFBundleIdentifier raw -o - \
        "$APP_DIR/Info.plist")" == "$SILEO_BUNDLE_IDENTIFIER" ]] || \
    die "upstream Sileo bundle identifier changed"
plutil -replace CFBundleVersion -string "$VERSION" "$APP_DIR/Info.plist"
[[ -f "$APP_DIR/Assets.car" ]] || die "upstream Sileo asset catalog is missing"
xcrun assetutil --info "$APP_DIR/Assets.car" >"$SILEO_ASSET_INFO"
rg -q '"RenditionName" : "AppIcon60x60@3x.png"' "$SILEO_ASSET_INFO" || \
    die "upstream Sileo asset catalog lacks its iPhone 13 icon"
[[ -f "$APP_DIR/AppIcon60x60@2x.png" ]] || \
    die "upstream Sileo standalone primary icon is missing"
# IconServices returns the generic grid when this nonstandard system-app mount
# advertises only the compiled AppIcon catalog. Publish explicit standalone
# phone renditions and remove CFBundleIconName so CFBundleIconFiles is the
# authoritative primary-icon route.
sips -s format png "$APP_DIR/AppIcon60x60@2x.png" \
    --out "$SILEO_NORMALIZED_ICON" >/dev/null
mv -f "$SILEO_NORMALIZED_ICON" "$APP_DIR/AppIcon60x60@2x.png"
sips -z 180 180 "$APP_DIR/AppIcon60x60@2x.png" \
    --out "$APP_DIR/AppIcon60x60@3x.png" >/dev/null
plutil -remove \
    'CFBundleIcons.CFBundlePrimaryIcon.CFBundleIconName' \
    "$APP_DIR/Info.plist"
plutil -replace 'CFBundleIcons.CFBundlePrimaryIcon.CFBundleIconFiles' \
    -json '["AppIcon60x60"]' "$APP_DIR/Info.plist"
plutil -replace CFBundleIconFiles -json '["AppIcon60x60"]' \
    "$APP_DIR/Info.plist"
[[ "$(sips -g pixelWidth "$APP_DIR/AppIcon60x60@3x.png" | \
        awk '/pixelWidth:/ { print $2 }')" == 180 ]] || \
    die "normalized Sileo iPhone 13 icon has the wrong width"
ldid -e "$APP_DIR/Sileo" >"$SILEO_SYSTEM_ENTITLEMENTS"
plutil -lint "$SILEO_SYSTEM_ENTITLEMENTS" >/dev/null || \
    die "upstream Sileo entitlements are invalid"
for entitlement in platform-application \
                   'com\.apple\.private\.security\.no-sandbox' \
                   'com\.apple\.private\.security\.no-container'; do
    require_true_entitlement "$SILEO_SYSTEM_ENTITLEMENTS" "$entitlement" \
        "$entitlement"
done
cp "$SILEO_SYSTEM_ENTITLEMENTS" \
    "$APP_DIR/CodexSystemEntitlements.plist"
chmod 0644 "$APP_DIR/CodexSystemEntitlements.plist"

# Preserve Sileo's upstream system-app identity and privileged no-sandbox
# entitlement set, then make the entire immutable bundle a direct Cryptex
# payload.  Every Mach-O receives an ad-hoc CodeDirectory and the generated
# Cryptex trust cache admits those exact bytes without a provisioning profile.
FRAMEWORKS_DIR="$APP_DIR/F"
SILEO_BROKER_DYLIB="$FRAMEWORKS_DIR/libcodex-sileo-broker.dylib"
PROCURSUS_LIB="$IMAGE_ROOT/usr/local/share/codex-bootstrap/procursus/usr/lib"
for library in libiosexec.1.dylib liblzma.5.dylib libzstd.1.5.5.dylib; do
    [[ -f "$PROCURSUS_LIB/$library" ]] || \
        die "missing Procursus runtime library: $PROCURSUS_LIB/$library"
done
mkdir -p "$FRAMEWORKS_DIR"
cp "$PROCURSUS_LIB/libiosexec.1.dylib" \
    "$FRAMEWORKS_DIR/libiosexec.1.dylib"
cp "$PROCURSUS_LIB/liblzma.5.dylib" \
    "$FRAMEWORKS_DIR/liblzma.5.dylib"
cp "$PROCURSUS_LIB/libzstd.1.5.5.dylib" \
    "$FRAMEWORKS_DIR/libzstd.real.dylib"
install_name_tool -rpath /opt/procursus/lib @loader_path/F "$APP_DIR/Sileo"
install_name_tool -id @rpath/libzstd.real.dylib \
    "$FRAMEWORKS_DIR/libzstd.real.dylib"
xcrun --sdk iphoneos clang \
    -arch arm64 \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -dynamiclib \
    -fblocks \
    -Wall -Wextra -Werror \
    -lsandbox \
    -Wl,-install_name,@rpath/libzstd.1.dylib \
    -Wl,-reexport_library,"$FRAMEWORKS_DIR/libzstd.real.dylib" \
    "$SCRIPT_DIR/sileo_zstd_reexport.c" \
    -o "$FRAMEWORKS_DIR/libzstd.1.dylib"
xcrun --sdk iphoneos clang \
    -arch arm64 \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -dynamiclib \
    -fblocks \
    -Wall -Wextra -Werror \
    -lsandbox \
    -Wl,-install_name,@loader_path/F/libcodex-sileo-broker.dylib \
    "$SCRIPT_DIR/sileo_broker_constructor.c" \
    -o "$SILEO_BROKER_DYLIB"
python3 "$SCRIPT_DIR/patch_load_dylib.py" "$APP_DIR/Sileo" \
    @loader_path/F/libcodex-sileo-broker.dylib
for library in "$FRAMEWORKS_DIR"/*.dylib; do
    codesign --force --sign - --timestamp=none \
        --pagesize 4096 "$library"
done

xcrun --sdk iphoneos clang \
    -arch arm64 \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -Wall -Wextra -Werror \
    "$SCRIPT_DIR/sileo_root_helper.c" \
    -o "$APP_DIR/giveMeRoot"
codesign --force --sign - --timestamp=none \
    --pagesize 4096 "$APP_DIR/giveMeRoot"
chmod 0755 "$APP_DIR/giveMeRoot"
rm -f "$APP_DIR/embedded.mobileprovision"
rm -rf "$APP_DIR/_CodeSignature"
codesign --force --sign - --timestamp=none \
    --pagesize 4096 --entitlements "$SILEO_SYSTEM_ENTITLEMENTS" \
    "$APP_DIR"
[[ ! -e "$APP_DIR/embedded.mobileprovision" ]] || \
    die "system Sileo unexpectedly contains a provisioning profile"
for entitlement in platform-application \
                   'com\.apple\.private\.security\.no-sandbox' \
                   'com\.apple\.private\.security\.no-container'; do
    ldid -e "$APP_DIR/Sileo" | rg -q "$entitlement" || \
        die "system Sileo lost required entitlement $entitlement"
done
codesign --verify --deep --strict --verbose=2 "$APP_DIR"
otool -l "$APP_DIR/Sileo" | rg -q 'path @loader_path/F' || \
    die "final Sileo app is missing its bundled-library rpath"
otool -L "$FRAMEWORKS_DIR/libzstd.1.dylib" | \
    rg -q '@rpath/libzstd.real.dylib' || \
    die "final Sileo zstd shim does not re-export bundled zstd"
otool -L "$APP_DIR/Sileo" | \
    rg -q '@loader_path/F/libcodex-sileo-broker.dylib' || \
    die "final Sileo app does not load its unique broker constructor"
otool -D "$SILEO_BROKER_DYLIB" | \
    rg -q '@loader_path/F/libcodex-sileo-broker.dylib' || \
    die "Sileo broker constructor has the wrong install name"
ditto --noqtn "$APP_DIR" "$SYSTEM_SILEO_APP"
chmod 0755 "$SYSTEM_SILEO_APP" "$SYSTEM_SILEO_APP/Sileo" \
    "$SYSTEM_SILEO_APP/giveMeRoot"
[[ "$(plutil -extract CFBundleIdentifier raw -o - \
        "$SYSTEM_SILEO_APP/Info.plist")" == "$SILEO_BUNDLE_IDENTIFIER" ]] || \
    die "Cryptex Sileo bundle identifier changed while copying"
[[ ! -e "$SYSTEM_SILEO_APP/embedded.mobileprovision" ]] || \
    die "Cryptex Sileo contains a provisioning profile"
[[ -f "$SYSTEM_SILEO_APP/Assets.car" ]] || \
    die "Cryptex Sileo lost its asset catalog"
[[ -f "$SYSTEM_SILEO_APP/AppIcon60x60@3x.png" ]] || \
    die "Cryptex Sileo lost its explicit iPhone 13 icon"
[[ -f "$SYSTEM_SILEO_APP/CodexSystemEntitlements.plist" ]] || \
    die "Cryptex Sileo lost its registration entitlements"

# Keep dpkg's package/dependency state without installing a mutable app under
# /var/jb. The Cryptex is the authoritative signed source; the boot daemon
# maintains one byte-verified, root-owned copy in the standard app container.
rm -rf "$APP_DIR"
dpkg-deb -b "$PACKAGE_ROOT" "$REPACKED_SILEO" >/dev/null
[[ "$(dpkg-deb -f "$REPACKED_SILEO" Version)" == \
    "$SILEO_PACKAGE_VERSION" ]] || \
    die "fixed system Sileo metadata package version mismatch"
cp "$REPACKED_SILEO" \
    "$IMAGE_ROOT/usr/local/share/codex-bootstrap/sileo.deb"
TRUSTED_SILEO_APP="$SYSTEM_SILEO_APP"
typeset -a prepared_sileo_machos=(
    "$SYSTEM_SILEO_APP/Sileo"
    "$SYSTEM_SILEO_APP/giveMeRoot"
    "$SYSTEM_SILEO_APP/F/libiosexec.1.dylib"
    "$SYSTEM_SILEO_APP/F/liblzma.5.dylib"
    "$SYSTEM_SILEO_APP/F/libcodex-sileo-broker.dylib"
    "$SYSTEM_SILEO_APP/F/libzstd.1.dylib"
    "$SYSTEM_SILEO_APP/F/libzstd.real.dylib"
)
typeset -a trusted_sileo_machos=(
    "${prepared_sileo_machos[@]}"
)
for (( index = 1; index <= ${#prepared_sileo_machos}; ++index )); do
    [[ "$(sha256_of "${prepared_sileo_machos[$index]}")" == \
       "$(sha256_of "${trusted_sileo_machos[$index]}")" ]] || \
        die "trusted Sileo payload changed while copying"
done

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
    --entitlements "$ELLEKIT_COMPAT_ENTITLEMENTS" \
    "$ELLEKIT_COMPAT_LOADER"
codesign --verify --strict --all-architectures "$ELLEKIT_COMPAT_LOADER" || \
    die "ElleKit compatibility loader signature is invalid"

xcrun --sdk iphoneos clang \
    -arch arm64 \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -Wall -Wextra -Werror \
    "$SCRIPT_DIR/codex_exec_worker.c" \
    -o "$EXEC_WORKER"
codesign --force --sign - --timestamp=none --pagesize 4096 \
    --entitlements "$EXEC_WORKER_ENTITLEMENTS" \
    "$EXEC_WORKER"
codesign --verify --strict --all-architectures "$EXEC_WORKER" || \
    die "execution worker signature is invalid"

# customd pins the finalized worker, candidate, candidate Info.plist, and
# launchctl bytes plus its fixed transaction helpers at build time. Build the
# helpers first, then customd only after every pinned input is complete. This
# prevents a later bootstrap step from silently invalidating its boot policy
# while retaining the system LaunchDaemon packaging.
"$CUSTOMD_TRACE_REEXEC_BUILDER" "$CUSTOMD_BUILD_DIRECTORY"
"$CUSTOMD_SETEXEC_BUILDER" "$CUSTOMD_BUILD_DIRECTORY"
CODEX_CUSTOMD_WORKER_PATH="$EXEC_WORKER" \
CODEX_CUSTOMD_CANDIDATE_PATH="$SPRINGBOARD_CANDIDATE" \
CODEX_CUSTOMD_CANDIDATE_INFO_PATH="$SPRINGBOARD_CANDIDATE_INFO" \
CODEX_CUSTOMD_LAUNCHCTL_PATH="$LAUNCHCTL" \
CODEX_CUSTOMD_TRACE_REEXEC_PROBE_PATH="$CUSTOMD_TRACE_REEXEC_BUILD_EXECUTABLE" \
CODEX_CUSTOMD_SETEXEC_HELPER_PATH="$CUSTOMD_SETEXEC_BUILD_EXECUTABLE" \
    "$CUSTOMD_BUILDER" "$CUSTOMD_BUILD_DIRECTORY"
[[ -x "$CUSTOMD_BUILD_EXECUTABLE" && -x "$CUSTOMCTL_BUILD_EXECUTABLE" && \
   -x "$CUSTOMD_REGISTRAR_BUILD_EXECUTABLE" && \
   -x "$CUSTOMD_TRACE_REEXEC_BUILD_EXECUTABLE" && \
   -x "$CUSTOMD_SETEXEC_BUILD_EXECUTABLE" ]] || \
    die "customd build did not produce all executables"
cp "$CUSTOMD_BUILD_EXECUTABLE" "$CUSTOMD_EXECUTABLE"
cp "$CUSTOMCTL_BUILD_EXECUTABLE" "$CUSTOMCTL_EXECUTABLE"
cp "$CUSTOMD_REGISTRAR_BUILD_EXECUTABLE" \
    "$CUSTOMD_REGISTRAR_EXECUTABLE"
cp "$CUSTOMD_TRACE_REEXEC_BUILD_EXECUTABLE" \
    "$CUSTOMD_TRACE_REEXEC_EXECUTABLE"
cp "$CUSTOMD_SETEXEC_BUILD_EXECUTABLE" "$CUSTOMD_SETEXEC_EXECUTABLE"
chmod 0755 "$CUSTOMD_EXECUTABLE" "$CUSTOMCTL_EXECUTABLE" \
    "$CUSTOMD_REGISTRAR_EXECUTABLE" "$CUSTOMD_TRACE_REEXEC_EXECUTABLE" \
    "$CUSTOMD_SETEXEC_EXECUTABLE"
[[ "$(sha256_of "$CUSTOMD_BUILD_EXECUTABLE")" == \
   "$(sha256_of "$CUSTOMD_EXECUTABLE")" && \
   "$(sha256_of "$CUSTOMCTL_BUILD_EXECUTABLE")" == \
   "$(sha256_of "$CUSTOMCTL_EXECUTABLE")" && \
   "$(sha256_of "$CUSTOMD_REGISTRAR_BUILD_EXECUTABLE")" == \
   "$(sha256_of "$CUSTOMD_REGISTRAR_EXECUTABLE")" && \
   "$(sha256_of "$CUSTOMD_TRACE_REEXEC_BUILD_EXECUTABLE")" == \
   "$(sha256_of "$CUSTOMD_TRACE_REEXEC_EXECUTABLE")" && \
   "$(sha256_of "$CUSTOMD_SETEXEC_BUILD_EXECUTABLE")" == \
   "$(sha256_of "$CUSTOMD_SETEXEC_EXECUTABLE")" ]] || \
    die "embedded customd executables changed while copying"
codesign --verify --strict --all-architectures "$CUSTOMD_EXECUTABLE" || \
    die "customd signature is invalid"
codesign --verify --strict --all-architectures "$CUSTOMCTL_EXECUTABLE" || \
    die "customctl signature is invalid"
codesign --verify --strict --all-architectures \
    "$CUSTOMD_REGISTRAR_EXECUTABLE" || \
    die "customd candidate registrar signature is invalid"
codesign --verify --strict --all-architectures \
    "$CUSTOMD_TRACE_REEXEC_EXECUTABLE" || \
    die "customd trace/re-exec probe signature is invalid"
codesign --verify --strict --all-architectures \
    "$CUSTOMD_SETEXEC_EXECUTABLE" || \
    die "customd SpringBoard SETEXEC helper signature is invalid"
cp "$CUSTOMD_JOB_PLIST_SOURCE" "$EMBEDDED_CUSTOMD_JOB_PLIST"
chmod 0644 "$EMBEDDED_CUSTOMD_JOB_PLIST"
plutil -lint "$EMBEDDED_CUSTOMD_JOB_PLIST" >/dev/null || \
    die "embedded customd job plist is invalid"
[[ "$(sha256_of "$CUSTOMD_JOB_PLIST_SOURCE")" == \
   "$(sha256_of "$EMBEDDED_CUSTOMD_JOB_PLIST")" ]] || \
    die "embedded customd job plist changed while copying"

xcrun --sdk iphoneos clang \
    -arch arm64 \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -fblocks \
    -Wall -Wextra -Werror \
    -I "$SCRIPT_DIR" \
    "$SCRIPT_DIR/sbinject_package_validator.c" \
    -o "$SBINJECT_PACKAGE_VALIDATOR"
codesign --force --sign - --timestamp=none --pagesize 4096 \
    "$SBINJECT_PACKAGE_VALIDATOR"
codesign --verify --strict --all-architectures \
    "$SBINJECT_PACKAGE_VALIDATOR" || \
    die "SBInject package validator signature is invalid"

typeset -a trusted_runtime_cdhashes
for candidate in \
    "$ELLEKIT_COMPAT_LOADER" \
    "$EXEC_WORKER" \
    "$CUSTOMD_EXECUTABLE" \
    "$CUSTOMCTL_EXECUTABLE" \
    "$CUSTOMD_REGISTRAR_EXECUTABLE" \
    "$CUSTOMD_TRACE_REEXEC_EXECUTABLE" \
    "$CUSTOMD_SETEXEC_EXECUTABLE" \
    "$SBINJECT_PACKAGE_VALIDATOR" \
    "$SBINJECT_GENERALHOOK" \
    "$SBINJECT_LSD_REGISTRATION_HOOK" \
    "$SBINJECT_PREFERENCES_BRIDGE" \
    "$SBINJECT_LAUNCHDHOOK" \
    "$SBINJECT_JITTERD" \
    "$SPRINGBOARD_CANDIDATE_GENERALHOOK" \
    "$SPRINGBOARD_CANDIDATE" \
    "$PREFERENCES_CANDIDATE_GENERALHOOK" \
    "$PREFERENCES_CANDIDATE" \
    "${prepared_sileo_machos[@]}" \
    "${trusted_ellekit_machos[@]}"; do
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

xcrun --sdk iphoneos clang \
    -arch arm64 \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -fobjc-arc -fblocks \
    -Wall -Wextra -Werror \
    "-DCODEX_SILEO_BUNDLE_IDENTIFIER=@\"$SILEO_BUNDLE_IDENTIFIER\"" \
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
cp "$SBINJECT_APT_CONFIG" "$EMBEDDED_SBINJECT_APT_CONFIG"
cp "$PREFERENCELOADER_PIN" "$EMBEDDED_PREFERENCELOADER_PIN"
cp "$SILEO_PIN" "$EMBEDDED_SILEO_PIN"
cp "$APT_LIST_NORMALIZER" "$EMBEDDED_APT_LIST_NORMALIZER"
chmod 0644 "$EMBEDDED_DEFAULT_SOURCES" \
    "$EMBEDDED_REPOSITORY_COMPAT_CONFIG" \
    "$EMBEDDED_SBINJECT_APT_CONFIG" \
    "$EMBEDDED_PREFERENCELOADER_PIN" \
    "$EMBEDDED_SILEO_PIN" \
    "$EMBEDDED_APT_LIST_NORMALIZER"
if [[ "$FORCE_CLEAN_INSTALL" == 1 ]]; then
    print -r -- "$VERSION" >"$EMBEDDED_CLEAN_INSTALL_TOKEN"
    chmod 0400 "$EMBEDDED_CLEAN_INSTALL_TOKEN"
fi
gpg --batch --yes --dearmor --output "$EMBEDDED_ELLEKIT_KEY" "$ELLEKIT_KEY"
gpg --batch --yes --dearmor --output "$EMBEDDED_BIGBOSS_KEY" "$BIGBOSS_KEY"
chmod 0644 "$EMBEDDED_ELLEKIT_KEY" "$EMBEDDED_BIGBOSS_KEY"
verify_keyring "$EMBEDDED_ELLEKIT_KEY" "$ELLEKIT_KEY_FINGERPRINT"
verify_keyring "$EMBEDDED_BIGBOSS_KEY" "$BIGBOSS_KEY_FINGERPRINT"

# [REDACTED] Packaging, payload selection, and validation details omitted.
printf '%s\n' 'TSS/Cryptex personalization and installation details are redacted from this educational source release.' >&2
exit 1
