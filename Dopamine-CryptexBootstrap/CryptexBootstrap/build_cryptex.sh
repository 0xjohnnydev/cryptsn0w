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
ELLEKIT_KEY_FINGERPRINT=71C9AF96CD2F3A8A837EFFBB015D4A9B1D4A2370
BIGBOSS_KEY_FINGERPRINT=A9C96A37115894A23B894107694D17D38764B4F4
IDENTIFIER=com.openai.codex.dopamine.bootstrap
VERSION=${CODEX_CRYPTEX_VERSION:-1.0.$(date -u +%Y%m%d%H%M%S)}
SILEO_BUNDLE_IDENTIFIER=${CODEX_SILEO_BUNDLE_IDENTIFIER:-org.coolstar.SileoStore}
TARGET_UDID=${CODEX_TARGET_UDID:-}
SILEO_DEVELOPMENT_IDENTITY=${CODEX_SILEO_DEVELOPMENT_IDENTITY:-}
SILEO_PROVISIONING_PROFILE=${CODEX_SILEO_PROVISIONING_PROFILE:-}
SILEO_DEVELOPMENT_ENTITLEMENTS=${CODEX_SILEO_DEVELOPMENT_ENTITLEMENTS:-}
FORCE_CLEAN_INSTALL=${CODEX_FORCE_CLEAN_INSTALL:-0}

CACHE_DIR="$SCRIPT_DIR/cache"
WORK_DIR="$SCRIPT_DIR/work"
OUT_DIR="$SCRIPT_DIR/out"
BOOTSTRAP_ARCHIVE="$CACHE_DIR/bootstrap_1900.tar.zst"
ELLEKIT_DEB="$CACHE_DIR/ellekit_1.2_iphoneos-arm64.deb"
SILEO_DEB="$REPO_DIR/Application/Dopamine/Resources/sileo.deb"
DEFAULT_SOURCES="$SCRIPT_DIR/dopamine-default.sources"
REPOSITORY_COMPAT_CONFIG="$SCRIPT_DIR/dopamine-repository-compat.conf"
SBINJECT_APT_CONFIG="$SCRIPT_DIR/sbinject-package.conf"
APT_LIST_NORMALIZER="$SCRIPT_DIR/normalize_apt_lists.sh"
ELLEKIT_KEY="$SCRIPT_DIR/keyrings/ellekit.asc"
BIGBOSS_KEY="$SCRIPT_DIR/keyrings/bigboss.asc"
OPAINJECT_DIR="$REPO_DIR/BaseBin/opainject"
IMAGE_ROOT="$WORK_DIR/image-root"
EMBEDDED_DEFAULT_SOURCES="$IMAGE_ROOT/usr/local/share/codex-bootstrap/dopamine-default.sources"
EMBEDDED_APT_CONFIG_DIR="$IMAGE_ROOT/usr/local/share/codex-bootstrap/apt"
EMBEDDED_REPOSITORY_COMPAT_CONFIG="$EMBEDDED_APT_CONFIG_DIR/99dopamine-repository-compat"
EMBEDDED_SBINJECT_APT_CONFIG="$EMBEDDED_APT_CONFIG_DIR/98sbinject-packages"
EMBEDDED_APT_LIST_NORMALIZER="$IMAGE_ROOT/usr/local/share/codex-bootstrap/normalize-apt-lists.sh"
EMBEDDED_CLEAN_INSTALL_TOKEN="$IMAGE_ROOT/usr/local/share/codex-bootstrap/clean-install-token.txt"
EMBEDDED_KEYRING_DIR="$IMAGE_ROOT/usr/local/share/codex-bootstrap/keyrings"
EMBEDDED_ELLEKIT_KEY="$EMBEDDED_KEYRING_DIR/ellekit.gpg"
EMBEDDED_BIGBOSS_KEY="$EMBEDDED_KEYRING_DIR/bigboss.gpg"
EMBEDDED_ELLEKIT_DEB="$IMAGE_ROOT/usr/local/share/codex-bootstrap/ellekit.deb"
TRUSTED_ELLEKIT_ROOT="$IMAGE_ROOT/usr/local/share/codex-bootstrap/trusted/ellekit-root"
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
SBINJECT_LAUNCHDHOOK="$IMAGE_ROOT/usr/local/lib/sbinject/launchdhook.dylib"
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
SIGNING_DIR="$WORK_DIR/signing"
SIGNING_CONFIG="$SIGNING_DIR/config.json"
GENERATED_ENTITLEMENTS="$SIGNING_DIR/sileo-development-entitlements.plist"

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

for tool in awk codesign curl dpkg-deb dwarfdump file find gpg ldid lipo nm plutil python3 rg security shasum tar xcrun zstd; do
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
verify_keyring "$ELLEKIT_KEY" "$ELLEKIT_KEY_FINGERPRINT"
verify_keyring "$BIGBOSS_KEY" "$BIGBOSS_KEY_FINGERPRINT"
[[ -f "$SCRIPT_DIR/patch_sileo_postinst.py" ]] || \
    die "missing Sileo maintainer-script compatibility patch"
[[ -f "$SCRIPT_DIR/sbinject_package_validator.c" ]] || \
    die "missing SBInject package validator source"
for source in \
    sbinject_protocol.h \
    litehook_rebind.h litehook_rebind.c \
    sbinject_launchdhook.c \
    sbinject_dyld_bypass.h sbinject_dyld_bypass.c \
    sbinject_generalhook.c sbinject_jitterd.m; do
    [[ -f "$SBINJECT_SOURCE_DIR/$source" ]] || \
        die "missing supplied SBInject integration source: $source"
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

mkdir -p "$CACHE_DIR" "$WORK_DIR" "$OUT_DIR" "$SIGNING_DIR"
SIGNING_ARGS=(
    --bundle-id "$SILEO_BUNDLE_IDENTIFIER"
    --output-json "$SIGNING_CONFIG"
    --output-entitlements "$GENERATED_ENTITLEMENTS"
)
[[ -z "$TARGET_UDID" ]] || SIGNING_ARGS+=(--device "$TARGET_UDID")
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
[[ "$(sha256_of "$SILEO_DEB")" == "$SILEO_SHA256" ]] || \
    die "opa334 Sileo package hash mismatch"
zstd -t "$BOOTSTRAP_ARCHIVE" >/dev/null

rm -rf "$IMAGE_ROOT" "$PACKAGE_ROOT" "$ELLEKIT_PACKAGE_ROOT" \
    "$CUSTOMD_BUILD_DIRECTORY" "$UNSIGNED_OUT" "$REPACKED_SILEO" \
    "$REPACKED_ELLEKIT" "$TRUSTED_RUNTIME_CDHASHES"
mkdir -p \
    "$IMAGE_ROOT/Library/LaunchDaemons" \
    "$IMAGE_ROOT/usr/local/bin" \
    "$IMAGE_ROOT/usr/local/lib" \
    "$IMAGE_ROOT/usr/local/lib/sbinject" \
    "$IMAGE_ROOT/usr/local/share/codex-bootstrap" \
    "$EMBEDDED_SBINJECT_ROOT" \
    "$EMBEDDED_APT_CONFIG_DIR" \
    "$EMBEDDED_KEYRING_DIR" \
    "$TRUSTED_ELLEKIT_ROOT" \
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
    -install_name /var/jb/usr/lib/sbinject/launchdhook.dylib \
    -o "$SBINJECT_LAUNCHDHOOK"
codesign --force --sign - --timestamp=none --pagesize 4096 \
    "$SBINJECT_LAUNCHDHOOK"

xcrun --sdk iphoneos clang \
    -arch arm64e \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -dynamiclib \
    -Os -Wall -Wextra -Werror \
    -I "$SBINJECT_SOURCE_DIR" \
    "$SBINJECT_SOURCE_DIR/sbinject_generalhook.c" \
    "$SBINJECT_SOURCE_DIR/sbinject_dyld_bypass.c" \
    -lsandbox \
    -install_name /var/jb/usr/lib/sbinject/generalhook.dylib \
    -o "$SBINJECT_GENERALHOOK"
codesign --force --sign - --timestamp=none --pagesize 4096 \
    "$SBINJECT_GENERALHOOK"

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
plutil -replace CFBundleIdentifier -string "$SILEO_BUNDLE_IDENTIFIER" \
    "$APP_DIR/Info.plist"

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
    "$SBINJECT_LAUNCHDHOOK" \
    "$SBINJECT_JITTERD" \
    "$SPRINGBOARD_CANDIDATE_GENERALHOOK" \
    "$SPRINGBOARD_CANDIDATE" \
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
cp "$APT_LIST_NORMALIZER" "$EMBEDDED_APT_LIST_NORMALIZER"
chmod 0644 "$EMBEDDED_DEFAULT_SOURCES" \
    "$EMBEDDED_REPOSITORY_COMPAT_CONFIG" \
    "$EMBEDDED_SBINJECT_APT_CONFIG" \
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
