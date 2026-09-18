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
UIKITTOOLS_URL=https://apt.procurs.us/pool/main/iphoneos-arm64-rootless/1900/uikittools/uikittools_2.1.8_iphoneos-arm64.deb
UIKITTOOLS_SHA256=5e634f0c7fb67f6344a6646583a9f1662cc9299a3d51817c1814bab4ecb3ecfb
ELLEKIT_KEY_FINGERPRINT=71C9AF96CD2F3A8A837EFFBB015D4A9B1D4A2370
BIGBOSS_KEY_FINGERPRINT=A9C96A37115894A23B894107694D17D38764B4F4
IDENTIFIER=com.openai.codex.dopamine.bootstrap
VERSION=${CODEX_CRYPTEX_VERSION:-1.0.$(date -u +%Y%m%d%H%M%S)}
SILEO_BUNDLE_IDENTIFIER=${CODEX_SILEO_BUNDLE_IDENTIFIER:-org.coolstar.SileoStore}
TARGET_UDID=${CODEX_TARGET_UDID:-}
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
UIKITTOOLS_DEB="$CACHE_DIR/uikittools_2.1.8_iphoneos-arm64.deb"
DEFAULT_SOURCES="$SCRIPT_DIR/dopamine-default.sources"
REPOSITORY_COMPAT_CONFIG="$SCRIPT_DIR/dopamine-repository-compat.conf"
RUNTIME_TRUST_APT_CONFIG="$SCRIPT_DIR/runtime-trust.conf"
APT_LIST_NORMALIZER="$SCRIPT_DIR/normalize_apt_lists.sh"
ELLEKIT_KEY="$SCRIPT_DIR/keyrings/ellekit.asc"
BIGBOSS_KEY="$SCRIPT_DIR/keyrings/bigboss.asc"
OPAINJECT_DIR="$REPO_DIR/BaseBin/opainject"
IMAGE_ROOT="$WORK_DIR/image-root"
EMBEDDED_DEFAULT_SOURCES="$IMAGE_ROOT/usr/local/share/codex-bootstrap/dopamine-default.sources"
EMBEDDED_APT_CONFIG_DIR="$IMAGE_ROOT/usr/local/share/codex-bootstrap/apt"
EMBEDDED_REPOSITORY_COMPAT_CONFIG="$EMBEDDED_APT_CONFIG_DIR/99dopamine-repository-compat"
EMBEDDED_RUNTIME_TRUST_APT_CONFIG="$EMBEDDED_APT_CONFIG_DIR/98codex-runtime-trust"
EMBEDDED_APT_LIST_NORMALIZER="$IMAGE_ROOT/usr/local/share/codex-bootstrap/normalize-apt-lists.sh"
EMBEDDED_BASE_CDHASHES="$IMAGE_ROOT/usr/local/share/codex-bootstrap/base-cdhashes.txt"
EMBEDDED_PROCURSUS_RUNTIME_BASELINE="$IMAGE_ROOT/usr/local/share/codex-bootstrap/procursus-runtime-baseline.plist"
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
EXEC_WORKER="$IMAGE_ROOT/usr/local/bin/codex-exec-worker"
EXEC_INTERPOSER="$IMAGE_ROOT/usr/local/lib/codex-exec-interposer.dylib"
DYLD_JB_ADMISSION_HOOK_SOURCE="$SCRIPT_DIR/../../Sources/codex-dyld-jb-admission-hook.c"
DYLD_JB_ADMISSION_HOOK_HEADER="$SCRIPT_DIR/../../Sources/codex-dyld-jb-admission-hook.h"
DYLD_JB_ADMISSION_HOOK="$IMAGE_ROOT/usr/local/lib/codex-dyld-jb-admission-hook.dylib"
DYLD_24A437_REFERENCE=${CODEX_DYLD_24A437_REFERENCE:-"$SCRIPT_DIR/../../build/dyld-24A437"}
DYLD_24A437_SHA256=ab9887ed96c9c08ad68d4c6a5c27e8289fb0c9e55ec3e134547292a1ec579608
ELLEKIT_COMPAT_ENTITLEMENTS="$SCRIPT_DIR/ellekit-compat-loader-entitlements.plist"
EXEC_WORKER_ENTITLEMENTS="$SCRIPT_DIR/exec-worker-entitlements.plist"
RUNTIME_TRUST_SOURCE=${CODEX_RUNTIME_TRUST_HELPER:-"$SCRIPT_DIR/../../build/appregistrard-srd-trust-derived/Build/Products/Release-iphoneos/appregistrard"}
RUNTIME_TRUST_HELPER="$IMAGE_ROOT/usr/local/bin/codex-runtime-trust"
RUNTIME_TRUST_CLIENT="$IMAGE_ROOT/usr/local/bin/codex-runtime-trust-client"
SPRINGBOARD_CANDIDATE_BUILDER="$SCRIPT_DIR/../../Scripts/build_springboard_candidate.py"
SPRINGBOARD_CANDIDATE_SOURCE=${CODEX_SPRINGBOARD_CANDIDATE_SOURCE:-"$SCRIPT_DIR/../../build/springboard-24A437/24A437__iPhone13,1/System/Library/CoreServices/SpringBoard.app/SpringBoard"}
SPRINGBOARD_CANDIDATE_INFO_SOURCE=${CODEX_SPRINGBOARD_CANDIDATE_INFO_SOURCE:-"$SCRIPT_DIR/../../build/springboard-candidate-24A437/Info.plist"}
SPRINGBOARD_CANDIDATE_DIRECTORY="$IMAGE_ROOT/usr/local/libexec/codex-springboard-candidate"
SPRINGBOARD_CANDIDATE="$SPRINGBOARD_CANDIDATE_DIRECTORY/SpringBoard"
SPRINGBOARD_CANDIDATE_INFO="$SPRINGBOARD_CANDIDATE_DIRECTORY/Info.plist"
SPRINGBOARD_CANDIDATE_ENTITLEMENTS="$SPRINGBOARD_CANDIDATE_DIRECTORY/entitlements.plist"
SPRINGBOARD_CANDIDATE_MANIFEST="$SPRINGBOARD_CANDIDATE_DIRECTORY/build-manifest.json"
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
PROCURSUS_RUNTIME_ENTITLEMENTS="$SIGNING_DIR/procursus-runtime-entitlements.plist"
PROCURSUS_RUNTIME_BASELINE_INPUT="$WORK_DIR/procursus-runtime-baseline.tsv"
PROCURSUS_RUNTIME_HISTORY_INPUT="$CACHE_DIR/procursus-runtime-history.tsv"
RUNTIME_INTERPOSER_INSTALL_NAME=/var/jb/usr/lib/codex-exec-interposer.dylib
DYLD_JB_ADMISSION_HOOK_INSTALL_NAME=/var/jb/usr/lib/codex-dyld-jb-admission-hook.dylib

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

enable_procursus_runtime_admission() {
    local candidate=$1
    local identifier
    local entitlement_key_path='com\.apple\.security\.cs\.allow-dyld-environment-variables'
    local skip_validation_key_path='com\.apple\.private\.skip-library-validation'
    local -a architectures

    architectures=($(lipo -archs "$candidate"))
    (( ${#architectures} > 0 )) || \
        die "Procursus executable has no architectures: $candidate"
    identifier=$(codesign -d --arch "${architectures[1]}" -vvv \
        "$candidate" 2>&1 | sed -n 's/^Identifier=//p')
    [[ -n "$identifier" ]] || \
        die "Procursus executable has no code identifier: $candidate"
    ldid -arch "${architectures[1]}" -e "$candidate" \
        >"$PROCURSUS_RUNTIME_ENTITLEMENTS"
    [[ -s "$PROCURSUS_RUNTIME_ENTITLEMENTS" ]] || \
        die "Procursus executable has no entitlements: $candidate"
    plutil -lint "$PROCURSUS_RUNTIME_ENTITLEMENTS" >/dev/null || \
        die "invalid Procursus entitlements: $candidate"
    python3 "$SCRIPT_DIR/patch_load_dylib.py" "$candidate" \
        "$RUNTIME_INTERPOSER_INSTALL_NAME" >/dev/null
    if plutil -extract "$entitlement_key_path" raw -o - \
        "$PROCURSUS_RUNTIME_ENTITLEMENTS" >/dev/null 2>&1; then
        plutil -replace "$entitlement_key_path" -bool true \
            "$PROCURSUS_RUNTIME_ENTITLEMENTS"
    else
        plutil -insert "$entitlement_key_path" -bool true \
            "$PROCURSUS_RUNTIME_ENTITLEMENTS"
    fi
    if plutil -extract "$skip_validation_key_path" raw -o - \
        "$PROCURSUS_RUNTIME_ENTITLEMENTS" >/dev/null 2>&1; then
        plutil -replace "$skip_validation_key_path" -bool true \
            "$PROCURSUS_RUNTIME_ENTITLEMENTS"
    else
        plutil -insert "$skip_validation_key_path" -bool true \
            "$PROCURSUS_RUNTIME_ENTITLEMENTS"
    fi
    codesign --force --sign - --timestamp=none --pagesize 4096 \
        --generate-entitlement-der --identifier "$identifier" \
        --entitlements "$PROCURSUS_RUNTIME_ENTITLEMENTS" "$candidate"
    codesign --verify --strict --all-architectures "$candidate" || \
        die "runtime-admission signature is invalid: $candidate"
    ldid -arch "${architectures[1]}" -e "$candidate" \
        >"$PROCURSUS_RUNTIME_ENTITLEMENTS"
    [[ "$(plutil -extract "$entitlement_key_path" raw -o - \
        "$PROCURSUS_RUNTIME_ENTITLEMENTS")" == true ]] || \
        die "runtime-admission entitlement is missing: $candidate"
    [[ "$(plutil -extract "$skip_validation_key_path" raw -o - \
        "$PROCURSUS_RUNTIME_ENTITLEMENTS")" == true ]] || \
        die "library-validation entitlement is missing: $candidate"
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
[[ -f "$APT_LIST_NORMALIZER" ]] || \
    die "missing APT package-list normalizer"
[[ -f "$SPRINGBOARD_CANDIDATE_BUILDER" ]] || \
    die "missing SpringBoard candidate builder"
[[ -f "$SPRINGBOARD_CANDIDATE_SOURCE" ]] || \
    die "missing pinned 24A437 SpringBoard source"
[[ -f "$SPRINGBOARD_CANDIDATE_INFO_SOURCE" ]] || \
    die "missing pinned 24A437 SpringBoard Info.plist source"
sh -n "$APT_LIST_NORMALIZER"
[[ -f "$ELLEKIT_KEY" ]] || die "missing ElleKit repository keyring"
[[ -f "$BIGBOSS_KEY" ]] || die "missing BigBoss repository keyring"
verify_keyring "$ELLEKIT_KEY" "$ELLEKIT_KEY_FINGERPRINT"
verify_keyring "$BIGBOSS_KEY" "$BIGBOSS_KEY_FINGERPRINT"
[[ -f "$SCRIPT_DIR/patch_sileo_postinst.py" ]] || \
    die "missing Sileo maintainer-script compatibility patch"
[[ -f "$SCRIPT_DIR/runtime_trust_client.c" ]] || \
    die "missing runtime trust broker client source"
[[ -f "$SCRIPT_DIR/codex_exec_interposer.c" ]] || \
    die "missing runtime execution interposer source"
[[ -f "$DYLD_JB_ADMISSION_HOOK_SOURCE" ]] || \
    die "missing dyld /var/jb admission hook source"
[[ -f "$DYLD_JB_ADMISSION_HOOK_HEADER" ]] || \
    die "missing dyld /var/jb admission hook header"
[[ -f "$DYLD_24A437_REFERENCE" ]] || \
    die "missing exact 24A437 dyld reference"
[[ "$(sha256_of "$DYLD_24A437_REFERENCE")" == "$DYLD_24A437_SHA256" ]] || \
    die "exact 24A437 dyld reference hash mismatch"
[[ -f "$SCRIPT_DIR/patch_load_dylib.py" ]] || \
    die "missing runtime interposer load-command patch"
[[ -f "$SCRIPT_DIR/prepare_runtime_baseline_history.py" ]] || \
    die "missing Procursus runtime baseline history helper"
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
fetch_pinned "$PREFERENCELOADER_URL" "$PREFERENCELOADER_SHA256" \
    "$PREFERENCELOADER_DEB"
fetch_pinned "$CHOICY_URL" "$CHOICY_SHA256" "$CHOICY_DEB"
fetch_pinned "$ALTLIST_URL" "$ALTLIST_SHA256" "$ALTLIST_DEB"
fetch_pinned "$UIKITTOOLS_URL" "$UIKITTOOLS_SHA256" "$UIKITTOOLS_DEB"
verify_deb_identity "$ELLEKIT_DEB" ellekit 1.2
verify_deb_identity "$PREFERENCELOADER_DEB" preferenceloader 2.2.8
verify_deb_identity "$CHOICY_DEB" com.opa334.choicy 1.5.4-2
verify_deb_identity "$ALTLIST_DEB" com.opa334.altlist 1.0.11
verify_deb_identity "$UIKITTOOLS_DEB" uikittools 2.1.8
[[ "$(sha256_of "$SILEO_DEB")" == "$SILEO_SHA256" ]] || \
    die "opa334 Sileo package hash mismatch"
zstd -t "$BOOTSTRAP_ARCHIVE" >/dev/null

PREVIOUS_PROCURSUS_ROOT="$IMAGE_ROOT/usr/local/share/codex-bootstrap/procursus"
PREVIOUS_PROCURSUS_RUNTIME_BASELINE="$IMAGE_ROOT/usr/local/share/codex-bootstrap/procursus-runtime-baseline.plist"
python3 "$SCRIPT_DIR/prepare_runtime_baseline_history.py" \
    "$PREVIOUS_PROCURSUS_ROOT" \
    "$PREVIOUS_PROCURSUS_RUNTIME_BASELINE" \
    "$PROCURSUS_RUNTIME_HISTORY_INPUT"

rm -rf "$IMAGE_ROOT" "$PACKAGE_ROOT" "$ORIGINAL_TRUSTED_PACKAGE_ROOT" \
    "$TRUSTED_PACKAGE_ROOT" \
    "$UNSIGNED_OUT" "$REPACKED_SILEO" "$TRUSTED_PACKAGE_CDHASHES" \
    "$TRUSTED_RUNTIME_CDHASHES" "$PROCURSUS_RUNTIME_BASELINE_INPUT"
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

# Build a fixed SpringBoard replacement from the exact extracted 24A437
# arm64e executable.  The helper pins the source hash/UUID/identifier,
# preserves every original entitlement, adds only the explicit debugging and
# runtime-code policy, regenerates XML+DER entitlement slots, and proves that
# the ad-hoc result is byte-for-byte deterministic.  It performs no device,
# TSS, personalization, or installation operation.
python3 "$SPRINGBOARD_CANDIDATE_BUILDER" \
    "$SPRINGBOARD_CANDIDATE_SOURCE" \
    "$SPRINGBOARD_CANDIDATE_DIRECTORY" \
    --info-plist "$SPRINGBOARD_CANDIDATE_INFO_SOURCE" >/dev/null
[[ -x "$SPRINGBOARD_CANDIDATE" ]] || \
    die "SpringBoard candidate was not produced"
[[ -f "$SPRINGBOARD_CANDIDATE_INFO" ]] || \
    die "SpringBoard candidate Info.plist was not produced"
[[ -f "$SPRINGBOARD_CANDIDATE_ENTITLEMENTS" ]] || \
    die "SpringBoard candidate entitlements were not produced"
[[ -f "$SPRINGBOARD_CANDIDATE_MANIFEST" ]] || \
    die "SpringBoard candidate manifest was not produced"
codesign --verify --strict --all-architectures --ignore-resources \
    "$SPRINGBOARD_CANDIDATE" || \
    die "SpringBoard candidate signature is invalid"

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

# Give every fixed Procursus executable a strong dependency on the fixed,
# trust-cached execution interposer. This avoids depending on dyld environment
# variables, which iOS can discard for platformized tools, while still routing
# only nonbaseline package payloads through the JIT worker. Preserve the
# bootstrap's existing platform/root policy; package-installed Mach-Os remain
# absent from the immutable Cryptex cache.
typeset -i procursus_runtime_executables=0
cp "$PROCURSUS_RUNTIME_HISTORY_INPUT" \
    "$PROCURSUS_RUNTIME_BASELINE_INPUT"
PROCURSUS_ROOT="$IMAGE_ROOT/usr/local/share/codex-bootstrap/procursus"
for candidate in \
    "$PROCURSUS_ROOT"/**/*(.); do
    file -b "$candidate" | rg -q '^Mach-O .*executable' || continue
    relative=${candidate#"$PROCURSUS_ROOT/"}
    original_sha256=$(sha256_of "$candidate")
    printf '%s\t%s\n' "$original_sha256" "$relative" \
        >>"$PROCURSUS_RUNTIME_BASELINE_INPUT"
    enable_procursus_runtime_admission "$candidate"
    normalized_sha256=$(sha256_of "$candidate")
    printf '%s\t%s\n' "$normalized_sha256" "$relative" \
        >>"$PROCURSUS_RUNTIME_BASELINE_INPUT"
    (( ++procursus_runtime_executables ))
done
(( procursus_runtime_executables > 0 )) || \
    die "Procursus runtime-admission executable set is empty"
python3 - "$PROCURSUS_RUNTIME_BASELINE_INPUT" \
    "$EMBEDDED_PROCURSUS_RUNTIME_BASELINE" \
    "$procursus_runtime_executables" <<'PY'
import pathlib
import plistlib
import re
import sys

source, destination, expected_count = sys.argv[1:]
entries = {}
for line in pathlib.Path(source).read_text().splitlines():
    digest, separator, relative = line.partition("\t")
    path = pathlib.PurePosixPath(relative)
    if (
        not separator
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
        or path.is_absolute()
        or not relative
        or any(component in {"", ".", ".."} for component in path.parts)
    ):
        raise SystemExit(f"invalid Procursus runtime baseline entry: {line!r}")
    entries.setdefault(relative, set()).add(digest)
if len(entries) != int(expected_count):
    raise SystemExit(
        f"Procursus runtime baseline count mismatch: {len(entries)} != "
        f"{expected_count}"
    )
with pathlib.Path(destination).open("wb") as stream:
    plistlib.dump(
        {
            "Version": 2,
            "Executables": {
                relative: sorted(digests)
                for relative, digests in sorted(entries.items())
            },
        },
        stream,
        fmt=plistlib.FMT_BINARY,
        sort_keys=True,
    )
PY
rm -f "$PROCURSUS_RUNTIME_ENTITLEMENTS"
print -r -- \
    "enabled runtime admission for $procursus_runtime_executables Procursus executables"

dpkg-deb -R "$SILEO_DEB" "$PACKAGE_ROOT"
python3 "$SCRIPT_DIR/patch_sileo_postinst.py" \
    "$PACKAGE_ROOT/DEBIAN/postinst"
APP_DIR="$PACKAGE_ROOT/var/jb/Applications/Sileo.app"
[[ -x "$APP_DIR/Sileo" && -x "$APP_DIR/giveMeRoot" ]] || \
    die "Sileo package is missing expected executables"
plutil -replace CFBundleIdentifier -string "$SILEO_BUNDLE_IDENTIFIER" \
    "$APP_DIR/Info.plist"

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
dpkg-deb -x "$UIKITTOOLS_DEB" "$ORIGINAL_TRUSTED_PACKAGE_ROOT/uikittools"
ditto --noqtn "$ORIGINAL_TRUSTED_PACKAGE_ROOT" "$TRUSTED_PACKAGE_ROOT"

# These jailbreak packages use legacy signatures that iOS 27 rejects even
# when the old cdhash is present in a Cryptex trust cache. Re-sign exact copies
# with a current ad-hoc CodeDirectory, retaining any declared entitlements.
for candidate in "$TRUSTED_PACKAGE_ROOT"/**/*(.); do
    file -b "$candidate" | rg -q '^Mach-O' || continue
    if [[ "$candidate" == "$TRUSTED_PACKAGE_ROOT/uikittools/"* ]]; then
        codesign --verify --strict --all-architectures "$candidate" || \
            die "pinned uikittools signature is invalid: $candidate"
        continue
    fi
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

xcrun --sdk iphoneos clang \
    -arch arm64 \
    -arch arm64e \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -dynamiclib \
    -install_name /var/jb/usr/lib/codex-exec-interposer.dylib \
    -Os -Wall -Wextra -Werror \
    "$SCRIPT_DIR/codex_exec_interposer.c" \
    -o "$EXEC_INTERPOSER"
codesign --force --sign - --timestamp=none --pagesize 4096 \
    "$EXEC_INTERPOSER"
codesign --verify --strict --all-architectures "$EXEC_INTERPOSER" || \
    die "execution interposer signature is invalid"

xcrun --sdk iphoneos clang \
    -arch arm64e \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -dynamiclib \
    -install_name "$DYLD_JB_ADMISSION_HOOK_INSTALL_NAME" \
    -Os -fvisibility=hidden -Wall -Wextra -Werror \
    "$DYLD_JB_ADMISSION_HOOK_SOURCE" \
    -o "$DYLD_JB_ADMISSION_HOOK"
codesign --force --sign - --timestamp=none --pagesize 4096 \
    "$DYLD_JB_ADMISSION_HOOK"
codesign --verify --strict --all-architectures \
    "$DYLD_JB_ADMISSION_HOOK" || \
    die "dyld /var/jb admission hook signature is invalid"
[[ "$(lipo -archs "$DYLD_JB_ADMISSION_HOOK")" == arm64e ]] || \
    die "dyld /var/jb admission hook is not exactly arm64e"
[[ "$(otool -D "$DYLD_JB_ADMISSION_HOOK" | tail -n 1)" == \
   "$DYLD_JB_ADMISSION_HOOK_INSTALL_NAME" ]] || \
    die "dyld /var/jb admission hook install name is invalid"

xcrun --sdk iphoneos clang \
    -arch arm64 \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -fblocks \
    -Wall -Wextra -Werror \
    -I "$SCRIPT_DIR" \
    "$SCRIPT_DIR/runtime_trust_client.c" \
    -o "$RUNTIME_TRUST_CLIENT"
codesign --force --sign - --timestamp=none --pagesize 4096 \
    "$RUNTIME_TRUST_CLIENT"
codesign --verify --strict --all-architectures "$RUNTIME_TRUST_CLIENT" || \
    die "runtime trust broker client signature is invalid"

[[ -x "$RUNTIME_TRUST_SOURCE" ]] || \
    die "runtime trust helper is unavailable: $RUNTIME_TRUST_SOURCE"
cp "$RUNTIME_TRUST_SOURCE" "$RUNTIME_TRUST_HELPER"
chmod 0755 "$RUNTIME_TRUST_HELPER"
codesign --verify --strict --all-architectures "$RUNTIME_TRUST_HELPER" || \
    die "runtime trust helper signature is invalid"
ldid -e "$RUNTIME_TRUST_HELPER" | rg -q \
    '<key>com.apple.private.amfi.can-load-trust-cache</key>' || \
    die "runtime trust helper lacks AMFI trust-cache entitlement"
ldid -e "$RUNTIME_TRUST_HELPER" | rg -q \
    '<key>com.apple.security.network.client</key>' || \
    die "runtime trust helper lacks TSS network entitlement"

typeset -a trusted_runtime_cdhashes
for candidate in \
    "$ELLEKIT_COMPAT_LOADER" \
    "$EXEC_WORKER" \
    "$EXEC_INTERPOSER" \
    "$DYLD_JB_ADMISSION_HOOK" \
    "$RUNTIME_TRUST_CLIENT" \
    "$RUNTIME_TRUST_HELPER" \
    "$SPRINGBOARD_CANDIDATE"; do
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
cp "$RUNTIME_TRUST_APT_CONFIG" \
    "$EMBEDDED_RUNTIME_TRUST_APT_CONFIG"
cp "$APT_LIST_NORMALIZER" "$EMBEDDED_APT_LIST_NORMALIZER"
chmod 0644 "$EMBEDDED_DEFAULT_SOURCES" \
    "$EMBEDDED_REPOSITORY_COMPAT_CONFIG" \
    "$EMBEDDED_RUNTIME_TRUST_APT_CONFIG" \
    "$EMBEDDED_APT_LIST_NORMALIZER"
gpg --batch --yes --dearmor --output "$EMBEDDED_ELLEKIT_KEY" "$ELLEKIT_KEY"
gpg --batch --yes --dearmor --output "$EMBEDDED_BIGBOSS_KEY" "$BIGBOSS_KEY"
chmod 0644 "$EMBEDDED_ELLEKIT_KEY" "$EMBEDDED_BIGBOSS_KEY"
verify_keyring "$EMBEDDED_ELLEKIT_KEY" "$ELLEKIT_KEY_FINGERPRINT"
verify_keyring "$EMBEDDED_BIGBOSS_KEY" "$BIGBOSS_KEY_FINGERPRINT"

# Generate the admission baseline from every Mach-O that will be present when
# cryptexctl creates the static trust cache.  Package-installed binaries are
# deliberately absent from this immutable set and therefore take the runtime
# worker path without rebuilding the Cryptex.
typeset -a base_cdhashes
for candidate in "$IMAGE_ROOT"/**/*(.); do
    file -b "$candidate" | rg -q '^Mach-O' || continue
    for architecture in $(lipo -archs "$candidate"); do
        cdhash=$(codesign -d --arch "$architecture" -vvvv "$candidate" \
            2>&1 | sed -n 's/^CDHash=//p')
        print -r -- "$cdhash" | rg -q '^[0-9a-f]{40}$' || \
            die "could not derive baseline $architecture cdhash for $candidate"
        base_cdhashes+=("$cdhash")
    done
done
(( ${#base_cdhashes} > 0 )) || die "runtime admission baseline is empty"
printf '%s\n' "${base_cdhashes[@]}" | sort -u \
    >"$EMBEDDED_BASE_CDHASHES"
chmod 0644 "$EMBEDDED_BASE_CDHASHES"

"$CRYPTEXCTL" create \
    --use-cryptex1-format \
    --use-product-class \
    --FCHP 0xff10 \
    --TYPE 3 \
    --STYP 0 \
    --CLAS 0xf2 \
    --identifier "$IDENTIFIER" \
    --version "$VERSION" \
    --output-directory "$UNSIGNED_OUT" \
    "$IMAGE_ROOT"

BUNDLE="$UNSIGNED_OUT/$IDENTIFIER.cxbd"
[[ -d "$BUNDLE/Restore/Cryptex" ]] || die "cryptexctl did not emit $BUNDLE"
VARIANT_DIRS=("$BUNDLE"/Restore/Cryptex/*(N/))
(( ${#VARIANT_DIRS} == 1 )) || die "expected one Cryptex variant"
TRUSTCACHE="${VARIANT_DIRS[1]}/gtcd"
TRUSTCACHE_DUMP="$OUT_DIR/trustcache.txt"
"$CRYPTEXCTL" dump-trust-cache "$TRUSTCACHE" >"$TRUSTCACHE_DUMP"
ENTRY_COUNT=$(sed -n 's/^entry count = //p' "$TRUSTCACHE_DUMP")
[[ "$ENTRY_COUNT" == <-> ]] || die "could not parse trust-cache entry count"
while IFS= read -r cdhash; do
    rg -q "^${cdhash} " "$TRUSTCACHE_DUMP" || \
        die "trusted package cdhash is absent from Cryptex trust cache: $cdhash"
done <"$TRUSTED_PACKAGE_CDHASHES"
while IFS= read -r cdhash; do
    rg -q "^${cdhash} " "$TRUSTCACHE_DUMP" || \
        die "trusted runtime cdhash is absent from Cryptex trust cache: $cdhash"
done <"$TRUSTED_RUNTIME_CDHASHES"
while IFS= read -r cdhash; do
    rg -q "^${cdhash} " "$TRUSTCACHE_DUMP" || \
        die "runtime admission baseline is absent from trust cache: $cdhash"
done <"$EMBEDDED_BASE_CDHASHES"

python3 - "$SUMMARY" "$BUNDLE" "$IDENTIFIER" "$VERSION" \
    "$BOOTSTRAP_ARCHIVE" "$SILEO_DEB" "$REPACKED_SILEO" \
    "$TRUSTCACHE" "$TRUSTCACHE_DUMP" "$ENTRY_COUNT" \
    "$SILEO_DEVELOPMENT_IDENTITY" "$SILEO_PROVISIONING_PROFILE" \
    "$SILEO_DEVELOPMENT_ENTITLEMENTS" "$DEFAULT_SOURCES" \
    "$EMBEDDED_DEFAULT_SOURCES" \
    "$REPOSITORY_COMPAT_CONFIG" \
    "$EMBEDDED_REPOSITORY_COMPAT_CONFIG" \
    "$APT_LIST_NORMALIZER" "$EMBEDDED_APT_LIST_NORMALIZER" \
    "$ELLEKIT_KEY" "$EMBEDDED_ELLEKIT_KEY" \
    "$ELLEKIT_KEY_FINGERPRINT" \
    "$BIGBOSS_KEY" "$EMBEDDED_BIGBOSS_KEY" \
    "$BIGBOSS_KEY_FINGERPRINT" \
    "$TRUSTED_PACKAGE_CDHASHES" \
    "$ELLEKIT_DEB" "$PREFERENCELOADER_DEB" "$CHOICY_DEB" \
    "$ALTLIST_DEB" "$UIKITTOOLS_DEB" "$TRUSTED_RUNTIME_CDHASHES" \
    "$ELLEKIT_COMPAT_LOADER" "$EXEC_WORKER" "$EXEC_INTERPOSER" \
    "$DYLD_JB_ADMISSION_HOOK" \
    "$RUNTIME_TRUST_CLIENT" "$RUNTIME_TRUST_HELPER" \
    "$SPRINGBOARD_CANDIDATE" "$SPRINGBOARD_CANDIDATE_INFO" \
    "$SPRINGBOARD_CANDIDATE_ENTITLEMENTS" \
    "$SPRINGBOARD_CANDIDATE_MANIFEST" <<'PY'
import hashlib
import json
import pathlib
import plistlib
import re
import sys

(
    summary_path,
    bundle,
    identifier,
    version,
    bootstrap,
    sileo,
    repacked_sileo,
    trustcache,
    trustcache_dump,
    entry_count,
    sileo_development_identity,
    sileo_provisioning_profile,
    sileo_development_entitlements,
    default_sources,
    embedded_default_sources,
    repository_compat_config,
    embedded_repository_compat_config,
    apt_list_normalizer,
    embedded_apt_list_normalizer,
    ellekit_key,
    embedded_ellekit_key,
    ellekit_key_fingerprint,
    bigboss_key,
    embedded_bigboss_key,
    bigboss_key_fingerprint,
    trusted_package_cdhashes,
    ellekit_deb,
    preferenceloader_deb,
    choicy_deb,
    altlist_deb,
    uikittools_deb,
    trusted_runtime_cdhashes,
    ellekit_compat_loader,
    exec_worker,
    exec_interposer,
    dyld_jb_admission_hook,
    runtime_trust_client,
    runtime_trust_helper,
    springboard_candidate,
    springboard_candidate_info,
    springboard_candidate_entitlements,
    springboard_candidate_manifest,
) = sys.argv[1:]

def sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

expected_default_source_uris = [
    "https://repo.chariz.com/",
    "https://havoc.app/",
    "http://apt.thebigboss.org/repofiles/cydia/",
    "https://ellekit.space/",
]
default_source_lines = pathlib.Path(default_sources).read_text().splitlines()
default_source_uris = [
    line.removeprefix("URIs: ")
    for line in default_source_lines
    if line.startswith("URIs: ")
]
expected_default_source_signed_by = [
    "3D32F8ECD0930A1BC4F2A4A817C6BB3FC4114BDF!",
    "C101A4205F8616491D9B23BAB4532449E1E8AA68!",
    "A9C96A37115894A23B894107694D17D38764B4F4!",
    "71C9AF96CD2F3A8A837EFFBB015D4A9B1D4A2370!",
]
default_source_signed_by = [
    line.removeprefix("Signed-By: ")
    for line in default_source_lines
    if line.startswith("Signed-By: ")
]
if default_source_uris != expected_default_source_uris:
    raise SystemExit(
        "Dopamine default APT source list mismatch: "
        f"expected {expected_default_source_uris}, got {default_source_uris}"
    )
if default_source_signed_by != expected_default_source_signed_by:
    raise SystemExit(
        "Dopamine default APT source keyring list mismatch: "
        f"expected {expected_default_source_signed_by}, "
        f"got {default_source_signed_by}"
    )
if any(line.startswith("Allow-Weak:") for line in default_source_lines):
    raise SystemExit(
        "default APT sources must keep signature verification enabled"
    )
if sha256(default_sources) != sha256(embedded_default_sources):
    raise SystemExit("embedded default APT source payload mismatch")
expected_repository_compat = (
    '// BigBoss currently signs its Release metadata with a legacy DSA/SHA-1 key.\n'
    '// Keep signature verification enabled while classifying SHA-1 as a warning.\n'
    'APT::Hashes::SHA1::Weak "true";\n'
    'APT::Key::Assert-Pubkey-Algo ">=rsa2048,ed25519,ed448,dsa1024";\n'
    'APT::Update::Post-Invoke-Success { "/var/jb/bin/sh '
    '/var/jb/usr/libexec/codex-normalize-apt-lists"; };\n'
)
repository_compat_text = pathlib.Path(repository_compat_config).read_text()
if repository_compat_text != expected_repository_compat:
    raise SystemExit("unexpected repository compatibility configuration")
if sha256(repository_compat_config) != sha256(embedded_repository_compat_config):
    raise SystemExit("embedded repository compatibility payload mismatch")
if sha256(apt_list_normalizer) != sha256(embedded_apt_list_normalizer):
    raise SystemExit("embedded APT package-list normalizer mismatch")
lines = pathlib.Path(trustcache_dump).read_text().splitlines()
cdhashes = [
    match.group(1)
    for line in lines
    if (match := re.match(r"^([0-9a-f]{40})\s+", line))
]
if len(cdhashes) != int(entry_count):
    raise SystemExit("trust-cache dump count mismatch")
trusted_cdhashes = sorted(
    set(pathlib.Path(trusted_package_cdhashes).read_text().splitlines())
)
trusted_runtime_hashes = sorted(
    set(pathlib.Path(trusted_runtime_cdhashes).read_text().splitlines())
)
missing_trusted_cdhashes = sorted(set(trusted_cdhashes) - set(cdhashes))
if missing_trusted_cdhashes:
    raise SystemExit(
        "trusted package cdhashes missing from trust cache: "
        + ", ".join(missing_trusted_cdhashes)
    )

build_manifest = plistlib.loads(
    pathlib.Path(bundle, "Restore", "BuildManifest.plist").read_bytes()
)
identities = build_manifest.get("BuildIdentities", [])
if len(identities) != 1:
    raise SystemExit(f"expected one Cryptex identity, got {len(identities)}")
identity = identities[0]
expected_identity = {
    "Cryptex1,ChipID": "0xff10",
    "Cryptex1,Type": 3,
    "Cryptex1,SubType": 0,
    "Cryptex1,ProductClass": "0xf2",
    "Cryptex1,NonceDomain": 3,
    "Cryptex1,UseProductClass": True,
    "Cryptex1,Version": "999.999.999.999.999,999",
    "Cryptex1,PreauthorizationVersion": "999.999.999.999.999,999",
}
mismatches = {
    key: {"expected": value, "actual": identity.get(key)}
    for key, value in expected_identity.items()
    if identity.get(key) != value
}
if mismatches:
    raise SystemExit(f"generic Cryptex identity mismatch: {mismatches}")

summary = {
    "identifier": identifier,
    "version": version,
    "bundle": str(pathlib.Path(bundle).resolve()),
    "cryptexIdentity": expected_identity,
    "inputs": {
        "bootstrap": {"path": bootstrap, "sha256": sha256(bootstrap)},
        "sileo": {"path": sileo, "sha256": sha256(sileo)},
        "repackedSileo": {
            "path": repacked_sileo,
            "sha256": sha256(repacked_sileo),
        },
        "defaultAptSources": {
            "path": default_sources,
            "sha256": sha256(default_sources),
            "embeddedPath": embedded_default_sources,
            "embeddedSha256": sha256(embedded_default_sources),
            "uris": default_source_uris,
            "signedBy": default_source_signed_by,
        },
        "repositoryCompatibility": {
            "path": repository_compat_config,
            "sha256": sha256(repository_compat_config),
            "embeddedPath": embedded_repository_compat_config,
            "embeddedSha256": sha256(embedded_repository_compat_config),
        },
        "aptListNormalizer": {
            "path": apt_list_normalizer,
            "sha256": sha256(apt_list_normalizer),
            "embeddedPath": embedded_apt_list_normalizer,
            "embeddedSha256": sha256(embedded_apt_list_normalizer),
        },
        "repositoryKeyrings": {
            "ellekit": {
                "path": ellekit_key,
                "sha256": sha256(ellekit_key),
                "embeddedPath": embedded_ellekit_key,
                "embeddedSha256": sha256(embedded_ellekit_key),
                "fingerprint": ellekit_key_fingerprint,
            },
            "bigboss": {
                "path": bigboss_key,
                "sha256": sha256(bigboss_key),
                "embeddedPath": embedded_bigboss_key,
                "embeddedSha256": sha256(embedded_bigboss_key),
                "fingerprint": bigboss_key_fingerprint,
            },
        },
        "trustedPackages": {
            "archives": [
                {
                    "package": package,
                    "version": package_version,
                    "path": archive,
                    "sha256": sha256(archive),
                }
                for package, package_version, archive in (
                    ("ellekit", "1.2", ellekit_deb),
                    ("preferenceloader", "2.2.8", preferenceloader_deb),
                    ("com.opa334.choicy", "1.5.4-2", choicy_deb),
                    ("com.opa334.altlist", "1.0.11", altlist_deb),
                    ("uikittools", "2.1.8", uikittools_deb),
                )
            ],
            "cdhashes": trusted_cdhashes,
        },
        "trustedRuntime": {
            "artifacts": [
                {
                    "name": "codex-ellekit-loader",
                    "path": ellekit_compat_loader,
                    "sha256": sha256(ellekit_compat_loader),
                },
                {
                    "name": "codex-exec-worker",
                    "path": exec_worker,
                    "sha256": sha256(exec_worker),
                },
                {
                    "name": "codex-exec-interposer.dylib",
                    "path": exec_interposer,
                    "sha256": sha256(exec_interposer),
                },
                {
                    "name": "codex-dyld-jb-admission-hook.dylib",
                    "path": dyld_jb_admission_hook,
                    "sha256": sha256(dyld_jb_admission_hook),
                },
                {
                    "name": "codex-runtime-trust-client",
                    "path": runtime_trust_client,
                    "sha256": sha256(runtime_trust_client),
                },
                {
                    "name": "codex-runtime-trust",
                    "path": runtime_trust_helper,
                    "sha256": sha256(runtime_trust_helper),
                },
                {
                    "name": "codex-springboard-candidate",
                    "path": springboard_candidate,
                    "sha256": sha256(springboard_candidate),
                },
            ],
            "cdhashes": trusted_runtime_hashes,
        },
        "springboardCandidate": {
            "artifact": {
                "path": springboard_candidate,
                "sha256": sha256(springboard_candidate),
            },
            "buildManifest": {
                "path": springboard_candidate_manifest,
                "sha256": sha256(springboard_candidate_manifest),
                "value": json.loads(
                    pathlib.Path(springboard_candidate_manifest).read_text()
                ),
            },
            "infoPlist": {
                "path": springboard_candidate_info,
                "sha256": sha256(springboard_candidate_info),
                "value": plistlib.loads(
                    pathlib.Path(springboard_candidate_info).read_bytes()
                ),
            },
            "entitlements": {
                "path": springboard_candidate_entitlements,
                "sha256": sha256(springboard_candidate_entitlements),
            },
            "installedPath": (
                "/var/jb/usr/libexec/codex-springboard-candidate/SpringBoard"
            ),
        },
    },
    "sileoDevelopmentSigning": {
        "identitySha1": sileo_development_identity,
        "provisioningProfile": {
            "path": sileo_provisioning_profile,
            "sha256": sha256(sileo_provisioning_profile),
        },
        "entitlements": {
            "path": sileo_development_entitlements,
            "sha256": sha256(sileo_development_entitlements),
        },
    },
    "trustCache": {
        "path": trustcache,
        "sha256": sha256(trustcache),
        "entryCount": int(entry_count),
        "cdhashes": cdhashes,
    },
}
pathlib.Path(summary_path).write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\n"
)
print(json.dumps(summary, indent=2, sort_keys=True))
PY

print -- "unsignedBundle=$BUNDLE"
print -- "buildSummary=$SUMMARY"
