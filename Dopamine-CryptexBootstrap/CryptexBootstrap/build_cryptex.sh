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
LDID_URL=https://apt.procurs.us/pool/main/iphoneos-arm64-rootless/1900/ldid/ldid_2.1.5-procursus7_iphoneos-arm64.deb
LDID_SHA256=f0808557064279e2e4febe443ed1e4fed76de42abf3491a45caca14915fd0895
LIBPLIST_URL='https://apt.procurs.us/pool/main/iphoneos-arm64-rootless/1900/libplist/libplist3_2.2.0%2Bgit20230130.4b50a5a_iphoneos-arm64.deb'
LIBPLIST_SHA256=87f3e16108cc943d1c22a77a7f6bbcdef1d2f48bab0a23f867833e09dbd7d3ea
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
LDID_DEB="$CACHE_DIR/ldid_2.1.5-procursus7_iphoneos-arm64.deb"
LIBPLIST_DEB="$CACHE_DIR/libplist3_2.2.0+git20230130.4b50a5a_iphoneos-arm64.deb"
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
RUNTIME_TRUST_SOURCE=${CODEX_RUNTIME_TRUST_HELPER:-"$SCRIPT_DIR/../../build/appregistrard-srd-trust-derived/Build/Products/Release-iphoneos/appregistrard"}
RUNTIME_TRUST_HELPER="$IMAGE_ROOT/usr/local/bin/codex-runtime-trust"
RUNTIME_TRUST_CLIENT="$IMAGE_ROOT/usr/local/bin/codex-runtime-trust-client"
SIGNEXEC="$IMAGE_ROOT/usr/local/bin/codex-signexec"
SIGNEXEC_LDID="$IMAGE_ROOT/usr/local/bin/codex-signexec-ldid"
SIGNEXEC_PAYLOAD_ENTITLEMENTS="$IMAGE_ROOT/usr/local/share/codex-bootstrap/signexec-payload-entitlements.plist"
JIT_ENABLE="$IMAGE_ROOT/usr/local/bin/codex-jit-enable"
LIVECONTAINER_HOST=${CODEX_LIVECONTAINER_HOST:-"$SCRIPT_DIR/../../build/livecontainer-derived/Build/Products/Release-iphoneos/LiveContainer.app"}
EMBEDDED_LIVECONTAINER_HOST="$IMAGE_ROOT/usr/local/share/codex-bootstrap/LiveContainer.app"
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
    # Platformized executables make dyld ignore __interpose sections, which
    # would silence the execution interposer; platform-application is not
    # needed for Procursus CLI tools, which are admitted by the Cryptex trust
    # cache and keep their explicit private entitlements.
    plutil -remove platform-application "$PROCURSUS_RUNTIME_ENTITLEMENTS" \
        >/dev/null 2>&1 || true
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

for tool in awk codesign curl dpkg-deb file find gpg ldid lipo nm plutil python3 rg security shasum tar xcrun zstd; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done
[[ -x "$CRYPTEXCTL" ]] || die "missing SRD cryptexctl: $CRYPTEXCTL"
[[ -f "$SILEO_DEB" ]] || die "missing opa334 Sileo package: $SILEO_DEB"
[[ -f "$DEFAULT_SOURCES" ]] || die "missing Dopamine default APT sources"
[[ -f "$REPOSITORY_COMPAT_CONFIG" ]] || \
    die "missing Dopamine repository compatibility configuration"
[[ -f "$APT_LIST_NORMALIZER" ]] || \
    die "missing APT package-list normalizer"
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

CRYPTEX_ONLY_SIGNING=0
if [[ "$SILEO_DEVELOPMENT_IDENTITY" == "cryptex-only" ]]; then
    CRYPTEX_ONLY_SIGNING=1
    print -- "Sileo signing mode: cryptex ad-hoc (no provisioning profile)"
else
    [[ -f "$SILEO_PROVISIONING_PROFILE" ]] || \
        die "missing Sileo provisioning profile: $SILEO_PROVISIONING_PROFILE"
    [[ -f "$SILEO_DEVELOPMENT_ENTITLEMENTS" ]] || \
        die "missing Sileo development entitlements: $SILEO_DEVELOPMENT_ENTITLEMENTS"
    security find-identity -v -p codesigning | \
        rg -q "$SILEO_DEVELOPMENT_IDENTITY" || \
        die "Sileo development identity is unavailable: $SILEO_DEVELOPMENT_IDENTITY"
fi
fetch_pinned "$BOOTSTRAP_URL" "$BOOTSTRAP_SHA256" "$BOOTSTRAP_ARCHIVE"
fetch_pinned "$ELLEKIT_URL" "$ELLEKIT_SHA256" "$ELLEKIT_DEB"
fetch_pinned "$PREFERENCELOADER_URL" "$PREFERENCELOADER_SHA256" \
    "$PREFERENCELOADER_DEB"
fetch_pinned "$CHOICY_URL" "$CHOICY_SHA256" "$CHOICY_DEB"
fetch_pinned "$ALTLIST_URL" "$ALTLIST_SHA256" "$ALTLIST_DEB"
fetch_pinned "$UIKITTOOLS_URL" "$UIKITTOOLS_SHA256" "$UIKITTOOLS_DEB"
fetch_pinned "$LDID_URL" "$LDID_SHA256" "$LDID_DEB"
verify_deb_identity "$LDID_DEB" ldid 2.1.5-procursus7
fetch_pinned "$LIBPLIST_URL" "$LIBPLIST_SHA256" "$LIBPLIST_DEB"
verify_deb_identity "$LIBPLIST_DEB" libplist3 2.2.0+git20230130.4b50a5a
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

zstd -dc "$BOOTSTRAP_ARCHIVE" | \
    tar -xf - -C "$WORK_DIR"
[[ -d "$WORK_DIR/var/jb" ]] || die "archive did not extract var/jb"
ditto --noqtn "$WORK_DIR/var/jb" \
    "$IMAGE_ROOT/usr/local/share/codex-bootstrap/procursus"
rm -rf "$WORK_DIR/var"

# ldid and package-installed tools link libplist/libcrypto from the jailbreak
# root.  The bootstrap's copies carry legacy-format signatures that iOS 27
# rejects even when the cdhash is trust-cached (the same failure class as the
# legacy tweak packages below).  Embed current-format ad-hoc re-signed copies
# and let the daemon synchronize them over the installed tree on repair.
rm -rf "$WORK_DIR/libplist-package"
dpkg-deb -x "$LIBPLIST_DEB" "$WORK_DIR/libplist-package"
install -m 0755 \
    "$WORK_DIR/libplist-package/var/jb/usr/lib/libplist-2.0.3.dylib" \
    "$IMAGE_ROOT/usr/local/share/codex-bootstrap/procursus/usr/lib/libplist-2.0.3.dylib"
for runtime_library in \
    "$IMAGE_ROOT/usr/local/share/codex-bootstrap/procursus/usr/lib/libplist-2.0.3.dylib" \
    "$IMAGE_ROOT/usr/local/share/codex-bootstrap/procursus/usr/lib/libcrypto.3.dylib"; do
    [[ -f "$runtime_library" ]] || \
        die "missing Procursus runtime library: ${runtime_library:t}"
    library_entitlements="$WORK_DIR/$(uuidgen).plist"
    ldid -e "$runtime_library" >"$library_entitlements" 2>/dev/null || true
    if [[ -s "$library_entitlements" ]]; then
        codesign --force --sign - --timestamp=none --pagesize 4096 \
            --generate-entitlement-der \
            --entitlements "$library_entitlements" "$runtime_library"
    else
        codesign --force --sign - --timestamp=none --pagesize 4096 \
            --generate-entitlement-der "$runtime_library"
    fi
    rm -f "$library_entitlements"
    codesign --verify --strict --all-architectures "$runtime_library" || \
        die "Procursus runtime library re-signature is invalid: ${runtime_library:t}"
done

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
codesign --force --sign - --timestamp=none \
    --pagesize 4096 "$APP_DIR/giveMeRoot"
chmod 0755 "$APP_DIR/giveMeRoot"

# Permanently signed Cryptex Sileo: ad-hoc and covered by the immutable trust
# cache, so the registered jailbreak copy never depends on a provisioning
# profile.  The broker constructor shim (the F/libzstd.1.dylib re-export
# trick) is applied to this copy exactly as the launcher IPA build does, and
# scoped absolute-path exceptions let its sandboxed dyld read the bundled
# runtime.
SILEO_CRYPTEX_ENTITLEMENTS="$SIGNING_DIR/sileo-cryptex-entitlements.plist"
python3 - "$SILEO_DEVELOPMENT_ENTITLEMENTS" "$SILEO_CRYPTEX_ENTITLEMENTS" <<'PY'
import plistlib
import sys

with open(sys.argv[1], "rb") as handle:
    entitlements = plistlib.load(handle)
# Operator-directed maximal trust level.  Admission comes from the Cryptex
# trust cache, so no provisioning profile is needed for any of these; the set
# mirrors the proven LiveContainer host profile.
entitlements.update({
    "com.apple.developer.kernel.increased-memory-limit": True,
    "com.apple.developer.kernel.extended-virtual-addressing": True,
    "com.apple.private.MobileContainerManager.allowed": True,
    "com.apple.private.security.container-manager": True,
    "com.apple.private.security.no-container": True,
    "com.apple.private.security.no-sandbox": True,
    "com.apple.private.security.sandbox": False,
    "com.apple.private.security.storage.AppBundles": True,
    "com.apple.private.security.storage.AppDataContainers": True,
    "com.apple.private.skip-library-validation": True,
    "com.apple.security.cs.allow-dyld-environment-variables": True,
    "com.apple.security.cs.allow-jit": True,
    "com.apple.security.cs.disable-library-validation": True,
    "dynamic-codesigning": True,
    "platform-application": True,
    "task_for_pid-allow": True,
})
with open(sys.argv[2], "wb") as handle:
    plistlib.dump(entitlements, handle)
PY
mkdir -p "$APP_DIR/F"
cp "$IMAGE_ROOT/usr/local/share/codex-bootstrap/procursus/usr/lib/libiosexec.1.dylib" \
    "$APP_DIR/F/libiosexec.1.dylib"
cp "$IMAGE_ROOT/usr/local/share/codex-bootstrap/procursus/usr/lib/liblzma.5.dylib" \
    "$APP_DIR/F/liblzma.5.dylib"
cp "$IMAGE_ROOT/usr/local/share/codex-bootstrap/procursus/usr/lib/libzstd.1.5.5.dylib" \
    "$APP_DIR/F/libzstd.real.dylib"
install_name_tool -rpath /opt/procursus/lib @loader_path/F "$APP_DIR/Sileo"
install_name_tool -id @rpath/libzstd.real.dylib "$APP_DIR/F/libzstd.real.dylib"
xcrun --sdk iphoneos clang \
    -arch arm64 \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -dynamiclib \
    -fblocks \
    -Wall -Wextra -Werror \
    -lsandbox \
    -Wl,-install_name,@rpath/libzstd.1.dylib \
    -Wl,-reexport_library,"$APP_DIR/F/libzstd.real.dylib" \
    "$SCRIPT_DIR/sileo_broker_constructor.c" \
    -o "$APP_DIR/F/libzstd.1.dylib"
for library in "$APP_DIR/F"/*.dylib; do
    codesign --force --sign - --timestamp=none --pagesize 4096 "$library"
done
codesign --force --sign - --timestamp=none \
    --pagesize 4096 --entitlements "$SILEO_CRYPTEX_ENTITLEMENTS" \
    --generate-entitlement-der \
    "$APP_DIR"
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
    --entitlements "$SCRIPT_DIR/ellekit-compat-loader-entitlements.plist" \
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
    --entitlements "$SCRIPT_DIR/exec-worker-entitlements.plist" \
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

# Serotonin-style runtime admission: a fixed signer/trust broker pair that
# resigns payload copies with get-task-allow and loads a personalized runtime
# trust cache for their cdhashes.
rm -rf "$WORK_DIR/ldid-package"
dpkg-deb -x "$LDID_DEB" "$WORK_DIR/ldid-package"
install -m 0755 "$WORK_DIR/ldid-package/var/jb/usr/bin/ldid" "$SIGNEXEC_LDID"
codesign --force --sign - --timestamp=none --pagesize 4096 "$SIGNEXEC_LDID"
codesign --verify --strict --all-architectures "$SIGNEXEC_LDID" || \
    die "signexec ldid signature is invalid"

xcrun --sdk iphoneos clang \
    -arch arm64 \
    -arch arm64e \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -Wall -Wextra -Werror \
    "$SCRIPT_DIR/codex_signexec.c" \
    -o "$SIGNEXEC"
codesign --force --sign - --timestamp=none --pagesize 4096 \
    --entitlements "$SCRIPT_DIR/signexec-entitlements.plist" \
    "$SIGNEXEC"
codesign --verify --strict --all-architectures "$SIGNEXEC" || \
    die "signexec signature is invalid"
ldid -e "$SIGNEXEC" | rg -q '<key>platform-application</key>' || \
    die "signexec lacks platform-application entitlement"

install -m 0644 "$SCRIPT_DIR/signexec-payload-entitlements.plist" \
    "$SIGNEXEC_PAYLOAD_ENTITLEMENTS"
plutil -lint "$SIGNEXEC_PAYLOAD_ENTITLEMENTS" >/dev/null || \
    die "invalid signexec payload entitlements"
ldid -e "$SIGNEXEC" >/dev/null || die "signexec entitlements unreadable"
rg -q '<key>get-task-allow</key>' "$SIGNEXEC_PAYLOAD_ENTITLEMENTS" || \
    die "signexec payload entitlements lack get-task-allow"

# Native JIT request helper for the LiveContainer host.  The host spawns this
# fixed trust-cached binary with its own pid; the helper only forwards the
# request for its parent process to the root broker's JIT socket, which then
# attaches the debugger lane through codex-exec-worker.
xcrun --sdk iphoneos clang \
    -arch arm64 \
    -arch arm64e \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -Wall -Wextra -Werror \
    "$SCRIPT_DIR/codex_jit_enable.c" \
    -o "$JIT_ENABLE"
codesign --force --sign - --timestamp=none --pagesize 4096 \
    --entitlements "$SCRIPT_DIR/signexec-entitlements.plist" \
    "$JIT_ENABLE"
codesign --verify --strict --all-architectures "$JIT_ENABLE" || \
    die "jit enable helper signature is invalid"

# The fixed LiveContainer host app ships inside the Cryptex so its Mach-Os are
# admitted by the immutable trust cache without any runtime personalization.
[[ -d "$LIVECONTAINER_HOST" ]] || \
    die "LiveContainer host app is unavailable: $LIVECONTAINER_HOST"
ditto --noqtn "$LIVECONTAINER_HOST" "$EMBEDDED_LIVECONTAINER_HOST"
codesign --verify --strict --all-architectures \
    "$EMBEDDED_LIVECONTAINER_HOST/LiveContainer" || \
    die "LiveContainer host signature is invalid"
ldid -e "$EMBEDDED_LIVECONTAINER_HOST/LiveContainer" | rg -q \
    '<key>get-task-allow</key>' || \
    die "LiveContainer host lacks get-task-allow"

# The BrokerProbe acceptance package ships in the Cryptex payload and is
# dpkg-installed by the daemon on every repair, so the runtime admission path
# (interposer -> signexec -> debugged worker) is exercised end to end on device
# and its markers are read back into the log.
zsh "$SCRIPT_DIR/Tests/BrokerProbe/build.sh" >/dev/null
install -m 0644 \
    "$SCRIPT_DIR/out/broker-probe/com.openai.codex.broker-probe_1.0.14_iphoneos-arm64.deb" \
    "$IMAGE_ROOT/usr/local/share/codex-bootstrap/codex-broker-probe.deb"

# The probe is a fixed acceptance artifact, so its binaries also ship in the
# image: the immutable Cryptex trust cache then covers the exact cdhashes that
# dpkg installs on device, and postinst can exec the probe directly.  This
# proves the dpkg lane even where runtime personalization is refused.
rm -rf "$WORK_DIR/broker-probe-package"
dpkg-deb -x \
    "$SCRIPT_DIR/out/broker-probe/com.openai.codex.broker-probe_1.0.14_iphoneos-arm64.deb" \
    "$WORK_DIR/broker-probe-package"
ditto --noqtn "$WORK_DIR/broker-probe-package/var/jb" \
    "$IMAGE_ROOT/usr/local/share/codex-bootstrap/broker-probe-content"

# The self-test probe stays base64-encoded so neither the baseline scan nor
# cryptexctl's trust-cache generation recognizes it as a Mach-O; the daemon
# decodes it on-device and runs it through codex-signexec.
xcrun --sdk iphoneos clang \
    -arch arm64 \
    -arch arm64e \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -Os -Wall -Wextra -Werror \
    "$SCRIPT_DIR/signexec_selftest.c" \
    -o "$WORK_DIR/signexec-selftest"
base64 "$WORK_DIR/signexec-selftest" | \
    tr -d '\r\n' >"$IMAGE_ROOT/usr/local/share/codex-bootstrap/signexec-selftest.b64"
chmod 0644 "$IMAGE_ROOT/usr/local/share/codex-bootstrap/signexec-selftest.b64"

typeset -a trusted_runtime_cdhashes
for candidate in \
    "$ELLEKIT_COMPAT_LOADER" \
    "$EXEC_WORKER" \
    "$EXEC_INTERPOSER" \
    "$RUNTIME_TRUST_CLIENT" \
    "$RUNTIME_TRUST_HELPER" \
    "$SIGNEXEC" \
    "$SIGNEXEC_LDID" \
    "$JIT_ENABLE"; do
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

# [REDACTED] Packaging, payload selection, and validation details omitted.
printf '%s\n' 'TSS/Cryptex personalization and installation details are redacted from this educational source release.' >&2
exit 1
