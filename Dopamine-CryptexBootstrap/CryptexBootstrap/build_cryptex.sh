#!/bin/zsh

set -euo pipefail

SCRIPT_DIR=${0:A:h}
REPO_DIR=${SCRIPT_DIR:h}
CRYPTEXCTL=/System/Library/SecurityResearch/usr/bin/cryptexctl.research
BOOTSTRAP_URL=https://apt.procurs.us/bootstraps/1900/bootstrap-ssh-iphoneos-arm64.tar.zst
BOOTSTRAP_SHA256=2c639b83423e4365a3a849e2bc7c56671cdcc8da534d424b6b1779a27c0c7c08
OPENSSH_CLIENT_URL=https://apt.procurs.us/pool/main/iphoneos-arm64-rootless/1900/openssh/openssh-client_9.7p1-1_iphoneos-arm64.deb
OPENSSH_CLIENT_SHA256=deafb689997363b3d86e0f5616c6878299fefb2ad292b6aede4227c2bb64af5d
OPENSSH_SERVER_URL=https://apt.procurs.us/pool/main/iphoneos-arm64-rootless/1900/openssh/openssh-server_9.7p1-1_iphoneos-arm64.deb
OPENSSH_SERVER_SHA256=578a172e679c961d2966caaf300bd0a43cfdf0a311741712690cfdb6e16eca54
OPENSSH_SFTP_SERVER_URL=https://apt.procurs.us/pool/main/iphoneos-arm64-rootless/1900/openssh/openssh-sftp-server_9.7p1-1_iphoneos-arm64.deb
OPENSSH_SFTP_SERVER_SHA256=d31534b270710381ddf5763f38458498c6bfe7308cbe09d1c45a1109d40dfb19
LDID_URL=https://apt.procurs.us/pool/main/iphoneos-arm64-rootless/1900/ldid/ldid_2.1.5-procursus7_iphoneos-arm64.deb
LDID_SHA256=f0808557064279e2e4febe443ed1e4fed76de42abf3491a45caca14915fd0895
LIBPLIST_URL=https://apt.procurs.us/pool/main/iphoneos-arm64-rootless/1900/libplist/libplist3_2.2.0+git20230130.4b50a5a_iphoneos-arm64.deb
LIBPLIST_SHA256=87f3e16108cc943d1c22a77a7f6bbcdef1d2f48bab0a23f867833e09dbd7d3ea
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
BUILD_STAGE=${CODEX_CRYPTEX_STAGE:-final}
PREFER_DIRECT_SILEO_REGISTRATION=${CODEX_PREFER_DIRECT_SILEO_REGISTRATION:-0}
HOST_SSH_AUTHORIZED_KEY=${CODEX_HOST_SSH_AUTHORIZED_KEY:-}
MAX_CRYPTEX_IMAGE_BYTES=$((128 * 1024 * 1024))
MAX_PREFERENCES_BRIDGE_BYTES=$((1024 * 1024))

CACHE_DIR="$SCRIPT_DIR/cache"
GPG_HOME="$CACHE_DIR/gnupg"
WORK_DIR="$SCRIPT_DIR/work"
OUT_DIR="$SCRIPT_DIR/out"
BOOTSTRAP_ARCHIVE="$CACHE_DIR/bootstrap_ssh_1900.tar.zst"
OPENSSH_CLIENT_DEB="$CACHE_DIR/openssh-client_9.7p1-1_iphoneos-arm64.deb"
OPENSSH_SERVER_DEB="$CACHE_DIR/openssh-server_9.7p1-1_iphoneos-arm64.deb"
OPENSSH_SFTP_SERVER_DEB="$CACHE_DIR/openssh-sftp-server_9.7p1-1_iphoneos-arm64.deb"
LDID_DEB="$CACHE_DIR/ldid_2.1.5-procursus7_iphoneos-arm64.deb"
LIBPLIST_DEB="$CACHE_DIR/libplist3_2.2.0+git20230130.4b50a5a_iphoneos-arm64.deb"
ELLEKIT_DEB="$CACHE_DIR/ellekit_1.2_iphoneos-arm64.deb"
PREFERENCELOADER_DEB="$CACHE_DIR/preferenceloader_2.3.3_iphoneos-arm64.deb"
SILEO_DEB="$REPO_DIR/Application/Dopamine/Resources/sileo.deb"
DEFAULT_SOURCES="$SCRIPT_DIR/dopamine-default.sources"
REPOSITORY_COMPAT_CONFIG="$SCRIPT_DIR/dopamine-repository-compat.conf"
SBINJECT_APT_CONFIG="$SCRIPT_DIR/sbinject-package.conf"
PREFERENCELOADER_PIN="$SCRIPT_DIR/preferenceloader.pref"
SILEO_PIN="$SCRIPT_DIR/sileo.pref"
LDID_PIN="$SCRIPT_DIR/ldid.pref"
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
EMBEDDED_LDID_PIN="$EMBEDDED_APT_CONFIG_DIR/99codex-fixed-ldid"
EMBEDDED_APT_LIST_NORMALIZER="$IMAGE_ROOT/usr/local/share/codex-bootstrap/normalize-apt-lists.sh"
EMBEDDED_CLEAN_INSTALL_TOKEN="$IMAGE_ROOT/usr/local/share/codex-bootstrap/clean-install-token.txt"
EMBEDDED_KEYRING_DIR="$IMAGE_ROOT/usr/local/share/codex-bootstrap/keyrings"
EMBEDDED_ELLEKIT_KEY="$EMBEDDED_KEYRING_DIR/ellekit.gpg"
EMBEDDED_BIGBOSS_KEY="$EMBEDDED_KEYRING_DIR/bigboss.gpg"
EMBEDDED_ELLEKIT_DEB="$IMAGE_ROOT/usr/local/share/codex-bootstrap/ellekit.deb"
EMBEDDED_PREFERENCELOADER_DEB="$IMAGE_ROOT/usr/local/share/codex-bootstrap/preferenceloader.deb"
EMBEDDED_OPENSSH_CLIENT_DEB="$IMAGE_ROOT/usr/local/share/codex-bootstrap/openssh-client.deb"
EMBEDDED_OPENSSH_SERVER_DEB="$IMAGE_ROOT/usr/local/share/codex-bootstrap/openssh-server.deb"
EMBEDDED_OPENSSH_SFTP_SERVER_DEB="$IMAGE_ROOT/usr/local/share/codex-bootstrap/openssh-sftp-server.deb"
EMBEDDED_LDID_DEB="$IMAGE_ROOT/usr/local/share/codex-bootstrap/ldid.deb"
EMBEDDED_LIBPLIST_DEB="$IMAGE_ROOT/usr/local/share/codex-bootstrap/libplist3.deb"
EMBEDDED_HOST_SSH_AUTHORIZED_KEY="$IMAGE_ROOT/usr/local/share/codex-bootstrap/host-ssh-authorized-keys"
TRUSTED_ELLEKIT_ROOT="$IMAGE_ROOT/usr/local/share/codex-bootstrap/trusted/ellekit-root"
TRUSTED_LDID_ROOT="$IMAGE_ROOT/usr/local/share/codex-bootstrap/trusted/ldid-root"
TRUSTED_LIBPLIST_ROOT="$IMAGE_ROOT/usr/local/share/codex-bootstrap/trusted/libplist-root"
SYSTEM_SILEO_APP="$IMAGE_ROOT/Applications/Sileo.app"
SILEO_SYSTEM_ENTITLEMENTS="$WORK_DIR/sileo-system-entitlements.plist"
SILEO_ASSET_INFO="$WORK_DIR/sileo-asset-info.json"
SILEO_NORMALIZED_ICON="$WORK_DIR/AppIcon60x60@2x.png"
TRUSTED_RUNTIME_CDHASHES="$WORK_DIR/trusted-runtime-cdhashes.txt"
ELLEKIT_COMPAT_LOADER="$IMAGE_ROOT/usr/local/bin/codex-ellekit-loader"
EXEC_WORKER="$IMAGE_ROOT/usr/local/bin/codex-exec-worker"
TROLLSTORE_BROKER_CLIENT="$IMAGE_ROOT/usr/local/bin/codex-trollstore-broker-client"
ELLEKIT_COMPAT_ENTITLEMENTS="$SCRIPT_DIR/ellekit-compat-loader-entitlements.plist"
EXEC_WORKER_ENTITLEMENTS="$SCRIPT_DIR/exec-worker-entitlements.plist"
SBINJECT_PACKAGE_VALIDATOR="$IMAGE_ROOT/usr/local/bin/sbinject-package-validator"
SBINJECT_SOURCE_DIR="$SCRIPT_DIR/SBInject"
SBINJECT_GENERALHOOK="$IMAGE_ROOT/usr/local/lib/sbinject/generalhook.dylib"
SBINJECT_AMFIHOOK="$IMAGE_ROOT/usr/local/lib/sbinject/amfihook.dylib"
SBINJECT_LAUNCHDHOOK="$IMAGE_ROOT/usr/local/lib/sbinject/launchdhook-v12.dylib"
SBINJECT_LSD_REGISTRATION_HOOK="$IMAGE_ROOT/usr/local/lib/sbinject/lsd-registration-hook.dylib"
SBINJECT_TROLLSTORE_REGISTRATION_HOOK="$IMAGE_ROOT/usr/local/lib/sbinject/trollstore-registration-hook.dylib"
SBINJECT_PREFERENCES_BRIDGE="$IMAGE_ROOT/usr/local/lib/sbinject/preferences-bridge.dylib"
PREFERENCES_BRIDGE_SUPPORT_DIR="$SBINJECT_SOURCE_DIR/PreferenceBridgeSupport"
PREFERENCES_BRIDGE_BUILD_DIRECTORY="$WORK_DIR/preferences-bridge-build"
SBINJECT_JITTERD="$IMAGE_ROOT/usr/local/bin/sbinject-jitterd"
SBINJECT_JITTERD_ENTITLEMENTS="$SBINJECT_SOURCE_DIR/jitterd-entitlements.plist"
SBINJECT_JITTERD_PLIST_SOURCE="$SBINJECT_SOURCE_DIR/com.openai.codex.sbinject.jitterd.plist"
EMBEDDED_SBINJECT_ROOT="$IMAGE_ROOT/usr/local/share/codex-bootstrap/sbinject"
EMBEDDED_SBINJECT_JITTERD_PLIST="$EMBEDDED_SBINJECT_ROOT/com.openai.codex.sbinject.jitterd.plist"
SPRINGBOARD_CANDIDATE_BUILDER="$SCRIPT_DIR/build_springboard_candidate.py"
AMFID_CANDIDATE_BUILDER="$SCRIPT_DIR/build_amfid_candidate.py"
TARGET_BUNDLE_ROOT=${CODEX_TARGET_BUNDLE_ROOT:-"$SCRIPT_DIR/../../build/target"}
SPRINGBOARD_CANDIDATE_SOURCE=${CODEX_SPRINGBOARD_CANDIDATE_SOURCE:-"$TARGET_BUNDLE_ROOT/SpringBoard.app/SpringBoard"}
SPRINGBOARD_CANDIDATE_INFO_SOURCE=${CODEX_SPRINGBOARD_CANDIDATE_INFO_SOURCE:-"$TARGET_BUNDLE_ROOT/SpringBoard.app/Info.plist"}
SPRINGBOARD_CANDIDATE_BUNDLE_SOURCE=${CODEX_SPRINGBOARD_CANDIDATE_BUNDLE_SOURCE:-${SPRINGBOARD_CANDIDATE_SOURCE:h}}
SPRINGBOARD_CANDIDATE_DIRECTORY="$EMBEDDED_SBINJECT_ROOT/SpringBoard.app"
SPRINGBOARD_CANDIDATE="$SPRINGBOARD_CANDIDATE_DIRECTORY/notSpringBoard"
SPRINGBOARD_CANDIDATE_INFO="$SPRINGBOARD_CANDIDATE_DIRECTORY/Info.plist"
SPRINGBOARD_CANDIDATE_ENTITLEMENTS="$SPRINGBOARD_CANDIDATE_DIRECTORY/entitlements.plist"
SPRINGBOARD_CANDIDATE_GENERALHOOK="$SPRINGBOARD_CANDIDATE_DIRECTORY/g"
PREFERENCES_CANDIDATE_SOURCE=${CODEX_PREFERENCES_CANDIDATE_SOURCE:-"$TARGET_BUNDLE_ROOT/Preferences.app/Preferences"}
PREFERENCES_CANDIDATE_INFO_SOURCE=${CODEX_PREFERENCES_CANDIDATE_INFO_SOURCE:-"$TARGET_BUNDLE_ROOT/Preferences.app/Info.plist"}
PREFERENCES_CANDIDATE_BUNDLE_SOURCE=${CODEX_PREFERENCES_CANDIDATE_BUNDLE_SOURCE:-${PREFERENCES_CANDIDATE_SOURCE:h}}
PREFERENCES_CANDIDATE_DIRECTORY="$EMBEDDED_SBINJECT_ROOT/Preferences.app"
PREFERENCES_CANDIDATE="$PREFERENCES_CANDIDATE_DIRECTORY/notPreferences"
PREFERENCES_CANDIDATE_INFO="$PREFERENCES_CANDIDATE_DIRECTORY/Info.plist"
PREFERENCES_CANDIDATE_ENTITLEMENTS="$PREFERENCES_CANDIDATE_DIRECTORY/entitlements.plist"
PREFERENCES_CANDIDATE_GENERALHOOK="$PREFERENCES_CANDIDATE_DIRECTORY/g"
AMFID_CANDIDATE_SOURCE=${CODEX_AMFID_CANDIDATE_SOURCE:-"$TARGET_BUNDLE_ROOT/amfid"}
AMFID_CANDIDATE_DIRECTORY="$EMBEDDED_SBINJECT_ROOT/amfid"
AMFID_CANDIDATE="$AMFID_CANDIDATE_DIRECTORY/notamfid"
AMFID_CANDIDATE_ENTITLEMENTS="$AMFID_CANDIDATE_DIRECTORY/notamfid.entitlements.plist"
AMFID_CANDIDATE_HOOK="$AMFID_CANDIDATE_DIRECTORY/a"
PATCHED_OPAINJECT_DIR="$WORK_DIR/opainject-ios27"
PATCHED_OPAINJECT_DYLD="$PATCHED_OPAINJECT_DIR/dyld.m"
PATCHED_OPAINJECT_ROP="$PATCHED_OPAINJECT_DIR/rop_inject.m"
PATCHED_OPAINJECT_THREAD_UTILS="$PATCHED_OPAINJECT_DIR/thread_utils.m"
PACKAGE_ROOT="$WORK_DIR/sileo-package"
REPACKED_SILEO="$WORK_DIR/sileo.launchable.deb"
ELLEKIT_PACKAGE_ROOT="$WORK_DIR/ellekit-package"
OPENSSH_PACKAGE_ROOT="$WORK_DIR/openssh-package"
LDID_PACKAGE_ROOT="$WORK_DIR/ldid-package"
LIBPLIST_PACKAGE_ROOT="$WORK_DIR/libplist-package"
REPACKED_ELLEKIT="$WORK_DIR/ellekit.cryptex-signed.deb"
REPACKED_LDID="$WORK_DIR/ldid.cryptex-signed.deb"
REPACKED_LIBPLIST="$WORK_DIR/libplist.cryptex-signed.deb"
UNSIGNED_OUT="$OUT_DIR/unsigned"
SUMMARY="$OUT_DIR/build-summary.json"
STAGE_WORK_DIR="$WORK_DIR/ssh-stage"
STAGE_OUT_DIR="$OUT_DIR/ssh-stage"
STAGE_SUMMARY="$STAGE_OUT_DIR/build-summary.json"

die() {
    print -u2 -- "error: $*"
    exit 1
}

[[ "$FORCE_CLEAN_INSTALL" == 0 || "$FORCE_CLEAN_INSTALL" == 1 ]] || \
    die "CODEX_FORCE_CLEAN_INSTALL must be 0 or 1"
[[ "$BUILD_STAGE" == final || "$BUILD_STAGE" == ssh ]] || \
    die "CODEX_CRYPTEX_STAGE must be final or ssh"
[[ "$PREFER_DIRECT_SILEO_REGISTRATION" == 0 || \
    "$PREFER_DIRECT_SILEO_REGISTRATION" == 1 ]] || \
    die "CODEX_PREFER_DIRECT_SILEO_REGISTRATION must be 0 or 1"

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

build_ssh_stage() {
    local authorized_key=${CODEX_STAGE_AUTHORIZED_KEY:-}
    local stage_image="$STAGE_WORK_DIR/image-root"
    local stage_extract="$STAGE_WORK_DIR/extracted"
    local stage_payload="$stage_image/usr/local/share/codex-stage-ssh"
    local stage_unsigned="$STAGE_OUT_DIR/unsigned"
    local launcher="$stage_image/usr/local/bin/codex-dopamine-bootstrap"
    local stage_host_key="$STAGE_WORK_DIR/host-key"
    local stage_sshd="$stage_payload/root/usr/sbin/sshd"
    local stage_sshd_entitlements="$STAGE_WORK_DIR/sshd-entitlements.plist"
    local bundle trustcache trustcache_dump image image_bytes entry_count
    local -a stage_variants

    for tool in awk curl ditto ldid plutil python3 shasum ssh-keygen stat tar xcrun zstd; do
        command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
    done
    [[ -x "$CRYPTEXCTL" ]] || die "missing SRD cryptexctl: $CRYPTEXCTL"
    [[ -f "$authorized_key" ]] || die "CODEX_STAGE_AUTHORIZED_KEY is required"
    [[ -f "$SCRIPT_DIR/stage_ssh_launcher.c" ]] || \
        die "missing stage SSH launcher"
    plutil -lint "$SCRIPT_DIR/com.openai.codex.dopamine.bootstrap.plist" >/dev/null || \
        die "invalid stage SSH launch daemon"

    mkdir -p "$CACHE_DIR" "$STAGE_OUT_DIR"
    fetch_pinned "$BOOTSTRAP_URL" "$BOOTSTRAP_SHA256" "$BOOTSTRAP_ARCHIVE"
    rm -rf "$STAGE_WORK_DIR" "$stage_unsigned"
    mkdir -p "$stage_extract" "$stage_image/usr/local/bin" \
        "$stage_image/Library/LaunchDaemons" "$stage_payload" \
        "$stage_unsigned"
    zstd -dc "$BOOTSTRAP_ARCHIVE" | tar -xf - -C "$stage_extract"
    [[ -x "$stage_extract/var/jb/usr/sbin/sshd" && \
       -x "$stage_extract/var/jb/usr/bin/ssh-keygen" ]] || \
        die "SSH bootstrap payload is incomplete"
    ditto --noqtn "$stage_extract/var/jb" "$stage_payload/root"
    ldid -e "$stage_sshd" >"$stage_sshd_entitlements"
    plutil -lint "$stage_sshd_entitlements" >/dev/null || \
        die "could not preserve temporary sshd entitlements"
    python3 - "$stage_sshd" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = bytearray(path.read_bytes())
needle = b"sshd\0Privilege separation user %s does not exist"
replacement = b"root\0Privilege separation user %s does not exist"
if data.count(needle) != 1:
    raise SystemExit("temporary sshd privilege-separation marker is not unique")
data[:] = data.replace(needle, replacement)

# This pinned Procursus sshd always chroots its pre-auth child.  A Cryptex
# launch daemon cannot perform that operation on iOS, and this isolated stage
# already runs as root with public-key-only access.  Replace only that call's
# ARM64 `bl _chroot` with `mov w0, #0`; the following error check then follows
# the normal success path.  Exact bytes keep this tied to the pinned archive.
privsep_chroot_call = 0x5301C
expected_call = bytes.fromhex("31980094")
return_success = bytes.fromhex("00008052")
if data[privsep_chroot_call:privsep_chroot_call + 4] != expected_call:
    raise SystemExit("temporary sshd chroot call does not match pinned binary")
data[privsep_chroot_call:privsep_chroot_call + 4] = return_success

# The same pinned build asks sandbox_init() for the removed
# `pure-computation` named profile.  The transfer daemon is already confined
# to loopback-over-usbmux, one ephemeral key, and this disposable Cryptex, so
# return immediately from ssh_sandbox_child instead of aborting pre-auth.
sandbox_child_entry = 0x2E018
expected_prologue = bytes.fromhex("ff4301d1")
return_instruction = bytes.fromhex("c0035fd6")
if data[sandbox_child_entry:sandbox_child_entry + 4] != expected_prologue:
    raise SystemExit("temporary sshd sandbox function does not match pinned binary")
data[sandbox_child_entry:sandbox_child_entry + 4] = return_instruction
path.write_bytes(data)
PY
    ldid -S"$stage_sshd_entitlements" -Cadhoc "$stage_sshd"
    cp "$authorized_key" "$stage_payload/authorized_keys"
    ssh-keygen -q -t ed25519 -N '' -f "$stage_host_key"
    cp "$stage_host_key" "$stage_payload/host-key"
    cp "$SCRIPT_DIR/stage_sshd_config" "$stage_payload/sshd_config"
    cp "$SCRIPT_DIR/com.openai.codex.dopamine.bootstrap.plist" \
        "$stage_image/Library/LaunchDaemons/"
    plutil -replace ThrottleInterval -integer 10 \
        "$stage_image/Library/LaunchDaemons/com.openai.codex.dopamine.bootstrap.plist"
    chmod 0600 "$stage_payload/authorized_keys" "$stage_payload/host-key"
    chmod 0644 "$stage_payload/sshd_config" \
        "$stage_image/Library/LaunchDaemons/com.openai.codex.dopamine.bootstrap.plist"

    xcrun --sdk iphoneos clang -arch arm64 \
        -miphoneos-version-min=17.0 -Os -Wall -Wextra -Werror \
        "$SCRIPT_DIR/stage_ssh_launcher.c" -o "$launcher"
    ldid -S"$SCRIPT_DIR/installer-entitlements.plist" -Cadhoc "$launcher"

    # [REDACTED] Packaging, payload selection, and validation details omitted.
    printf '%s\n' 'TSS/Cryptex personalization and installation details are redacted from this educational source release.' >&2
    exit 1
}

if [[ "$BUILD_STAGE" == ssh ]]; then
    build_ssh_stage
    exit 0
fi

for tool in awk codesign curl dpkg-deb gpg ldid lipo plutil python3 rg shasum sips stat tar xcrun zstd; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done
[[ -x "$CRYPTEXCTL" ]] || die "missing SRD cryptexctl: $CRYPTEXCTL"
sh -n "$APT_LIST_NORMALIZER"
mkdir -p "$GPG_HOME"
chmod 0700 "$GPG_HOME"
export GNUPGHOME="$GPG_HOME"
verify_keyring "$ELLEKIT_KEY" "$ELLEKIT_KEY_FINGERPRINT"
verify_keyring "$BIGBOSS_KEY" "$BIGBOSS_KEY_FINGERPRINT"

mkdir -p "$CACHE_DIR" "$WORK_DIR" "$OUT_DIR"
fetch_pinned "$BOOTSTRAP_URL" "$BOOTSTRAP_SHA256" "$BOOTSTRAP_ARCHIVE"
fetch_pinned "$OPENSSH_CLIENT_URL" "$OPENSSH_CLIENT_SHA256" \
    "$OPENSSH_CLIENT_DEB"
fetch_pinned "$OPENSSH_SERVER_URL" "$OPENSSH_SERVER_SHA256" \
    "$OPENSSH_SERVER_DEB"
fetch_pinned "$OPENSSH_SFTP_SERVER_URL" "$OPENSSH_SFTP_SERVER_SHA256" \
    "$OPENSSH_SFTP_SERVER_DEB"
fetch_pinned "$LDID_URL" "$LDID_SHA256" "$LDID_DEB"
fetch_pinned "$LIBPLIST_URL" "$LIBPLIST_SHA256" "$LIBPLIST_DEB"
fetch_pinned "$ELLEKIT_URL" "$ELLEKIT_SHA256" "$ELLEKIT_DEB"
fetch_pinned "$PREFERENCELOADER_URL" "$PREFERENCELOADER_SHA256" \
    "$PREFERENCELOADER_DEB"
[[ "$(sha256_of "$SILEO_DEB")" == "$SILEO_SHA256" ]] || \
    die "opa334 Sileo package hash mismatch"
zstd -t "$BOOTSTRAP_ARCHIVE" >/dev/null

rm -rf "$IMAGE_ROOT" "$PACKAGE_ROOT" "$ELLEKIT_PACKAGE_ROOT" \
    "$OPENSSH_PACKAGE_ROOT" "$LDID_PACKAGE_ROOT" \
    "$LIBPLIST_PACKAGE_ROOT" \
    "$PREFERENCES_BRIDGE_BUILD_DIRECTORY" \
    "$UNSIGNED_OUT" "$REPACKED_SILEO" \
    "$REPACKED_ELLEKIT" "$REPACKED_LDID" "$REPACKED_LIBPLIST" \
    "$TRUSTED_RUNTIME_CDHASHES" \
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
    "$AMFID_CANDIDATE_DIRECTORY" \
    "$EMBEDDED_APT_CONFIG_DIR" \
    "$EMBEDDED_KEYRING_DIR" \
    "$TRUSTED_ELLEKIT_ROOT" \
    "$TRUSTED_LDID_ROOT" \
    "$TRUSTED_LIBPLIST_ROOT" \
    "$PREFERENCES_BRIDGE_BUILD_DIRECTORY/module-cache" \
    "$PACKAGE_ROOT" \
    "$UNSIGNED_OUT"

cp "$OPENSSH_CLIENT_DEB" "$EMBEDDED_OPENSSH_CLIENT_DEB"
cp "$OPENSSH_SERVER_DEB" "$EMBEDDED_OPENSSH_SERVER_DEB"
cp "$OPENSSH_SFTP_SERVER_DEB" "$EMBEDDED_OPENSSH_SFTP_SERVER_DEB"
chmod 0644 "$EMBEDDED_OPENSSH_CLIENT_DEB" \
    "$EMBEDDED_OPENSSH_SERVER_DEB" \
    "$EMBEDDED_OPENSSH_SFTP_SERVER_DEB"
if [[ -n "$HOST_SSH_AUTHORIZED_KEY" ]]; then
    [[ -f "$HOST_SSH_AUTHORIZED_KEY" ]] || \
        die "CODEX_HOST_SSH_AUTHORIZED_KEY is not a regular file"
    [[ $(wc -l <"$HOST_SSH_AUTHORIZED_KEY") -eq 1 ]] || \
        die "host SSH authorized key must contain exactly one key"
    rg -q '^ssh-ed25519 [A-Za-z0-9+/]+={0,2}( .*)?$' \
        "$HOST_SSH_AUTHORIZED_KEY" || \
        die "host SSH authorized key is not an Ed25519 public key"
    cp "$HOST_SSH_AUTHORIZED_KEY" "$EMBEDDED_HOST_SSH_AUTHORIZED_KEY"
    chmod 0600 "$EMBEDDED_HOST_SSH_AUTHORIZED_KEY"
fi

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

# TrollStore Lite invokes ldid as a nested process while its own helper runs
# through the JIT worker.  That nested exec is a separate kernel admission
# decision, so pin and fixed-trust this one infrastructure executable.  Apps
# signed by it remain outside the trust cache and use the generic launcher.
dpkg-deb -R "$LIBPLIST_DEB" "$LIBPLIST_PACKAGE_ROOT"
[[ "$(dpkg-deb -f "$LIBPLIST_DEB" Package)" == libplist3 && \
   "$(dpkg-deb -f "$LIBPLIST_DEB" Version)" == \
       '2.2.0+git20230130.4b50a5a' && \
   "$(dpkg-deb -f "$LIBPLIST_DEB" Architecture)" == iphoneos-arm64 ]] || \
    die "pinned libplist package identity changed"
FIXED_LIBPLIST="$LIBPLIST_PACKAGE_ROOT/var/jb/usr/lib/libplist-2.0.3.dylib"
[[ -f "$FIXED_LIBPLIST" ]] || die "pinned libplist package has no dylib"
codesign --force --sign - --timestamp=none --pagesize 4096 \
    "$FIXED_LIBPLIST"
codesign --verify --strict --all-architectures "$FIXED_LIBPLIST" || \
    die "fixed libplist signature is invalid"
dpkg-deb --root-owner-group -b "$LIBPLIST_PACKAGE_ROOT" \
    "$REPACKED_LIBPLIST" >/dev/null
cp "$REPACKED_LIBPLIST" "$EMBEDDED_LIBPLIST_DEB"
chmod 0644 "$EMBEDDED_LIBPLIST_DEB"
dpkg-deb -x "$REPACKED_LIBPLIST" "$TRUSTED_LIBPLIST_ROOT"
TRUSTED_LIBPLIST="$TRUSTED_LIBPLIST_ROOT/var/jb/usr/lib/libplist-2.0.3.dylib"
[[ "$(sha256_of "$FIXED_LIBPLIST")" == \
   "$(sha256_of "$TRUSTED_LIBPLIST")" ]] || \
    die "embedded libplist payload changed after repacking"

dpkg-deb -R "$LDID_DEB" "$LDID_PACKAGE_ROOT"
[[ "$(dpkg-deb -f "$LDID_DEB" Package)" == ldid && \
   "$(dpkg-deb -f "$LDID_DEB" Version)" == 2.1.5-procursus7 && \
   "$(dpkg-deb -f "$LDID_DEB" Architecture)" == iphoneos-arm64 ]] || \
    die "pinned ldid package identity changed"
FIXED_LDID="$LDID_PACKAGE_ROOT/var/jb/usr/bin/ldid"
[[ -x "$FIXED_LDID" ]] || die "pinned ldid package has no executable"
codesign --force --sign - --timestamp=none --pagesize 4096 \
    --identifier com.openai.codex.fixed-ldid \
    --entitlements "$EXEC_WORKER_ENTITLEMENTS" \
    "$FIXED_LDID"
codesign --verify --strict --all-architectures "$FIXED_LDID" || \
    die "fixed ldid signature is invalid"
dpkg-deb --root-owner-group -b "$LDID_PACKAGE_ROOT" "$REPACKED_LDID" \
    >/dev/null
cp "$REPACKED_LDID" "$EMBEDDED_LDID_DEB"
chmod 0644 "$EMBEDDED_LDID_DEB"
dpkg-deb -x "$REPACKED_LDID" "$TRUSTED_LDID_ROOT"
TRUSTED_LDID="$TRUSTED_LDID_ROOT/var/jb/usr/bin/ldid"
[[ "$(sha256_of "$FIXED_LDID")" == "$(sha256_of "$TRUSTED_LDID")" ]] || \
    die "embedded ldid payload changed after repacking"

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
    -install_name /var/jb/usr/lib/sbinject/launchdhook-v12.dylib \
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
    -I "$SBINJECT_SOURCE_DIR" \
    "$SBINJECT_SOURCE_DIR/sbinject_amfihook.m" \
    "$SBINJECT_SOURCE_DIR/litehook_rebind.c" \
    -framework Foundation \
    -install_name @loader_path/a \
    -o "$SBINJECT_AMFIHOOK"
codesign --force --sign - --timestamp=none --pagesize 4096 \
    "$SBINJECT_AMFIHOOK"

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

xcrun --sdk iphoneos clang \
    -arch arm64 \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -dynamiclib \
    -fobjc-arc -fblocks \
    -Os -Wall -Wextra -Werror \
    "$SBINJECT_SOURCE_DIR/sbinject_trollstore_registration_hook.m" \
    -framework Foundation \
    -install_name \
        /var/jb/usr/lib/sbinject/trollstore-registration-hook.dylib \
    -o "$SBINJECT_TROLLSTORE_REGISTRATION_HOOK"
codesign --force --sign - --timestamp=none --pagesize 4096 \
    "$SBINJECT_TROLLSTORE_REGISTRATION_HOOK"

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
    --target springboard \
    --info-plist "$SPRINGBOARD_CANDIDATE_INFO_SOURCE" \
    --executable-name notSpringBoard \
    --bundle-executable notSpringBoard \
    --load-dylib @loader_path/g \
    --load-dylib-patcher "$SCRIPT_DIR/patch_load_dylib.py" >/dev/null

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

# Build a standalone, device-matched amfid copy rather than injecting an
# ad-hoc dylib into Apple's live system binary. The fixed hook and resigned
# candidate are immutable Cryptex trust-cache entries; get-task-allow lets the
# existing jitterd attach/detach lane grant the candidate its debug state.
[[ -f "$AMFID_CANDIDATE_SOURCE" ]] || \
    die "missing device-matched amfid source"
cp "$SBINJECT_AMFIHOOK" "$AMFID_CANDIDATE_HOOK"
chmod 0755 "$AMFID_CANDIDATE_HOOK"
python3 "$AMFID_CANDIDATE_BUILDER" \
    "$AMFID_CANDIDATE_SOURCE" "$AMFID_CANDIDATE" \
    --load-dylib @loader_path/a \
    --load-dylib-patcher "$SCRIPT_DIR/patch_load_dylib.py" >/dev/null
codesign --verify --strict --all-architectures "$AMFID_CANDIDATE" || \
    die "amfid candidate signature is invalid"
otool -L "$AMFID_CANDIDATE" | rg -q '^\s+@loader_path/a ' || \
    die "amfid candidate does not preload its fixed hook"
ldid -e "$AMFID_CANDIDATE" | rg -q '<key>get-task-allow</key>' || \
    die "amfid candidate lacks get-task-allow"
[[ "$(sha256_of "$AMFID_CANDIDATE_HOOK")" == \
   "$(sha256_of "$SBINJECT_AMFIHOOK")" ]] || \
    die "amfid hook changed while copying"

zstd -dc "$BOOTSTRAP_ARCHIVE" | \
    tar -xf - -C "$WORK_DIR"
[[ -d "$WORK_DIR/var/jb" ]] || die "archive did not extract var/jb"
ditto --noqtn "$WORK_DIR/var/jb" \
    "$IMAGE_ROOT/usr/local/share/codex-bootstrap/procursus"
rm -rf "$WORK_DIR/var"

# The bootstrap archive and the standalone OpenSSH packages are released on
# independent schedules.  Trust and compare the exact pinned package payload
# that dpkg installs, rather than whichever OpenSSH build happened to be in
# the base archive.
mkdir -p "$OPENSSH_PACKAGE_ROOT"
for package in "$OPENSSH_CLIENT_DEB" "$OPENSSH_SFTP_SERVER_DEB" \
               "$OPENSSH_SERVER_DEB"; do
    dpkg-deb -x "$package" "$OPENSSH_PACKAGE_ROOT"
done
[[ -x "$OPENSSH_PACKAGE_ROOT/var/jb/usr/bin/ssh-keygen" && \
   -x "$OPENSSH_PACKAGE_ROOT/var/jb/usr/sbin/sshd" ]] || \
    die "pinned OpenSSH package payload is incomplete"
ditto --noqtn "$OPENSSH_PACKAGE_ROOT/var/jb" \
    "$IMAGE_ROOT/usr/local/share/codex-bootstrap/procursus"
OPENSSH_CONFIG="$IMAGE_ROOT/usr/local/share/codex-bootstrap/procursus/etc/ssh/sshd_config"
grep -qx 'UsePAM yes' "$OPENSSH_CONFIG" || \
    die "pinned OpenSSH configuration no longer has the expected PAM setting"
sed -i '' 's/^UsePAM yes$/UsePAM no/' "$OPENSSH_CONFIG"
grep -qx 'UsePAM no' "$OPENSSH_CONFIG" || \
    die "could not disable PAM for rootless public-key SSH"
rg -q '^AuthorizedKeysFile[[:space:]]+\.ssh/authorized_keys$' \
    "$OPENSSH_CONFIG" || \
    die "pinned OpenSSH authorized-keys path changed"
sed -i '' \
    's#^AuthorizedKeysFile[[:space:]].*$#AuthorizedKeysFile /var/jb/var/root/.ssh/authorized_keys#' \
    "$OPENSSH_CONFIG"
rg -q '^AuthorizedKeysFile /var/jb/var/root/\.ssh/authorized_keys$' \
    "$OPENSSH_CONFIG" || \
    die "could not select the rootless OpenSSH authorized-keys path"
typeset -a trusted_openssh_machos=(
    "$IMAGE_ROOT/usr/local/share/codex-bootstrap/procursus/usr/bin/ssh"
    "$IMAGE_ROOT/usr/local/share/codex-bootstrap/procursus/usr/bin/ssh-keygen"
    "$IMAGE_ROOT/usr/local/share/codex-bootstrap/procursus/usr/libexec/sftp-server"
    "$IMAGE_ROOT/usr/local/share/codex-bootstrap/procursus/usr/sbin/sshd"
)
typeset -a trusted_ldid_machos=(
    "$TRUSTED_LDID"
    "$TRUSTED_LIBPLIST"
    "$IMAGE_ROOT/usr/local/share/codex-bootstrap/procursus/usr/lib/libcrypto.3.dylib"
    "$IMAGE_ROOT/usr/local/share/codex-bootstrap/procursus/usr/lib/libiosexec.1.dylib"
)
for candidate in "${trusted_ldid_machos[@]}"; do
    [[ -f "$candidate" ]] || \
        die "fixed ldid runtime dependency is missing: ${candidate:t}"
    codesign --verify --strict --all-architectures "$candidate" || \
        die "fixed ldid runtime signature is invalid: ${candidate:t}"
done

# iOS 27 removed launch_active_user_switch from libSystem. Procursus launchctl
# does not use it for bootout/bootstrap, but its strong unused import prevents
# dyld from starting the executable at all. Make only that import weak, retain
# the original launchctl entitlements, and let the generated Cryptex trust
# cache cover the resulting exact code directory.
LAUNCHCTL="$IMAGE_ROOT/usr/local/share/codex-bootstrap/procursus/usr/bin/launchctl"
python3 "$SCRIPT_DIR/patch_weak_import.py" \
    "$LAUNCHCTL" _launch_active_user_switch
codesign --force --sign - --timestamp=none --pagesize 4096 \
    --preserve-metadata=identifier,entitlements "$LAUNCHCTL"

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
    die "upstream Sileo asset catalog lacks its 60pt icon"
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
    die "normalized Sileo icon has the wrong width"
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
    die "Cryptex Sileo lost its explicit 60pt icon"
[[ -f "$SYSTEM_SILEO_APP/CodexSystemEntitlements.plist" ]] || \
    die "Cryptex Sileo lost its registration entitlements"

# Keep dpkg's package/dependency state without installing a mutable app under
# /var/jb. The Cryptex is the authoritative signed source; the boot daemon
# maintains one byte-verified, root-owned copy in the standard app container.
rm -rf "$APP_DIR"
SILEO_STATE_DIR="$PACKAGE_ROOT/var/jb/usr/share/codex-bootstrap"
mkdir -p "$SILEO_STATE_DIR"
printf '%s\n' "$SILEO_PACKAGE_VERSION" \
    >"$SILEO_STATE_DIR/sileo-system-app"
chmod 0644 "$SILEO_STATE_DIR/sileo-system-app"
dpkg-deb --root-owner-group -b "$PACKAGE_ROOT" "$REPACKED_SILEO" >/dev/null
[[ "$(dpkg-deb -f "$REPACKED_SILEO" Version)" == \
    "$SILEO_PACKAGE_VERSION" ]] || \
    die "fixed system Sileo metadata package version mismatch"
cp "$REPACKED_SILEO" \
    "$IMAGE_ROOT/usr/local/share/codex-bootstrap/sileo.deb"
typeset -a prepared_sileo_machos=(
    "$SYSTEM_SILEO_APP/Sileo"
    "$SYSTEM_SILEO_APP/giveMeRoot"
    "$SYSTEM_SILEO_APP/F/libiosexec.1.dylib"
    "$SYSTEM_SILEO_APP/F/liblzma.5.dylib"
    "$SYSTEM_SILEO_APP/F/libcodex-sileo-broker.dylib"
    "$SYSTEM_SILEO_APP/F/libzstd.1.dylib"
    "$SYSTEM_SILEO_APP/F/libzstd.real.dylib"
)

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
    -I "$SBINJECT_SOURCE_DIR" \
    "$SCRIPT_DIR/codex_exec_worker.c" \
    "$SBINJECT_SOURCE_DIR/litehook_rebind.c" \
    -o "$EXEC_WORKER"
codesign --force --sign - --timestamp=none --pagesize 4096 \
    --identifier com.openai.codex.sbinject.app-launcher \
    --entitlements "$EXEC_WORKER_ENTITLEMENTS" \
    "$EXEC_WORKER"
codesign --verify --strict --all-architectures "$EXEC_WORKER" || \
    die "execution worker signature is invalid"

xcrun --sdk iphoneos clang \
    -arch arm64 \
    -miphoneos-version-min=17.0 \
    -isysroot "$SDKROOT" \
    -fblocks \
    -Wall -Wextra -Werror \
    -I "$SCRIPT_DIR" \
    "$SCRIPT_DIR/trollstore_broker_client.c" \
    -o "$TROLLSTORE_BROKER_CLIENT"
codesign --force --sign - --timestamp=none --pagesize 4096 \
    --identifier com.openai.codex.trollstore-broker-client \
    --entitlements "$EXEC_WORKER_ENTITLEMENTS" \
    "$TROLLSTORE_BROKER_CLIENT"
codesign --verify --strict --all-architectures \
    "$TROLLSTORE_BROKER_CLIENT" || \
    die "TrollStore broker client signature is invalid"

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
    "$TROLLSTORE_BROKER_CLIENT" \
    "$SBINJECT_PACKAGE_VALIDATOR" \
    "$SBINJECT_GENERALHOOK" \
    "$SBINJECT_AMFIHOOK" \
    "$SBINJECT_LSD_REGISTRATION_HOOK" \
    "$SBINJECT_TROLLSTORE_REGISTRATION_HOOK" \
    "$SBINJECT_PREFERENCES_BRIDGE" \
    "$SBINJECT_LAUNCHDHOOK" \
    "$SBINJECT_JITTERD" \
    "$SPRINGBOARD_CANDIDATE_GENERALHOOK" \
    "$SPRINGBOARD_CANDIDATE" \
    "$PREFERENCES_CANDIDATE_GENERALHOOK" \
    "$PREFERENCES_CANDIDATE" \
    "$AMFID_CANDIDATE_HOOK" \
    "$AMFID_CANDIDATE" \
    "${prepared_sileo_machos[@]}" \
    "${trusted_ellekit_machos[@]}" \
    "${trusted_ldid_machos[@]}" \
    "${trusted_openssh_machos[@]}"; do
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
    "-DCODEX_PREFER_DIRECT_SILEO_REGISTRATION=$PREFER_DIRECT_SILEO_REGISTRATION" \
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
cp "$LDID_PIN" "$EMBEDDED_LDID_PIN"
cp "$APT_LIST_NORMALIZER" "$EMBEDDED_APT_LIST_NORMALIZER"
chmod 0644 "$EMBEDDED_DEFAULT_SOURCES" \
    "$EMBEDDED_REPOSITORY_COMPAT_CONFIG" \
    "$EMBEDDED_SBINJECT_APT_CONFIG" \
    "$EMBEDDED_PREFERENCELOADER_PIN" \
    "$EMBEDDED_SILEO_PIN" \
    "$EMBEDDED_LDID_PIN" \
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
