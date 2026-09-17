#!/bin/zsh

set -euo pipefail

SCRIPT_DIR=${0:A:h}
PROJECT_ROOT=${SCRIPT_DIR:h}
UPSTREAM_DIR="$PROJECT_ROOT/Dopamine-upstream"
OVERLAY_DIR="$SCRIPT_DIR/CryptexBootstrap"
UPSTREAM_URL=https://github.com/opa334/Dopamine.git
UPSTREAM_COMMIT=939a3a21400f0dc6d6163b2b5999ba2ace0d2732
MANAGED_MARKER="$UPSTREAM_DIR/.codex-cryptex-bootstrap-managed"
CRYPTEXCTL=/System/Library/SecurityResearch/usr/bin/cryptexctl.research
IPHONE_17_PRO_MAX_UDID=00008150-0018252C1130C01C
IPHONE_12_MINI_UDID=00008101-001C39641A9B001E
DEFAULT_SILEO_BUNDLE_IDENTIFIER=org.coolstar.SileoStore
IPHONE_12_MINI_SILEO_BUNDLE_IDENTIFIER=com.johnnyfranks.codex.profilebootstrap12mini

ACTION=prepare
DEVICE=
ALLOW_UNVERIFIED=0
NO_REPLACE=0
NO_BREW=0

die() {
    print -u2 -- "error: $*"
    exit 1
}

usage() {
    cat <<'EOF'
Usage: ./Dopamine-CryptexBootstrap/setup.sh [options]

Prepare a pinned opa334/Dopamine tree and the local Python/signing environment.
The build is host-only. Install additionally writes the provisioned app and
nonpersistent Cryptex to one connected device.

Options:
  --prepare                 Prepare and preflight only (default)
  --build                   Prepare and build a matched Cryptex/Sileo pair
  --install                 Prepare, build, personalize, validate, and install
  --device UDID             Select a connected paired device
  --allow-unverified-device Bypass the validated two-device target guard
  --no-replace              Refuse an older installed copy of this Cryptex
  --no-brew                 Report missing Homebrew tools without installing
  -h, --help                Show this help

Optional signing overrides:
  CODEX_SILEO_DEVELOPMENT_IDENTITY
  CODEX_SILEO_PROVISIONING_PROFILE
  CODEX_SILEO_DEVELOPMENT_ENTITLEMENTS
  CODEX_SILEO_BUNDLE_IDENTIFIER
  CODEX_SPRINGBOARD_SOURCE (required for build/install; target OS SpringBoard)
  CODEX_LAUNCHD_SOURCE (required for build/install; target OS launchd)
EOF
}

while (( $# > 0 )); do
    case "$1" in
        --prepare)
            ACTION=prepare
            ;;
        --build)
            ACTION=build
            ;;
        --install)
            ACTION=install
            ;;
        --device)
            (( $# >= 2 )) || die "--device requires a UDID"
            DEVICE=$2
            shift
            ;;
        --allow-unverified-device)
            ALLOW_UNVERIFIED=1
            ;;
        --no-replace)
            NO_REPLACE=1
            ;;
        --no-brew)
            NO_BREW=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1 (try --help)"
            ;;
    esac
    shift
done

TARGET_UDID=${CODEX_TARGET_UDID:-$DEVICE}
if [[ -n "${CODEX_TARGET_UDID:-}" && -n "$DEVICE" && \
    "$CODEX_TARGET_UDID" != "$DEVICE" ]]; then
    die "--device and CODEX_TARGET_UDID select different devices"
fi
if [[ -z "${CODEX_SILEO_BUNDLE_IDENTIFIER:-}" ]]; then
    case "$TARGET_UDID" in
        "$IPHONE_12_MINI_UDID")
            CODEX_SILEO_BUNDLE_IDENTIFIER=$IPHONE_12_MINI_SILEO_BUNDLE_IDENTIFIER
            ;;
        "$IPHONE_17_PRO_MAX_UDID"|"")
            CODEX_SILEO_BUNDLE_IDENTIFIER=$DEFAULT_SILEO_BUNDLE_IDENTIFIER
            ;;
        *)
            CODEX_SILEO_BUNDLE_IDENTIFIER=$DEFAULT_SILEO_BUNDLE_IDENTIFIER
            ;;
    esac
fi
export CODEX_SILEO_BUNDLE_IDENTIFIER
if [[ -n "$TARGET_UDID" ]]; then
    export CODEX_TARGET_UDID=$TARGET_UDID
fi

[[ "$(uname -s)" == Darwin ]] || die "this flow requires macOS"

# Homebrew is often absent from PATH in automation shells even when installed.
if ! command -v brew >/dev/null 2>&1; then
    for candidate in /opt/homebrew/bin/brew /usr/local/bin/brew; do
        if [[ -x "$candidate" ]]; then
            path=("${candidate:h}" $path)
            break
        fi
    done
fi

typeset -A FORMULA_FOR
FORMULA_FOR=(
    dpkg-deb dpkg
    gpg gnupg
    ldid ldid
    python3 python
    rg ripgrep
    zstd zstd
)
BREW_TOOLS=(dpkg-deb gpg ldid python3 rg zstd)
missing_formulas=()
for tool in "${BREW_TOOLS[@]}"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing_formulas+=("${FORMULA_FOR[$tool]}")
    fi
done
missing_formulas=("${(@u)missing_formulas}")
if (( ${#missing_formulas} > 0 )); then
    (( NO_BREW == 0 )) || \
        die "missing tools; install Homebrew formulae: ${missing_formulas[*]}"
    command -v brew >/dev/null 2>&1 || die \
        "Homebrew is required for: ${missing_formulas[*]} (https://brew.sh)"
    print -- "Installing missing Homebrew dependencies: ${missing_formulas[*]}"
    brew install "${missing_formulas[@]}"
fi

HOST_TOOLS=(
    awk codesign curl ditto dpkg-deb file git gpg install_name_tool ldid lipo make nm
    otool plutil python3 rsync security shasum tar xcrun zstd rg
)
for tool in "${HOST_TOOLS[@]}"; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required host tool: $tool"
done
python3 - <<'PY' || die "Python 3.10 or newer is required"
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PY
[[ -x "$CRYPTEXCTL" ]] || die \
    "missing $CRYPTEXCTL; install the Security Research Device host tools"
xcrun --sdk iphoneos --show-sdk-path >/dev/null 2>&1 || die \
    "the iPhoneOS SDK is unavailable; select a full Xcode installation with xcode-select"

prepare_upstream() {
    if [[ -e "$UPSTREAM_DIR" && ! -d "$UPSTREAM_DIR/.git" ]]; then
        die "$UPSTREAM_DIR exists but is not a Git working tree"
    fi
    if [[ ! -d "$UPSTREAM_DIR/.git" ]]; then
        print -- "Fetching pinned opa334/Dopamine commit..."
        mkdir -p "$UPSTREAM_DIR"
        git -C "$UPSTREAM_DIR" init -q
        git -C "$UPSTREAM_DIR" remote add origin "$UPSTREAM_URL"
        print -r -- "$UPSTREAM_URL@$UPSTREAM_COMMIT" >"$MANAGED_MARKER"
        if ! git -C "$UPSTREAM_DIR" fetch --depth=1 origin "$UPSTREAM_COMMIT"; then
            git -C "$UPSTREAM_DIR" fetch --filter=blob:none --depth=512 origin 3.x
        fi
        git -C "$UPSTREAM_DIR" checkout -q --detach "$UPSTREAM_COMMIT"
    else
        [[ -f "$MANAGED_MARKER" && \
            "$(<"$MANAGED_MARKER")" == "$UPSTREAM_URL@$UPSTREAM_COMMIT" ]] || die \
            "$UPSTREAM_DIR was not created by this setup script; move it aside first"
        [[ "$(git -C "$UPSTREAM_DIR" remote get-url origin)" == "$UPSTREAM_URL" ]] || \
            die "unexpected Dopamine origin in $UPSTREAM_DIR"
        [[ -z "$(git -C "$UPSTREAM_DIR" status --porcelain --untracked-files=no)" ]] || \
            die "tracked changes exist in generated Dopamine-upstream; preserve or revert them first"
        if ! git -C "$UPSTREAM_DIR" cat-file -e "$UPSTREAM_COMMIT^{commit}" 2>/dev/null; then
            git -C "$UPSTREAM_DIR" fetch --depth=1 origin "$UPSTREAM_COMMIT"
        fi
        git -C "$UPSTREAM_DIR" checkout -q --detach "$UPSTREAM_COMMIT"
    fi
    [[ "$(git -C "$UPSTREAM_DIR" rev-parse HEAD)" == "$UPSTREAM_COMMIT" ]] || \
        die "Dopamine checkout does not match pinned commit $UPSTREAM_COMMIT"
    expected_opainject=$(git -C "$UPSTREAM_DIR" ls-tree "$UPSTREAM_COMMIT" \
        BaseBin/opainject | awk '{print $3}')
    [[ -n "$expected_opainject" ]] || \
        die "pinned Dopamine commit has no opainject submodule"
    git -C "$UPSTREAM_DIR" submodule update --init --depth=1 BaseBin/opainject
    [[ "$(git -C "$UPSTREAM_DIR/BaseBin/opainject" rev-parse HEAD)" == \
        "$expected_opainject" ]] || \
        die "opainject checkout does not match pinned Dopamine gitlink"
}

prepare_upstream
mkdir -p "$UPSTREAM_DIR/CryptexBootstrap"
rsync -a --delete \
    --exclude '/cache/' \
    --exclude '/work/' \
    --exclude '/out/' \
    --exclude '/__pycache__/' \
    "$OVERLAY_DIR/" "$UPSTREAM_DIR/CryptexBootstrap/"

print -- "Preparing pinned Python environment..."
make -C "$PROJECT_ROOT" python
"$PROJECT_ROOT/.venv/bin/python" \
    "$PROJECT_ROOT/tools/patch_pymobiledevice3_remotexpc.py"

SIGNING_DIR="$UPSTREAM_DIR/CryptexBootstrap/work/signing"
mkdir -p "$SIGNING_DIR"
SIGNING_ARGS=(
    --bundle-id "$CODEX_SILEO_BUNDLE_IDENTIFIER"
    --output-json "$SIGNING_DIR/setup-check.json"
    --output-entitlements "$SIGNING_DIR/sileo-development-entitlements.plist"
)
[[ -z "$TARGET_UDID" ]] || SIGNING_ARGS+=(--device "$TARGET_UDID")
[[ -z "${CODEX_SILEO_DEVELOPMENT_IDENTITY:-}" ]] || \
    SIGNING_ARGS+=(--identity "$CODEX_SILEO_DEVELOPMENT_IDENTITY")
[[ -z "${CODEX_SILEO_PROVISIONING_PROFILE:-}" ]] || \
    SIGNING_ARGS+=(--profile "$CODEX_SILEO_PROVISIONING_PROFILE")
[[ -z "${CODEX_SILEO_DEVELOPMENT_ENTITLEMENTS:-}" ]] || \
    SIGNING_ARGS+=(--entitlements "$CODEX_SILEO_DEVELOPMENT_ENTITLEMENTS")
"$PROJECT_ROOT/.venv/bin/python" \
    "$UPSTREAM_DIR/CryptexBootstrap/configure_signing.py" \
    "${SIGNING_ARGS[@]}"

if [[ "$ACTION" == prepare ]]; then
    print -- ""
    print -- "Ready. Build with:"
    print -- "  ./Dopamine-CryptexBootstrap/setup.sh --build"
    print -- "Install on the validated connected device with:"
    print -- "  ./Dopamine-CryptexBootstrap/setup.sh --install"
    exit 0
fi

DEPLOY_ARGS=("$ACTION")
[[ -z "$DEVICE" ]] || DEPLOY_ARGS+=(--device "$DEVICE")
(( ALLOW_UNVERIFIED == 0 )) || DEPLOY_ARGS+=(--allow-unverified-device)
(( NO_REPLACE == 0 )) || DEPLOY_ARGS+=(--no-replace)
exec "$PROJECT_ROOT/.venv/bin/python" \
    "$UPSTREAM_DIR/CryptexBootstrap/deploy.py" \
    "${DEPLOY_ARGS[@]}"
