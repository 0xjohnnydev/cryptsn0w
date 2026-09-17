#!/bin/zsh

set -euo pipefail

SCRIPT_DIR=${0:A:h}
SOURCE_APP=${CODEX_SILEO_SOURCE_APP:-$SCRIPT_DIR/work/sileo-package/var/jb/Applications/Sileo.app}
PROCURSUS_LIB=${CODEX_PROCURSUS_LIB:-$SCRIPT_DIR/work/image-root/usr/local/share/codex-bootstrap/procursus/usr/lib}
DEVELOPMENT_IDENTITY=${CODEX_SILEO_DEVELOPMENT_IDENTITY:-}
PROVISIONING_PROFILE=${CODEX_SILEO_PROVISIONING_PROFILE:-}
ENTITLEMENTS=${CODEX_SILEO_DEVELOPMENT_ENTITLEMENTS:-}
SIGNING_CONFIG="$SCRIPT_DIR/work/signing/config.json"
BUILD_SUMMARY="$SCRIPT_DIR/out/build-summary.json"

die() {
    print -u2 -- "error: $*"
    exit 1
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

for tool in awk codesign ditto file install_name_tool ldid otool plutil python3 rg security shasum tr xcrun; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done
[[ -d "$SOURCE_APP" && -x "$SOURCE_APP/Sileo" ]] || \
    die "missing built Sileo app: $SOURCE_APP"
for library in libiosexec.1.dylib liblzma.5.dylib libzstd.1.5.5.dylib; do
    [[ -f "$PROCURSUS_LIB/$library" ]] || \
        die "missing Procursus runtime library: $PROCURSUS_LIB/$library"
done
[[ -f "$SIGNING_CONFIG" ]] || \
    die "missing paired signing config; run build_cryptex.sh first"
[[ -f "$BUILD_SUMMARY" ]] || \
    die "missing Cryptex build summary; run build_cryptex.sh first"
CONFIG_IDENTITY=$(json_field "$SIGNING_CONFIG" identitySha1)
CONFIG_PROFILE=$(json_field "$SIGNING_CONFIG" profile)
CONFIG_ENTITLEMENTS=$(json_field "$SIGNING_CONFIG" entitlements)
[[ -z "$DEVELOPMENT_IDENTITY" || "$DEVELOPMENT_IDENTITY" == "$CONFIG_IDENTITY" ]] || \
    die "signing identity differs from the paired Cryptex build"
[[ -z "$PROVISIONING_PROFILE" || "${PROVISIONING_PROFILE:A}" == "${CONFIG_PROFILE:A}" ]] || \
    die "provisioning profile differs from the paired Cryptex build"
DEVELOPMENT_IDENTITY=$CONFIG_IDENTITY
PROVISIONING_PROFILE=$CONFIG_PROFILE
ENTITLEMENTS=$CONFIG_ENTITLEMENTS
BUILD_VERSION=$(json_field "$BUILD_SUMMARY" version)
SAFE_VERSION=$(print -rn -- "$BUILD_VERSION" | tr -c 'A-Za-z0-9._-' '_')
OUTPUT_IPA=${CODEX_SILEO_LAUNCHER_IPA:-$SCRIPT_DIR/out/Sileo.brokered-$SAFE_VERSION.ipa}
OUTPUT_SUMMARY=${CODEX_SILEO_LAUNCHER_SUMMARY:-$SCRIPT_DIR/out/sileo-brokered-$SAFE_VERSION.json}
[[ -f "$PROVISIONING_PROFILE" ]] || \
    die "missing provisioning profile: $PROVISIONING_PROFILE"
[[ -f "$ENTITLEMENTS" ]] || die "missing entitlements: $ENTITLEMENTS"
[[ ! -e "$OUTPUT_IPA" ]] || die "refusing to overwrite $OUTPUT_IPA"
[[ ! -e "$OUTPUT_SUMMARY" ]] || die "refusing to overwrite $OUTPUT_SUMMARY"
security find-identity -v -p codesigning | rg -q "$DEVELOPMENT_IDENTITY" || \
    die "development identity is unavailable: $DEVELOPMENT_IDENTITY"

STAGE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/codex-sileo-brokered.XXXXXX")
PAYLOAD_DIR="$STAGE_DIR/Payload"
APP_DIR="$PAYLOAD_DIR/Sileo.app"
FRAMEWORKS_DIR="$APP_DIR/F"
cleanup() {
    [[ ! -d "$STAGE_DIR" ]] || rm -rf -- "$STAGE_DIR"
}
trap cleanup EXIT
mkdir -p "$PAYLOAD_DIR" "${OUTPUT_IPA:h}"
ditto --noqtn "$SOURCE_APP" "$APP_DIR"
cp "$PROVISIONING_PROFILE" "$APP_DIR/embedded.mobileprovision"
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

SDKROOT=$(xcrun --sdk iphoneos --show-sdk-path)
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
    "$SCRIPT_DIR/sileo_broker_constructor.c" \
    -o "$FRAMEWORKS_DIR/libzstd.1.dylib"
for library in "$FRAMEWORKS_DIR"/*.dylib; do
    codesign --force --sign "$DEVELOPMENT_IDENTITY" --timestamp=none \
        --pagesize 4096 "$library"
done
codesign --force --sign "$DEVELOPMENT_IDENTITY" --timestamp=none \
    --pagesize 4096 --entitlements "$ENTITLEMENTS" "$APP_DIR"
codesign --verify --deep --strict --verbose=2 "$APP_DIR"

otool -l "$APP_DIR/Sileo" | rg -q 'path @loader_path/F'
otool -L "$FRAMEWORKS_DIR/libzstd.1.dylib" | \
    rg -q '@rpath/libzstd.real.dylib'
ditto -c -k --sequesterRsrc --keepParent "$PAYLOAD_DIR" "$OUTPUT_IPA"

python3 - "$OUTPUT_SUMMARY" "$OUTPUT_IPA" "$APP_DIR" \
    "$DEVELOPMENT_IDENTITY" "$PROVISIONING_PROFILE" \
    "$BUILD_SUMMARY" "$BUILD_VERSION" <<'PY'
import hashlib
import json
import pathlib
import sys

summary, ipa, app, identity, profile, build_summary, build_version = sys.argv[1:]

def sha256(path: str) -> str:
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

result = {
    "ipa": str(pathlib.Path(ipa).resolve()),
    "ipaSha256": sha256(ipa),
    "cryptexVersion": build_version,
    "cryptexBuildSummarySha256": sha256(build_summary),
    "sileoSha256": sha256(str(pathlib.Path(app, "Sileo"))),
    "rootHelperSha256": sha256(str(pathlib.Path(app, "giveMeRoot"))),
    "constructorShimSha256": sha256(
        str(pathlib.Path(app, "F", "libzstd.1.dylib"))
    ),
    "bundledRuntime": {
        name: sha256(str(pathlib.Path(app, "F", name)))
        for name in (
            "libiosexec.1.dylib",
            "liblzma.5.dylib",
            "libzstd.real.dylib",
        )
    },
    "developmentIdentitySha1": identity,
    "provisioningProfile": {
        "path": profile,
        "sha256": sha256(profile),
    },
}
pathlib.Path(summary).write_text(
    json.dumps(result, indent=2, sort_keys=True) + "\n"
)
print(json.dumps(result, indent=2, sort_keys=True))
PY
