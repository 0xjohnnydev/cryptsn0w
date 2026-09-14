#!/bin/zsh

set -euo pipefail

SCRIPT_DIR=${0:A:h}
SOURCE_APP=${CODEX_SILEO_SOURCE_APP:-$SCRIPT_DIR/work/sileo-package/var/jb/Applications/Sileo.app}
PROCURSUS_LIB=${CODEX_PROCURSUS_LIB:-$SCRIPT_DIR/work/image-root/usr/local/share/codex-bootstrap/procursus/usr/lib}
DEVELOPMENT_IDENTITY=${CODEX_SILEO_DEVELOPMENT_IDENTITY:-845279DD92AA160D4148B0F42C60D6B12CDB8454}
PROVISIONING_PROFILE=${CODEX_SILEO_PROVISIONING_PROFILE:-/Users/johnnyfranks/Library/Developer/Xcode/UserData/Provisioning Profiles/1e1053f5-0740-44ec-bc5a-c94ba800f4c7.mobileprovision}
ENTITLEMENTS=${CODEX_SILEO_DEVELOPMENT_ENTITLEMENTS:-$SCRIPT_DIR/sileo-development-entitlements.plist}
OUTPUT_IPA=${CODEX_SILEO_LAUNCHER_IPA:-$SCRIPT_DIR/out/Sileo.brokered-v36.ipa}
OUTPUT_SUMMARY=${CODEX_SILEO_LAUNCHER_SUMMARY:-$SCRIPT_DIR/out/sileo-brokered-v36.json}

die() {
    print -u2 -- "error: $*"
    exit 1
}

for tool in awk codesign ditto file install_name_tool ldid otool plutil rg security shasum xcrun; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done
[[ -d "$SOURCE_APP" && -x "$SOURCE_APP/Sileo" ]] || \
    die "missing built Sileo app: $SOURCE_APP"
for library in libiosexec.1.dylib liblzma.5.dylib libzstd.1.5.5.dylib; do
    [[ -f "$PROCURSUS_LIB/$library" ]] || \
        die "missing Procursus runtime library: $PROCURSUS_LIB/$library"
done
[[ -f "$PROVISIONING_PROFILE" ]] || \
    die "missing provisioning profile: $PROVISIONING_PROFILE"
[[ -f "$ENTITLEMENTS" ]] || die "missing entitlements: $ENTITLEMENTS"
[[ ! -e "$OUTPUT_IPA" ]] || die "refusing to overwrite $OUTPUT_IPA"
[[ ! -e "$OUTPUT_SUMMARY" ]] || die "refusing to overwrite $OUTPUT_SUMMARY"
security find-identity -v -p codesigning | rg -q "$DEVELOPMENT_IDENTITY" || \
    die "development identity is unavailable: $DEVELOPMENT_IDENTITY"

STAGE_DIR=$(mktemp -d /private/tmp/codex-sileo-brokered.XXXXXX)
PAYLOAD_DIR="$STAGE_DIR/Payload"
APP_DIR="$PAYLOAD_DIR/Sileo.app"
FRAMEWORKS_DIR="$APP_DIR/F"
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

python3 - "$OUTPUT_SUMMARY" "$OUTPUT_IPA" "$STAGE_DIR" "$APP_DIR" \
    "$DEVELOPMENT_IDENTITY" "$PROVISIONING_PROFILE" <<'PY'
import hashlib
import json
import pathlib
import sys

summary, ipa, stage, app, identity, profile = sys.argv[1:]

def sha256(path: str) -> str:
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

result = {
    "ipa": str(pathlib.Path(ipa).resolve()),
    "ipaSha256": sha256(ipa),
    "stageDirectory": stage,
    "app": app,
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
