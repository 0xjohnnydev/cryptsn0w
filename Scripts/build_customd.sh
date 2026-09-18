#!/bin/sh
set -eu

SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPOSITORY_ROOT=$(CDPATH= cd -- "$SCRIPT_DIRECTORY/.." && pwd)
OUTPUT_DIRECTORY=${1:-"$REPOSITORY_ROOT/build/customd"}
CUSTOMD_OUTPUT="$OUTPUT_DIRECTORY/customd"
CUSTOMCTL_OUTPUT="$OUTPUT_DIRECTORY/customctl"
REGISTRAR_OUTPUT="$OUTPUT_DIRECTORY/customd-candidate-registrar"

: "${CODEX_CUSTOMD_WORKER_PATH:?set CODEX_CUSTOMD_WORKER_PATH to the intended codex-exec-worker}"
: "${CODEX_CUSTOMD_CANDIDATE_PATH:?set CODEX_CUSTOMD_CANDIDATE_PATH to the intended SpringBoard candidate}"
: "${CODEX_CUSTOMD_CANDIDATE_INFO_PATH:?set CODEX_CUSTOMD_CANDIDATE_INFO_PATH to the intended candidate Info.plist}"
: "${CODEX_CUSTOMD_LAUNCHCTL_PATH:?set CODEX_CUSTOMD_LAUNCHCTL_PATH to the intended installed launchctl}"
: "${CODEX_CUSTOMD_TRACE_REEXEC_PROBE_PATH:?set CODEX_CUSTOMD_TRACE_REEXEC_PROBE_PATH to the intended trace re-exec probe}"
: "${CODEX_CUSTOMD_SETEXEC_HELPER_PATH:?set CODEX_CUSTOMD_SETEXEC_HELPER_PATH to the intended SpringBoard SETEXEC helper}"

for PINNED_ARTIFACT in \
    "$CODEX_CUSTOMD_WORKER_PATH" \
    "$CODEX_CUSTOMD_CANDIDATE_PATH" \
    "$CODEX_CUSTOMD_CANDIDATE_INFO_PATH" \
    "$CODEX_CUSTOMD_LAUNCHCTL_PATH" \
    "$CODEX_CUSTOMD_TRACE_REEXEC_PROBE_PATH" \
    "$CODEX_CUSTOMD_SETEXEC_HELPER_PATH"; do
    [ -f "$PINNED_ARTIFACT" ] || {
        echo "error: missing customd pinned artifact: $PINNED_ARTIFACT" >&2
        exit 1
    }
done

mkdir -p "$OUTPUT_DIRECTORY"

COMMON_FLAGS="-target arm64e-apple-ios27.0 -std=c17 -Wall -Wextra -Werror -O2 -fno-common"

"$SCRIPT_DIRECTORY/build_customd_candidate_registrar.sh" \
    "$OUTPUT_DIRECTORY"
REGISTRAR_SHA256=$(shasum -a 256 "$REGISTRAR_OUTPUT" | awk '{print $1}')
WORKER_SHA256=$(shasum -a 256 "$CODEX_CUSTOMD_WORKER_PATH" | awk '{print $1}')
CANDIDATE_SHA256=$(shasum -a 256 "$CODEX_CUSTOMD_CANDIDATE_PATH" | awk '{print $1}')
CANDIDATE_INFO_SHA256=$(shasum -a 256 "$CODEX_CUSTOMD_CANDIDATE_INFO_PATH" | awk '{print $1}')
LAUNCHCTL_SHA256=$(shasum -a 256 "$CODEX_CUSTOMD_LAUNCHCTL_PATH" | awk '{print $1}')
TRACE_REEXEC_PROBE_SHA256=$(shasum -a 256 "$CODEX_CUSTOMD_TRACE_REEXEC_PROBE_PATH" | awk '{print $1}')
SETEXEC_HELPER_SHA256=$(shasum -a 256 "$CODEX_CUSTOMD_SETEXEC_HELPER_PATH" | awk '{print $1}')
CANDIDATE_SIZE=$(stat -f '%z' "$CODEX_CUSTOMD_CANDIDATE_PATH")
if strings -a "$CODEX_CUSTOMD_WORKER_PATH" | \
    grep -- '--macho-inplace' >/dev/null; then
    WORKER_HAS_MACHO_INPLACE=1
    LEGACY_WORKER_RUNTIME_PATCH=0
else
    WORKER_HAS_MACHO_INPLACE=0
    case "$WORKER_SHA256" in
        6d346b388e844e4e8eee487ad2261f7a97ec8508e7bfaa7ed9ceab97bf697657)
            LEGACY_WORKER_RUNTIME_PATCH=1
            ;;
        *)
            echo "error: worker lacks --macho-inplace and is not the admitted legacy build" >&2
            exit 1
            ;;
    esac
fi
for PINNED_SHA256 in "$REGISTRAR_SHA256" "$WORKER_SHA256" \
    "$CANDIDATE_SHA256" "$CANDIDATE_INFO_SHA256" \
    "$LAUNCHCTL_SHA256" "$TRACE_REEXEC_PROBE_SHA256" \
    "$SETEXEC_HELPER_SHA256"; do
    if [ "${#PINNED_SHA256}" -ne 64 ]; then
        echo "error: invalid customd pinned sha256" >&2
        exit 1
    fi
done
case "$CANDIDATE_SIZE" in
    ''|*[!0-9]*)
        echo "error: invalid candidate size" >&2
        exit 1
        ;;
esac

xcrun --sdk iphoneos clang $COMMON_FLAGS -Wl,-dead_strip \
    "-DCUSTOMD_EXPECTED_REGISTRAR_SHA256_HEX=\"$REGISTRAR_SHA256\"" \
    "-DCUSTOMD_EXPECTED_WORKER_SHA256_HEX=\"$WORKER_SHA256\"" \
    "-DCUSTOMD_EXPECTED_CANDIDATE_SHA256_HEX=\"$CANDIDATE_SHA256\"" \
    "-DCUSTOMD_EXPECTED_CANDIDATE_INFO_SHA256_HEX=\"$CANDIDATE_INFO_SHA256\"" \
    "-DCUSTOMD_EXPECTED_LAUNCHCTL_SHA256_HEX=\"$LAUNCHCTL_SHA256\"" \
    "-DCUSTOMD_EXPECTED_TRACE_REEXEC_PROBE_SHA256_HEX=\"$TRACE_REEXEC_PROBE_SHA256\"" \
    "-DCUSTOMD_EXPECTED_SETEXEC_HELPER_SHA256_HEX=\"$SETEXEC_HELPER_SHA256\"" \
    "-DCUSTOMD_EXPECTED_CANDIDATE_SIZE=$CANDIDATE_SIZE" \
    "-DCUSTOMD_WORKER_HAS_MACHO_INPLACE=$WORKER_HAS_MACHO_INPLACE" \
    "-DCUSTOMD_LEGACY_WORKER_RUNTIME_PATCH=$LEGACY_WORKER_RUNTIME_PATCH" \
    "$REPOSITORY_ROOT/Sources/customd.c" -o "$CUSTOMD_OUTPUT"
xcrun --sdk iphoneos clang $COMMON_FLAGS -Wl,-dead_strip \
    "$REPOSITORY_ROOT/Sources/customctl.c" -o "$CUSTOMCTL_OUTPUT"

codesign --force --sign - --identifier com.openai.customd \
    --generate-entitlement-der --timestamp=none "$CUSTOMD_OUTPUT"
codesign --force --sign - --identifier com.openai.customctl \
    --generate-entitlement-der --timestamp=none "$CUSTOMCTL_OUTPUT"

codesign --verify --strict "$CUSTOMD_OUTPUT"
codesign --verify --strict "$CUSTOMCTL_OUTPUT"
plutil -lint "$REPOSITORY_ROOT/Sources/com.openai.customd.plist"
file "$CUSTOMD_OUTPUT" "$CUSTOMCTL_OUTPUT" "$REGISTRAR_OUTPUT"
shasum -a 256 "$CUSTOMD_OUTPUT" "$CUSTOMCTL_OUTPUT" "$REGISTRAR_OUTPUT"
