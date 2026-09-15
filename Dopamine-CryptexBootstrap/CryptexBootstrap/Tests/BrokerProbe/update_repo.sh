#!/bin/zsh

set -euo pipefail

SCRIPT_DIR=${0:A:h}
BOOTSTRAP_DIR=${SCRIPT_DIR:h:h}
OUTPUT_DIR="$BOOTSTRAP_DIR/out/broker-probe"
REPO_DIR="$OUTPUT_DIR/repo"
PACKAGE_VERSION=${1:-1.0.14}
DEB="$OUTPUT_DIR/com.openai.codex.broker-probe_${PACKAGE_VERSION}_iphoneos-arm64.deb"

if [[ ! -f "$DEB" ]]; then
    print -u2 "missing package: $DEB"
    exit 1
fi

mkdir -p "$REPO_DIR"
install -m 0644 "$DEB" "$REPO_DIR/${DEB:t}"

cd "$REPO_DIR"
dpkg-scanpackages --multiversion . /dev/null >Packages
gzip -9cn Packages >Packages.gz

RELEASE_TMP=$(mktemp "$REPO_DIR/.Release.XXXXXX")
{
    printf 'Origin: Codex Runtime Verification\n'
    printf 'Label: Codex Broker Probe\n'
    printf 'Suite: stable\n'
    printf 'Codename: broker-probe\n'
    printf 'Date: %s\n' "$(LC_ALL=C date -u '+%a, %d %b %Y %H:%M:%S +0000')"
    printf 'Architectures: iphoneos-arm64\n'
    printf 'Components: main\n'
    printf 'Description: Codex runtime admission verification repository\n'

    printf 'MD5Sum:\n'
    for file in Packages Packages.gz; do
        printf ' %s %s %s\n' "$(md5 -q "$file")" "$(stat -f %z "$file")" "$file"
    done
    for algorithm in 1 256 512; do
        printf 'SHA%s:\n' "$algorithm"
        for file in Packages Packages.gz; do
            printf ' %s %s %s\n' \
                "$(shasum -a "$algorithm" "$file" | awk '{print $1}')" \
                "$(stat -f %z "$file")" "$file"
        done
    done
} >"$RELEASE_TMP"
mv -f "$RELEASE_TMP" Release

shasum -a 256 "$DEB" Packages Packages.gz Release
