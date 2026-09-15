#!/bin/zsh

# Atomically select the proven patched Gadget or its untouched official
# rollback copy.  Existing cache contents are retained under build/.

set -euo pipefail

script_dir=${0:A:h}
project_root=${script_dir:h}
cache="$HOME/.cache/frida/gadget-ios.dylib"
patched="$project_root/build/frida-ios27-host/gadget-ios.17.17.0.code-page-plan.dylib"
official="$project_root/build/frida-ios27-host/gadget-ios.17.17.0.official.dylib"
patched_sha=10a34a745f3e2342004847ee921119ff50fc41ea6ffc949b0c6a4ccd37182c71
official_sha=1c5855bacfbe2e2ed3029b15a44110967609416676c2e3f9e998a83b1c3a4bf5

if (( $# != 1 )) || [[ $1 != patched && $1 != official ]]; then
    print -u2 -- "usage: $0 patched|official"
    exit 64
fi

if [[ $1 == patched ]]; then
    source_path=$patched
    expected_sha=$patched_sha
else
    source_path=$official
    expected_sha=$official_sha
fi

if [[ ! -f $source_path ]]; then
    print -u2 -- "missing staged Gadget: $source_path"
    exit 66
fi
actual_sha=$(shasum -a 256 "$source_path" | awk '{ print $1 }')
if [[ $actual_sha != $expected_sha ]]; then
    print -u2 -- "refusing unexpected Gadget SHA-256: $actual_sha"
    exit 65
fi
codesign --verify --strict --verbose=2 "$source_path"

mkdir -p -- "${cache:h}" "$project_root/build/frida-ios27-host/cache-backups"
if [[ -f $cache ]]; then
    current_sha=$(shasum -a 256 "$cache" | awk '{ print $1 }')
    if [[ $current_sha == $expected_sha ]]; then
        print -- "already-selected=$1"
        print -- "sha256=$current_sha"
        exit 0
    fi
    timestamp=$(date -u +%Y%m%dT%H%M%SZ)
    backup="$project_root/build/frida-ios27-host/cache-backups/gadget-ios.${timestamp}.${current_sha}.dylib"
    cp -p -- "$cache" "$backup"
    print -- "backup=$backup"
fi

temporary=$(mktemp "${cache:h}/.gadget-ios.install.XXXXXX")
cleanup() {
    [[ -n ${temporary:-} && -f $temporary ]] && rm -f -- "$temporary"
}
trap cleanup EXIT INT TERM
cp -p -- "$source_path" "$temporary"
codesign --verify --strict --verbose=2 "$temporary"
mv -f -- "$temporary" "$cache"
temporary=''

print -- "selected=$1"
print -- "cache=$cache"
print -- "sha256=$expected_sha"
