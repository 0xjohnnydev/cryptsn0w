#!/bin/sh

set -eu

lists_directory=${1:-/var/jb/var/lib/apt/lists}
[ -d "$lists_directory" ] || exit 0

for package_list in "$lists_directory"/*Packages; do
    [ -f "$package_list" ] || continue

    # Some otherwise valid repositories publish a final control paragraph
    # without its line or paragraph terminator. apt-get accepts the download,
    # while later libapt consumers reject the entire package cache at EOF.
    if [ -n "$(/var/jb/usr/bin/tail -c 1 "$package_list")" ]; then
        printf '\n\n' >>"$package_list"
    elif [ -n "$(/var/jb/usr/bin/tail -c 2 "$package_list")" ]; then
        printf '\n' >>"$package_list"
    fi
done
