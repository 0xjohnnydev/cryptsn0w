# SBInject integration

This directory is the main-jailbreak port of the ad-hoc `SBInject` proof that
was supplied alongside the repository.  It intentionally keeps the proof's
four required stages and drops its unrelated process-wide policy changes:

1. a narrowly scoped launchd hook redirects only SpringBoard;
2. `jitterd` marks only that exact replacement process debugged;
3. the replacement's compact `@loader_path/g` pre-main hook installs the
   supplied dyld mmap/fcntl validation bypass; and
4. the hook loads ElleKit's injector before SpringBoard enters `main`.

The launchd hook is inert unless the root-owned
`/var/jb/var/lib/sbinject/enabled` marker exists.  Three replacement launches
inside sixty seconds remove that marker and return launchd to the stock
SpringBoard path.  A failed redirected spawn also falls back immediately.

The dyld signatures and offsets are pinned to the dyld shipped on the target
iPhone 13 (SHA-256
`ab9887ed96c9c08ad68d4c6a5c27e8289fb0c9e55ec3e134547292a1ec579608`).

ElleKit 1.2 is installed from one pinned, fully ad-hoc-signed package whose
five Mach-Os are included in the fixed Cryptex trust cache. This is the only
package-level exception and guarantees that the pre-main hook can load ElleKit
before any Sileo tweak transaction. Incoming Sileo package payloads are never
added to a trust cache. The fixed Sileo broker validates its prefetched
archives directly before APT/dpkg (APT's shell-based hook cannot run on the
rootless `/var/jb` layout), identifies dylibs in the standard rootless tweak
directories, requires this SBInject lane to be ready, and marks a respring. The
debugged replacement SpringBoard and its dyld bypass provide the sole admission
path for the ad-hoc signed third-party tweak dylibs ElleKit loads.
