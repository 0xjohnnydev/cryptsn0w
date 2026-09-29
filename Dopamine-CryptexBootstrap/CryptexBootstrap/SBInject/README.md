# SBInject integration

This directory is the main-jailbreak port of the ad-hoc `SBInject` proof that
was supplied alongside the repository.  It intentionally keeps the proof's
four required stages and drops its unrelated process-wide policy changes:

1. a narrowly scoped launchd hook redirects only SpringBoard;
2. `jitterd` marks only that exact replacement process debugged;
3. the replacement's compact `@loader_path/g` pre-main hook installs the
   supplied dyld mmap/fcntl validation bypass; and
4. the hook loads ElleKit's injector before SpringBoard enters `main`.

The same pre-main JIT/dyld lane redirects the stock Settings executable to the
resigned `notPreferences` candidate. It loads pinned PreferenceLoader 2.3.3,
then the fixed `preferences-bridge.dylib` that adapts registrations to iOS 27's
`SettingsSidebarListState`. The bridge discovers Swift metadata at runtime,
updates the section array and both lookup dictionaries before SwiftUI evaluates
each snapshot, and sends row selections through libprefs to the installed
preference bundle controller. It is inert when the iOS 27 model class is absent.

Before ElleKit loads, the same lane loads `legacy-tweak-compat.dylib`. This
fixed library provides common iOS 27 repairs for old tweak windows and old
PreferenceLoader cells. It retries missing legacy file, preference, framework,
and tool paths under `/var/jb`. It sends only an exact Settings respring request
to the fixed root broker operation. It does not provide a general root command
interface. It also exports four small functions for exact class, method, and
path mappings. Their declarations are in
`sbinject_legacy_tweak_compat.h`. The optional mapping file is
`/var/jb/etc/sbinject/legacy-tweak-compat.plist`. It must be a regular,
root-owned file. It must not be writable by a group or other users. Its maximum
size is 64 KiB. This is the supported format:

```plist
{
    ClassAliases = {
        LegacyClassName = CurrentClassName;
    };
    PathPrefixes = {
        "/usr/local/share/LegacyTweak/" =
            "/var/jb/usr/share/LegacyTweak/";
    };
    SelectorAliases = (
        {
            Class = CurrentClassName;
            Legacy = "oldMethod:";
            Current = "newMethod:";
            ClassMethod = false;
        }
    );
}
```

The library applies only exact class and method mappings with matching argument
counts. A configured path must start in a supported legacy tweak directory and
must end under `/var/jb`. The default path repair first uses an existing Apple
path. It does not redirect Apple system preference files. It does not translate
changed data types or changed behavior. A load failure does not stop ElleKit or
the target process.

After a package transaction, the bootstrap scans installed tweak, framework,
and preference bundle Mach-O files. Mach-O is the executable file format on
iOS. If a file needs a library from an old absolute path, and the matching
`/var/jb` library exists, the bootstrap updates that dependency and signs the
changed file again. It never follows the scan outside `/var/jb`.

The launchd hook is inert unless the root-owned
`/var/jb/var/lib/sbinject/enabled` marker exists.  Three replacement launches
inside sixty seconds remove that marker and return launchd to the stock
SpringBoard path.  A failed redirected spawn also falls back immediately.

The dyld bypass locates its two syscall stubs uniquely in the live dyld image
using the supplied SBInject signature scan. It has no model-specific offset or
dyld hash.

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
PreferenceLoader, libprefs, and installed preference bundles use that same
Sileo-managed JIT/dyld lane and are not added to the fixed trust cache.

Sileo itself is fixed control-plane code, not an incoming package exception.
Its main executable, helper, uniquely named broker constructor, and bundled
libraries live only in the Cryptex system-app bundle; their CDHashes are
asserted in the generated fixed trust cache. A second fixed hook is admitted
only for the exact `/usr/libexec/lsd` process and enables iOS 27's modern
containerized system-app registration call. Its readiness marker is bound to
the live `lsd` PID and current boot. The trust cache is never changed after
installation.
