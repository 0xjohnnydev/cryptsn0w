# Cryptex runtime overlay

**Redacted source:** TSS request construction, personalization, and related
installation details are intentionally omitted. The files retain placeholders
for educational reference.

Historical documentation for an obsolete project. See the
[project status](../../README.md) before using these instructions.

This directory is self-contained when copied into the pinned Dopamine checkout.
It builds and deploys the production runtime and its temporary SSH acquisition
stage; it contains no research probes.

## Components

[REDACTED: Related request, payload, or installation details omitted.]

An install builds and installs a temporary Cryptex with its own launch daemon
and public-key-only SSH server. It copies the device's SpringBoard and
Preferences bundles and `amfid` executable into the ignored `build/target/`
directory, builds from those inputs, then replaces the stage with the final
Cryptex. The flow is designed to complete without a reboot.

## Installed model

`/var/jb` is a managed symlink to a randomized Procursus root in the active
preboot directory. Repair mode accepts it only when ownership, symlink target,
manifest, and active preboot parent match this installer.

The authoritative Sileo bundle lives in the read-only Cryptex. The boot daemon
maintains an exact root-owned copy in an application container created by
MobileContainerManager:

```text
/var/containers/Bundle/Application/<managed UUID>/Sileo.app
```

LaunchServices registers that path under the original
`org.coolstar.SileoStore` identifier as a non-removable system app. Its icon,
assets, translations, localizations, and dictionaries remain in the copied
upstream bundle. Sileo has no provisioning profile or signing expiration.
On iOS 27, the marketing iPhone 18 generation (`iPhone19,*`) first registers
through the installer's entitled LaunchServices client. If that lane fails it
falls back to the existing `lsd` registration hook; other hardware keeps the
hook-first behavior.

The Debian `org.coolstar.sileo` package contains dependency and maintainer
metadata, plus one state marker that keeps the package in dpkg's database. It
does not contain a second mutable application bundle. APT pins the local
`2.5.1+codex1` version. Sileo updates therefore ship in a new Cryptex.

## Package operations

The authenticated root broker accepts the bounded command shapes used by
Sileo. Package archives are validated before the no-download APT transaction.
Shell maintainer scripts use the rootless shell; Mach-O maintainers are wrapped
through `codex-exec-worker --macho`. Install, remove, reinstall, and update all
prepare the resulting tweak state. Sileo’s bottom-sheet action performs the
user-requested respring rather than the post hook respringing by itself.

ElleKit 1.2 is the only package-level fixed-trust exception. Third-party tweak
dylibs are not added to a mutable trust cache; the resigned SpringBoard and
Settings candidates enter through SBInject’s pre-main JIT/dyld path.

## SpringBoard and Settings

The launchd hook redirects stock SpringBoard to
`/var/jb/System/Library/CoreServices/SpringBoard.app/notSpringBoard`.
`sbinject-jitterd` grants the exact replacement process its debugged/JIT state,
the `@loader_path/g` hook performs the bounded RW-to-RX and dyld handoff, and
ElleKit loads tweaks before `main`.

Settings uses the same route at
`/var/jb/Applications/Preferences.app/notPreferences`. The candidate preserves
the device entitlements and merges the debugger/task-port keys. The fixed
PreferenceLoader bridge publishes legacy preference bundles into iOS 27’s
`SettingsSidebarListState` and forwards supported pane respring commands to the
same broker.

`legacy-tweak-compat.dylib` is a small shared compatibility library. A dynamic
library, or dylib, is code that several processes can load. The launch path
loads this library before ElleKit in SpringBoard, Settings, and managed apps
that enable tweak injection. On iOS 27 it attaches old overlay windows to the
active window scene. In Settings it also restores supported legacy row heights
and subtitle text for third-party PreferenceLoader bundles. In SpringBoard it
connects old application shortcut item and action hooks to the iOS 27
context-menu provider. It retries missing legacy tweak paths under `/var/jb`.
It gives old virtual icons a safe application result. It also maps the old
lock-screen flashlight and camera button getters to the current quick-action
button list. It maps the old volume HUD value getter to its current name.
It restores the standard process names for the managed SpringBoard and
Settings copies before ElleKit loads tweaks. It also retries old tool launches
from the rootless tool directories. An exact Settings respring request uses the
fixed root broker operation. The library does not give a tweak general root
broker access.

For other App Store apps, the compatibility launch path requires both an
enabled Shadow policy and a secure marker from the trusted app launcher. An app
cannot opt into this privileged path by itself.

The package preparation step also repairs an old absolute dylib dependency
when the old file is absent and its `/var/jb` file exists. A dylib dependency
is the path to another library that code needs before it can start. The repair
stays inside installed tweak, framework, and preference bundle directories.

One root-owned property list can add exact class, method, and path mappings
without a new tweak patch. The library ignores unsafe mapping files and does
not guess class or method mappings. It does not redirect an existing Apple
file or an Apple system preference file. Create
`/var/mobile/.sbinject-legacy-compat-disabled` to disable the library.

Safe mode does not rename or disable installed tweaks. Crash attribution strips
PAC bits and identifies a loaded tweak when a matching image is available.

## SSH and reboot recovery

The base image uses the pinned Procursus SSH bootstrap. Exact OpenSSH 9.7p1-1
client, server, and SFTP Debian packages are also embedded so repair mode can
restore an older `/var/jb`. The boot daemon verifies the installed bytes against
their Cryptex copies and bootstraps `system/com.openssh.sshd`.

On an unchanged reboot, the local fast path verifies all fixed bytes and package
versions, re-registers Sileo, starts jitterd, the Sileo root broker, and SSH,
then arms Settings and replaces SpringBoard. It needs neither network access nor
a connected Mac.

## Outputs

[REDACTED: Related request, payload, or installation details omitted.]

Bootstrap diagnostics are written to
`/var/tmp/codex-dopamine-cryptex-bootstrap.log`.
