# Cryptex runtime overlay

This directory is self-contained when copied into the pinned Dopamine checkout.
It builds and deploys the production runtime and its temporary SSH acquisition
stage; it contains no research probes.

## Components

- `build_cryptex.sh` builds the complete image and enforces pinned hashes,
  signatures, trust-cache membership, and the 128 MiB ceiling.
- `codex_dopamine_bootstrap.m` installs or repairs `/var/jb`, registers system
  Sileo, restores launch jobs, brokers package work, redirects SpringBoard and
  Settings, and handles reboot recovery.
- `codex_exec_worker.c` executes only Mach-O dpkg maintainer scripts through
  the debugged SBInject-compatible child path.
- `SBInject/` contains the launchd redirect, JIT broker, pre-main hook, lsd
  registration hook, and iOS 27 PreferenceLoader bridge.
- `deploy.py`, `personalize_generic_cryptex1.py`, and
  `install_cryptex_bootstrap.py` perform the two-Cryptex installation.

An install uses the already-loaded base-bootstrap job to mount an ephemeral
public-key-only SSH payload without rebooting. It copies the device's own
SpringBoard and Preferences bundles into the ignored `build/target/` directory,
builds the candidates from those exact files, then replaces the stage with the
final Cryptex. Nothing in the tracked repository is tied to a device model,
UDID, Apple binary hash, UUID, or dyld offset.

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
Every Mach-O architecture must pass strict static signature validation before
APT can install the archive or request a respring.
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

Generated content is ignored under `cache/`, `work/`, and `out/`.
`out/build-summary.json` records the image size and trust-cache entries.
`out/runs/<run-id>/` records both installations, personalization, Sileo launch,
and icon verification.

Bootstrap diagnostics are written to
`/var/tmp/codex-dopamine-cryptex-bootstrap.log`.
