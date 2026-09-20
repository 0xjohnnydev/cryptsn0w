# Dopamine Cryptex bootstrap overlay

This overlay combines a pinned Dopamine 3.x Procursus bootstrap with the local
SBInject SpringBoard and Settings path. Sileo is an immutable, ad-hoc-signed
system app whose signed source is inside the Cryptex. It keeps its upstream bundle identifier,
`org.coolstar.SileoStore`, and has no provisioning profile or signing expiry.

## Requirements

- macOS with a full Xcode installation and the iPhoneOS 27 SDK selected;
- the Security Research Device host tools, including
  `/System/Library/SecurityResearch/usr/bin/cryptexctl.research`;
- Homebrew when a listed command-line dependency is missing; and
- an unlocked, paired iPhone in Developer Mode for installation.

An Apple Development certificate and provisioning profile are not required.
The build uses ad-hoc CodeDirectories and admits the exact fixed binaries in the
Cryptex trust cache. The PreferenceLoader bridge is built with Xcode and does
not require Theos.

## Reproducible build and install

Run commands from the repository root.

Prepare the pinned upstream checkout and Python environment:

```sh
./Dopamine-CryptexBootstrap/setup.sh
```

Build without touching a phone:

```sh
./Dopamine-CryptexBootstrap/setup.sh --build
```

Install on the validated iPhone 13:

```sh
./Dopamine-CryptexBootstrap/setup.sh --install \
  --device 00008110-000C542E0EA8201E
```

`setup.sh` fetches the pinned opa334/Dopamine tree, copies this source overlay
into the generated tree, builds and verifies the Cryptex, captures the attached
device's current nonce, personalizes the image, validates it, and replaces at
most one older managed Cryptex. After installation the driver:

1. restarts only a stale pre-install bootstrap process when one survived the
   Cryptex swap;
2. refreshes a root-owned, byte-identical copy at the fixed application
   container path and waits for LaunchServices to register
   `org.coolstar.SileoStore` as a non-removable system app;
3. launches that exact registered path and verifies it remains alive; and
4. removes the legacy `com.lilycohl.sileo27b8` provisioned app only after the
   system copy passes those checks.

No host connection is needed for later reboots, package transactions, resprings,
or Settings preference panes. On an unchanged installation the boot daemon uses
a local-only fast path, verifies and re-registers the fixed runtime copy, starts
the package broker, and re-arms the SpringBoard and Settings redirects.

The default device guard supports the checked-in target matrix shown by
`setup.sh --help`. Use `--allow-unverified-device` only for reviewed porting
work. `--no-replace` makes installation refuse an older managed Cryptex instead
of replacing it.

Pinned upstream:

- repository: `https://github.com/opa334/Dopamine.git`
- branch: `3.x`
- commit: `939a3a21400f0dc6d6163b2b5999ba2ace0d2732`

Other pinned inputs include Procursus bootstrap 1900, ElleKit 1.2,
PreferenceLoader 2.3.3, and Dopamine's bundled Sileo 2.5.1. Every downloaded
archive is accepted only at its checked-in SHA-256 digest.

## Sileo system-app model

The Cryptex contains the authoritative `Applications/Sileo.app` with its
upstream privileged entitlements, original bundle ID, and no
`embedded.mobileprovision`. At boot the daemon copies that exact signed tree to
the fixed, root-owned standard application container and verifies every file
before registration. Its seven
runtime Mach-Os are individually ad-hoc signed before the image trust cache is
created:

- `Sileo` and `giveMeRoot`;
- bundled `libiosexec` and `liblzma`;
- a zstd re-export shim and its pinned real zstd library; and
- `libcodex-sileo-broker.dylib`, loaded by an explicit unique
  `LC_LOAD_DYLIB` so dyld cannot satisfy it with a shared-cache zstd image.

The Debian package installed in `/var/jb` carries dependency and maintainer
metadata only. It is versioned `2.5.1+codex1`; APT pins that exact local version
and rejects repository replacements of `org.coolstar.sileo`. Updating Sileo
therefore means building and installing a new Cryptex, preventing a normal repo
update from placing a conflicting mutable Sileo bundle under `/var/jb`.

The stable application-container copy is required because IconServices returns
the generic grid for an app registered directly from a generic Cryptex mount.
Trust still comes only from the identical Cryptex CodeDirectories; the copy is
not managed by dpkg and repo updates cannot replace it.

Sileo's constructor consumes the process-bound extensions prepared by the boot
daemon and interposes only the spawn/wait operations needed for package work and
respring. The root broker authenticates the live client PID and its exact
LaunchServices path before accepting a bounded command. Package-installed tweak
code is never added to a runtime trust cache.

## Outputs and size

Generated files live under the ignored
`Dopamine-upstream/CryptexBootstrap/{cache,work,out}` directories. The current
iPhone 13 image is about 44 MB; the build and installer independently enforce a
128 MiB ceiling. No IPA is produced.

`out/build-summary.json` records pinned input hashes, the system-Sileo runtime
hashes, fixed control-plane hashes, and the complete trust-cache dump.
`out/runs/<run-id>/` contains device context, personalization, validation,
installation, and system-app launch results. Generated images, tickets, caches,
and logs do not belong in Git.

## Runtime notes

Preference panes use pinned PreferenceLoader/libprefs plus the arm64e
`SettingsSidebarListState` bridge. SBInject loads both before the resigned
Settings executable enters `main`. Legacy pane respring commands are reduced to
the recognized `sbreload`/`killall SpringBoard` shapes and sent through the
authenticated broker.

SpringBoard injection remains entirely on the SBInject JIT route. The launchd
hook redirects the stock process to the fixed replacement, jitterd grants the
debugged/JIT state, the pre-main hook performs the bounded RW-to-RX transition,
and ElleKit loads installed tweaks. No post-boot trust-cache extension or
per-package signing path exists.

Safe mode does not rename or disable tweak files. PAC-stripped crash addresses
are attributed to loaded tweak ranges when possible, and the alert uses
SpringBoard's existing foreground presenter.
