# CryptSn0w

**Redacted source:** TSS request construction, personalization, and related
installation details are intentionally omitted. The files retain placeholders
for educational reference.

**This project is obsolete.** Apple patched the TSS/Cryptex bug it relied on.
The original signing and installation flow is no longer usable for new
installs. The code is shared for educational purposes and to document the work.

CryptSn0w packaged an SBInject-based jailbreak as a device-personalized
Cryptex: a disk image with an associated trust cache and an Apple signing
ticket. The original installer obtained that ticket from Apple's signing
service. The request and installation details are redacted from this source.

The project includes SpringBoard and Settings tweak injection through
ElleKit, Sileo package management, PreferenceLoader, optional root SSH, and
a macOS installer. The bootstrap also contains code to restore its services
after a reboot.

## How it was put together

The installer used a temporary SSH payload to copy SpringBoard, Settings, and
`amfid` (the system code-signature validation daemon) from the connected phone.
It then built the final Cryptex using those device-matched inputs. The Apple
binaries are not included in this repository.

The Cryptex held the bootstrap, Sileo, ElleKit, SSH, and a fixed trust cache.
SBInject redirected SpringBoard and Settings to the replacement bundles.
Package scripts and installed apps used a broker and launcher, with a
JIT/dyld loading path for third-party code. See the source for the details.

## Building the source

These instructions are kept for reference. Building the code does not restore
the patched TSS/Cryptex path.

The original build environment required:

- macOS with full Xcode and the iPhoneOS SDK selected
- Apple Security Research Device host tools, including
  `/System/Library/SecurityResearch/usr/bin/cryptexctl.research`
- Homebrew, or the required host utilities installed separately
- Python 3.10 or newer
- A paired device for any steps that read device-specific inputs

From the repository root:

```sh
./Dopamine-CryptexBootstrap/setup.sh --prepare
make validate
make build
```

The setup script checks out a pinned Dopamine revision and applies the local
overlay to `Dopamine-upstream/`. The bootstrap and package archives have
committed SHA-256 checks; direct Python dependencies have pinned versions.
Build output goes to:

```text
Dopamine-upstream/CryptexBootstrap/out/build-summary.json
Dopamine-upstream/CryptexBootstrap/out/unsigned/*.cxbd
```

For a host-only build, supply these files from the target device:

```text
build/target/SpringBoard.app/
build/target/Preferences.app/
build/target/amfid
```

`build/` is ignored by Git. Set `CODEX_TARGET_BUNDLE_ROOT` to use a different
input directory. The normal install flow copies all three inputs over its
temporary SSH connection.

## Historical install command

The old install flow used:

```sh
./Dopamine-CryptexBootstrap/setup.sh --install --device <UDID>
```

[REDACTED: Related request, payload, or installation details omitted.]

This flow depended on the now-patched TSS/Cryptex bug and is included only as a
reference.

## macOS app

The SwiftUI app runs the same installer as the command line. It requires
macOS 14 or newer and Swift 6.2 or newer to build:

```sh
make app
open dist/CryptSn0w.app
```

Keep the app in `dist/` so it can find the repository, or select the repository
with the app's folder chooser. Retained root SSH access is off by default;
the temporary SSH stage is always part of installation. The app is subject
to the same TSS/Cryptex limitation described above. See
[MacApp/README.md](MacApp/README.md) for its build and UI details.

## Source layout

| Path | Contents |
| --- | --- |
| `Dopamine-CryptexBootstrap/setup.sh` | Dependency setup and build/install entry point |
| `Dopamine-CryptexBootstrap/CryptexBootstrap/` | Cryptex build, deployment, and runtime code |
| `Dopamine-CryptexBootstrap/CryptexBootstrap/SBInject/` | SpringBoard and Settings injection |
| `MacApp/` | SwiftUI installer and app packaging |

The main runtime log was `/var/tmp/codex-dopamine-cryptex-bootstrap.log`.
App launcher and TrollStore registration logs were
`/var/mobile/.sbinject-app-launcher.log` and
`/var/mobile/.sbinject-trollstore-registration.log`.
