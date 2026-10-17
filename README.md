# CryptSn0w

**Redacted source:** TSS request construction, personalization, and related
installation details are intentionally omitted. The files retain placeholders
for educational reference.

**This project is obsolete.** Apple patched the TSS/Cryptex bug it relied on. The code
is shared for educational purposes and to document the work. It is no longer
a working jailbreak method.

CryptSn0w packaged an SBInject-based jailbreak as a device-personalized
Cryptex: a disk image with an associated trust cache and an Apple signing
ticket. It relied on the TSS/Cryptex bug to obtain that ticket.

The project includes SpringBoard and Settings tweak injection through
ElleKit, Sileo package management, PreferenceLoader, optional root SSH, and
a macOS installer. The bootstrap also contains code to restore its services
after a reboot.

## How it was put together

The installer used a temporary SSH payload to copy SpringBoard and Settings
from the connected phone. It then built replacement bundles and installed
the final Cryptex. This kept the Apple binaries matched to the device;
they are not included in this repository.

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
- A paired device for any steps that read device-specific inputs

From the repository root:

```sh
./Dopamine-CryptexBootstrap/setup.sh --prepare
make validate
make build
```

The setup script fetches pinned dependencies and applies the local overlay
to `Dopamine-upstream/`. Downloads are checked against committed SHA-256 hashes.
Build output goes to:

```text
Dopamine-upstream/CryptexBootstrap/out/build-summary.json
Dopamine-upstream/CryptexBootstrap/out/unsigned/*.cxbd
```

For a host-only build, the device's Apple app bundles belong in:

```text
build/target/SpringBoard.app/
build/target/Preferences.app/
```

`build/` is ignored by Git. Set `CODEX_TARGET_BUNDLE_ROOT` to use a different
bundle directory.

## Historical install command

The old install flow used:

```sh
./Dopamine-CryptexBootstrap/setup.sh --install --device <UDID>
```

It installed a temporary SSH Cryptex, copied the device's app bundles, then
built and installed the final Cryptex without a reboot. Per-run files were
saved under `Dopamine-upstream/CryptexBootstrap/out/runs/`.

This flow depended on the now-patched TSS/Cryptex bug and is included only as a
reference.

## macOS app

The SwiftUI app runs the same installer as the command line. It requires
Swift 6.2 or newer:

```sh
make app
open dist/CryptSn0w.app
```

Keep the app in `dist/` so it can find the repository, or select the repository
with the app's folder chooser. Root SSH is off by default and was an optional
part of installation. The app is subject to the same TSS/Cryptex limitation described
above. See [MacApp/README.md](MacApp/README.md) for its build and UI details.

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
