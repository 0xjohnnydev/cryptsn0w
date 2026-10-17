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
