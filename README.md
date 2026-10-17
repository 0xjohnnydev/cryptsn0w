# CryptSn0w

**Redacted source:** TSS request construction, personalization, and related
installation details are intentionally omitted. The files retain placeholders
for educational reference.

**This project is obsolete.** Apple patched the TSS/Cryptex bug it relied on.
The original signing and installation flow is no longer usable for new
installs. The code is shared for educational purposes and to document the work.

<p align="center">
  <img src="docs/images/cryptsn0w-gui.png" alt="CryptSn0w macOS GUI (historical screenshot)" width="500">
</p>

CryptSn0w packaged an SBInject-based jailbreak as a device-personalized
Cryptex: a disk image with an associated trust cache and an Apple signing
ticket. The original installer obtained that ticket from Apple's signing
service. The request and installation details are redacted from this source.

The project includes SpringBoard and Settings tweak injection through
ElleKit, Sileo package management, PreferenceLoader, optional root SSH, and
a macOS installer. The bootstrap also contains code to restore its services
after a reboot.

## How it worked

The bootstrap and loaders lived in a Cryptex with a fixed trust cache. New
package binaries and tweaks ran through those trusted components using JIT
(just-in-time) execution permissions. The loaders mapped their code into
executable memory, with dyld handling linking, so supported payloads did not
need a new trust-cache entry each time.

The broker routed package executables and install scripts through a trusted
worker. SBInject used the same idea to load compatible tweaks into SpringBoard
and Settings. Some binaries still needed patching or ad-hoc signing, but no
new Apple-signed trust cache was needed for each payload. Changing the fixed
bootstrap itself still required rebuilding it.

See the [worker](Dopamine-CryptexBootstrap/CryptexBootstrap/codex_exec_worker.c)
and [SBInject loader](Dopamine-CryptexBootstrap/CryptexBootstrap/SBInject/sbinject_dyld_bypass.c)
for the implementation.

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

## Credits

### Maintainers and project contributions

- **[0xjohnny](https://github.com/0xjohnnydev)** — project
  maintainer; the original root SSH proof of concept, Cryptex bootstrap,
  build and signing workflow, Sileo bootstrap and package handling, reboot
  recovery, and later iOS compatibility and runtime fixes.
- **[GenericCoding](https://github.com/GenericCoding)** — project maintainer;
  SBInject and Sileo integration, Settings/PreferenceLoader integration, the
  two-stage installer, native macOS app, TrollStore/app-launcher integration,
  and runtime fixes.
- **[Varik Matevosyan / var77](https://github.com/var77)** — project maintainer;
  device-discovery fixes in the CLI and macOS app so a phone connected over
  both USB and Wi-Fi appears as one device, with USB preferred.
- **[hrtowii](https://github.com/hrtowii)** — the original SBInject proof of
  concept that this port builds on.

Other repository collaborators include
[jakeashacks](https://github.com/jakeashacks), and
[forcequitOS](https://github.com/forcequitOS).

### Upstream projects

- **opa334** — [Dopamine](https://github.com/opa334/Dopamine),
  [opainject](https://github.com/opa334/opainject),
  [litehook](https://github.com/opa334/litehook),
  [libSandy](https://github.com/opa334/libSandy), and
  [AltList](https://github.com/opa334/AltList).
- **Évelyne Bélanger and the ElleKit contributors** —
  [ElleKit](https://github.com/tealbathingsuit/ellekit), used for tweak injection
  and hooking.
- **Sileo Team** — [Sileo](https://github.com/Sileo/Sileo), the package manager.
  This product includes software developed by the Sileo Team.
- **Dustin Howett, Dhinak G, Yves000, and the PreferenceLoader contributors** —
  [PreferenceLoader](https://github.com/Yves000/preferenceloader), including the
  Swift metadata, heap, and string helpers used by the Settings bridge.
- **Procursus Team** — the [Procursus bootstrap and packages](https://github.com/ProcursusTeam/Procursus)
  and the [ldid fork](https://github.com/ProcursusTeam/ldid), based on
  [saurik's ldid](https://git.saurik.com/ldid.git).
- **jjolano** — [HookKit](https://github.com/jjolano/HookKit) and
  [Shadow](https://github.com/jjolano/shadow).
- **Frida contributors** — [Frida Gum](https://github.com/frida/frida-gum), used
  by HookKit's Gum provider.
- **doronz88 and the pymobiledevice3 contributors** —
  [pymobiledevice3](https://github.com/doronz88/pymobiledevice3), used for device
  communication and Cryptex services.
- **m1stadev** — [PyIMG4](https://github.com/m1stadev/PyIMG4), used to parse and
  check Image4 manifests.
- The maintainers of [OpenSSH](https://www.openssh.com/),
  [libplist](https://github.com/libimobiledevice/libplist), and
  [Requests](https://github.com/psf/requests) for the SSH, plist, and HTTP tools
  used by this project.

The copied PreferenceLoader helpers retain their
[source attribution](Dopamine-CryptexBootstrap/CryptexBootstrap/SBInject/PreferenceBridgeSupport/UPSTREAM.md)
and [license](Dopamine-CryptexBootstrap/CryptexBootstrap/SBInject/PreferenceBridgeSupport/LICENSE).
