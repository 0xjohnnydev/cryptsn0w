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

## How it was put together

The installer used a temporary SSH payload to copy SpringBoard, Settings, and
`amfid` (the system code-signature validation daemon) from the connected phone.
It then built the final Cryptex using those device-matched inputs. The Apple
binaries are not included in this repository.

The Cryptex held the bootstrap, Sileo, ElleKit, SSH, and a fixed trust cache.
SBInject redirected SpringBoard and Settings to the replacement bundles.
Package scripts and installed apps used a broker and launcher, with a
JIT/dyld loading path for third-party code.

## How JIT avoided per-binary trust-cache updates

The trust cache covered a fixed set of bootstrap binaries, loaders, and
injection components. It contained their code hashes, so a new or modified
binary on disk did not automatically become trusted. Adding every package's
binaries to that cache would have meant updating the cache whenever those
binaries changed.

Instead, supported package executables ran through an already trusted worker,
and supported tweaks loaded inside an SBInject-managed process. The worker or
target process first needed the debugged state that allowed it to execute code
from memory. This was a property of that process, not a new trust-cache entry
for the payload.

JIT means *just in time*. Here, the project used that execution model to run
existing native machine code; it did not compile each tweak from source.
Apple's dynamic loader, **dyld**, still handled loading and linking. The loader
hooks adjusted its signature checks and copied payload code into anonymous
memory, which was writable while being filled and then made executable.
That let supported payloads run without adding their hashes to the fixed
trust cache.

The package broker routed supported native install scripts and executables
through `codex-exec-worker`. The SBInject hooks used the same approach in
SpringBoard and Settings so ElleKit could load compatible tweak libraries.
This avoided a new trust-cache signing round trip for each supported payload.
Some files were still patched, rehashed, or ad-hoc signed as part of preparing
them for the loader; that was separate from getting a new Apple-signed trust
cache.

This did not make every installed binary trusted system-wide. Code had to use
the supported worker or injection path, and compatibility depended on the
target process and OS build. Changing the fixed bootstrap or loader binaries
still required rebuilding their installation. The whole arrangement depended
on the original bootstrap being installed, which is why the patched
TSS/Cryptex path still makes this an obsolete project.

The relevant code is in
[`codex_exec_worker.c`](Dopamine-CryptexBootstrap/CryptexBootstrap/codex_exec_worker.c),
[`sbinject_dyld_bypass.c`](Dopamine-CryptexBootstrap/CryptexBootstrap/SBInject/sbinject_dyld_bypass.c),
and [`sbinject_jitterd.m`](Dopamine-CryptexBootstrap/CryptexBootstrap/SBInject/sbinject_jitterd.m).

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
