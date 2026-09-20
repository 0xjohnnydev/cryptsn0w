# Dopamine 3.x generic-Cryptex bootstrap lane

This directory adapts opa334's Dopamine 3.x Procursus bootstrap to a persistent
generic Cryptex1 on the validated iOS 27 targets. It contains the fixed
SBInject control plane, original-ID system Sileo, ElleKit exception, and iOS 27
PreferenceLoader bridge.

## Architecture

The installed environment has three parts:

1. `/var/jb` is a managed symlink to a randomized Procursus tree under the
   active preboot UUID. Repair mode accepts it only when the symlink, manifest,
   ownership, and active preboot parent match this installer.
2. `Applications/Sileo.app` in the read-only Cryptex is the authoritative signed
   source. The boot daemon maintains a byte-identical, root-owned copy at
   `/var/containers/Bundle/Application/D7A9C65A-1FD8-4D9C-AC8D-4E8E5143A191/Sileo.app`,
   which LaunchServices registers as the non-removable system app
   `org.coolstar.SileoStore`. The standard path is needed for IconServices;
   trust still comes from the identical Cryptex CodeDirectories. There is no
   provisioning profile, team-specific identifier, IPA, periodic re-sign, or
   profile expiration.
3. SpringBoard and Settings use only the SBInject pre-main JIT path. No package
   operation adds code to a runtime trust cache.

The Cryptex system app contains seven fixed-trust Mach-Os: Sileo, `giveMeRoot`,
`libiosexec`, `liblzma`, the zstd shim and real zstd library, and the unique
`libcodex-sileo-broker.dylib`. Sileo has an explicit
`LC_LOAD_DYLIB @loader_path/F/libcodex-sileo-broker.dylib`; this prevents dyld
from substituting an existing shared-cache zstd image for the constructor.

The constructor consumes process-bound extensions before Sileo initializes,
then interposes the narrow spawn/wait surface used by package operations and
respring. The root broker authenticates the calling PID, uid, executable path,
and current LaunchServices registration before running a bounded command below
the managed jailbreak root.

## Build and install

Run the top-level wrapper from the repository root:

```sh
# Prepare pinned sources and the Python environment.
./Dopamine-CryptexBootstrap/setup.sh

# Reproducible host-only build; no phone or Apple signing identity is needed.
./Dopamine-CryptexBootstrap/setup.sh --build

# Build, personalize, validate, and install on the attached iPhone 13.
./Dopamine-CryptexBootstrap/setup.sh --install \
  --device 00008110-000C542E0EA8201E
```

Requirements are macOS, a full Xcode/iPhoneOS 27 SDK, the Security Research
Device host tools, and the command-line dependencies checked by `setup.sh`.
Installation additionally needs the paired phone unlocked and in Developer
Mode. An Apple Development certificate or mobile provisioning profile is not a
requirement.

The lower-level host-only driver, after setup has populated
`Dopamine-upstream`, is:

```sh
.venv/bin/python Dopamine-upstream/CryptexBootstrap/deploy.py build
```

The lower-level install form is:

```sh
.venv/bin/python Dopamine-upstream/CryptexBootstrap/deploy.py install \
  --device 00008110-000C542E0EA8201E
```

Every normal run creates a fresh numeric Cryptex version. `--no-replace`
refuses an older managed copy. `--allow-unverified-device` bypasses the exact
target guard and is intended only for reviewed porting work.

The install driver records any pre-existing bootstrap PID before replacement.
If that exact process survives the Cryptex swap, it sends only that stale PID a
SIGTERM so launchd starts the new mounted executable. It then waits for the
original Sileo ID and build-unique bundle version to become a non-removable
system registration, launches the exact fixed container path, checks that the
process stays alive, verifies the real 60pt @3x icon, and only
then removes the legacy `com.lilycohl.sileo27b8` app.

## Package model

The embedded `org.coolstar.sileo` Debian package contains dependency and
maintainer metadata but no mutable app bundle. Its local version is
`2.5.1+codex1`. APT gives that exact installed version priority 1001 and rejects
all repository versions of the same package, so a normal update cannot create a
conflicting `/var/jb/Applications/Sileo.app`. Update Sileo by installing a new
Cryptex build.

Sileo's fixed root broker prevalidates archives with
`sbinject-package-validator` before invoking APT's no-download transaction. The
validator recognizes standard rootless tweak layouts and permits SpringBoard
tweaks only through the SBInject route. A successful install, remove, reinstall,
or update leaves the respring decision to Sileo's own bottom sheet; the post
hook prepares the next replacement state but does not respring by itself.

ElleKit 1.2 is the sole package-level fixed-trust exception. The build pins its
archive, preserves required entitlements while ad-hoc signing its Mach-Os,
installs the same bytes under `/var/jb`, and admits their CDHashes in the static
Cryptex trust cache. Third-party tweak packages are not embedded, re-signed, or
added to a dynamic trust cache.

Sileo itself runs as `mobile`. The broker remains root and accepts only its
declared command shapes. The original bottom-sheet respring command is mapped
to the same SBInject prepare/redirect path used by package state changes.

## SpringBoard and Settings

The fixed launchd hook redirects only stock SpringBoard to
`/var/jb/System/Library/CoreServices/SpringBoard.app/notSpringBoard`. The
general hook asks `sbinject-jitterd` to grant the exact process debugged/JIT
state, verifies pinned dyld signatures, performs the bounded RW-to-RX
transition, installs the supplied mmap/fcntl bypass, and loads ElleKit before
`main`. PID 1 is never a general injection target.

Settings follows the same pre-main route with its own replacement bundle. The
candidate preserves the original entitlements and adds the required debugger,
JIT, and task-port keys; arm64e PAC bits are stripped before attribution and
address comparisons.

PreferenceLoader 2.3.3 supplies libprefs and the legacy controllers. The local
arm64e bridge publishes valid registrations into iOS 27's
`SettingsSidebarListState` arrays and identifier maps, then routes selections
back to those controllers. Pane respring calls are limited to recognized
`sbreload` and `killall SpringBoard` shapes and forwarded to the authenticated
broker.

For a Settings acceptance check,
`/var/mobile/.sbinject-generalhook.log` should report, in order,
`jitterd-ready`, `dyld-bypass-ready`, `ellekit-ready`,
`preferenceloader-ready`, and `preferences-bridge-ready`. The bridge count is
written to `/var/mobile/.sbinject-preferences-bridge.log`.

## Reboot and safe mode

On each reboot the Cryptex daemon starts locally, verifies or atomically refreshes
the fixed Sileo copy, injects the fixed registration predicate hook into the
exact `/usr/libexec/lsd` process, registers the stable application path, starts
the brokers, and re-arms SpringBoard and Settings.
The `lsd` readiness marker contains the current PID and must be fresh for the
current boot; a restarted daemon cannot reuse stale readiness state.

When the installed manifest and fixed bytes match, startup takes a network-free
fast path and does not reinstall packages or refresh repositories. Package and
redirect behavior does not require a Mac after the initial Cryptex install.

Safe mode never renames, removes, or disables tweak files. Fatal PC/LR values
are PAC-stripped and matched against loaded tweak text ranges; Objective-C
exceptions also inspect tweak frames and hooked method implementations. The
alert uses SpringBoard's existing foreground presenter and identifies the tweak
when attribution is available.

## Outputs and acceptance checks

Generated files are ignored under `cache/`, `work/`, and `out/`. The current
iPhone 13 image is approximately 44 MB and must remain below the enforced
128 MiB ceiling. `out/build-summary.json` records every pinned input, fixed
runtime hash, and trust-cache entry. Each install writes device context,
personalization, validation, installation, and system-Sileo verification JSON
under `out/runs/<run-id>/`.

Useful successful bootstrap log gates are:

- `sileoSystemRegistration ... registered=true ... type=System`;
- `fastBootPayloadExact=true` on an unchanged install;
- `sileoSystemRootBrokerReady=true`;
- `fastBootControlPlane ... rootBroker=true`;
- `result=success mode=fast-boot`; and
- the Sileo constructor messages `constructor consumed 6 sandbox extensions`
  and `constructor broker initialization complete`.

For an explicitly destructive replacement of only this installer's managed
root, set `CODEX_FORCE_CLEAN_INSTALL=1`. The installer verifies the `/var/jb`
symlink, manifest, root ownership, and active preboot parent before deleting its
own old tree.
