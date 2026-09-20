# Dopamine 3.x generic-Cryptex bootstrap lane

This directory adapts opa334's Dopamine 3.x Procursus/Sileo bootstrap to the
generic Cryptex1 path for iPhone18,2 / 24A435, iPhone14,5 (iPhone 13) / 24A435,
and iPhone13,1 (iPhone 12 mini) / 24A437. It supplies a managed rootless
Procursus tree, provisioned Sileo, and the fixed SBInject control plane. The
Cryptex trust cache covers only fixed bootstrap/control-plane artifacts; Sileo
package payloads never enter a post-boot or per-package trust-cache path.

## Working layout

The device has two deliberately separate pieces:

1. `/var/jb` is a managed symlink to a randomized Procursus tree below the
   active preboot UUID. `prep_bootstrap.sh` and opa334's bundled Sileo package
   are installed there once. A later Cryptex version enters repair mode only
   when the symlink target and rollback manifest exactly match this installer.
2. Sileo is a normal Apple Development-provisioned app whose complete runtime
   executable set is also admitted by the fixed Cryptex trust cache. The build
   requires byte-identical copies of the main executable, root helper,
   constructor shim, and three bundled libraries in the app, IPA, and trusted
   Cryptex payload, then proves every resulting CDHash is present in the cache.
   The attached iPhone 13 target uses `com.lilycohl.sileo27b8`, matching its
   installed profile; other targets retain their configured bundle identifier.
   Its three non-system pre-main dependencies (`liblzma`, `libzstd`, and
   `libiosexec`) are signed by the same team and bundled under `Sileo.app/F`.
   The app's `/opt/procursus/lib` rpath is changed to `@loader_path/F`.

The bundled `libzstd.1.dylib` is a small re-export shim. Its constructor asks
the root Cryptex job for process-bound sandbox extensions before Sileo's own
initializers execute, then re-exports the unmodified Procursus zstd library.
The broker accepts a request only when `proc_pidpath` identifies the live PID
as the exact Sileo executable currently registered by LaunchServices. It
grants access only to the managed Procursus root and the required mobile data
paths. Root process requests are separately validated and limited to the
known Procursus commands used by Sileo.

The provisioned app and Cryptex are a matched pair. `giveMeRoot` in the app
must be byte-identical to the CMS-signed helper included in the mounted
Cryptex trust cache. Build the Cryptex first, build the Sileo app from that
output second, install the app third, and mount the personalized Cryptex last.

This constructor path is necessary because iOS rejects an `execve` transition
from a provisioned launcher into a second Sileo image, even when the target is
Apple Development-signed, trust-cached, and inside the same app bundle.

## One-command setup

Run this from the root of the private workspace, not from a manually copied
overlay:

```sh
./Dopamine-CryptexBootstrap/setup.sh --install
```

The setup script checks the SRD `cryptexctl.research` installation and full
iPhoneOS SDK, installs missing build utilities through an existing Homebrew,
creates the pinned Python virtual environment, fetches the pinned
opa334/Dopamine tree, and discovers an unexpired Apple Development profile
whose certificate and application identifier match Sileo. It then performs
the required order automatically:

1. Build and verify the generic Cryptex and its trust cache.
2. Build the exact provisioned Sileo app paired with that Cryptex.
3. Verify all three copies of `giveMeRoot` are byte-identical.
4. Install the provisioned app through a no-admin userspace tunnel.
5. Capture a fresh nonce and device identity, then request and validate a
   current Cryptex1 ticket.
6. Validate the complete signed bundle against live device state before
   requesting a persistent install and replacing at most one older copy of this
   non-Apple Cryptex.

The default device guard permits paired physical iPhone18,2 and iPhone14,5 /
iOS 27.0 (24A435), plus iPhone13,1 / iOS 27.0 (24A437), targets. Pass `--device
UDID` when more than one eligible device is attached. The explicit
`--allow-unverified-device` escape hatch is available for reviewed porting work.

The host-only forms are:

```sh
./Dopamine-CryptexBootstrap/setup.sh          # prepare and signing preflight
./Dopamine-CryptexBootstrap/setup.sh --build  # host-only build
```

The install path uses pymobiledevice3's in-process userspace RemoteXPC
transport.

## Signing

Signing is automatic when Xcode has installed a valid development certificate
and profile compatible with the target's configured Sileo bundle identifier.
The selector verifies
the profile is unexpired, includes `get-task-allow`, contains the installed
certificate, and covers the bundle identifier. It derives the minimal app
entitlements from that profile rather than checking in machine-specific team
values.

On a host with multiple identities, these optional overrides narrow selection:

```sh
export CODEX_SILEO_DEVELOPMENT_IDENTITY=<certificate-SHA1-or-unique-name>
export CODEX_SILEO_PROVISIONING_PROFILE=/absolute/path/profile.mobileprovision
export CODEX_SILEO_DEVELOPMENT_ENTITLEMENTS=/absolute/path/entitlements.plist
```

The custom entitlement file is still checked against the selected profile's
application identifier, team, and `get-task-allow` fields.

## Advanced manual build

After `setup.sh` has prepared `Dopamine-upstream`, the lower-level driver is:

```sh
.venv/bin/python Dopamine-upstream/CryptexBootstrap/deploy.py build
```

It invokes `build_cryptex.sh` before `build_sileo_launcher.sh`, generates a
fresh numeric Cryptex version, and gives the IPA and its JSON summary matching
versioned names. The driver enforces that build order.

`build_sileo_launcher.sh` emits the direct Sileo main executable with the
constructor broker. Set `CODEX_SILEO_LAUNCHER_IPA` and
`CODEX_SILEO_LAUNCHER_SUMMARY` to fresh paths for additional builds.

The Cryptex build verifies the pinned Procursus and opa334 Sileo SHA-256
values, validates the generic `999.*` identity, dumps every trust-cache cdhash,
and records the development identity/profile hashes in
`out/build-summary.json`. Per-run app, personalization, validation, and install
summaries are written under the ignored `CryptexBootstrap/out` tree.

The build derives the SBInject SpringBoard replacement from the pinned 24A435
iPhone 13 arm64e executable. `Scripts/build_springboard_candidate.py`
checks its SHA-256, UUID, and `com.apple.springboard` identifier; preserves its
original entitlement dictionary; adds the explicitly configured debugger/JIT
policy; regenerates XML and DER entitlement slots; and proves the ad-hoc output
is deterministic. Its otherwise-unused `LC_RPATH` is converted to
`LC_LOAD_DYLIB @loader_path/g`, allowing the fixed pre-main general hook to run
before SpringBoard initializes. The installer places the preserved bundle at
`/var/jb/System/Library/CoreServices/SpringBoard.app` with executable
`notSpringBoard`. Alternate source paths can be supplied with the
`CODEX_SPRINGBOARD_CANDIDATE_*` variables, but the executable must still match
the pinned exact-build identity.

The root installer refreshes the complete signed APT source set and performs a
non-mutating `apt-get check` before launching Sileo. Treat
`aptUpdateExit=0`, `aptDependencyCheckExit=0`,
`sileoSystemRootBrokerReady=true`,
`root broker preflight complete`, and `result=success` as the acceptance
gates for the complete package-index and broker path.

The stock Procursus archive includes the chain
`shshd -> libdimentio0 -> libkrw0 -> libkrw0-plugin`. This compatibility lane
detects that dormant package chain and removes it only after checking that no
package outside the exact removal set depends on it.

The bootstrap pins PreferenceLoader 2.3.3 from the maintained
`Yves000/preferenceloader` release for libprefs, filtering, and legacy pane
construction. Build 24A435 replaced its older `PrimarySettingsListModel` with
`SettingsSidebarListState`, so the Cryptex also carries a fixed arm64e bridge
for that exact iOS 27 model. SBInject loads PreferenceLoader and then the bridge
synchronously before the resigned Settings executable enters `main`. The
bridge inserts all valid registrations into the Swift section array and both
identifier lookup dictionaries, and resolves selections back through libprefs.
The canonical rootless MobileSubstrate path is preferred; the TweakInject path
is retained only as a compatibility fallback.

The bridge is built directly with Xcode from the local Objective-C/Swift files
under `SBInject/`; its five small metadata helpers are pinned in
`SBInject/PreferenceBridgeSupport` with their upstream commit and LGPL license.
No Theos checkout or network source fetch is part of the build.

For a live Settings acceptance check, the pre-main stage log at
`/var/mobile/.sbinject-generalhook.log` must contain, in order,
`jitterd-ready`, `dyld-bypass-ready`, `ellekit-ready`,
`preferenceloader-ready`, and `preferences-bridge-ready`. The bounded bridge
log at `/var/mobile/.sbinject-preferences-bridge.log` then reports the number of
published rows. A bridge failure remains isolated behind the existing
Preferences crash-loop fallback and does not disable SpringBoard injection.

## Runtime model

The SpringBoard path is entirely SBInject. A fixed launchd hook redirects only
the stock SpringBoard spawn to `notSpringBoard`. Its pre-main hook synchronously
asks the root `sbinject-jitterd` Mach service to attach/detach the exact calling
PID, which grants the debugged/JIT state. The hook then verifies the pinned dyld
signatures, changes only the target pages from `RW|COPY` back to `RX`, installs
the supplied mmap/fcntl validation bypass, and loads ElleKit before SpringBoard
main. No writable-and-executable mapping is requested.

Sileo's fixed root broker prefetches the resolved archives, invokes the same
`sbinject-package-validator` logic directly, and only then launches APT with
Sileo's original no-download transaction. This broker-native step is required
because rootless APT hardcodes the nonexistent `/bin/sh` when launching a
`DPkg::Pre-Install-Pkgs` command and otherwise exits with its own code 100
before the validator starts. The broker extracts each incoming archive into a
bounded temporary directory, classifies standard rootless tweak dylibs,
recognizes ElleKit's injector in the same dependency transaction, and creates
a root-owned respring marker. After a successful `apt`, `apt-get`, or `dpkg`
transaction, the broker activates the SBInject replacement if SpringBoard is
still stock, or restarts the active replacement once, so ElleKit discovers the
new tweak. ElleKit 1.2 is the sole fixed-trust package exception: the build
pins its upstream archive, ad-hoc signs every arm64/arm64e Mach-O while
preserving the loader entitlements, embeds the repacked `.deb`, and places the
same cdhashes in the Cryptex trust cache. The bootstrap installs that exact
package before activating SBInject, so Sileo sees the dependency as satisfied
and the pre-main hook always has `libinjector.dylib` available. No third-party
tweak package is embedded or re-signed. Mixed tweak packages may also carry
preference bundles or helper Mach-Os, but those extra executables receive no
implied fixed-trust admission.

There is no runtime trust-cache helper, TSS request, cache journal, replay verb,
or package fallback. The fixed Cryptex trust cache contains the pinned ElleKit
exception and the bootstrap control plane only; it is never extended from a
Sileo transaction. A repair install removes the legacy APT hook, helper,
client, dyld-admission library, execution interposer, admission baselines, and
journal before package work begins. If
SBInject is unavailable, SpringBoard tweak installation fails closed instead of
silently switching back to dynamic trust. Launch failures fall back to stock
SpringBoard; three replacement launches in sixty seconds disable redirection,
and `/var/mobile/.eksafemode` always selects stock SpringBoard.

For an explicitly destructive replacement of this installer's managed root,
set `CODEX_FORCE_CLEAN_INSTALL=1` for the build/install run. The installer
validates the `/var/jb` symlink, rollback manifest, active preboot parent, and
root ownership before atomically staging and deleting only its own old root.
It then creates a fresh randomized root containing the new SBInject bootstrap.

Sileo's Featured cards can reference optional repositories in addition to the
standard Procursus, Chariz, Havoc, BigBoss, and ElleKit set. Add the card's
repository when a featured package comes from another source.
