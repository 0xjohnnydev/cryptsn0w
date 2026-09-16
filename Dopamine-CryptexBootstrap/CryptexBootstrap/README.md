# Dopamine 3.x generic-Cryptex bootstrap lane

This directory adapts opa334's Dopamine 3.x Procursus/Sileo bootstrap to the
generic Cryptex1 path demonstrated on iPhone18,2 / 24A435 and iPhone13,1
(iPhone 12 mini) / 24A437. It supplies a generic Cryptex1 trust cache, a managed
rootless Procursus tree, the Sileo root broker, a fixed runtime-admission worker,
and a provisioned Sileo app.

## Working layout

The device has two deliberately separate pieces:

1. `/var/jb` is a managed symlink to a randomized Procursus tree below the
   active preboot UUID. `prep_bootstrap.sh` and opa334's bundled Sileo package
   are installed there once. A later Cryptex version enters repair mode only
   when the symlink target and rollback manifest exactly match this installer.
2. `org.coolstar.SileoStore` is a normal Apple Development-provisioned app.
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

The default device guard permits only paired physical iPhone18,2 / iOS 27.0
(24A435) and iPhone13,1 / iOS 27.0 (24A437) targets. Pass `--device UDID` when
more than one eligible device is attached. The explicit
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
and profile compatible with `org.coolstar.SileoStore`. The selector verifies
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

The root installer performs a non-mutating `apt-get check` before launching
Sileo. Treat `aptDependencyCheckExit=0`, `sileoSystemRootBrokerReady=true`,
`root broker preflight complete`, and `result=success` as the acceptance
gates for the complete package-index and broker path.

The stock Procursus archive includes the chain
`shshd -> libdimentio0 -> libkrw0 -> libkrw0-plugin`. This compatibility lane
detects that dormant package chain and removes it only after checking that no
package outside the exact removal set depends on it.

The installer requests cryptexd's persistent DDI settings. The latest recorded
iPhone 12 mini install completed with `persistence=2` and
`noncePersistence=1`. A subsequent full reboot remounted the exact build and
started the daemon, Sileo, and root broker. The broker replayed the nonce-bound
runtime trust journal before starting its injection lanes.

## Latest iPhone 12 mini acceptance

Cryptex version `1.0.20260916131317.993376` installed successfully with a
validated 459-entry trust cache whose SHA-256 is
`4c8d76c52cfc0d111ce17e1b7ee9c0db12382b11ab34882a46965dc888db4c19`.
Its corrected trust-cached loader reproduced hookd's `RW|COPY -> write -> RX`
sequence on the device, verified effective protection `0x5`, and called the
generated function for return value 42. The final trusted ElleKit injection
into SpringBoard returned status 0, and the injector heartbeat reports
`safeMode=false`. PID 1 remains excluded by explicit guards.

BrokerProbe 1.0.18 then passed the post-boot dynamic-trust path. The broker
generated a three-entry cache from the incoming archive, personalized the
complete `gtcd` IM4P with the persisted Generic Cryptex1 nonce, and loaded it
through AMFI with status 0 before `dpkg` unpack. The new arm64e dylib was absent
from the static cache; direct loading into stable SpringBoard PID 1751 returned
0, dyld image verification passed, and its constructor emitted a PID-matched
marker. SpringBoard remained alive, no new crash appeared, heartbeats stayed
`safeMode=false`, and PID 1 remained excluded. See
[`iphone12mini-postboot-dynamic-trust-20260916.md`](../../findings/iphone12mini-postboot-dynamic-trust-20260916.md)
for the exact results and hashes.

The accepted personalized cache is also persisted only after AMFI returns 0.
Entries are kept under a root-owned, mode-0700 journal epoch derived from the
persisted nonce, named by SHA-256, and validated for ownership, link count,
permissions, size, and digest before replay. On the clean-reboot pass, the first
pre-replay BrokerProbe load failed, journal replay returned 0, and BrokerProbe's
constructor then ran in new SpringBoard PID 37. The dylib CDHash remained absent
from the static cache and the post-boot log contained no new TSS request. See
[`iphone12mini-clean-reboot-runtime-trust-20260916.md`](../../findings/iphone12mini-clean-reboot-runtime-trust-20260916.md).

## Runtime model

The runtime consists of the managed Procursus tree, provisioned Sileo app, root
broker, a fixed interposer/debugger-softened worker, and a static Cryptex trust
cache for the stable infrastructure. Direct executable launches are attempted
first; non-baseline/admission-failing package Mach-Os are routed through the
fixed worker's bounded `--macho` path. Rebuild and repersonalize when the fixed
trusted infrastructure or baseline changes, not once per package payload. Full
Mach-O compatibility remains explicit acceptance work rather than proven
transparent system-wide `execve` behavior. New package dylibs with structurally
valid Apple ad-hoc CodeDirectories can now take the post-boot `gtcd` path;
completely unsigned or malformed files cannot.

Sileo's Featured cards can reference optional repositories in addition to the
standard Procursus, Chariz, Havoc, BigBoss, and ElleKit set. Add the card's
repository when a featured package comes from another source.
