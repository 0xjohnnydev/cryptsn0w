# Dopamine 3.x generic-Cryptex bootstrap lane

This directory adapts opa334's Dopamine 3.x Procursus/Sileo bootstrap to the
generic Cryptex1 path demonstrated on the paired iPhone18,2 running 24A435.
It supplies a generic Cryptex1 trust cache, a managed rootless Procursus tree,
the Sileo root broker, and a provisioned Sileo app. Procursus executables run
while the matching nonpersistent Cryptex trust cache is mounted.

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
   replacing at most one older copy of this non-Apple Cryptex.

The default device guard permits only a paired physical iPhone18,2 on iOS 27.0
(24A435). Pass `--device UDID` when more than one eligible device is attached.
The explicit `--allow-unverified-device` escape hatch is available for porting,
but that configuration has not been validated by this project.

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

Installation is nonpersistent at the cryptexd layer. Rebooting or unmounting
the Cryptex clears its trust cache and root broker while `/var/jb` and the
managed preboot payload persist. Rerun `setup.sh --install` after reboot to
remount the matched Cryptex before using Sileo.

## Runtime model

The runtime consists of the managed Procursus tree, provisioned Sileo app,
root broker, and a static Cryptex trust cache. Rebuild and repersonalize the
Cryptex after installing packages that add ad-hoc Mach-O files, then execute
those files under the refreshed trust cache.

Sileo's Featured cards can reference optional repositories in addition to the
standard Procursus, Chariz, Havoc, BigBoss, and ElleKit set. Add the card's
repository when a featured package comes from another source.
