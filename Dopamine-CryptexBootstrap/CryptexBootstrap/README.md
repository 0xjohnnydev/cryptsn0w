# Dopamine 3.x generic-Cryptex bootstrap lane

**Redacted source:** TSS request construction, personalization, and related
installation details are intentionally omitted. The files retain placeholders
for educational reference.

[REDACTED: Related request, payload, or installation details omitted.]

For the SpringBoard JIT spawn path, set `CODEX_SPRINGBOARD_SOURCE` to the
`SpringBoard` executable inside a complete `SpringBoard.app` copied from the
**same OS build as the target device** before building. The build copies and
reseals the app with its existing entitlements plus bare `get-task-allow` and
`dynamic-codesigning`,
embeds the result at
`usr/local/share/codex-bootstrap/SpringBoard.app/SpringBoard`, and verifies its
CDHash in the Cryptex trust cache. The build fails if the source is absent or
does not have the `com.apple.springboard` identifier. The iPhone14,5 / 24A435
source is available at `build/iphone13-24A435/SpringBoard.app/SpringBoard` after
the root SSH extraction. This packaging step does
not itself install a launchd spawn redirect or prove that SpringBoard launches
from the copied path.

On iPhone14,5 / 24A435, version `1.0.20260917080208.373171` replaced only
`com.openai.codex.dopamine.bootstrap`; the separate SSH Cryptex remained mounted.
The mounted SpringBoard SHA-256 matched the build's signed executable:
`0c77ab5d13a72da74e34d95a844fb1c4250697b3e8274804c1b531f7290f665b`.
The live `com.apple.SpringBoard` service still uses the system executable.
`launchctl debug` returned 45 (operation not supported) for both `user/501`
and `user/foreground`, so no test restart was attempted. The device's launchd
binary imports both `posix_spawn` and `posix_spawnp` from libSystem and uses
chained fixups. PID 1 injection, spawn redirection, and JIT tweak loading are
still unverified on this device.

The next build additionally requires `CODEX_LAUNCHD_SOURCE` to point to the
same device's `/sbin/launchd` copy. The build verifies its UUID and the two
authenticated `posix_spawn`/`posix_spawnp` import slots before packaging the
trust-cached `codex-launchd-spawn-redirect.dylib`. The explicit
`codex-ellekit-loader --inject-launchd <mounted-dylib-path>` route uses
opainject's task-port lane and deliberately does not ptrace PID 1. This source
path has not yet been installed or run in launchd; a successful `task_for_pid`
or memory write alone is not injection proof.

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

[REDACTED: Related request, payload, or installation details omitted.]

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

[REDACTED: Related request, payload, or installation details omitted.]

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

[REDACTED: Related request, payload, or installation details omitted.]

The root installer performs a non-mutating `apt-get check` before launching
Sileo. Treat `aptDependencyCheckExit=0`, `sileoSystemRootBrokerReady=true`,
`root broker preflight complete`, and `result=success` as the acceptance
gates for the complete package-index and broker path.

The stock Procursus archive includes the chain
`shshd -> libdimentio0 -> libkrw0 -> libkrw0-plugin`. This compatibility lane
detects that dormant package chain and removes it only after checking that no
package outside the exact removal set depends on it.

[REDACTED: Related request, payload, or installation details omitted.]

## Latest iPhone 12 mini acceptance

Cryptex version `1.0.20260916131317.993376` installed successfully with a
validated 459-entry trust cache whose SHA-256 is
`4c8d76c52cfc0d111ce17e1b7ee9c0db12382b11ab34882a46965dc888db4c19`.
Its corrected trust-cached loader reproduced hookd's `RW|COPY -> write -> RX`
sequence on the device, verified effective protection `0x5`, and called the
generated function for return value 42. The final trusted ElleKit injection
into SpringBoard returned status 0, and the injector heartbeat reports
`safeMode=false`. PID 1 remains excluded by explicit guards.
[REDACTED: TSS/Cryptex personalization and installation details are redacted from this educational source release.]

[REDACTED: Related request, payload, or installation details omitted.]

## Runtime model
[REDACTED: TSS/Cryptex personalization and installation details are redacted from this educational source release.]

Sileo's Featured cards can reference optional repositories in addition to the
standard Procursus, Chariz, Havoc, BigBoss, and ElleKit set. Add the card's
repository when a featured package comes from another source.
