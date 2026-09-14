# Dopamine 3.x generic-Cryptex bootstrap lane

**Redacted source:** TSS request construction, personalization, and related
installation details are intentionally omitted. The files retain placeholders
for educational reference.

[REDACTED: Related request, payload, or installation details omitted.]

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

## Host build

The default signing values match the local John Franks development profile.
They can be replaced without editing the scripts:

```sh
export CODEX_SILEO_DEVELOPMENT_IDENTITY=<certificate-SHA1>
export CODEX_SILEO_PROVISIONING_PROFILE=/absolute/path/profile.mobileprovision
export CODEX_SILEO_DEVELOPMENT_ENTITLEMENTS=/absolute/path/entitlements.plist
```

Build the generic Cryptex and then the provisioned Sileo app from the
repository root. Do not reverse these commands:

```sh
./CryptexBootstrap/build_cryptex.sh
./CryptexBootstrap/build_sileo_launcher.sh
```

Despite its legacy filename, `build_sileo_launcher.sh` now emits the direct
Sileo main executable with the constructor broker; it does not build an exec
launcher. Set `CODEX_SILEO_LAUNCHER_IPA` and
`CODEX_SILEO_LAUNCHER_SUMMARY` to fresh paths for additional builds.

The Cryptex build verifies the pinned Procursus and opa334 Sileo SHA-256
values, validates the generic `999.*` identity, dumps every trust-cache cdhash,
and records the development identity/profile hashes in
`out/build-summary.json`. The app build verifies the entire signed bundle and
records its component hashes in `out/sileo-brokered-v36.json`.

Before installation, verify the two helper hashes match the
`rootHelperSha256` value in the launcher summary:

```sh
shasum -a 256 \
  CryptexBootstrap/work/sileo-package/var/jb/Applications/Sileo.app/giveMeRoot
unzip -p CryptexBootstrap/out/Sileo.brokered-v36.ipa \
  Payload/Sileo.app/giveMeRoot | shasum -a 256
jq -r .rootHelperSha256 CryptexBootstrap/out/sileo-brokered-v36.json
```

## Install order

Install the provisioned app before mounting a new Cryptex version so the root
job resolves the current Bundle and Data container UUIDs:

```sh
PYTHON=/path/to/pymobiledevice3-venv/bin/python
UDID=00008150-0018252C1130C01C

"$PYTHON" -m pymobiledevice3 apps install --developer --tunnel "$UDID" \
  CryptexBootstrap/out/Sileo.brokered-v36.ipa
```

[REDACTED: Related request, payload, or installation details omitted.]

```sh
[REDACTED: Related request, payload, or installation details omitted.]
```

Run the guarded installer once with `--validate-only`; proceed with
`--replace-installed` only when the live preflight identifies exactly one
older version of this non-Apple Cryptex:

```sh
[REDACTED: Related request, payload, or installation details omitted.]
```

The root installer performs a non-mutating `apt-get check` before launching
Sileo. Treat `aptDependencyCheckExit=0`, `sileoSystemRootBrokerReady=true`,
`root broker preflight complete`, and `result=success` as the acceptance
gates. The original missing Packages-index failure is resolved only when all
of these pass; a clean-looking UI alone is not sufficient.

The stock Procursus archive includes the chain
`shshd -> libdimentio0 -> libkrw0 -> libkrw0-plugin`. This compatibility lane
does not provide Dopamine's kernel-RW plugin. If no real provider is installed,
the root installer removes only that dormant three-package chain after
checking that no package outside the exact removal set depends on it. It never
installs a fake `libkrw0-plugin` provider.

Installation is nonpersistent at the cryptexd layer. Rebooting or unmounting
the Cryptex removes its trust cache and root broker; `/var/jb` and the managed
preboot payload intentionally persist. Do not launch this Sileo build without
remounting the matching Cryptex first.

## Scope

[REDACTED: Related request, payload, or installation details omitted.]

Sileo's Featured cards come from repositories that are not part of the base
Procursus source set. `Package Unavailable` on those cards means their
third-party source has not been added; it is distinct from an APT lists or
dependency-database failure.
