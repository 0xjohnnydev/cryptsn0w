# Dopamine 3.x generic-Cryptex bootstrap lane

This directory adapts opa334's Dopamine 3.x Procursus/Sileo bootstrap to the
generic Cryptex1 path demonstrated on the paired iPhone18,2 running 24A435.
It does not invoke Dopamine's kernel exploit, kernel trust-cache loader, PID 1
hook, BaseBin startup path, or tweak injection. Procursus executables remain
usable only while the matching nonpersistent Cryptex trust cache is mounted.

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

Capture a fresh device context, then personalize the unsigned bundle with the
workspace's verified generic-Cryptex personalizer:

```sh
"$PYTHON" CryptexBootstrap/capture_device_context.py \
  --udid "$UDID" --nonce-domain 3 \
  --out-dir CryptexBootstrap/out/device-context-current --tunneld

CHIP_JSON="$(tr -d '\n' < CryptexBootstrap/out/device-context-current/chip.json)"
NONCE_HEX="$(tr -d '\n' < CryptexBootstrap/out/device-context-current/nonce.hex)"

"$PYTHON" ../tools/cryptexd-static/personalize_generic_cryptex1.py \
  --bundle CryptexBootstrap/out/unsigned/com.openai.codex.dopamine.bootstrap.cxbd \
  --chip-json "$CHIP_JSON" \
  --nonce-hex "$NONCE_HEX" \
  --out-dir CryptexBootstrap/out/personalized-current
```

Run the guarded installer once with `--validate-only`; proceed with
`--replace-installed` only when the live preflight identifies exactly one
older version of this non-Apple Cryptex:

```sh
SIGNED=CryptexBootstrap/out/personalized-current/com.openai.codex.dopamine.bootstrap.signed.cxbd
COMMON=(
  --bundle "$SIGNED"
  --build-summary CryptexBootstrap/out/build-summary.json
  --udid "$UDID"
  --tunneld
  --replace-installed
)
"$PYTHON" CryptexBootstrap/install_cryptex_bootstrap.py \
  "${COMMON[@]}" --validate-only \
  --result-json CryptexBootstrap/out/validate-current.json
"$PYTHON" CryptexBootstrap/install_cryptex_bootstrap.py \
  "${COMMON[@]}" \
  --result-json CryptexBootstrap/out/install-current.json
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

This is a Procursus/Sileo compatibility lane, not the complete Dopamine
runtime. It does not load tweaks or provide Dopamine's launchd/kernel hooks.
Packages that add new ad-hoc Mach-O files are not automatically added to the
mounted trust cache; rebuild and repersonalize the Cryptex before executing
those new files.

Sileo's Featured cards come from repositories that are not part of the base
Procursus source set. `Package Unavailable` on those cards means their
third-party source has not been added; it is distinct from an APT lists or
dependency-database failure.
