# SBInject Cryptex jailbreak

This repository builds the SBInject jailbreak as a persistent,
device-personalized Cryptex. The maintained scope is deliberately small:

- SBInject replacement SpringBoard with ElleKit tweak loading
- resigned Settings with PreferenceLoader support
- fixed-trust, original-bundle-ID Sileo as a system app
- Sileo install, remove, reinstall, update, maintainer-script, and respring flows
- OpenSSH (`com.openssh.sshd`)
- automatic control-plane and UI recovery after reboot

## Device inputs

No device model, UDID, OS build, Apple executable hash, Mach-O UUID, or dyld
offset is committed. A host-only build reads device-matched bundles from:

```text
build/target/SpringBoard.app/
build/target/Preferences.app/
```

`build/` is ignored because these Apple binaries are local inputs. The normal
install command obtains both bundles from the selected phone automatically.
For a host-only build, different paths can be supplied with
`CODEX_TARGET_BUNDLE_ROOT` or the individual
`CODEX_SPRINGBOARD_CANDIDATE_SOURCE`,
`CODEX_SPRINGBOARD_CANDIDATE_INFO_SOURCE`,
`CODEX_PREFERENCES_CANDIDATE_SOURCE`, and
`CODEX_PREFERENCES_CANDIDATE_INFO_SOURCE`.

## Requirements

- macOS with full Xcode and the iPhoneOS SDK selected
- Apple Security Research Device host tools, including
  `/System/Library/SecurityResearch/usr/bin/cryptexctl.research`
- Homebrew, unless every required host utility is already installed
- a paired, connected target device

The setup script pins the Dopamine upstream commit, Python dependencies,
Procursus SSH bootstrap, OpenSSH packages, Sileo, ElleKit, and
PreferenceLoader. Downloads are checked against committed SHA-256 values.

## Build

```sh
./Dopamine-CryptexBootstrap/setup.sh --prepare
make validate
make build
```

`setup.sh` creates `Dopamine-upstream/` at the pinned commit and copies the
small local overlay into it. A successful build emits:

```text
Dopamine-upstream/CryptexBootstrap/out/build-summary.json
Dopamine-upstream/CryptexBootstrap/out/unsigned/*.cxbd
```

The build fails if the Cryptex image exceeds 128 MiB, if a pinned input has
changed, or if a required fixed-trust CDHash is absent from the generated trust
cache.

## Install or replace

```sh
./Dopamine-CryptexBootstrap/setup.sh --install --device <UDID>
```

One install command performs two live Cryptex installs through the already
loaded base-bootstrap job. It first swaps in a temporary key-only SSH payload,
copies the phone's own SpringBoard and Settings bundles over USB-forwarded SSH,
builds the resigned candidates, then replaces that payload with the final
Cryptex. No reboot or manual phone command is required. The ephemeral key is
removed after handoff, and the final step verifies system Sileo's registration,
launch, and icon.

Per-run inputs and results are retained below:

```text
Dopamine-upstream/CryptexBootstrap/out/runs/
```

## Native macOS installer

Build and open the redsn0w-style SwiftUI front end with:

```sh
make app
open dist/CryptSn0w.app
```

CryptSn0w uses the supplied running-pineapple image as both its logo and
macOS application icon. Keep the app in `dist/` and it locates this repository
automatically; a folder chooser is available if the app is moved. Connect and
unlock a paired phone, choose it from the device selector, then press
**Jailbreak**. The app runs the exact same two-stage, no-reboot installer shown
above. Persistent root SSH is disabled by default and requires an explicit
opt-in during installation before **Device > Open SSH Shell…** is available.

The app requires Swift 6.2 or newer. `make app` produces an ad-hoc-signed
native application and does not embed Apple device binaries or build output in
Git. See `MacApp/README.md` for the compact app layout.

## Runtime design

The Cryptex supplies a fixed-trust system Sileo, ElleKit exception, SSH
payload, SBInject hooks, jitter daemon, package validator, root broker, and the
two resigned Apple app candidates. SpringBoard and Settings are redirected
through SBInject; third-party tweak code remains on its JIT/dyld path rather
than entering a mutable trust cache.

`codex-exec-worker` has one production role: execute Mach-O dpkg maintainer
scripts for Sileo through the debugged/JIT-compatible child path. Shell
maintainer scripts run normally. Removing the worker would break package
lifecycle operations for packages with binary pre/post scripts.

At each boot the Cryptex launch daemon verifies the installed bytes, restores
the SBInject jitter and Sileo broker jobs, registers Sileo at its stable system
application path, starts OpenSSH, arms Settings, and replaces stock SpringBoard
with the current resigned candidate. Package state changes prepare the next
SpringBoard state, while the user-facing Sileo respring action performs the
restart.

The Sileo application bundle is copied intact, including its localization,
translation, dictionary, asset-catalog, and icon resources.

## Repository layout

```text
Dopamine-CryptexBootstrap/
  setup.sh                       pinned upstream/environment orchestration
  patch_pymobiledevice3_remotexpc.py
  CryptexBootstrap/              complete build, deploy, and runtime overlay
    SBInject/                    SpringBoard/Settings injection components
    build_cryptex.sh             reproducible Cryptex build
    deploy.py                    build/personalize/install verification
    codex_dopamine_bootstrap.m   reboot recovery and Sileo control plane
    codex_exec_worker.c          Mach-O package-script executor
MacApp/
  Package.swift                  native SwiftUI installer
  build_app.sh                   release .app/icon/signing packager
  Resources/PineappleLogo.png    installer logo and icon source
```

Runtime bootstrap diagnostics are written to
`/var/tmp/codex-dopamine-cryptex-bootstrap.log`; terminal success and failure
markers are adjacent in `/var/tmp/`.
