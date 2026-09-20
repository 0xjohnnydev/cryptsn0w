# Dopamine Cryptex bootstrap overlay

**Redacted source:** TSS request construction, personalization, and related
installation details are intentionally omitted. The files retain placeholders
for educational reference.

[REDACTED: Related request, payload, or installation details omitted.]

## Requirements

- macOS with a full Xcode installation and the iPhoneOS 27 SDK selected;
- the Security Research Device host tools, including
  `/System/Library/SecurityResearch/usr/bin/cryptexctl.research`;
- Homebrew (only used when a listed build dependency is missing);
- the paired iPhone connected over USB, unlocked, and in Developer Mode for
  installation; and
- one valid local Apple Development identity/profile for the Sileo launcher
  bundle selected for that device.

The bridge does **not** require Theos. Its small Swift metadata helpers are
vendored at a pinned upstream commit and compile with Xcode's toolchain.

## Reproducible build and install

From the repository root, prepare the pinned upstream checkout and toolchain:

```sh
./Dopamine-CryptexBootstrap/setup.sh
```

Build without touching the phone:

```sh
./Dopamine-CryptexBootstrap/setup.sh --build \
  --device 00008110-000C542E0EA8201E
```

Passing the target device to `--build` selects the same validated Sileo bundle
identifier and development profile that `--install` will use. This avoids
accidentally building the iPhone 13 artifact with another device's profile.

Install the matched Sileo/Cryptex pair on the validated iPhone 13:

```sh
./Dopamine-CryptexBootstrap/setup.sh --install \
  --device 00008110-000C542E0EA8201E
```

`setup.sh` installs missing build tools with an existing Homebrew installation,
creates the pinned Python virtual environment, fetches only the pinned
opa334/Dopamine commit, copies this overlay into the generated
`Dopamine-upstream` working tree, and auto-selects a valid local Apple
Development profile for the target's configured Sileo identifier. It also applies the pinned
RemoteXPC flow-control patch used for large Cryptex image transfers.

The install driver is restart-safe. Every build gets a unique numeric version;
if USB/RemoteXPC drops after cryptexd committed that exact version, rerunning the
validated install recognizes it instead of uninstalling or duplicating it.

Pinned upstream:

- repository: `https://github.com/opa334/Dopamine.git`
- branch: `3.x`
- commit: `939a3a21400f0dc6d6163b2b5999ba2ace0d2732`

Other pinned runtime inputs include PreferenceLoader `2.3.3` (release SHA-256
`eaacb5204e13dee166cc44763566bbbd565fbf3cf1ecc25b1a2f432b6bee6f86`),
ElleKit `1.2`, the Procursus 1900 bootstrap, and opa334's bundled Sileo package.
Every remote archive is accepted only at its checked-in digest.

For a machine with multiple signing identities, optional overrides are
`CODEX_SILEO_DEVELOPMENT_IDENTITY`, `CODEX_SILEO_PROVISIONING_PROFILE`, and
`CODEX_SILEO_DEVELOPMENT_ENTITLEMENTS`. Run `setup.sh --help` for the device
guard and selection options.

[REDACTED: Related request, payload, or installation details omitted.]

## Outputs and size

Build products live only under the ignored
`Dopamine-upstream/CryptexBootstrap/{cache,work,out}` directories. Current
validated iPhone 13 builds are about 45 MB for the image, 4.1 MB for the Sileo
IPA, and 138 KB for the iOS 27 Settings bridge; build and install independently
enforce a 128 MB image ceiling, and the bridge has a 1 MiB ceiling. None of
those generated artifacts belongs in Git.

`out/build-summary.json` records every pinned input digest, all fixed-control
plane hashes, the full trust-cache dump, and the six byte-identical Sileo
runtime copies. `out/runs/<run-id>/` contains the device context, ticket checks,
validation, and final installation result for an install attempt.

Sileo's main executable, root helper, constructor shim, and three bundled
libraries are copied byte-for-byte into the fixed Cryptex trust set. The build
derives and verifies every architecture CDHash before producing the image, and
the installer checks both the registered app and `/var/jb` copies against those
exact inputs. Package-installed tweak code is never added to a trust cache.

Preference panes use pinned PreferenceLoader/libprefs plus the local arm64e
`SettingsSidebarListState` bridge. The bridge is loaded pre-main only in the
resigned Settings process, publishes every valid PreferenceLoader registration,
keeps the Swift snapshot lookup dictionaries coherent, and routes a selected
row to the existing preference controller. Its support-source provenance and
license are in `CryptexBootstrap/SBInject/PreferenceBridgeSupport/`.

Legacy preference-pane respring buttons are handled inside that same bridge.
Only `sbreload` and `killall SpringBoard` command shapes are intercepted; they
become a dedicated, peer-authenticated root-broker operation. The bridge
provides compatible `posix_spawn`, `posix_spawnp`, `system`, and `waitpid`
semantics to the pane without exposing arbitrary root command execution.

On an unchanged installation, reboot startup takes a local-only fast path. It
verifies the fixed Cryptex payload and pinned package versions byte-for-byte,
starts jitterd and the Sileo broker, re-arms the SpringBoard and Settings
redirects, and never waits for APT or repository networking. SpringBoard and
Settings activation does not depend on the Sileo data container being unlocked;
the file broker waits locally for first unlock if data protection delays it.

SBInject safe mode does not uninstall, rename, or disable tweak files. Fatal
signal PC/LR values are PAC-stripped and matched against loaded tweak text
ranges, while uncaught Objective-C exceptions also inspect tweak frames and
live hooked method implementations. The resulting alert uses SpringBoard's
existing foreground presenter—never a new key window—so safe mode remains
interactive while identifying the tweak when the crash supplies attributable
code. If no tweak frame exists, the alert explicitly reports an unknown tweak
instead of guessing.

The on-device repair path maintains Dopamine's standard Chariz, Havoc,
BigBoss, and ElleKit entries in
`/var/jb/etc/apt/sources.list.d/dopamine-default.sources`. Procursus remains the
bootstrap feed. The installer deploys the pinned repository keys, configures
BigBoss's verified legacy-signature compatibility, restores Procursus metadata,
synchronizes the trust-cached `launchctl` and `uiopen` executables, and refreshes
the complete repository set. Custom repository files remain available beside
the managed defaults.
