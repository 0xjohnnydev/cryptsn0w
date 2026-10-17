# Dopamine Cryptex overlay

**Redacted source:** TSS request construction, personalization, and related
installation details are intentionally omitted. The files retain placeholders
for educational reference.

Historical documentation for an obsolete project. See the
[project status](../README.md) before using these instructions.

This directory contains the reproducible wrapper and source overlay for the
SBInject jailbreak. The supported runtime consists of Sileo/package operations,
SBInject SpringBoard, Settings/PreferenceLoader, OpenSSH, and reboot recovery.

From the repository root:

```sh
./Dopamine-CryptexBootstrap/setup.sh --prepare
make validate
./Dopamine-CryptexBootstrap/setup.sh --build
./Dopamine-CryptexBootstrap/setup.sh --install --device <UDID>
```

`setup.sh` checks out opa334/Dopamine commit
`939a3a21400f0dc6d6163b2b5999ba2ace0d2732`, initializes its pinned
`BaseBin/opainject` submodule, copies `CryptexBootstrap/` into that generated
tree, and prepares the pinned Python environment. Generated upstream sources,
downloads, work products, tickets, and install results remain ignored.

The build requires macOS, full Xcode with the iPhoneOS SDK, and Apple’s
Security Research Device Cryptex host tools. Homebrew supplies missing command
line dependencies unless `--no-brew` is passed.

Host-only builds read local device inputs from:

```text
build/target/SpringBoard.app/
build/target/Preferences.app/
build/target/amfid
```

The `--install` flow builds and installs a temporary SSH Cryptex, copies those
inputs from the selected phone, then builds and installs the final Cryptex.
The temporary image includes its own launch daemon and SSH server. The flow
is designed to complete without a reboot.

The upstream commit and direct Python dependency versions are pinned; bootstrap
and package archives are checked against committed hashes. The image is rejected
above 128 MiB. Sileo retains `org.coolstar.SileoStore`, has no provisioning
profile, and is registered as a non-removable system app. The pinned SSH
bootstrap and OpenSSH Debian packages keep `com.openssh.sshd` available after
repair and reboot.

See the repository [README](../README.md) for the operator workflow and
[CryptexBootstrap/README.md](CryptexBootstrap/README.md) for runtime details.
