# CryptSn0w for macOS

**Redacted source:** TSS request construction, personalization, and related
installation details are intentionally omitted. The files retain placeholders
for educational reference.

Historical documentation for an obsolete project. The app uses the same
patched TSS/Cryptex path as the command-line installer. See the
[project status](../README.md).

CryptSn0w is the native SwiftUI front end for the repository's installer.
Its layout is patterned after the classic Pangu utility:
a connected-device selector, a single Jailbreak action, concise status, and
the supplied running-pineapple artwork.

The app launches the same reproducible command-line flow:

```sh
./Dopamine-CryptexBootstrap/setup.sh --install --device <UDID>
```

It does not contain a second GUI-only jailbreak implementation.

## Build

From the repository root, run:

```sh
make app
open dist/CryptSn0w.app
```

The build requires Swift 6.2 or newer, generates the macOS icon from
`Resources/PineappleBrushLogo.png`, signs the local app ad hoc, and places ignored
output under `dist/` and `MacApp/.build/`.

Keep the built app in `dist/` so it can locate the repository automatically.
If it is moved, choose **Device > Choose Repository…**.

## Tests

Run `make test` from the repository root. This checks the script syntax and
runs the desktop app tests and bootstrap file-handling tests. The latter use
temporary files and simulate root ownership; they do not require root access.
The desktop tests use temporary commands to check device
selection, large command output, errors, and complete log files. They do not
run the jailbreak installer.

To also run five read-only device-discovery checks, set
`CRYPTSN0W_TEST_REPOSITORY` to the repository's absolute path and
`CRYPTSN0W_TEST_DEVICE` to a connected device's UDID before running `make test`.

## Devices and installation

The selector is populated from `pymobiledevice3 usbmux list`; it is not a
free-text UDID field. Connect and unlock a paired iPhone, trust the Mac, and
use the refresh control if it was connected after launch. Press **Jailbreak**
to run the complete no-reboot pull, resign, Cryptex build, and install flow.

Persistent root SSH is off by default. The unchecked **Enable root SSH access
for this Mac** option passes `--enable-host-ssh` only when explicitly selected.

Every GUI install writes the complete combined installer output to a timestamped
file under `~/Library/Logs/CryptexSn0w`. The current file can be revealed with
the status view's **Show Log** button or **Device > Show Install Log**, and a
failure alert includes its exact path so the log can be sent without copying
the shortened on-screen status.

## SSH shell menu

After an SSH-enabled successful install, **Device > Open SSH Shell…** reads
the latest matching `flow-summary.json`, uses its `hostSSHPrivateKey`, starts
an authenticated usbmux forward from a free localhost port to device port
2222, and opens `ssh` in Terminal. The forward process stays owned by the app;
opening another shell replaces the prior forward. If the latest install did
not retain a host key, the menu remains disabled and the main window explains
how to enable it.
