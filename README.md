# untitled

**Redacted source:** TSS request construction, personalization, and related
installation details are intentionally omitted. The files retain placeholders
for educational reference.

`untitled` is an iOS 27 security-research project. It builds a Cryptex-hosted
Procursus and Sileo environment, gives that environment a small root broker,
and uses it to study which kinds of native code iOS will admit after boot.

> **Project state — 2026-09-20:** the iPhone 13 / 24A435 path boots the SBInject
> SpringBoard and Settings replacements, loads ElleKit tweaks and PreferenceLoader
> panes, and runs original-ID Sileo as a system app whose exact trust source is
> the Cryptex. Sileo,
> package operations, respring, and reboot recovery no longer depend on an Apple
> Development profile or host-side re-signing. This remains an SRD research
> project tied to exact builds, not a general retail-device installer.

## Start here

If you are new to the project, read these sections in order:

1. [Where the project stands](#where-the-project-stands) explains what is
   proven, experimental, and still missing.
2. [The idea in plain English](#the-idea-in-plain-english) explains the design
   without assuming jailbreak or kernel knowledge.
3. [Quick start](#quick-start) shows the supported build and install path.
4. [Evidence and deeper reading](#evidence-and-deeper-reading) links to the
   detailed measurements.

[REDACTED: Related request, payload, or installation details omitted.]

## Where the project stands

In this README, **proven** means that the result was observed on a physical
device and recorded with enough information to distinguish a real pass from a
successful-looking API return. **Experimental** means that code exists, but
the complete current path has not passed its device acceptance test.

[REDACTED: Related request, payload, or installation details omitted.]

### The shortest honest summary

The current iPhone 13 lane is a repeatable rootless-style environment: the
Cryptex carries the fixed control plane and Sileo, while third-party
SpringBoard tweaks remain ordinary `/var/jb` packages loaded by ElleKit inside
the SBInject replacement. This result is specific to the checked-in device and
OS identities and does not imply arbitrary system-wide code admission.

## The idea in plain English

iOS does not decide whether code may run by asking only “is this process
root?” It separately checks the executable's signature, the system trust
state, the target process, and whether executable memory was created through
an authorized path. This project works with those checks instead of treating
root as a universal bypass.

The main flow is:

```text
[REDACTED: Related request, payload, or installation details omitted.]
```

There are two separate runtime strategies:

- SpringBoard tweak dylibs are loaded only in the SBInject replacement. Jitterd
  marks that exact process debugged, its pre-main hook applies the supplied
  dyld validation bypass with an `RW -> RX` transition, and ElleKit loads the
  ad-hoc signed dylibs. Sileo never creates a per-package trust cache.
- Code supplied as data can run inside the already admitted worker. This
  avoids a new trust-cache entry for every calculation, but it does not turn
  the worker into a system-wide `execve` bypass.

### Small glossary

[REDACTED: Related request, payload, or installation details omitted.]

## Validated configurations

The automatic device guard accepts only these exact tuples:

| Device | OS | Build | Recorded coverage |
| --- | --- | --- | --- |
| iPhone18,2 | iOS 27.0 | 24A435 | Cryptex/Sileo work and native USB/RSD Frida proof |
| iPhone14,5 (iPhone 13) | iOS 27.0 | 24A435 | SBInject source integration and target dyld signature validation |
| iPhone13,1 (iPhone 12 mini) | iOS 27.0 | 24A437 | Persistent bootstrap, worker, and earlier SpringBoard research |

The host is macOS with full Xcode and the iPhoneOS SDK. The generated Dopamine
tree is pinned to the upstream `3.x` commit
`939a3a21400f0dc6d6163b2b5999ba2ace0d2732`. Python dependencies are pinned in
[`requirements.txt`](requirements.txt).

An exact UDID is required when multiple validated devices are connected. The
`--allow-unverified-device` flag only disables the local guard; it does not
make another device or build supported.

## Safety and scope

- Use a dedicated research device and keep recoverable backups of anything
  important. These experiments can respring the UI or require device recovery.
- Never attach to, suspend, signal, inject into, or dynamically test
  launchd/PID 1. The checked-in runtime paths contain explicit PID and
  executable-path guards, but the operator still owns this boundary.
- Keep the phone unlocked and connected during installation.
- Do not interpret root, platform status, a task port, or a successful
  `vm_protect` return as proof that code executed. The acceptance records check
  the resulting process, image list, memory protection, and observable output.
- Generated tickets, keys, device logs, and build
  products stay in ignored local directories. Review them before moving any
  artifact elsewhere.

## Prerequisites

### Mac

Install or configure:

- macOS and Homebrew;
- full Xcode, with an iPhoneOS SDK selected by `xcrun`;
- Apple Security Research Device host tools, including
  `/System/Library/SecurityResearch/usr/bin/cryptexctl.research`;
- Git access to this private repository; and
- enough disk space for the generated Dopamine checkout, package cache, build
  products, and device evidence.

Quick checks:

```sh
xcodebuild -version
xcrun --sdk iphoneos --show-sdk-path
test -x /System/Library/SecurityResearch/usr/bin/cryptexctl.research \
  && echo "cryptexctl.research is available"
```

If command-line tools are pointing at the lightweight SDK instead of full
Xcode, select Xcode for the current shell:

```sh
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
```

`setup.sh` can install missing `dpkg`, `gnupg`, `ldid`, `ripgrep`, and `zstd`
formulae through Homebrew. Xcode, Homebrew, and the SRD tools must already be
available.

### Sileo signing

No Apple Development identity or provisioning profile is used. The build
preserves Sileo's upstream system-app entitlements, gives every bundled Mach-O
an ad-hoc CodeDirectory, omits `embedded.mobileprovision`, and places the exact
CDHashes in the static Cryptex trust cache. LaunchServices registers the mounted
bundle as the non-removable system app `org.coolstar.SileoStore`.

Sileo's installed Debian metadata version is `2.5.1+codex1`. APT rejects repo
replacements of that package; update Sileo by building a new Cryptex instead of
installing a mutable app under `/var/jb`.

### iPhone

Before installation:

- enable Developer Mode;
- connect over USB;
- unlock the phone;
- accept the Mac trust/pairing prompt; and
- confirm that Xcode can see the paired device:

```sh
xcrun devicectl list devices
```

The installer uses pymobiledevice3's userspace RemoteXPC tunnel. It does not
require a separately managed root tunnel for the normal setup flow.

## Quick start

Clone the private repository:

```sh
gh repo clone 0xjohnnydev/untitled
cd untitled
```

or:

```sh
git clone https://github.com/0xjohnnydev/untitled.git
cd untitled
```

### 1. Prepare the host

```sh
./Dopamine-CryptexBootstrap/setup.sh
```

This creates the pinned Python environment, fetches the pinned upstream
Dopamine revision into the ignored `Dopamine-upstream/` tree, and applies the
tracked overlay.

To report missing Homebrew dependencies without installing them:

```sh
./Dopamine-CryptexBootstrap/setup.sh --no-brew
```

### 2. Build without touching the phone

```sh
./Dopamine-CryptexBootstrap/setup.sh --build
```

This is the right first test after changing fixed Cryptex contents. Host build
success is necessary, but it is not a device acceptance result.

### 3. Build, personalize, validate, and install

With one prepared and unlocked validated phone connected:

```sh
./Dopamine-CryptexBootstrap/setup.sh --install
```

If more than one eligible phone is connected:

```sh
./Dopamine-CryptexBootstrap/setup.sh --install --device <UDID>
```

To refuse replacement of an older project Cryptex:

```sh
./Dopamine-CryptexBootstrap/setup.sh --install --no-replace
```

The install command performs these broad steps:

[REDACTED: Related request, payload, or installation details omitted.]

If you deliberately port to a different physical device or build, select it
explicitly:

```sh
./Dopamine-CryptexBootstrap/setup.sh --install \
  --device <UDID> \
  --allow-unverified-device
```

Keep that result separate from the validated matrix until it has its own full
acceptance record.

## What success looks like

A successful accepted run has more than an exit code. Confirm all of the
following in the newest run summary and device markers:

- ticket and payload validation are true;
- the expected Cryptex identifier and generated version match;
- the bootstrap completion marker reports `result=success` and UID 0;
- LaunchServices reports `org.coolstar.SileoStore` as non-removable and not
  developer-built, with the fixed managed application-container URL;
- Sileo launches from that exact URL and remains alive after its constructor
  consumes the six process-bound extensions;
- the root broker is ready;
- package configuration and `apt-get check` exit 0;
- Sileo is running as `mobile`, while privileged package work stays in the
  root broker; and
- fixed files on the device match the files whose hashes entered the build
  summary and trust cache.

Install metadata is written below:

```text
[REDACTED: Related request, payload, or installation details omitted.]
```

These outputs are ignored because they can include device-bound or
machine-local material. Selected, reviewed evidence is copied into
[`findings/`](findings/) for version control.

The bootstrap configures Procursus, Chariz, Havoc, BigBoss, and ElleKit in
Sileo. It installs the managed repository keys and compatibility policy, then
runs an APT consistency check before declaring success. Existing custom source
files remain alongside the managed defaults.

## Separate research workflows

These workflows are useful after understanding the main bootstrap. They are
not required for a first host build.

### Minimal root SSH proof

The older, separate proof of concept builds a small Cryptex, proves UID 0 over
key-only SSH, and can open an interactive shell:

```sh
./untitled.py
```

Select a device or run one command and save its result:

```sh
./untitled.py --device <UDID>
./untitled.py --command 'id' --result-json build/root-proof.json
```

Its payload, generated host/client keys, tickets, and results remain under the
ignored `build/` directory.

### Native Frida validation

Frida 17.17.0 works on the validated iPhone18,2 lane over Apple's native
USB/RSD debugger transport. The checked-in Gum patch covers allocator-owned
executable trampolines that the stock page plan missed.

Install the pinned host packages, select the known patched Gadget, and run the
bounded test against an exact UDID:

```sh
uv pip install --python build/frida-host-venv/bin/python \
  -r requirements-frida.txt
Scripts/select-frida-ios27-gadget.zsh patched
Scripts/run-frida-ios27-usb-smoke.zsh --udid <UDID>
```

After that passes, use the same guarded transport against a disposable target:

```sh
Scripts/frida-ios27-usb.zsh -p <disposable-pid>
```

The wrapper rejects PID 1, ambiguous device selection, and remote-server
selectors. Keep the legacy device-side Frida server stopped during this test;
otherwise Fruity may choose a different transport and invalidate the result.

The patched and official rollback Gadgets are selected explicitly:

```sh
Scripts/select-frida-ios27-gadget.zsh patched
Scripts/select-frida-ios27-gadget.zsh official
```

See [`ARBITRARY_EXEC_STRATEGY.md`](ARBITRARY_EXEC_STRATEGY.md) for the patch,
artifact hashes, debugger-page sequence, and interpretation of the result.

### Current `customd` development lane

`customd` is intended to keep a tightly constrained, debugger-authorized host
available after boot and expose only fixed, identity-checked operations through
a root-owned local socket. Its current source includes:

- a versioned client/daemon protocol;
- strict path, owner, mode, inode, PID, UUID, and hash checks;
- a fixed SpringBoard candidate registrar;
- bounded trace/re-exec and SETEXEC helpers; and
- installation hooks for a persistent system launch daemon.

This list describes implemented code, **not a passing end-to-end result**. The
latest accepted SpringBoard result remains trusted-library injection into the
stock process. The fixed candidate has passed only the stopped-child admission
test. Do not use the new activation operations as a normal setup step until a
dated finding records candidate launch, injection, health, and stock recovery
in one accepted run.

## The important technical boundary

The full explanation lives in
[`ARBITRARY_EXEC_STRATEGY.md`](ARBITRARY_EXEC_STRATEGY.md) and
[`findings/txm-debug-region-24A435.md`](findings/txm-debug-region-24A435.md).
The beginner-sized version is:

1. iOS first decides whether a process may contain invalid or newly generated
   code. Developer Mode alone is not enough. The fixed worker qualifies through
   its accepted `get-task-allow` state; stock SpringBoard does not.
2. iOS then authorizes each executable copy-on-write region. A debugger-
   entitled caller and the already-authorized target state are both required.
3. A working page sequence is `RW|COPY`, write and flush, then `RX`. Asking for
   `RX` before the initial write produced a real failure in the probe.
4. A trust cache handles valid code identities. It does not make an unsigned or
   malformed Mach-O structurally valid.

That is why all of these statements can be true at the same time: the project
has root, can obtain a task port, can load a trusted dylib into SpringBoard, and
still cannot execute arbitrary fresh native pages inside stock SpringBoard.

## Troubleshooting

### `missing ... cryptexctl.research`

Install the authorized SRD host tooling and verify the exact absolute path in
[Prerequisites](#prerequisites). This repository cannot substitute for that
tool or for device eligibility.

### `the iPhoneOS SDK is unavailable`

Select full Xcode, then retry:

```sh
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
xcrun --sdk iphoneos --show-sdk-path
```

### No connected validated target

Unlock and reconnect the phone, accept the trust prompt, and inspect:

```sh
xcrun devicectl list devices
```

Use `--device <UDID>` when selection is ambiguous. Reserve
`--allow-unverified-device` for deliberate porting work.

### Sileo installation fails

Confirm Developer Mode, an unlocked phone, and a fresh pairing. The install
summary's `systemSileoVerification` must show the original bundle ID, a Cryptex
URL, `builtByDeveloper: false`, and `removable: false`. There is no profile to
renew. If a pre-install bootstrap survived replacement, the driver restarts
only that recorded stale PID and waits for the new registration.

### RemoteXPC reports `GOAWAY error 3`

[REDACTED: Related request, payload, or installation details omitted.]

### Cryptex personalization is rejected

[REDACTED: Related request, payload, or installation details omitted.]

### Sileo reports a missing APT `Packages` directory

Use the newest matched Sileo/Cryptex pair and check the acceptance gates in the
running-proof document. A Featured-card “Package Unavailable” message can be a
separate third-party repository issue.

## Repository map

[REDACTED: Related request, payload, or installation details omitted.]

## Evidence and deeper reading

Start with these records:

[REDACTED: Related request, payload, or installation details omitted.]

## Updating an existing clone

```sh
git pull --ff-only
./Dopamine-CryptexBootstrap/setup.sh
```

[REDACTED: Related request, payload, or installation details omitted.]
