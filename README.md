# untitled

**Redacted source:** TSS request construction, personalization, and related
installation details are intentionally omitted. The files retain placeholders
for educational reference.

Private iOS 27 security-research workspace for the validated iPhone18,2
(24A435) and iPhone13,1 / iPhone 12 mini (24A437) lanes.

## Status checklist

Proven:

- [x] Install and validate a persistent-requested Cryptex with a 459-entry
  static trust cache on the iPhone 12 mini.
- [x] Start the Sileo root broker and complete brokered `whoami`, package
  configuration, and `apt-get check` with exit 0.
- [x] Load the already trust-cached ElleKit injector into SpringBoard through
  privileged task-port access and ROP into SpringBoard's existing dyld code.
- [x] Execute newly generated native code in a debugger-authorized process and
  run patched Frida Interceptor/NativeFunction over native USB/RSD.
- [x] Reproduce the executable-page primitive in the installed on-device worker
  without requiring the Mac.
- [x] Exclude launchd/PID 1 through explicit PID and executable-path guards.

Not yet proven:

- [ ] Complete a clean-reboot acceptance pass for Cryptex remount, trust-cache
  availability, daemon startup, worker self-test, and Sileo launch.
- [ ] Rebuild and install the no-APT-preinstall-hook revision, then pass
  BrokerProbe through unpack, `postinst`, executable launch, and tweak loading.
- [ ] Reliably run arbitrary package Mach-Os through the fixed worker without
  adding each payload to the trust cache.
- [ ] Load a completely unsigned arbitrary dylib into SpringBoard or another
  protected process; the successful SpringBoard payload was trust-cached.
- [ ] Demonstrate executable-page admission inside a system process that lacks
  `get-task-allow`; obtaining its task port and loading a trusted dylib do not
  prove that its newly generated native pages can execute.
- [ ] Provide transparent system-wide `execve`, complete Mach-O semantics, or
  arbitrary new entitlements for loaded payloads.

## Debugger/JIT boundary

Two external statements that initially sounded contradictory describe different
levels of authority:

- The stock debugger-JIT route requires `get-task-allow` on the **target**
  process. A privileged helper, root caller, or task port does not transfer that
  entitlement to SpringBoard. On TXM/SPTM devices, setting `CS_DEBUGGED` alone is
  also insufficient: each executable region must pass the debugger-backed page
  preparation protocol. See the [current debugger-JIT integration guidance](https://github.com/StikDebug/StikJIT/blob/main/INTEGRATION.md).
  XNU likewise keeps [task-port authorization](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_proc.c#L5585-L5664)
  separate from `ptrace`'s call to
  [`cs_allow_invalid`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_cs.c#L193-L245),
  which has its own MAC-policy and `pmap` gates.
- A public full-jailbreak daemon can claim to JIT processes and inject tweaks
  because it is only one component of a kernel-assisted stack. Its
  [system hook](https://github.com/mineek/DopamineekPublic/blob/5aeee4bb9516d9c9268c67279950e09e9fb2f03f/BaseBin/systemhook/src/main.c)
  manually requests debug state when ordinary `ptrace` cannot set it, while its
  [kernel helper](https://github.com/mineek/DopamineekPublic/blob/5aeee4bb9516d9c9268c67279950e09e9fb2f03f/BaseBin/libjailbreak/src/kernel.c)
  directly changes process, `vm_map`, and `pmap` code-signing state. The same
  stack also provides a
  [dynamic trust-cache service](https://github.com/mineek/DopamineekPublic/blob/5aeee4bb9516d9c9268c67279950e09e9fb2f03f/BaseBin/launchdhook/src/jbserver/jbdomain_systemwide.c)
  for newly installed native files.

The reported `vm_protect` argument-order fix has a version-specific explanation
that points to a kernel-call broker rather than a new AMFI bypass. The public
`vm_protect`/`mach_vm_protect` ABI remains
`task, address, size, set_maximum, new_protection`, and this project's calls use
that order. The kernel-internal `vm_map_protect` ABI did change, however:
[XNU 10002 used](https://github.com/apple-oss-distributions/xnu/blob/xnu-10002.81.5/osfmk/vm/vm_map.c#L5890-L5895)
`map, start, end, new_protection, set_maximum`, whereas
[XNU 11215 uses](https://github.com/apple-oss-distributions/xnu/blob/xnu-11215.81.4/osfmk/vm/vm_map.c#L5602-L5607)
`map, start, end, set_maximum, new_protection`. The installed KDK 27.0 arm64e
DWARF confirms the newer order. A direct kernel caller ported from the older ABI
would put the intended RX protection bits in `set_maximum` and `false` in
`new_protection`, effectively requesting maximum protection `VM_PROT_NONE`.
Correcting that swap would make the last page-protection transition begin
working and could easily be described informally as fixing code signing.

It still does not supply the missing authorization. With the correct order,
[XNU treats the transition as a debugger/COW-region association](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/vm/vm_map.c#L6136-L6181),
and the code-signing monitor permits such a
[debug region only in an already debug-authorized address space](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/code_signing.h#L725-L742).
On the current path, a denied association removes execute permission even
though the outer protection operation can still return success. XNU also says
that the monitor does not base enforcement on its diagnostic trust-level value,
and its general address-space exemption is limited to stage-2-translation
pmaps. Platformization or a high reported trust level therefore does not replace
`CS_DEBUGGED`/TXM `allowsInvalidCode`. The clue explains how executable pages
began working after that prerequisite existed; it does not explain how a non-
`get-task-allow` system process acquired it.

The particular daemon named in the external claim has no public implementation
that was located, so its private mechanism remains unverified. The closest
public analogue above is not a launch-daemon-only technique and does not
establish an NDA-only bypass. This project currently has a durable root Cryptex
daemon and privileged task-port access, but not the kernel-write,
`vm_map`/`pmap`, or launchd-hook authority used by that public architecture. The
separate [public ROP-injector documentation](https://github.com/opa334/opainject)
also warns that an arm64e target crashes when the injected dylib is absent from
the trust cache. The proven split is:

- debugger-authorized JIT and Frida inside the fixed `get-task-allow` worker;
- trusted-library task-port/ROP injection into SpringBoard;
- no proof yet of arbitrary unsigned native execution inside SpringBoard.

[REDACTED: Related request, payload, or installation details omitted.]

## Validated configuration

- iPhone18,2: iOS 27.0 (24A435), including the native USB/RSD Frida proof
- iPhone13,1 (iPhone 12 mini): iOS 27.0 (24A437), including the latest
  Procursus/Sileo bootstrap deployment
- Host: macOS with a full Xcode iPhoneOS SDK
- Upstream Dopamine: branch `3.x`, commit
  `939a3a21400f0dc6d6163b2b5999ba2ace0d2732`
- Python dependencies: pinned in `requirements.txt`

The default device guard accepts only these exact device/version/build tuples.
Pass an exact UDID when both validated devices are connected; use the documented
override only when deliberately porting to another configuration.

## Prerequisites

### Mac

Install or configure the following before running setup:

- macOS with Homebrew available.
- Full Xcode with the iPhoneOS SDK.
- The iPhoneOS SDK selected by `xcrun`.
- Apple Security Research Device host tools, including
  `/System/Library/SecurityResearch/usr/bin/cryptexctl.research`.
- Git access to this private repository.

Quick checks:

```sh
xcodebuild -version
xcrun --sdk iphoneos --show-sdk-path
test -x /System/Library/SecurityResearch/usr/bin/cryptexctl.research \
  && echo "cryptexctl.research is available"
```

Set the full Xcode developer directory for the current shell when needed:

```sh
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
```

`setup.sh` installs missing `dpkg`, `gnupg`, `ldid`, `ripgrep`, and `zstd` formulae
through Homebrew. Install Xcode, Homebrew, and the SRD host tools first.

### Apple Development signing

Xcode must have:

- a valid Apple Development certificate in the login keychain;
- an unexpired iOS development provisioning profile whose application-ID
  pattern covers `org.coolstar.SileoStore`;
- the target iPhone registered in that profile.

In Xcode, sign in under **Settings → Accounts**, create an Apple Development
certificate if necessary, and build a simple automatically signed iOS app to
the connected device once. A compatible wildcard team profile is sufficient.

You can confirm that a code-signing identity is visible with:

```sh
security find-identity -v -p codesigning
```

The setup script discovers and validates the identity/profile automatically,
then generates machine-local signing configuration in an ignored work tree.

### iPhone

Before installation:

- enable Developer Mode;
- connect over USB for the initial run;
- unlock the device;
- accept the Mac trust/pairing prompt;
- confirm the device appears as connected and paired:

```sh
xcrun devicectl list devices
```

The installation uses pymobiledevice3's in-process userspace RemoteXPC tunnel,
so the setup flow runs directly as the current user.

## Clone

Authenticate to GitHub with an account that can read the private repository,
then use either form:

```sh
gh repo clone 0xjohnnydev/untitled
cd untitled
```

or:

```sh
git clone https://github.com/0xjohnnydev/untitled.git
cd untitled
```

## One-command installation

With the prepared and unlocked iPhone connected:

```sh
./Dopamine-CryptexBootstrap/setup.sh --install
```

That command performs the complete ordered workflow:

[REDACTED: Related request, payload, or installation details omitted.]

If exactly one validated device is connected it is selected automatically.
When several eligible devices are present, pass the target UDID:

```sh
./Dopamine-CryptexBootstrap/setup.sh --install --device <UDID>
```

To require a clean Cryptex install state:

```sh
./Dopamine-CryptexBootstrap/setup.sh --install --no-replace
```

## Prepare and build separately

Run the default host-only mode to fetch upstream, create the venv, and validate
signing:

```sh
./Dopamine-CryptexBootstrap/setup.sh
```

Build the complete matched pair in host-only mode:

```sh
./Dopamine-CryptexBootstrap/setup.sh --build
```

Check Homebrew dependencies and report any missing formulae:

```sh
./Dopamine-CryptexBootstrap/setup.sh --build --no-brew
```

Generated build products are written below:

```text
[REDACTED: Related request, payload, or installation details omitted.]
```

Generated upstream sources, caches, tickets, IPAs, profiles, and run logs live
in ignored work directories.

## Signing overrides

Automatic selection is recommended. On a Mac with multiple teams or profiles,
the following environment variables narrow or replace the selection:

```sh
export CODEX_SILEO_DEVELOPMENT_IDENTITY=<certificate-SHA1-or-unique-name>
export CODEX_SILEO_PROVISIONING_PROFILE=/absolute/path/profile.mobileprovision
export CODEX_SILEO_DEVELOPMENT_ENTITLEMENTS=/absolute/path/entitlements.plist

./Dopamine-CryptexBootstrap/setup.sh --install
```

The identity must be installed, included in the selected profile, and valid for
code signing. A custom entitlement plist is still checked against the
profile's application identifier, team identifier, and `get-task-allow` value.

## Porting to another device configuration

Select another connected physical device explicitly:

```sh
./Dopamine-CryptexBootstrap/setup.sh --install \
  --device <UDID> \
  --allow-unverified-device
```

This mode retains pairing, provisioning, Cryptex validation, ticket validation,
and Apple's server-side authorization while relaxing the local validated-matrix
check.

## After installation

The Cryptex launch daemon prepares or repairs the managed Procursus tree,
creates Dopamine's bootstrap marker before package scripts run, installs the
managed repository keys and policy, synchronizes `launchctl` and `uiopen` to
their trust-cached copies, starts the root broker, performs `apt-get check`,
and launches Sileo. Keep the device unlocked during this stage.

Successful host-side run metadata is saved in the newest
`Dopamine-upstream/CryptexBootstrap/out/runs/<run-id>/flow-summary.json`.
Detailed on-device acceptance gates and the known-good run are documented in
[`RUNNING_PROOF_20260914.md`](Dopamine-CryptexBootstrap/CryptexBootstrap/RUNNING_PROOF_20260914.md).

[REDACTED: Related request, payload, or installation details omitted.]

## Current runtime status

The latest accepted iPhone 12 mini deployment is Cryptex version
`1.0.20260915200055.800872`. Its validated trust cache contains 459 entries;
its SHA-256 is
`40ea85a4d0cb33393f5d5611b1bdd7c7d7084330cc0cc6abf37968325c5109c0`.
The on-device runtime worker self-test and root-broker `whoami` both exited 0,
the guarded ElleKit injector loaded into SpringBoard with status 0, package
configuration and `apt-get check` exited 0, and PID 1 remained explicitly out
of scope.

A later BrokerProbe 1.0.14 update exposed the remaining package-install edge:
three attempts stopped before payload unpack and `postinst` because the already
installed image's APT pre-install client returned 100. The current source removes
that obsolete hook and routes non-baseline executable launches through the
fixed interposer and debugger-softened worker. That source change has not yet
been rebuilt, installed, or used to pass BrokerProbe, so arbitrary package
payload execution remains a pending acceptance gate rather than a claimed
result. See [`ARBITRARY_EXEC_STRATEGY.md`](ARBITRARY_EXEC_STRATEGY.md) for the
measured boundary and next tests.

## Default Sileo repositories

The bootstrap configures the standard Dopamine repository set:

- Procursus
- Chariz (`https://repo.chariz.com/`)
- Havoc (`https://havoc.app/`)
- BigBoss (`http://apt.thebigboss.org/repofiles/cydia/`)
- ElleKit (`https://ellekit.space/`)

The four Dopamine sources are maintained in
`/var/jb/etc/apt/sources.list.d/dopamine-default.sources`. Fresh bootstrap and
repair runs verify that file and install the ElleKit and BigBoss keys in
`/var/jb/etc/apt/trusted.gpg.d`. The managed APT policy at
`/var/jb/etc/apt/apt.conf.d/99dopamine-repository-compat` keeps BigBoss's
fingerprint-pinned legacy signature valid while reporting its SHA-1 digest as
a warning. Sileo receives populated package indexes for all five repositories
when it opens. Custom repository files remain alongside the managed defaults.

## Root SSH proof of concept

The separate root-SSH lane builds its own minimal Cryptex payload, installs it,
proves UID 0 through key-only SSH, and opens an interactive shell:

```sh
./untitled.py
```

Select a device explicitly or run one command and save its result:

```sh
./untitled.py --device <UDID>
./untitled.py --command 'id' --result-json build/root-proof.json
```

`untitled.py` creates the same pinned Python environment when needed. Its
generated payload, host key, client key, tickets, and results remain under the
ignored `build` directory.

## iOS 27 Frida runtime validation

Native Frida 17.17.0 USB/RSD injection and Gum Interceptor are working on the
iPhone18,2 / 24A435 lane. Frida's existing iOS 26+ page-plan support covered
image patches but did
not cover Gum's allocator-owned executable trampolines. The checked-in
`Patches/frida-gum-17.17.0-ios27-code-page-plan.patch` adds those allocations
to the debugger plan. The official host binding remains untouched.

Install the host packages, select the proven universal patched Gadget, and run
the bounded test against an exact UDID:

```sh
uv pip install --python build/frida-host-venv/bin/python \
  -r requirements-frida.txt
Scripts/select-frida-ios27-gadget.zsh patched
Scripts/run-frida-ios27-usb-smoke.zsh --udid <UDID>
```

The wrapper uses Apple's Python 3.9 with the Frida abi3 extension from the host
venv; this avoids a macOS 27 RSD-discovery failure observed under Homebrew
Python. The test refuses a listener on device TCP 27042, starts only the exact
`untitled-frida-debug-target`, proves an `Interceptor` callback and
`NativeFunction(getpid)`, and revalidates the PID/path before cleanup. It never
starts or restarts a device-side Frida server or policyd and contains no PID 1
attach or signal path.

After the smoke test passes, use the same transport in the interactive CLI:

```sh
Scripts/frida-ios27-usb.zsh -p <disposable-pid>
```

That wrapper is pinned to the validated UDID, refuses remote/ambiguous device
selectors, and rejects PID 1/launchd targets. Keep the legacy device-side
Frida server stopped so Fruity cannot select the wrong route.

The proven patched Gadget has SHA-256
`10a34a745f3e2342004847ee921119ff50fc41ea6ffc949b0c6a4ccd37182c71`.
The untouched official rollback copy has SHA-256
`1c5855bacfbe2e2ed3029b15a44110967609416676c2e3f9e998a83b1c3a4bf5`.
Both are staged under `build/frida-ios27-host/`; switch explicitly with:

```sh
Scripts/select-frida-ios27-gadget.zsh patched
Scripts/select-frida-ios27-gadget.zsh official
```

A source-pinned rebuild is available separately:

```sh
export IOS_CERTID=<Apple-Development-certificate-SHA1>
Scripts/build-frida-ios27-gadget.zsh
```

The older `Scripts/frida-ios27-smoke-test.py` remains a guarded device-server
GTA/non-GTA A/B diagnostic. Do not run it at the same time as the native USB
test: its TCP 27042 server intentionally selects a different route.

The Cryptex also carries a hard-coded dynamic-code probe. Its entitlement-only
`MAP_JIT` attempt returned `EINVAL`, and its ordinary RW-to-RX child was killed.
The successful alternative is `Scripts/bless_jit26_probe.py`, which uses the
iOS 26+ debugger page broker and returned 42 from a newly written RX page.

Together these results support one fixed trusted worker that accepts runtime
modules as data, avoiding a trust-cache entry per module. They do not bypass
AMFI for arbitrary fresh Mach-O `execve`. LiveContainer implications,
appregistrard's separate role, platformization limits, exact artifact
provenance, and the next worker/daemon architecture are documented in
[`ARBITRARY_EXEC_STRATEGY.md`](ARBITRARY_EXEC_STRATEGY.md).

Never attach Frida to launchd/PID 1. Reproduce launchd-facing behavior in a
disposable project worker and inspect the real service through logs and other
non-mutating diagnostics.

## Updating an existing clone

```sh
git pull --ff-only
./Dopamine-CryptexBootstrap/setup.sh
```

The setup script resynchronizes the checked-in overlay while preserving the
ignored `cache`, `work`, and `out` directories in the generated upstream tree.

## Troubleshooting

### `missing ... cryptexctl.research`

Install the authorized Apple Security Research host tooling and verify the
absolute path shown in the prerequisites.

### `the iPhoneOS SDK is unavailable`

Select full Xcode for the shell:

```sh
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
xcrun --sdk iphoneos --show-sdk-path
```

Then rerun setup.

### `no valid code-signing identity` or `no unexpired development profile`

Open Xcode, sign in to the intended team, create an Apple Development
certificate, and build an automatically signed iOS app to the target device.
If multiple teams are present, use the signing overrides above.

### `no connected validated iOS 27 target found`

Unlock and reconnect the device, accept its trust prompt, and inspect:

```sh
xcrun devicectl list devices
```

Reserve `--allow-unverified-device` for reviewed porting work.

### Sileo installation fails

Confirm Developer Mode is enabled and that the selected provisioning profile
contains the connected device. Building an automatically signed app to that
device once in Xcode usually resolves registration and profile refresh issues.

### RemoteXPC reports `GOAWAY error 3`

[REDACTED: Related request, payload, or installation details omitted.]

### Cryptex personalization is rejected

[REDACTED: Related request, payload, or installation details omitted.]

### Sileo reports a missing APT `Packages` directory

Use the newest matched app/Cryptex pair and confirm the on-device acceptance
gates in the running-proof document. Treat a Featured-card
`Package Unavailable` message as a separate third-party repository configuration
issue.

## Repository contents

[REDACTED: Related request, payload, or installation details omitted.]

[REDACTED: Related request, payload, or installation details omitted.]

See
[`Dopamine-CryptexBootstrap/CryptexBootstrap/README.md`](Dopamine-CryptexBootstrap/CryptexBootstrap/README.md)
for the architecture, trust model, and lower-level workflow details.
