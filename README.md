# untitled

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
- [x] Generate, personalize, and load a Generic Cryptex1 `gtcd` trust cache
  after boot using Apple TSS, then inject its newly trusted BrokerProbe dylib
  into stable SpringBoard PID 1751 and observe the constructor in that same
  PID. This is the working compatibility fallback, not the no-TSS goal.
- [x] Persist accepted runtime `gtcd` caches in a nonce-bound, root-owned
  journal and replay them before broker/injector startup. After a full reboot,
  the exact Cryptex remounted and BrokerProbe loaded in new SpringBoard PID 37
  without another TSS request; heartbeats remained `safeMode=false`.
- [x] Execute newly generated native code in a debugger-authorized process and
  run patched Frida Interceptor/NativeFunction over native USB/RSD.
- [x] Reproduce the executable-page primitive in the installed on-device worker
  without requiring the Mac; the direct device probe completed
  `RW|COPY -> write -> RX`, observed effective protection `0x5`, and returned
  `42` from the generated AArch64 function.
- [x] Install BrokerProbe 1.0.18 through Sileo with package SHA-256
  `ebd11b5bbdba0249f8d6dc3dafa67a2a0f4d3a4c5ce695316cb1fc56207c50f9`;
  its fail-closed `postinst`, runtime trust load, protected-process injection,
  image-list check, and PID-matched constructor marker all passed.
- [x] Exclude launchd/PID 1 through explicit PID and executable-path guards.

Not yet proven:

- [ ] Admit a newly installed native tweak entirely on-device with Apple TSS
  unavailable. The current per-package `gtcd` path is TSS-backed. The local
  Dopamine mechanism instead appends cdhashes to the live TXM trust-cache list,
  but requires retained `kread`/`kwrite`/`kalloc`; this Cryptex root environment
  does not currently expose those primitives.
- [ ] Generalize the single passing BrokerProbe executable test to arbitrary
  package Mach-Os and full child-process semantics.
- [ ] Load a completely unsigned or structurally malformed dylib. The proven
  post-boot path accepts a valid Apple ad-hoc CodeDirectory without CMS; it does
  not make an invalid signature structurally valid.
- [ ] Demonstrate executable-page admission inside a system process that lacks
  `get-task-allow`; obtaining its task port and loading a trusted dylib do not
  prove that its newly generated native pages can execute.
- [ ] Provide transparent system-wide `execve`, complete Mach-O semantics, or
  arbitrary new entitlements for loaded payloads.

## Debugger/JIT boundary

Two independent TXM decisions explain the current behavior:

1. `AllowInvalidCode` authorizes the target address space. In the
   [exact 24A435 TXM](findings/txm-debug-region-24A435.md), developer mode is
   mandatory and the request then needs either
   `get-task-allow` on the target, or a caller with
   `research.com.apple.license-to-operate` while the device's security-research
   configuration is enabled. A separate development override exists but is not
   enabled by this retail configuration. Root, a task port, platform status, and
   a high diagnostic trust level are not substitutes for this state.
2. `AssociateDebugRegion` authorizes each executable COW region. Its caller
   needs `com.apple.private.cs.debugger`, and the target address space must
   already have TXM `allowsInvalidCode`. If this association is denied, XNU can
   remove execute permission while the outer protection operation still returns
   success.

That is the primitive working in this root environment now. The fixed
trust-cached worker spawns a `get-task-allow` child and attaches to it; XNU's
[`cs_allow_invalid`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_cs.c#L193-L245)
path establishes the child address-space state, and the debugger-entitled fixed
binary performs the page operations. Root launches and coordinates those
admitted components; it is not itself the executable-page authorization.

The public `vm_protect`/`mach_vm_protect` argument order is:

`task, address, size, set_maximum, new_protection`

The current public hook daemon uses that ABI order end to end. Its
[sender](Dopamine-upstream/BaseBin/libjailbreak/src/hookd.c#L104-L110) stores
`set_maximum` before `prot`, and its
[receiver](Dopamine-upstream/BaseBin/hookd/src/main.c#L71-L80) calls
`vm_protect(task, address, size, set_maximum, prot)`. The first public revision
containing this path already has the correct request layout.

The debugger-page probe also required the operation sequence `RW|COPY`, write
and flush, then RX; doing RX before the first `mach_vm_write` failed with
`KERN_INVALID_ADDRESS`. That is a real page-operation constraint, but it was
not opa's trust-cache "order" point. Upstream commit
`123eef3689c1610d3c3718646ece50b8354c6b90` changes SPTM/TXM trust-cache
insertion from the list head to the list tail, because TXM prepends signed
caches and cannot update the `prevptr` in Dopamine's read-only allocation. That
live-list insertion is the presently working no-TSS mechanism in a jailbreak
that retains kernel read/write; this root environment has not yet supplied the
required kernel/SPTM primitive.

The same distinction explains the remaining SpringBoard boundary. The fixed
worker presently satisfies both TXM decisions, but SpringBoard lacks
`get-task-allow`, and this retail device does not enable the security-research
configuration required by the LTO branch. Loading a trust-cached library and
obtaining its task port do not set TXM `allowsInvalidCode`. A kernel-assisted
stack can set that target state directly before routing page changes through its
debugger-entitled hook daemon; this Cryptex environment does not currently have
that kernel-write equivalent. The separate
[public ROP-injector documentation](https://github.com/opa334/opainject) also
warns that an arm64e target crashes when the injected dylib is absent from the
trust cache. The proven split is:

- debugger-authorized JIT and Frida inside the fixed `get-task-allow` worker;
- statically or dynamically trusted-library task-port/ROP injection into
  SpringBoard;
- no proof yet of arbitrary unsigned native execution inside SpringBoard.

The primary workflow builds a Dopamine 3.x Procursus/Sileo compatibility
environment, signs Sileo with the operator's own Apple Development profile,
personalizes a generic Cryptex1 through Apple's service, validates the complete
matched pair, and requests a persistent Cryptex install on an eligible paired
device. A separate root-SSH proof of concept is also included. The expected
environment has the SRD host tools and Cryptex1 personalization eligibility.

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

1. Checks the host tools, Xcode SDK, and SRD `cryptexctl`.
2. Creates `.venv`, installs the pinned Python requirements, and applies the
   checked-in RemoteXPC flow-control compatibility patch.
3. Fetches only the pinned opa334/Dopamine commit into the ignored
   `Dopamine-upstream` working tree.
4. Copies the checked-in Cryptex bootstrap overlay into that working tree.
5. Selects a matching local development certificate/profile and derives the
   minimal Sileo entitlements.
6. Downloads and hash-checks the pinned Procursus bootstrap and default tweak
   packages, then validates the ElleKit and BigBoss signing-key fingerprints.
7. Builds the generic Cryptex, managed repository configuration, and trust
   cache.
8. Builds the provisioned Sileo app paired to that exact Cryptex.
9. Verifies the working, Cryptex, and IPA copies of `giveMeRoot` have the same
   SHA-256.
10. Installs the provisioned app through the userspace tunnel.
11. Captures fresh device identifiers and a nonce, requests a Cryptex1 ticket,
    and verifies every returned ticket field and payload digest.
12. Runs a live validation, then requests the persistent Cryptex install and
    replaces a single older project Cryptex when one is present.

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
Dopamine-upstream/CryptexBootstrap/out/
├── build-summary.json
├── Sileo.brokered-<version>.ipa
├── sileo-brokered-<version>.json
├── unsigned/com.openai.codex.dopamine.bootstrap.cxbd/
└── runs/<run-id>/
    ├── device-context/
    ├── personalized/
    ├── validate.json
    ├── install.json
    └── flow-summary.json
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
The current iPhone 12 mini package and executable-page evidence is recorded in
[`iphone12mini-runtime-acceptance-20260915.md`](findings/iphone12mini-runtime-acceptance-20260915.md).

The installer requests cryptexd's persistent DDI settings. The latest recorded
iPhone 12 mini install used `persistence=2` and `noncePersistence=1`. A full
reboot then remounted the exact build and started its daemon, Sileo, and root
broker. The broker replayed the persisted runtime trust cache before starting
its injectors.
An install run generates a fresh Cryptex version and device-bound
personalization data; rerun it when changing fixed Cryptex contents or
recovering from an OS update, nonce roll, invalidated ticket, or damaged state.

## Current runtime status

The latest accepted iPhone 12 mini deployment is Cryptex version
`1.0.20260916131317.993376`. Its validated 459-entry static trust cache has
SHA-256
`4c8d76c52cfc0d111ce17e1b7ee9c0db12382b11ab34882a46965dc888db4c19`.
The installed runtime-trust helper has SHA-256
`3ed965eb83c6ca207b9fdb3366508fea20b8e6a1502fc025a82985d5002e58f0`
and CDHash `79f622d1933399a79df8da466fc91d0ec10cf778`.

BrokerProbe 1.0.18 then proved the separate post-boot payload-trust boundary.
The broker generated a three-entry runtime cache, TSS personalized its complete
`gtcd` IM4P against the persisted Generic Cryptex1 nonce, and AMFI loaded it
with status 0. The arm64e dylib CDHash
`19dcf02f0ddf1a82695426b50c1819d6739f861a` was absent from the static
baseline. Direct ROP `dlopen` into stable SpringBoard PID 1751 succeeded, the
image-list check returned true, and the dylib constructor emitted a PID-matched
marker. The same SpringBoard remained alive, no new crash report appeared, and
fresh heartbeats reported `safeMode=false`. PID 1 remained explicitly out of
scope. See
[`iphone12mini-postboot-dynamic-trust-20260916.md`](findings/iphone12mini-postboot-dynamic-trust-20260916.md)
for exact hashes, failure distinctions, and raw evidence links.

The follow-up full reboot proved the persistence half. The broker replayed the
root-owned journal with status 0 before becoming ready. BrokerProbe's CDHash was
still absent from the static cache; nevertheless its constructor ran in the new
SpringBoard PID 37, and no runtime-helper TSS or CFNetwork activity occurred
between boot and activation. See
[`iphone12mini-clean-reboot-runtime-trust-20260916.md`](findings/iphone12mini-clean-reboot-runtime-trust-20260916.md).

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

Rerun `./Dopamine-CryptexBootstrap/setup.sh --install`. Setup reapplies the
checked-in pymobiledevice3 flow-control patch before opening a userspace tunnel,
and the installer can reuse a still-current personalized run for diagnosis.

### Cryptex personalization is rejected

Reconnect and unlock the device, then rerun `--install` so setup captures a
fresh nonce. A persistent TSS rejection indicates an eligibility or
authorization problem to resolve with the configured research account/device.

### Sileo reports a missing APT `Packages` directory

Use the newest matched app/Cryptex pair and confirm the on-device acceptance
gates in the running-proof document. Treat a Featured-card
`Package Unavailable` message as a separate third-party repository configuration
issue.

## Repository contents

- `Sources/`, `build.sh`, and `untitled.py`: minimal Cryptex-backed root SSH
  proof of concept.
- `Dopamine-CryptexBootstrap/`: one-command setup and source overlay for the
  Dopamine 3.x Procursus/Sileo compatibility environment.
- `tools/cryptexd-static/`: generic Cryptex1 personalization and guarded install
  helpers.
- `tools/atc-streamingzip-chain-static/`: AirTraffic/StreamingZip
  research helpers.
- `findings/`: static-analysis and runtime evidence, including the TXM gates and
  current iPhone 12 mini acceptance record.

Build outputs are organized under `build/` and
`Dopamine-upstream/CryptexBootstrap/out/`. Rebuild and repersonalize the Cryptex
when changing its fixed trusted infrastructure or static baseline. The current
runtime design routes non-baseline package executables through the fixed worker;
the BrokerProbe unpack, root `postinst`, and root executable test passed. Newly
installed tweak dylibs still need an explicit trusted-payload or equivalent
dynamic-trust design before they can be injected into SpringBoard.

See
[`Dopamine-CryptexBootstrap/CryptexBootstrap/README.md`](Dopamine-CryptexBootstrap/CryptexBootstrap/README.md)
for the architecture, trust model, and lower-level workflow details.
