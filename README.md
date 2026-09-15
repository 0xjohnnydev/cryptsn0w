# untitled

Private iOS 27 security-research workspace for the validated iPhone18,2
(24A435) and iPhone13,1 / iPhone 12 mini (24A437) lanes.

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

The installer requests cryptexd's persistent DDI settings. The latest recorded
iPhone 12 mini install used `persistence=2` and `noncePersistence=1` and
completed successfully. A separate clean-reboot acceptance pass has not yet
been captured, so treat reboot persistence as configured but not fully proven.
An install run generates a fresh Cryptex version and device-bound
personalization data; rerun it when changing fixed Cryptex contents or
recovering from an OS update, nonce roll, invalidated ticket, or damaged state.

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
- `findings/`: relocated-symlink finding documentation.

Build outputs are organized under `build/` and
`Dopamine-upstream/CryptexBootstrap/out/`. Rebuild and repersonalize the Cryptex
when changing its fixed trusted infrastructure or static baseline. The current
runtime design instead routes non-baseline package executables through the fixed
worker, but that package-install path still needs the BrokerProbe acceptance run
described above.

See
[`Dopamine-CryptexBootstrap/CryptexBootstrap/README.md`](Dopamine-CryptexBootstrap/CryptexBootstrap/README.md)
for the architecture, trust model, and lower-level workflow details.
