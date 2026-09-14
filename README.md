# untitled

Private iPhone18,2 / iOS 27.0 (24A435) security-research workspace.

The primary workflow builds a Dopamine 3.x Procursus/Sileo compatibility
environment, signs Sileo with the operator's own Apple Development profile,
personalizes a generic Cryptex1 through Apple's service, validates the complete
matched pair, and mounts the nonpersistent Cryptex on an eligible paired
device. A separate root-SSH proof of concept is also included. The expected
environment has the SRD host tools and Cryptex1 personalization eligibility.

## Validated configuration

- Device: iPhone18,2
- OS: iOS 27.0
- Build: 24A435
- Host: macOS with a full Xcode iPhoneOS SDK
- Upstream Dopamine: branch `3.x`, commit
  `939a3a21400f0dc6d6163b2b5999ba2ace0d2732`
- Python dependencies: pinned in `requirements.txt`

The default device guard selects this exact product, version, and build. Use the
documented override when deliberately porting to another configuration.

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

`setup.sh` installs missing `dpkg`, `ldid`, `ripgrep`, and `zstd` formulae
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
2. Creates `.venv` and installs the pinned Python requirements.
3. Fetches only the pinned opa334/Dopamine commit into the ignored
   `Dopamine-upstream` working tree.
4. Copies the checked-in Cryptex bootstrap overlay into that working tree.
5. Selects a matching local development certificate/profile and derives the
   minimal Sileo entitlements.
6. Downloads and hash-checks the pinned Procursus bootstrap.
7. Builds the generic Cryptex and its trust cache.
8. Builds the provisioned Sileo app paired to that exact Cryptex.
9. Verifies the working, Cryptex, and IPA copies of `giveMeRoot` have the same
   SHA-256.
10. Installs the provisioned app through the userspace tunnel.
11. Captures fresh device identifiers and a nonce, requests a Cryptex1 ticket,
    and verifies every returned ticket field and payload digest.
12. Runs a live validation, then installs the nonpersistent Cryptex and replaces
    a single older project Cryptex when one is present.

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

The generated upstream checkout, caches, tickets, IPAs, profiles, and run logs
stay in ignored work directories.

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
starts the root broker, performs `apt-get check`, and asks `uiopen` to launch
Sileo. Keep the device unlocked during this stage, then open Sileo manually if
needed.

Successful host-side run metadata is saved in the newest
`Dopamine-upstream/CryptexBootstrap/out/runs/<run-id>/flow-summary.json`.
Detailed on-device acceptance gates and the known-good run are documented in
[`RUNNING_PROOF_20260914.md`](Dopamine-CryptexBootstrap/CryptexBootstrap/RUNNING_PROOF_20260914.md).

The Cryptex and its trust cache are nonpersistent. After reboot, the managed
Procursus tree remains at `/var/jb`; reconnect and remount a fresh Cryptex with:

```sh
./Dopamine-CryptexBootstrap/setup.sh --install
```

The driver generates a fresh Cryptex version and fresh device-bound
personalization data for each run.

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

### `no connected, paired iPhone18,2 on iOS 27.0 (24A435) found`

Unlock and reconnect the device, accept its trust prompt, and inspect:

```sh
xcrun devicectl list devices
```

Reserve `--allow-unverified-device` for reviewed porting work.

### Sileo installation fails

Confirm Developer Mode is enabled and that the selected provisioning profile
contains the connected device. Building an automatically signed app to that
device once in Xcode usually resolves registration and profile refresh issues.

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
- `tools/atc-streamingzip-chain-static/`: source-only AirTraffic/StreamingZip
  research helpers.
- `findings/`: relocated-symlink finding documentation.

Generated device images, personalized tickets, signed IPAs, provisioning
profiles, logs, firmware images, virtual environments, caches, IDA databases,
and keys stay in ignored local paths. Rebuild and repersonalize the Cryptex to
add newly installed ad-hoc Mach-O files to its trust cache.

See
[`Dopamine-CryptexBootstrap/CryptexBootstrap/README.md`](Dopamine-CryptexBootstrap/CryptexBootstrap/README.md)
for the architecture, trust model, and lower-level workflow details.
