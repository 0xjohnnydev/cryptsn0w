# untitled

**Redacted source:** TSS request construction, personalization, and related
installation details are intentionally omitted. The files retain placeholders
for educational reference.

Private iPhone18,2 / iOS 27.0 (24A435) security-research workspace.

[REDACTED: Related request, payload, or installation details omitted.]

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

The Cryptex and its trust cache are nonpersistent. After reboot, the managed
Procursus tree remains at `/var/jb`; reconnect and remount a fresh Cryptex with:

```sh
./Dopamine-CryptexBootstrap/setup.sh --install
```

[REDACTED: Related request, payload, or installation details omitted.]

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
