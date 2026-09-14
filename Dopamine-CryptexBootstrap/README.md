# Dopamine Cryptex bootstrap overlay

**Redacted source:** TSS request construction, personalization, and related
installation details are intentionally omitted. The files retain placeholders
for educational reference.

[REDACTED: Related request, payload, or installation details omitted.]

From the repository root, the normal entry point is:

```sh
./Dopamine-CryptexBootstrap/setup.sh --install
```

Safer incremental modes are available:

```sh
./Dopamine-CryptexBootstrap/setup.sh          # host checks and preparation
./Dopamine-CryptexBootstrap/setup.sh --build  # host-only matched build
```

`setup.sh` installs missing build tools with an existing Homebrew installation,
creates the pinned Python virtual environment, fetches only the pinned
opa334/Dopamine commit, copies this overlay into the generated
`Dopamine-upstream` working tree, and auto-selects a valid local Apple
Development profile for `org.coolstar.SileoStore`. It also applies the pinned
RemoteXPC flow-control patch used for large Cryptex image transfers.

Pinned upstream:

- repository: `https://github.com/opa334/Dopamine.git`
- branch: `3.x`
- commit: `939a3a21400f0dc6d6163b2b5999ba2ace0d2732`

For a machine with multiple signing identities, optional overrides are
`CODEX_SILEO_DEVELOPMENT_IDENTITY`, `CODEX_SILEO_PROVISIONING_PROFILE`, and
`CODEX_SILEO_DEVELOPMENT_ENTITLEMENTS`. Run `setup.sh --help` for the device
guard and selection options.

[REDACTED: Related request, payload, or installation details omitted.]

The on-device repair path maintains Dopamine's standard Chariz, Havoc,
BigBoss, and ElleKit entries in
`/var/jb/etc/apt/sources.list.d/dopamine-default.sources`. Procursus remains the
bootstrap feed. The installer deploys the pinned repository keys, configures
BigBoss's verified legacy-signature compatibility, restores Procursus metadata,
synchronizes the trust-cached `launchctl` and `uiopen` executables, and refreshes
the complete repository set. Custom repository files remain available beside
the managed defaults.
