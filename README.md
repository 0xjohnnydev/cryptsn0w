# untitled

Private iPhone18,2 / iOS 27.0 (24A435) security-research workspace.

## Dopamine/Sileo quick start

On a Mac with full Xcode, the Security Research Device host tools, Homebrew,
and an Apple Development certificate/profile installed:

```sh
git clone https://github.com/0xjohnnydev/untitled.git
cd untitled
./Dopamine-CryptexBootstrap/setup.sh --install
```

The script fetches the pinned public opa334/Dopamine commit without its full
history, installs the pinned Python environment and any missing Homebrew build
tools, finds a compatible local development profile, builds a matched
Cryptex/Sileo pair, selects the connected paired iPhone, and runs the guarded
validate-then-install flow. It uses pymobiledevice3's userspace tunnel and does
not need `sudo`.

Use `./Dopamine-CryptexBootstrap/setup.sh` for a non-mutating host preflight or
`--build` for a host-only build. Device installation is guarded to iPhone18,2
on iOS 27.0 (24A435) unless `--allow-unverified-device` is explicitly passed.
Run `--help` for device selection and signing override options.

The device must be paired, unlocked when requested, in Developer Mode, and
eligible for the relevant Cryptex1 personalization service. The custom
Cryptex is nonpersistent and must be mounted again after a reboot.

## Contents

The repository contains:

- the original Cryptex-backed root SSH proof of concept in `Sources/`,
  `untitled.py`, and `build.sh`;
- the source-only Dopamine 3.x Procursus/Sileo compatibility overlay in
  `Dopamine-CryptexBootstrap/`;
- the AirTraffic/StreamingZip and generic Cryptex1 source tools used by the
  research in `tools/`;
- the relocated-symlink finding write-up in `findings/`.

Generated device images, personalized tickets, signed IPAs, provisioning
profiles, device logs, firmware images, virtual environments, caches, IDA
databases, and private keys are intentionally excluded. They can be rebuilt
or recaptured from the checked-in source.
