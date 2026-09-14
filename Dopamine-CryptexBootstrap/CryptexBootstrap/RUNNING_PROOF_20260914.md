# Sileo/Procursus running proof — 2026-09-14

Validated on an iPhone18,2 running iOS 27.0 build 24A435.

## Matched build

- Cryptex identifier: `com.openai.codex.dopamine.bootstrap`
- Cryptex version: `1.0.20260914213008.887224`
- trust-cache entries: 448
- trust-cache SHA-256:
  `62645d35a1d92ebf77513598f4a882ec7dcd4fca88cb88d41dfc84ecac5ffb09`
- Sileo bundle identifier: `org.coolstar.SileoStore`
- Sileo IPA SHA-256:
  `a802a941d8621da3b37c95c4282754c5d56dcfd95ba0d0241d78c7b021ecc7e8`
- Cryptex and IPA `giveMeRoot` SHA-256:
  `582931125417eb514d6e2a5d6aa611fa6371019de43238dcbc56504afdf753f3`
- every personalization and live-ticket check passed

## Replacement installation

The documented command completed successfully:

```sh
./Dopamine-CryptexBootstrap/setup.sh --install \
  --device <DEVICE_UDID> \
  --no-brew
```

The run replaced Cryptex version `1.0.20260914212439.794825`. The new image
transferred through a fresh userspace RemoteXPC session on attempt 1, and the
result contains `validated=true`, the exact expected identifier/version, and
all ticket checks set to true.

## On-device acceptance

- root installer marker: `result=success`
- effective installer UID: 0
- `uiopenExit=0`
- `/var/jb/.installed_dopamine`: root:wheel, mode 0644
- `dpkg --configure -a`: exit 0
- `apt-get check`: exit 0
- `sileoSystemRootBrokerReady=true`
- Sileo running as `mobile`
- Sileo root broker running as `root`
- `launchctl` and `uiopen` match their exact Cryptex trust-cache inputs

## Post-review source build

After the final error-path guard was added to the ElleKit compatibility helper,
the documented host-only command also completed successfully:

```sh
./Dopamine-CryptexBootstrap/setup.sh --build --no-brew
```

That build produced matched version `1.0.20260914213748.338261`, retained 448
trust-cache entries, compiled the helper for arm64 and arm64e, and verified that
the working, Cryptex, and IPA copies of `giveMeRoot` have the same SHA-256.

## Repository acceptance

Sileo has populated package indexes for the standard repository set:

- Procursus: 1,405,142-byte Packages index
- Chariz: 1,187,121-byte Packages index
- Havoc: 2,722,813-byte Packages index
- BigBoss: 205,035-byte Packages index
- ElleKit: 29,387-byte Packages index

The managed ElleKit and BigBoss keys are root-owned in
`/var/jb/etc/apt/trusted.gpg.d`. The source stanzas pin their primary
fingerprints, and APT debug output reports the pinned BigBoss `VALIDSIG` while
classifying its current SHA-1 digest as a compatibility warning.

## Evidence

- `out/runs/20260914T213034Z-45a42789/flow-summary.json`
- `out/runs/20260914T213034Z-45a42789/validate.json`
- `out/runs/20260914T213034Z-45a42789/install.json`
- `out/runs/20260914T213034Z-45a42789/personalized/summary.json`
- `out/build-summary.json`
- `out/sileo-brokered-1.0.20260914213008.887224.json`

This is the release acceptance record for the managed Procursus/Sileo
environment, root broker, standard repository set, and generic Cryptex1 trust
cache.
