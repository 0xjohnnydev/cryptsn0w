# Sileo/Procursus running proof — 2026-09-14

Validated on an iPhone18,2 running iOS 27.0 build 24A435.

## Matched build

[REDACTED: Related request, payload, or installation details omitted.]

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

[REDACTED: Related request, payload, or installation details omitted.]

[REDACTED: Related request, payload, or installation details omitted.]
