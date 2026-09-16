# iPhone 12 mini post-boot dynamic trust acceptance

## Result
[REDACTED: TSS/Cryptex personalization and installation details are redacted from this educational source release.]

The active Cryptex was version `1.0.20260916114900.304681`. Its 459-entry static
trust cache has SHA-256
`8169d76f92eac787331141543bfc055d0a6d0ca23d16b957b684fb4ce8d5013a`.
The installed runtime-trust helper has SHA-256
`f1bd95f5cc600a8df803e5655bcc2be709376bb4605ad49907bfd9d17739c187`
and CDHash `54cf4cce470a5cfec7711273c123a6fb929e1f4c`.

BrokerProbe 1.0.18 had these acceptance measurements:

- package SHA-256:
  `ebd11b5bbdba0249f8d6dc3dafa67a2a0f4d3a4c5ce695316cb1fc56207c50f9`;
- `BrokerProbe.dylib` arm64e CDHash:
  `19dcf02f0ddf1a82695426b50c1819d6739f861a`;
- the package copied to Sileo's container was read back byte-for-byte before
  installation; and
- all three package Mach-Os passed Apple's strict ad-hoc signature verification
  before packaging.

## Required fixes
[REDACTED: TSS/Cryptex personalization and installation details are redacted from this educational source release.]

The next probe used `ldid -S`. Although Security.framework could extract a
CDHash for trust-cache generation, Apple's verifier classified the output as
not signed, and dyld rejected the arm64e slice as `code signature invalid`.
Changing the test payloads to Apple's ad-hoc `codesign --sign -` output fixed
the image. Dynamic trust does not make a structurally unsigned or malformed
Mach-O valid; it authorizes a valid CodeDirectory without requiring a CMS
identity.

## Device evidence

The successful transaction logged:

```text
[REDACTED: Related request, payload, or installation details omitted.]
```

The independent final process query still showed SpringBoard PID 1751 at the
exact path `/System/Library/CoreServices/SpringBoard.app/SpringBoard`, together
with the Cryptex daemon and root broker. Re-flushing crash reports produced no
new SpringBoard report after the injection. Injector heartbeats remained
`safeMode=false`.

The earlier PID 1745 report is also diagnostic: its image list contains
`libinjector.dylib`, while its triggered frame is SpringBoard's own
`BKSDisplayServicesStart` assertion with `backboardd isn't running -- or we
couldn't talk to it`. That was an early respring/startup failure, not an AMFI
rejection of the injector. The final test avoided respring, required one exact
SpringBoard PID to remain unchanged for five seconds, and injected only then.

Raw evidence is preserved in
`findings/protected-dylib-1.0.17-20260916.log` and
`findings/crashreports/SpringBoard-2026-09-16-075727.ips`. The complete
reproducible appregistrard source delta is
`Patches/appregistrard-ios27-postboot-full.patch`.

## Scope

This proves a working post-boot dynamic trust-cache path for valid ad-hoc-signed
Mach-Os and proves one dynamically trusted dylib inside an Apple system binary.
It does not claim that completely unsigned or malformed files work. The package
executables still took the existing debugged-worker fallback because the spawn
interposer intentionally compares them with its static baseline; therefore this
run is not presented as direct main-image `execve` proof. The later clean-reboot
and automatic-replay acceptance is recorded in
`findings/iphone12mini-clean-reboot-runtime-trust-20260916.md`.
