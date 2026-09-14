# Sileo/Procursus running proof — 2026-09-14

Device: iPhone18,2, iOS 27.0 build 24A435

UDID: `00008150-0018252C1130C01C`

Installed generic Cryptex:

- identifier: `com.openai.codex.dopamine.bootstrap`
- version: `1.0.20260914.52`
- trust-cache entries: 390
- trust-cache SHA-256:
  `acc88d59d60a251cf492b56e4fda818222bfb13c4acf6ccc04950e3b4684d5ce`
- personalization and every live ticket check passed
- v51 was the only Cryptex replaced; the Apple DDI and
  `com.0xjohnnydev.untitled` remained installed

Installed Sileo app:

- bundle identifier: `org.coolstar.SileoStore`
- signer: `Apple Development: John Franks (53Q8J86F3D)`
- team: `7LGY4NE2VM`
- profile validated by installation_proxy
- launcher artifact: `out/Sileo.brokered-v36.ipa`
- IPA SHA-256:
  `e2f7f5855605848cf4f1b69911436e868e5dbc90b764d98c110d8c6a64f5cf80`
- Cryptex and IPA `giveMeRoot` SHA-256:
  `51da46a319687feed9f3d26f5ae5ef783b35c0d4552868029fff106edd11d990`

Final v52 mount and launch at 08:48:

- `kernelPackageCompatibility=not-needed`
- `aptDependencyCheckExit=0`
- the registered `giveMeRoot` changed from mobile-owned `0644` to root-owned
  `0755` and passed the exact-byte check
- `sileoSystemRootBrokerReady=true`
- root installer logged `result=success`
- Sileo consumed six process-bound extensions
- `root broker preflight complete`
- the virtualized `giveMeRoot -> /var/jb/usr/bin/whoami` task exited 0
- Sileo opened and read the Procursus `Packages` index through `/var/jb`
- the Packages tab renders the Procursus updates and installed-package lists
  with no missing-folder alert

APT compatibility repair:

- the base archive's unresolved chain was
  `shshd -> libdimentio0 -> libkrw0 -> libkrw0-plugin`
- the generic-Cryptex lane deliberately does not impersonate a kernel-RW
  plugin provider
- a guarded one-time transaction removed only `shshd`, `libdimentio0`, and
  `libkrw0` after reverse-dependency and Essential/Protected checks
- the final root-side `apt-get check` returned 0

Evidence files:

- `out/validate-v52.json`
- `out/install-v52.json`
- `out/personalized-v52/summary.json`
- `out/sileo-brokered-v36.json`
- `out/device-run-20260914-0735/current-v52.png`
- `out/device-run-20260914-0735/packages-v52.png`
- `out/device-run-20260914-042951/bootstrap-v27.ndjson`
- `out/device-run-20260914-0735/sileo-process-v42.ndjson`

This proves a working root daemon plus Procursus/Sileo compatibility
environment. It does not claim Dopamine kernel hooks, a kernel-RW provider,
or tweak injection.
